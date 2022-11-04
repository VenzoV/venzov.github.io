---
layout: post
title: Gozi String Decryption
---

Sample Hash: 0a66e8376fc6d9283e500c6e774dc0a109656fd457a0ce7dbf40419bc8d50936
Sample link: https://bazaar.abuse.ch/sample/0a66e8376fc6d9283e500c6e774dc0a109656fd457a0ce7dbf40419bc8d50936/

![image](https://user-images.githubusercontent.com/107503502/199960228-90a98d26-8e55-410e-b4ea-98c6140417f9.png)




OSINT:

//TODO


Potentially Packed Sample:

Pestudio Data:
	• Fairly high entropy, 7.239
	• 32 bit file
	• Two extra sections, .crt & .erloc -> most likely due to packing activity. Not too sure.
	• Not many imports
	• Probable anti debugging by looking at functions.
	• No useful strings are found











IDA  also has trouble loading the sample. So I will try to unpack the file with x32 dbg.
Considering OSINT sources and sandbox analysis we may have packed code, and also some shellcode involved which might be what's decrypting the unpacked code.


X32 Debug - Unpacking:

Breakpoints:
	•  bp VirtualProtect
	•  bp VirtualAlloc
	•  bp IsDebuggerPresent
	•  bp WriteProcessMemory
	•  bp createprocessinternalw

We will try to catch the VirtualAlloc to follow eax. This will be the region of memory that should be written to.

First Virtual Alloc






Second VirtualAlloc seems more promising, we get an mz header, and assume at this point that this is the unpacked code:



We get more errors and the file does not seem to be able to be opened by pestudio and pe-bear.
So third virtual alloc:


This seems to be better, but the file is mapped in memory. So we need to rebase it:



Rebasing:

Raw Address = Virtual Address
Raw Size = virtualaddress([Section+1] - Section) where Section1 is .rdata and Section is .text. From there you basically subtract the next section rawsize from the current one.

Rdata - .text
.data - .rdata
Etc

Before:



After:




So now imports are resolved, we can save and load into pestudio again.

Everything seems to load fine.

Another to get the unpacked file, is to run until VirtualProtect follow the first stack argument which is the original exectuable. The malware will substitute itself with the unpacked code.
Once this is done, we can dump out the sample.





Static Analysis:

The .bss section is for variables. Also this seems to have high entropy from PEstudio.

 A quick check on IDA we see some unk_* variables. By following the xrefs some are use in conjuction with LoadLibraryA and GetProcAddress.

None of the xrefs seems to be in a decryption function.

By analyzing further we can see that the sample will load the .bss section and decrypt all strings at once. Following the evidence of the method.

Going through the functions, it is possible to notice a string ".ssb" this is definitely refering to the .bss section.

We also see above the instruction mov ecx,[edx+0x3Ch]. 0x3C is the offset for the header e_lfanew which is basically the start of the PE header.

So the malware gets a reference to this header because it will need to go through the sections to find .bss section.

To further corroborate this hypothesis, we can trace back edx value, to make sure it is the base address. Going back we will see that edx will be equal to [bpb+hinstDLL] where per the msft

Documentation: 

A handle to the DLL module. The value is the base address of the DLL. The HINSTANCE of a DLL is the same as the HMODULE of the DLL, 
so hinstDLL can be used in calls to functions that require a module handle.










So to figura out what else is going on in the code, we expect that the headers are parsed, we will use the header structs to see what the constants are referencing.
We’ll need to import IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, and IMAGE_SECTION_HEADER.

At the start of the function edx has the base address + the offset for the start of the PE header. From there we add the relative offsets and assign the right name of the header portion.

Example:

In the above code, we reached the section table already, so exc has the base for the Section Table.





The next offset is 0x10 which from the image above, we see is SizeOfRawData




So the whole block cleaned up will be:


			


The function gets the VirtualAddress and SizeOfRawData of the .bss section, where are encrypted variables are located.

Checking out the code for this section and cleaning it up a bit, we see a potential decryption function. It seems to be using the campagn id (date) to generate a key, but also we need to figure out what a1 is.
So jumping back we find out where it is filled out.










Key generation:

So the key is generated with the following:  key = VirtualAddressBSS + DWORD1 + DWORD 2 + [0-18] where the dword are the campaign id strings concatenated. 
The number 0-18 dervies from the system_time_0_18  var seen above - 1. We will have to test this out to figure out which is the correct number.



The decryption:

The following code need to convert DWORD to int and then back. The results should be always a 32 bit word.
To do this the result will be (n & 0xffffffff)  to yield a 32-bit number.



Retrieving .bss section:



Now let's put everything together throwing in a regex for matching campaign dates:


import binascii, sys, pefile, re, struct

def decryptSection(stringData, stringKey):
    lastEncoded = 0
    decodedBytes = b""
    for i in range(0, len(stringData), 4):
        encodedBytes = struct.unpack("I", stringData[i:i+4])[0]
        if encodedBytes:
            decodedBytes += struct.pack("I", (lastEncoded - stringKey + encodedBytes) & 0xFFFFFFFF)
            lastEncoded = encodedBytes
        else:
            break
    return decodedBytes

def main():
    encryptedStrings = ""
    isfbBinary = open(sys.argv[1], "rb").read()
    print ("Analysing...")
    dateRegex = rb"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) ([0-9 ]){1,2} \d{4}"
    regexMatches = re.search(dateRegex, isfbBinary)
    if not regexMatches:
        print ("Failed to locate campaign date.")
        return 1
    campaignDate = isfbBinary[regexMatches.start():regexMatches.end()]
    print ("Campaign Date:", campaignDate)
    pe = pefile.PE(data=isfbBinary)
    for section in pe.sections:
        if b".bss" in section.Name:
            print ("Located encrypted string blob.")
            bssVirtualAddress = section.VirtualAddress
            bssFileAddress = section.PointerToRawData
            encryptedStrings = isfbBinary[section.PointerToRawData:section.PointerToRawData + section.SizeOfRawData]
    if not encryptedStrings:
        print ("Failed to find encrypted string blob.")
        return 1

    keyPart1 = struct.unpack("<I", campaignDate[0:4])[0]
    keyPart2 = struct.unpack("<I", campaignDate[4:8])[0]
    stringKey = keyPart1 + keyPart2 
    stringKey += bssVirtualAddress
    stringKey += 18
    print ("String Key:", hex(stringKey))
    decryptedBytes = decryptSection(encryptedStrings, stringKey)
    print ("Decrypted strings.")
    finalBinary = isfbBinary[:bssFileAddress] + decryptedBytes + isfbBinary[bssFileAddress + len(decryptedBytes):]
    open("decoded.bin", "wb").write(finalBinary)

if __name__ == '__main__':
    main()


Once we launch the script with our .bin we get the same .bin but with the .bss section modifed.



![image](https://user-images.githubusercontent.com/107503502/199960169-217ba5ee-02e1-4a6c-b209-fccffc0d2614.png)
