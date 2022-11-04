---
layout: post
title: Gozi String Decryption
---


Sample Hash: 0a66e8376fc6d9283e500c6e774dc0a109656fd457a0ce7dbf40419bc8d50936
Sample link: https://bazaar.abuse.ch/sample/0a66e8376fc6d9283e500c6e774dc0a109656fd457a0ce7dbf40419bc8d50936/

![image](https://user-images.githubusercontent.com/107503502/199960818-6e4396c6-e6a0-494c-a37d-bc1f9f6b83c0.png)


Potentially Packed Sample:

Pestudio Data:
	• Fairly high entropy, 7.239
	• 32 bit file
	• Two extra sections, .crt & .erloc -> most likely due to packing activity. Not too sure.
	• Not many imports
	• Probable anti debugging by looking at functions.
	• No useful strings are found

![image](https://user-images.githubusercontent.com/107503502/199960883-23682ade-6826-404c-853b-ca9913cdb88e.png)

![image](https://user-images.githubusercontent.com/107503502/199960892-d2897ebf-3d23-4380-b4e0-686f6bcfac6d.png)

![image](https://user-images.githubusercontent.com/107503502/199960918-d8c5573d-1c89-4518-a8d4-9f504dc853ab.png)

![image](https://user-images.githubusercontent.com/107503502/199960925-d7748659-54a1-4d88-a519-1b877563f8b8.png)

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

![image](https://user-images.githubusercontent.com/107503502/199960958-9f3c4b7b-b371-49be-a29a-f3a15c29ac3a.png)

![image](https://user-images.githubusercontent.com/107503502/199960975-09fe3d63-5a63-49b4-b78c-93b96cddc9c5.png)

Second VirtualAlloc seems more promising, we get an mz header, and assume at this point that this is the unpacked code:

![image](https://user-images.githubusercontent.com/107503502/199961022-2c8146f9-9fe9-4e59-8b53-48f6f0f9e1a1.png)

We get more errors and the file does not seem to be able to be opened by pestudio and pe-bear.
So third virtual alloc:
![image](https://user-images.githubusercontent.com/107503502/199961062-63dd78cb-d1a6-4eec-b8c5-ecb1d49e92bb.png)

This seems to be better, but the file is mapped in memory. So we need to rebase it:

![image](https://user-images.githubusercontent.com/107503502/199961087-319bc195-f90d-4b9f-bddb-0eec9d8767d5.png)

Rebasing:

Raw Address = Virtual Address
Raw Size = virtualaddress([Section+1] - Section) where Section1 is .rdata and Section is .text. From there you basically subtract the next section rawsize from the current one.

Rdata - .text
.data - .rdata
Etc

Before:
![image](https://user-images.githubusercontent.com/107503502/199961120-74f109e8-c698-45a5-a8ea-d7220d5e9353.png)

After:
![image](https://user-images.githubusercontent.com/107503502/199961149-27097361-9992-44a6-bc3f-0674656efb73.png)

![image](https://user-images.githubusercontent.com/107503502/199961159-cbe48d70-8e60-4714-b937-2b84bde6818d.png)

So now imports are resolved, we can save and load into pestudio again.

Everything seems to load fine.

Another to get the unpacked file, is to run until VirtualProtect follow the first stack argument which is the original exectuable. The malware will substitute itself with the unpacked code.
Once this is done, we can dump out the sample.

![image](https://user-images.githubusercontent.com/107503502/199961193-3530300d-21c5-45f1-8f9e-97cfe249333f.png)



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
![image](https://user-images.githubusercontent.com/107503502/199961264-c82cea41-55e3-4507-a989-88500bbdcb6c.png)
![image](https://user-images.githubusercontent.com/107503502/199961271-e7f296aa-814c-4613-ac26-a672ca1466ae.png)
![image](https://user-images.githubusercontent.com/107503502/199961280-ff23ca74-03fb-420d-8683-4b7f8882e1f3.png)
![image](https://user-images.githubusercontent.com/107503502/199961286-df4751ff-0a69-4455-90f4-c859c88af037.png)

So to figura out what else is going on in the code, we expect that the headers are parsed, we will use the header structs to see what the constants are referencing.
We’ll need to import IMAGE_DOS_HEADER, IMAGE_NT_HEADERS, and IMAGE_SECTION_HEADER.

At the start of the function edx has the base address + the offset for the start of the PE header. From there we add the relative offsets and assign the right name of the header portion.

Example:

In the above code, we reached the section table already, so exc has the base for the Section Table.

![image](https://user-images.githubusercontent.com/107503502/199961319-061037f0-f51b-49e3-ac93-bde92e475a0d.png)
![image](https://user-images.githubusercontent.com/107503502/199961335-5c68e4a3-75d6-4d83-a889-d7639ac26375.png)

The next offset is 0x10 which from the image above, we see is SizeOfRawData

![image](https://user-images.githubusercontent.com/107503502/199961364-5bcce091-50cf-4fe1-a391-2bc70d3f3674.png)

So the whole block cleaned up will be:

![image](https://user-images.githubusercontent.com/107503502/199961387-2151477e-2d19-4181-946d-31a1863c5c01.png)
![image](https://user-images.githubusercontent.com/107503502/199961396-5890755e-6738-46b2-a365-5cd46a2f222b.png)

The function gets the VirtualAddress and SizeOfRawData of the .bss section, where are encrypted variables are located.

Checking out the code for this section and cleaning it up a bit, we see a potential decryption function. It seems to be using the campagn id (date) to generate a key, but also we need to figure out what a1 is.
So jumping back we find out where it is filled out.

![image](https://user-images.githubusercontent.com/107503502/199961418-037f229c-e29d-45d3-a975-5d2ebf38e4ef.png)
![image](https://user-images.githubusercontent.com/107503502/199961426-90a96e37-5112-4858-a196-6b3c17f688fa.png)
![image](https://user-images.githubusercontent.com/107503502/199961434-0cc9c4f4-5722-4c24-926d-1087a7dc63b0.png)
![image](https://user-images.githubusercontent.com/107503502/199961444-fdd1d776-adac-4bb0-98d8-8f1ef035eabb.png)

Key generation:

So the key is generated with the following:  key = VirtualAddressBSS + DWORD1 + DWORD 2 + [0-18] where the dword are the campaign id strings concatenated. 
The number 0-18 dervies from the system_time_0_18  var seen above - 1. We will have to test this out to figure out which is the correct number.

![image](https://user-images.githubusercontent.com/107503502/199961474-81a3629f-e9c7-45f5-81c6-b87d4df14803.png)

The decryption:

The following code need to convert DWORD to int and then back. The results should be always a 32 bit word.
To do this the result will be (n & 0xffffffff)  to yield a 32-bit number.

![image](https://user-images.githubusercontent.com/107503502/199961499-6d003cb5-dae2-4cbb-88fb-7128b6e261d7.png)

Retrieving .bss section:

![image](https://user-images.githubusercontent.com/107503502/199961540-6ff209ec-754b-42fb-a415-26b3fb268e2b.png)


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

![image](https://user-images.githubusercontent.com/107503502/199961640-76b3f399-118f-448e-951b-8f29c9d3a222.png)

























