---
layout: post
title: DEobfuscating WSHRAT
---
{::options parse_block_html="true" /}

## Sample Information

| SHA25 | SHA1 | MD5|
|---------|-------|------|
|058c764614c8b0b457852a71ab93b559f81abb9e13b7fc2d6c6a4962881bf062 | 550faad818bb76d01333f0469ea6e715feaef2f0 | a4e4a7b64b91de9bf076b0581e0604b9
 
## First Stage

The script starts by defining the **".proc()"** function and adding it as a method to the String[] type.
The function, once called will convert content to string and then perform eval().
This is used within the code to launch code saved as string.

![Pasted image 20230731230644](https://github.com/VenzoV/venzov.github.io/assets/107503502/2b03fab8-d709-498e-a51b-a99b3b8fb92a)

The second function defined in the same way is **".nan()"**. This code simply inverts the contents of an array of length 3.

![Pasted image 20230731230657](https://github.com/VenzoV/venzov.github.io/assets/107503502/7dfb461e-4e36-4b02-9e0d-5ceb653b3426)

Third function defines the the function **"turn()"** this is simply used to reverse a string. Nothing to special.

![Pasted image 20230731230715](https://github.com/VenzoV/venzov.github.io/assets/107503502/fbb15290-5192-4dfc-afef-944611701602)

The first array in which the **"turn()"** function is used is **"sH1n3k0N"**. The output can be obtained easily by just looking at the code, but for sanity sake we will use node to help with a neat output.


![image](https://github.com/VenzoV/venzov.github.io/assets/107503502/e1ee3760-2cea-4b8a-ae91-99aead691017)


``` 
Code:
var sH1n3k0N = [null,
("|tcejbOetaerC".turn() + "txeTdaeR".turn() + "|undefined|\x61\x64\x6F\x64\x62\x2E|" + "noitisoP|teSrahC".turn()).split("|").concat("epyT".turn(), "nepO".turn())
];

Values:
CreateObject,
ReadText,
undefined,
adodb.,
CharSet,
Position,
Type,
Open
 ```


Following the **"proc()"** function is used to run code saved as string. 
The code defines another function and stores into a variable.
This simply fetches the giant base64 blob that is in var **"s0fStu"**. 
A regex pattern is defined, which searches for {digit} and then a function is run.

The base64 encoded blob decodes to other JavaScript code, but it is broken, and misses some pieces. This is because towards the end of the file the substitution function is called on this array blob and the **{digits}** strings are changed.
Using node we can run a modified version of the file so that just these functions are called and print out the result to a file to get the second stage.
![Pasted image 20230731230519](https://github.com/VenzoV/venzov.github.io/assets/107503502/38f3234d-5ad8-435f-be26-8528fd59c878)

The rest of the code works with another array, but for now let's check the second stage.
## Second Stage

The second stage obfuscation is mainly based on large array of printable strings, represented as hex values. 
I wrote two little scripts:
1. Print the array of strings as readable chars. Nothing special
2. Use regex to swap the values of the array into the variables in the code

This should make the second stage more readable.
The content once this is done is huge and the file seems to contain PE files in base64. 
So there is quiet a lot of content to go through.

Array with hex values of strings:

![Pasted image 20230803001722](https://github.com/VenzoV/venzov.github.io/assets/107503502/835a000c-6edf-4d3a-83ff-38c97f7628ec)

Example of how array is used:

![Pasted image 20230803001800](https://github.com/VenzoV/venzov.github.io/assets/107503502/32c1bfc8-910b-4a7d-8f00-f162bc4cc51a)

Script used to substitute the array values into the variable referencing the array.

```js
import re
VmsIAAa = [array of strings decoded from original hex values]

with open("First_DataBlob_cleaned.js") as h:
	code = h.read()
	for i, value in enumerate(VmsIAAa):
		code = re.sub(fr"VmsIAAa\[{i}\]",repr(value),code)
print(code)
 ```

The initial array can be extracted and decoded with the following code:

```js
const fs = require('fs')
//VmsIAAa should be declared above as a variable, just copy and paste from the original script
data = JSON.stringify(VmsIAAa, null, 4)
// Write data in 'Output.txt' .
fs.writeFile('Output.txt', data, (err) => {
// In case of a error throw err.
if (err) throw err;
})
 ```

The code now is more readable and we can work through it:
![Pasted image 20230803002615](https://github.com/VenzoV/venzov.github.io/assets/107503502/47c7404f-3f2e-49a9-b4c9-fccbdf7df4cc)

The first function seems to retrieve the URL it will be calling to initially:
![Pasted image 20230803002945](https://github.com/VenzoV/venzov.github.io/assets/107503502/aaea85a6-8322-4e03-8901-fa561c88827a)

The code is very large and will take a look at it in another time and add part 2 if I am able to.
Since this first part was just to deobfuscate the initial sample.


## Notice

I am pretty sure that other analysts out there have done similar analysis. 
This work was more of a personal exercise to get brush up some skills and also to learn how to write better articles for the future.
This is by no means an extensive or new analysis that only I have performed. 

## References 

* https://bazaar.abuse.ch/sample/058c764614c8b0b457852a71ab93b559f81abb9e13b7fc2d6c6a4962881bf062/
* https://tria.ge/230730-h2n7hsgd99/behavioral2
* [JScript Deobfuscation - More WSHRAT (Malware Analysis) - YouTube](https://www.youtube.com/watch?v=XDAiS6KBDOs)
