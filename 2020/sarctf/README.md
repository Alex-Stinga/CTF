## Sarctf  

Sarctf  by Saratov State University is a beginner-medium ctf, but mostly beginner, with the Sherlock Holmes theme. I also like the Sherlock Holmes movies and books
so this ctf which was a bit different, in a nostalgic way, from the rest i played. I liked that it didn't have a pwn category because i suck 
at it, and i don't have the patience to analyze the problem and find ways to solve it.  
In this one i liked very much the forensics category because i learned so much about how to use Wireshark, and also how to make a screen capture
in Windows.


# **FORENSICS**

### Blogger


We are given a pcap file which seems to contain data captured from a wireless keyboard.
Analazing the pcap we notice that each packet has one character. Each character is kept in the Leftover Capture Data section of some of the packets.  
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/sarctf/blogger/sarctf_blogger_2.png)

To assemble the characters captured we need to get those values from the Wireshark, convert them to ascii and assemble the flag.
To get those values we need to Right Click on the Leftover Capture Data section and select Add as columns. To save the data to a file go to File -> Packet Dissections -> Save as CVS
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/sarctf/blogger/sarctf_blogger1.png)

After removing all other colums than Leftovers, we have only the values [keystrokes.cvs](https://github.com/Alex-Stinga/CTF/blob/master/2020/sarctf/blogger/keystrokes.cvs).  
Using the following script we can decode the characters and assemble the flag.  

```python
#!/usr/bin/python

newmap = {
2: 'PostFail',
4: 'a',
5: 'b',
6: 'c',
7: 'd',
8: 'e',
9: 'f',
10: 'g',
11: 'h',
12: 'i',
13: 'j',
14: 'k',
15: 'l',
16: 'm',
17: 'n',
18: 'o',
19: 'p',
20: 'q',
21: 'r',
22: 's',
23: 't',
24: 'u',
25: 'v',
26: 'w',
27: 'x',
28: 'y',
29: 'z',
30: '1',
31: '2',
32: '3',
33: '4',
34: '5',
35: '6',
36: '7',
37: '8',
38: '9',
39: '0',
40: 'Enter',
41: 'esc',
42: 'del',
43: 'tab',
44: 'space',
45: '-',
47: '[',
48: ']',
56: '/',
57: 'CapsLock',
79: 'RightArrow',
80: 'LetfArrow'
}

#read the file
with open('keystrokes.cvs', 'r') as myKeys:
	content = myKeys.readlines()
		
for line in content:
	bytesArray = bytearray.fromhex(line.strip())
	# print(bytesArray)
	for byte in bytesArray:
		if byte != 0:
			keyVal = int(byte)		
			# print(byte)

			if keyVal in newmap:
				if newmap[keyVal] != 'PostFail':
					if newmap[keyVal] == 'space':
						print(' ')
					else:
						print(newmap[keyVal])
			else:
				print('No map found for this value:',str(keyVal))

#sherlock john and henry then visit the hollow in the hope of finding the hound on the way john notices what seems to be flag 
# flag{like_a_b100dh0und}

```
#### Useful links
This article helped me to solve the challenge, and was very well presented. I took the python code and adapted a little bit.
https://medium.com/@ali.bawazeeer/kaizen-ctf-2018-reverse-engineer-usb-keystrok-from-pcap-file-2412351679f4  

https://ask.wireshark.org/question/4641/how-to-activate-leftover-capture-data/  

https://osqa-ask.wireshark.org/questions/45128/export-wireshark-capture-to-csv-or-excel-file  


# **REV**

### Doc Holmes

We are given some.file, on which i applied the file command and seems to be a Microsoft word file. I used binwalk on it and i got a few image files. After extracting them, one of them contained the flag.

![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/sarctf/doc_holmes/doc%20hlmes.jpg)

FLAG{PrOMinentPlace}


### Crossw0rd

This one was very fun. I just had to jump from function to function and assemble the flag.
	1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28
F	L A  G { 3 a 5 y r  3  v  3 r  5  i  n  g  }

FLAG{3a5yr3v3r5ing}

### Deep dive

We are given an archive which contains another archive ... and so on. I didn't solved this challenge during the ctf. The following scipt is from ctftime. I just want to keep it here because it might be helpful sometime. 

```bash
#!/bin/bash
while true;do

ftype=$(file flag.txt)

if [[ $ftype == *"XZ"* ]]; then
		echo "[+] XZ"
		mv flag.txt flag.txt.xz; tar xf flag.txt.xz
fi

if [[ $ftype == *"gzip"* ]]; then
		echo "[+] gzip"
		mv flag.txt flag.txt.gz; gzip -d -f flag.txt
fi


if [[ $ftype == *"Zip"* ]]; then
		echo "[+] zip"
		echo A | unzip flag.txt
fi


if [[ $ftype == *"POSIX tar"* ]]; then
		echo "[+] POSIX tar"
		tar xf flag.txt
fi


if [[ $ftype == *"bzip2"* ]]; then
		echo "[+] bzip2"
		bzip2 -d flag.txt; mv flag.txt.out flag.txt
fi


if [[ $ftype == *"ASCII"* ]]; then
		echo "[+] ASCII"
		cat flag.txt; break
fi


done


```
FLAG{matri0sha256}

# **STEGO**

### Resher

I didn't solve this one during the ctf, so the following solve is borrowed from other team. I found this writeup very useful because i can modify this file smartly.

cat flag_there_original.jpg | python -c 'import sys; data=sys.stdin.read(); data=data.replace(b"\xE0\x01",b"\xFF\x01", 3); sys.stdout.write(data)' >out.jpg

FLAG{G0OD_s3E!}

![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/sarctf/reSHER/flag_there_original.jpg)
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/sarctf/reSHER/out.jpg)


### Red king

I used zsteg and i got only the first part from the initial text, so that means the information was written the other way. To solve this challenge i used Stegsolve.jar with the red channel, lsb , and column extraction. 

I chosed the red cannel because 'red king' was an indicative to the color channel, lsb because the image didn't seemed to be noisy or modified and column because i got the first part of it using zsteg. The zsteg result that guided me was zsteg m0r1ar7y.png b1, r, lsb, yx.

To extract the hidden message, in Stegsolve.jar go to  Analyse -> Data Extract.
Looking through other writeups i find someone used https://georgeom.net/StegOnline/upload which seems a great tool i may be using in the future.

![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/sarctf/red_king/m0r1ar7y.png)

FLAG{who_is_moriarty}


# **CRYPTO**

### Invitation

I was given a pdf file which contained dancing man encoded text. I decoded it uding decode.fr and a lot of time.

![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/sarctf/invitation/dancing.png)

It was indeed like old times when at that hour I found myself seated beside him in a hansommy revolver in my pocket and the thrill of adventure in my heart Holmes was cold and 
stern and silent As the gleam of the street lamps flashed upon his austere features I saw that his brows were drawn down in thought and his thin lips compressed I knew not
what wild beast we were about to hunt town in the dark jungle of criminal London but I was well as sured from the bear in gof this master hunts man flag disco in Saratov that the 
adventure was a most grave one while the sardonic smile which occasionally broke through his ascetic gloom boded little good for the object of our quest

FLAG{disco_in_Saratov}

# **MISC**

### True Detective

We are given a link to a google form to complete. This form has a photo of a street or store in London which has the name erased from it and we need to find out what the text is. I solved this challenge by opening the source of the page and  found the flag scattered. All i did was to asseble the flag.

FLAG{08c49c3d9ae88983437729747bcf1be8}
