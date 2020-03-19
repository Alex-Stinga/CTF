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


# **MISC**

### True Detective

We are given a link to a google form to complete. This form has a photo of a street or store in London which has the name erased from it and we need to find out what the text is. I solved this challenge by opening the source of the page and  found the flag scattered. All i did was to asseble the flag.

FLAG{08c49c3d9ae88983437729747bcf1be8}
