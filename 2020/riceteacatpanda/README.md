## RiceTeaCatPanda
RiceTeaCatPanda is a beginner friendly CTF (Capture The Flag competition) that crosses a variety of random ideas and challenges to solve, including but not limited to cryptography, web, binary, forensics, general computer skills, data analysis, AI hacking, and talking!  

# **CRYPTOGRAPHY**

### HOOOOOOOOOOMEEEEEE RUNNNNNNNNNNNNN!!!!! 
#### Statement
AND JAKE IS ROUNDING THE BASES
HE PASSES BASE 32!!!
HE ROUNDS BASE 64!!!!!!!
WE'RE WITNESSING A MIRACLE!!!!!!!!!!!!!

Next base is base85  
__rtcp{uH_JAk3_w3REn't_y0u_4t_Th3_uWust0r4g3}__

### 15
After copy-pasting the encoded text in decode.fr using the monoalphabetic substitution we get the flag.  
__RTCP{C4R3FUL_W1TH_3X1F_D4T4}__

### Don't Give The GIANt a COOKie
Looking at the given value 69acad26c0b7fa29d2df023b4744bf07, it seems is a md5 hash. Using https://crackstation.net we got the string value chocolate mmm.  
__rtcp{chocolate mmm}__

### Pandas like salads
We are given a photo of a piece of paper with the pigpen cipher encoded flag. After mapping every symbol with it's english corespondant we can decode the flag ysay{hmkahr_qqgdia_unr_kw_yrq_pm_nnfb}. After reading carefully the challenge description we see the word CUTENESS written in capital letters, so this must be the key to decoding the flag. The first algorith that came into my mind was Vigenere, and this one was the correct one. After decrypting the flag we notice is still encoded wyhu{uisifx_xmtzqi_sty_gj_uzy_ns_ujsx} . This time i tried caesar because of the challenge name, and we got the plaintext.  
__rtcp{pandas_should_not_be_put_in_pens}__

### That's Some Interesting Tea(rs).......
We are given a base32 encoded text which decoded is: wvcpRLNKBz2zqpFs9UcrvLAgXjgwyquv4GbW2FXC9Y7ZW4dzkcZk9t7t3vSnjdUDUwBCVDZdj6XZ5xoTr6UXxbag1PrytSVoU5ZzCinrYsMJ7Aac8A8S7cJTmnbSs9PZHgEmRCkMir2WWYygs7SwESfbTV.
Which decoded from base58 is : BGJz4dCH0UuQZ2Q9vLExJUKcrvdIoYRwrspUSms5eRJoVc3WAztlKjjkEXDJuI1uqXQT3OdCcm8LjC12gR3Fd1EfZ2isyNxfe55MiOvz2DYGDb9dh
Which deocded from base62 is: RWNiZjFIWldwWEY+W0RfMFByVVEyKUssa0ghYllMMWdfdEVAVmRsPDFMRHRUQ2dWOXQwUVQkV0Y+R2FvRisi
Which deocded from base64 is: Ecbf1HZWpXF>[D_0PrUQ2)K,kH!bYL1g_tE@Vdl<1LDtTCgV9t0QT$WF>GaoF+".
Which decoded from base85 is the flag.  
__rtcp{th4t5_50m3_54lty_t34_1_bl4m3_4ll_th0s3_t34rs}__

### Wrong way
Take the data and base64 encoded it.The data looked like it was a wrong way decoded string from a base. The result is: RTcPUnEXPEcTEDpLAceS. Addapting it to the flag requirements is:  
__RTcP{UnEXPEcTED_pLAceS}__

###That's a Lot of Stuff . . .
The long String of values was decoded from HEX, then decoded from OCTal, the decoded from base64. Special to cyberchef who figure it to out to decode from hex, then oct.   
__rtcp{c0nv3rs10ns_ar3_4_c00L_c4ts}__


# **WEB**

### Robots. Yeah, I know, pretty obvious.

This name gives us a hint: to go to robots.txt page of the website, https://riceteacatpanda.wtf/robots.txt. Doing that we see 2 pages /flag and /robot-nurses. Going to flag we got rick-rolled and /robot-nurses gives us the flag.
__rtcp{r0b0t5_4r3_g01ng_t0_t4k3_0v3r_4nd_w3_4r3_s0_scr3w3d}__

### No Sleep

The page https://riceteacatpanda.wtf/onlyrealgamers only displays the countown, and flag will be revealed after the ending of the competiotion.
To get the flag i just modified the time on my computer to be N days later.  
__rtcp{w0w_d1d_u_st4y_up?}__

### Phishing for flags
We are given an archive of emails. After unzip it we have a few eml files. Looking through the files we find in GIVE ME BACK MY EYEHOLES.eml a link to https://riceteacatpanda.wtf/phisingemail . Going to this page we see the flag.
__rtcp{r34d_b3f0rE_yOU_C1iCk}__

### Uwu?
We are redirected through n pages to get to the uwustorage. I used burp suite to intercept all pages, and you-better-wash-your-rice has the flag.  
__rtcp{uwu_,_1_f0und_y0u}__

### Phishing for flags
We are given an archive of emails. After unzip it we have a few eml files. Looking through the files we find in GIVE ME BACK MY EYEHOLES.eml a link to https://riceteacatpanda.wtf/phisingemail . Going to this page we see the flag.
__rtcp{r34d_b3f0rE_yOU_C1iCk}__

### What's in the box
Just follow the hint. Add the image to the bookmarks and go to the pagethere is no page, but the source code. After analysing it we see some comments with parts of the flag. After putting it them together we get the flag.  
rtcp{k4wA1I_kitT3nz_4_tH3_w1N!!_41232345}

# **FORENSICS**

### BTS-Crazed
I downloaded the song and listed all the strings of the file. Using 'strings Save /Me.mp3 | grep 'rtcp' i could find the flag.
__rtcp{j^cks0n_3ats_r1c3}__

### Chugalug's Footpads
Given 2 pictures we need to find the differences between them. I used the xxd command to get hex dump of the 2 files, and then  i looked  for different characters in differences.txt to assemble the flag.

xxd left.png > left.txt
xxd right.png > right.txt
diff left.txt right.txt > differences.txt

Opening the differences.txt we look for differences between the lines and join the flag characters.
rtcp{Th3ze_^r3_n0TcH4nC1a5}

### Allergic College Application
I opened the given file with notepad++ and tried to validate the flag as the chinese characters, and it seems this was the expected thing to do.
__rtcp{我_只_修改_了_两_次}__

### cat chat
I converted the given string formed entirely from nya,meow and purr to morse code. The nya = ., meow = -, purr = /
After i got the text WAIT_WAIT_WHAT_THE_HECK_IS_GOING_ON_HERE, i headed to discord's catchat where i found dozens of chat talks. I copy-pasted the chat into a txt file, and i replaced the  nya,meow and purr to morse code and used decode.fr to decode the text. In the decoded text was the flag.  
__RTCP{TH15_1Z_A_C4T_CH4T_N0T_A_M3M3_CH4T}__

# **GENERAL SKILLS**

### Sticks and stones
We are given a huge file with possible flags and incomplete flags. The way i found it was to CRTF+F the _ (underscore).  
__rtcp{w0Rd5_HuRt_,_d0n'T_Bu11y_,_k1Dz}__

### Types of Rice and Cookies, Because Those Definitely Go Together Well
Just google types of web cookies. After you find the 3 main types check whick one of them is.  
__rtcp{persistent_cookies}__

### pandamonium
The long string of A had nothing to do with the flag. Thanks to a hint from discord which said is related to chemistry, I looked up the number values in the periodic table of elements, and took the elements name and joined them with the letters given. And added the needed _(underscore).  
__rtcp{PaNNeD_AmMoNiA}__

### Treeeeeeee
Looking at unziped archive we see lots of folders with sub-subfolders. I used the following command to list all the jpg files 
'find . -name  '*.jpg' -exec file {} \; '  and the i looked for an image which had a cat in it. The file with the flag was ENP92.jpg .
__rtcp{meow_sharp_pidgion_rice_tree}__

### Basic c4
It turns out is an encoding. Just took the file and drop it on thiss webite: http://www.cccc.io.
__rtcp{c42CW3TbiGhvptM36RJJ9ScctgkskjvZPo6dG8JexzZRvzQR6hwovZJLDkYK5pZ6cq9e7fX1ShUiYUdM7H1Uuqj64G}__

### Come eat Grandma
Just look at the history of version of the spreadsheet you'll se the file: "and oh, woah, a FLAG," which has the flag. I solved just thanks to the hint 'from historical reasons'.  
__rtcp{D0n't_E^t_Gr4NDmA_734252}__

# **MISC**

### Strong password

The password is the name of the ctf.  
__rtcp{rice_tea_cat_panda}__

