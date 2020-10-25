# EfiensCTF-Writeup
> Short write-ups for CTF Challenges from HCMUT Information Security club Efiens

2020's Efiens Member Recruitment Challenge includes 2 stages. This write-ups attempt to summarize the process of solving CTF challenges as well as relevant codes/ scripts used. Unless otherwise stated, all the files included in the repositories are written on the author's behalf. List of references are at the end, while noteworthy help, advice and suggestions are also mentioned in the write-ups. 

The challenges were hosted on Efiens' Website, [Efiens](https://ctf.efiens.com/challenges)

## Round 1
It is to be noted that "Unsolved" problems mean problems that I could not solve in the contest time. Some of this was eventually solved, which will be highlighted and have its own writeups deep down.

| **Category**      | **Name**                  | **Score**                                                                                                    | **Status**                                                
|--------------|------------------------------|-----------|-----------|     
| Linux | [grep](#grep) | 200 | Solved
| Linux | [Hide and Seek](#hide-and-seek) | 300 | Solved
| Linux | [git](#git) | 400 | Solved
| Linux | [nmap](#nmap) | 800 | Solved
| Linux | [env](#env) | 800 | Solved
| Linux | sudo -l | 1000 | Unsolved
| Web | [Treasure Seeker 1](#treasure-seeker-1) | 400 | Solved
| Web | [Treasure Seeker 2](#treasure-seeker-2) | 400 | Solved
| Web | [Slow Down](#slow-down) | 400 | Solved
| Web | [Local File Inclusion 101](#local-file-inclusion-101) | 500 | Solved
| Web | [Guess Flag](#guess-flag) | 600 | Solved
| Web | Dummy HTML Tester | 800 | Unsolved
| Web | Deserialization | 800 | Unsolved
| Web | Cạp Cạp Restaurant | 1000 | Unsolved
| Forensics | [noob keylogger](#noob-keylogger) | 1000 | Unsolved
| Forensics | [pro keylogger](#pro-keylogger) | 1000 | Unsolved
| RE | [Basic Android](#basic-android) | 250 | Solved
| RE | [Im so XORry](#im-so-xorry) | 500 | Solved
| RE | Easy to crack | 750 | Unsolved
| RE | [Doom](#doom) | 1000 | Unsolved
| Crypto | [Repeated](#repeated) | 400 | Solved
| Crypto | [JuSt_AnOtHeR_CrYpT0_ChALl](#just_another_crypt0_chall) | 600 | Unsolved
| Crypto | [Can you read this?](#can-you-read-this) | 1000 | Unsolved
| Pwn | [simple_bof](#simple_bof) | 250 | Solved
| Pwn | [advanced_bof](#advanced_bof) | 500 | Solved
| Pwn | [bank](#bank) | 750 | Solved
| Pwn | [login](#login) | 1000 | Unsolved


## Linux

### grep
This one is a simple introduction to the *grep* command of Linux which can be powerful in searching for patterns in a file. The provided file *flag.txt* on the site was a long text file with complicated characters, which proves difficulty in finding the flag by hand. 

Using *grep*, one could type
```
grep "efiens" flag.txt
```
to yield the string(s) containing the pattern specified, as well as neighboring characters. This proved to be enough to find the flag hidden in the text.

Flag: **efiensctf{warm_up_challenge}**



### Hide and Seek
This one was initially named *advanced grep*, which tells all about what you need to get another 300 trivial points. In this problem, the server folder is a complex hierarchy of folders nested inside, each with long and complicated name. This means brute-force searching for a *flag.txt* is unrealistic, therefore we have to adopt a better search method from grep - this time with an additional option *-r* to search for the pattern in every files in the structure. We perform the following command on the top-level folder:
```
grep -r "efiens" CQjctl
```
and obtain the flag **efiensctf{needle_in_a_haystack}**


### git
The server now introduces a folder containing only one file *flag.c*. However, the string containing the flag in the code is blank. As the title of the challenge suggested, we might think that the file *used to* have the flag, but the user has updated the code and committed the change to git. However, this provides a visible exploitation as we can view the git history (which is what it's known for). A simple command
```
git log -p
```
is enough to review the history of committed code, which reveal what the *flag* string used to be.
Flag: **efiensctf{use_git_for_tracking_changes}**


### nmap
Once again, the challenge title gives pretty much usable suggestion as to what we should do. The server folder is blank, and the only thing we can explore is the *nmap* command, which scans the locally available (open) ports at the server. These ports can tell us important information about the server, and the user itself. Initially I cannot find any open port outside the default 22 for ssh. Fortunately, the admin was kind and considerate enough to give a (possibly) game-ending suggestion, a suggestion that makes this 800-point challenge looks like a 400-point one. Apparently the usual *nmap* command only scans the first few thousand ports, while the total numbers of ports can go up to 65535. Therefore, we have to run
```
nmap -p- localhost
```
to actually scan all open port. The commands reveal another open port numbered 5041 was available for exploit. We use netcat to connect to this port
```
nc 45.77.254.247 5041
```
to reveal the flag **efiensctf{sc4n_p0rt}**


## Web


### Treasure Seeker 1
> First Hint: Browser Inspector

> Second Hint: HTML attribute: maxlength

A really simple problem that is also pretty popular amongst high school students about using Inspect Element, this one surprisingly took me hours to solve. As with any web exploitation, we started with viewing the web page source (Ctrl + U). However, I was too distracted to realize the unmissable comment *-- KEY: thisisKEY --* right in the beginning of the source. This is also the password that needs to be typed in the input field on the site. However, we can see the site's input is limited to length 6, which can easily be bypassed (contemporarily) by changing the HTML field of it to any value greater than 10 or smaller than 0 (or just straight up delete it). This proves to be enough to obtain the password, and the flag, which spells **efiensctf{n0thiNg_c4N_sT0p_H4ck3R!!!}**


### Treasure Seeker 2
A problem with the same point as the first Treasure Seeker. However, this one was more comprehensive and somewhat trickier in hindsight. The website now has two pages, one of which displays a game where upon clicking on a chest, you immediately open a file named *flag* (shown on the browser bar). However, this "flag" is nothing but a funny GIF. Nonetheless, the file name, *flag*, gives us some tips as what to do next - manipulating the extension. And by changing the extension field on the bar, which initially shows *treasure=flag&format=png* to *treasure=flag&format=txt*, we get the exact thing we wanted - a real flag. **efiensctf{Gg_w3lL_Pl4y_!_TH1S_1S_y0ur_Tr34s!!}**

### Slow down
> First hint: HTTP Status Code

> Second hint: Intercept HTTP

> Third hint: Intercept HTTP with Burp Suite or use Curl

The fact that this 400-point problem has 2 additional hints (costing 10 and 40 points, each) and still only has half the number of solves in comparison with *Treasure Seeker 2* indicates the notion of HTTP Interception was still quite new to most contestants. As suggested by the third hint, I used the commmand
```
curl 35.220.150.8:4443
```
to bypass the HTTP redirection and obtain the flag.


### Local File Inclusion 101
This one could be a probable advancement from Treasure Seeker 2, where we can explore files and folders available on the site to reveal subtle to substantial truths. The website has a tab named *Flag*, which echoes *You can get the flag.txt in "Root Directory"*. Apparently, the "flag" shown as the image in the bar's file inclusion field(*p=flag.php*) is only a file at the current web folder. The real *flag.txt* is located at the Root Directory, which can be several levels above the current folder. I was not really knowledgable at exploring the hierarchy on website, so I just spammed *../* additionally into the file inclusion field until the real flag appears. This proves to be successful after only three tries, as changing *p=flag.php* to *p=../../../flag.txt* is enough. 
Flag: **efiensctf{l0c4l_f1l3_1nclus10n_1s_b4s1c!}**


### Guess Flag
> Keywords: PHP, Type juggling

> Hint: PHP Type juggling : strcmp()

In this challenge, the site's source code is partially revealed right on the user interface to give us hints on what to do. As suggested by the hint, we can exploit the exceptions of the function *strcmp* on PHP to return True (even if it's not supposed to be so). After brief searching on Google, I discovered that *strcmp* and *strcasecmp* will return 1 when the compared variable is an array. Therefore, we will use F12 and change the field *name="flag"* in the input into *name="flag[]"*. This makes *strcasecmp* returns 1 along with the desired flag, as well as a useful warning
```
Warning: strcasecmp() expects parameter 1 to be string, array given in /var/www/html/index.php on line 23
```
Flag: **efiensctf{Y0h_gu3ss_1s_s0_fun}**


## Forensics

### noob keylogger
This is one of the challenges where my ineffective searching strategies costed me valuable points. The file provided by the drive attached was 2GB, which was huge enough to bar anyone from trying to bare-search the flag inside. However, after downloading, I discovered we can try using *grep* to find something useful in the 16 billion bits of dump memory. The command *grep "efiens" noob_keylogger.raw* didn't yield desirable result, however, as it only prints *Binary file matches* in the result. I was discouraged and unintelligent enough to ignore this apparently revealing result and try other ways, not realizing I can just simply modify the *grep* options to print out the matched strings from the binary file. Ultimately, this command works the finest in exploring the keylogged data from the dump:
```
strings noob_keylogger.raw | grep "efiens"
```
Turns out the keylogger records several Google search results involving the flag. I chose the longest matched result and pasted it into the browser to reveal the rightly formatted flag ASCII, which is **efiensctf{n0w_y0u_hav3_kn0wn_ab0ut_k3yl0gg3r}**

### pro keylogger
It is probable the challenge's author did not expect users to use *grep* or hex editor to solve these forensics challenges (they are both 1000-pointer items), since it just makes the two trivial and similar. The only difference is that now the pattern *"efiens"* seems to be complicated to search for. However, changing the pattern to
```
strings Pro_keylogger.raw | grep "ctf"
```
apparently yields the search result. Again, we use the Google search keylog data to reveal the flag as **efiensctf{k3yl0gg3r_w!th_rand0m_funct!0n}**

## Reverse Engineering

### Basic Android
This one was a piece of cake for anyone who has known about Android executable binary. The *.apk* extension allows user to reverse engineer using online tools quite easily and can provide valuable source code information if not protected carefully enough. For the provided *.apk* file, I use the online apk_to_java decompiler to produce the Java source code of the project (there are many other tools that can do this, including Visual Studio and even Github). After inspecting *MainActivity.Java*, we can discover the wanted flag.
Flag: **efiensctf{it_is_not_that_hard_right?}**


### Im so XORry
In this challenge, the C source for the password-checking part was given. At first glance, we can see that the flag must have a required length of 38. After that, the following code is provided to check every 38 characters of the password to match a certain pattern:
```
for (int i = 0; i < 19; i++)
{	
  input[0x25 - i] = input[0x25 - i] ^ input[seed[i]];
  input[seed[i]] = input[0x25 - i] ^ input[seed[i]];
  input[0x25 - i] = input[0x25 - i] ^ input[seed[i]];
}
if (strcmp(flag, input) != 0)
{
  puts("WRONG!!!!!");
  return 1;
}
```  
where *seed[]* is an array containing the permutation of 1 to 19, and *flag[]* is a 38-element array containing the anagram of our wanted flag. 

The first loop looks a bit complicated, but we can use the property of the XOR function: 
```
a^b = c => a^c = b && b^c = a
```
which, after applying to the three commands, reveal that it will swap the value of *input[0x25-i]* and *input[seed[i]]* after the operation. And this is also an important usage of XOR which can quickly swaps variable without declaring new temporaries. Knowing, we can add a brief code in the same source file
```
char ctf[38];
for (int i = 0; i < 19; i++){
    ctf[0x25 - i] = flag[seed[i]];
    ctf[seed[i]] = flag[0x25 - i];
}
for (int i = 0; i < 38; i++) printf("%c",ctf[i]);
```
to reveal the password. **efiensctf{bUT_7h0s3_XOr_aR3_th3_s4me!}** 


### doom
This is also a game where you try to kill the opponent by taking over its health. Apparently, this is not the goal of the challenge. Whatever we try to enter will eventually reveal ourselves as a fool. Therefore, knowing a fool I was, I decided to follow suggestions and download [Ghidra](https://ghidra-sre.org) to inspect the file in a better sense. Ghidra surprisingly performed really well on the binary, detailing a whole *Verify* function to assign the flag. In this function, the 10-element array for the first 10 characters was provided, while a second 10-element array is unknown. We also know that the function will check if the product of each corresponding element from the two array matches. With this knowledge, we can write a short code to find the next 10 elements and print them as characters together to form the passwords inside the brackets.

Flag: **efiensctf{y0u_Kn0w_y0u_w4n7_m3}**


## Crypto

### Repeated 
At first glance, the *chall.txt* file attached in the challenge contains base64 characters, which quickly prompted me to use a base 64 decoder. However, first attempt on using the decoder failed to show comprehensible flag - hence, we have to turn our attention to the challenge's title: repeated. From the suggestion and from several sources online, I learned that one can encode a text in base64 several times to improve security. Thus, we need an automatic script to loop the decoding and only stop until it discovers the pattern we wanted (*"efiens"*). A simple python script could be given as followed:
```

```
After about 35 loops, the pattern is finally found and we got the flag - as well as a lesson about repeated encoding.

Flag: **efiensctf{34sy_b4se64}**

### JuSt_AnOtHeR_CrYpT0_ChALl
This challenge gave us 3 *.txt* file, each of which obeys a popular cryptography pattern. In the first part, despite the fact that no clue was given, we could quickly deduce parts of the text to give some clue about the decoding rule. It was visible that this text *rsvrafpgs{* should translate to *efiensctf{*. We could easily see that this follows a Caesar cipher substitution rule, specifically with offset 13 (more commonly known as ROT_13). Using [dcode.fr](https://www.dcode.fr/rot-13-cipher), we obtain the first part of the flag as well as a key to the second part: *stronk*.

The second file did not look much difference from the first part, with several words in the text guessable as well as a part ending by *{* implying it should translate to *efiensctf*. The key provided in the first part, which was a multiple-char word, implied that we could use a more developed shifting rule: Vigenere Cipher. Again, using [dcode.fr](https://www.dcode.fr/vigenere-cipher) with key *STRONK*, we quickly received the second part of the flag as well as a hint to the third part: *RSA*.

RSA is a well known modern cryptography technique with several variants. In *part3.txt*, however, users were given a very large modulus *N*, a small *e = 3* and a long cipher text *c*. After some searching, I realized we could break the encryption using Wiener's attack to discover the message. However, my search for a script implementing this online was ineffective, and thus, I could not complete the challenge in time. Fortunately, after the contest, a fellow user of mine suggested the python script that could effectively solve the challenge. The script use *gmpy2* library and could be written as followed:
```
gs = gmpy2.mpz(c)
gm = gmpy2.mpz(n)	
ge = gmpy2.mpz(e)
root, exact = gmpy2.iroot(gs, ge)
print(hex(root))
```
where c, n, e were to be supplied as the input from *part3.txt*. After obtaining the hex, we can decode it into ASCII string and obtain the final part of the flag.

Flag: **efiensctf{Im4g1n3_us1ng_R0t13_4nd_V1g3n3r3_1n_2020_:PepeLaugh:}

### Can you guess this?
> First hint: a poem named "Hàn Tín điểm binh", which was inspired by the inauguration of the Chinese Remainder Theorem

> Second hint: apparently another poem implying using the Chinese Remainder Theorem, but with more clarity?

The challenge looked a little bit intimidating at first glance, but careful inspection on the attached code and output file could deduce the rule of encryption. From the code, we could see that the hidden *flag* (as a string) will be converted into decimal, where it would undergo a total of 4 modulus operation on 4 different large divisor (provided in the array *mystery*, which could also be found in the output), and joined (separated by space ' ') to form the output message - which spelled *Welcome to ^^ "EfiensCTF 2020" :)))*. From the source code, and from the given hint, we could foresee a way to find the original flag. We will split the output message into 4 strings listed in an array *r*, then converted each of them into long decimals. The Chinese Remainder theorem could then be performed with 4 known modulus operation (the divisors would be the *mystery* array, while the remainder would be the *r* array) and deduce the original dividend. The only problem then was to know how to split the message into the four strings. Although it seemed impossible to try every scenario, we could eliminate most cases by using the two rules:

> Each string in *r* must be separated by its neighboring string by a space, ' '

> The decimal-converted value of each *r* must be smaller than its respective divisor in *mystery*.

Using this, I came up to 2 feasible division pattern: *['Welcome','to ^^','"EfiensCTF','2020" :)))']* and *['Welcome','to','^^ "EfiensCTF','2020" :)))']*. Once again, using [dcode.fr](https://www.dcode.fr/chinese-remainder), we could see the second pattern yielding a comprehensible decimals which, after being decoded into ASCII string, will form the flag: **efiensctf{th3_th30r3m_th4t_m4d3_1n_ch1n@}**.

## PWN

### simple_bof
> Learn the correct way to "gets" in C

This "simple-titled" challenge was a nice introduction to buffer overflow exploitation. Reading *simple_bof.c*, we could see that the *flag* value was located right over the *name* value, which had an allocated size of 28. The *gets()* function used in the code could be exploited as an input with larger size than *name* would still be written on the memory and, thus, overwrite the *flag* value. For this challenge, we only need to input any string with a length greater than 28 (unless your 29th character is *'\0'*, which could be quite impossible to achieve by spamming the keyboard) and the *flag* value would be written with the 29th character's ASCII value. This was enough for the program to spit out the flag, either foolishly unintentional or ingeniously intentional in practice.

Flag: **efiensctf{d0_y0u_kn0w_wha7_15_b0f_n0w?}**


### advanced_bof 
> What can wrongly "gets" do?

This challenge requires a little bit more effort in inspecting the code. This time, the program would only spit out the flag if the 4-char-long *Code* variable located right above name has the value of *"DEAD"*. Knowing how the *gets()* naively overwrite anything inside the memory stack, we could simply overflow the input with 28th arbitrary characters, and have the 29th to 32nd characters inputted as *DEAD*. 

Flag: **efiensctf{k1ll1ng_7h3_c0d3_15_v3ry_3a5y}**

### bank 
> Hint: Integer overflow/underflow

In this challenge, the program attempts to encourage us to rob a bank via the terminal, which is both unrealistic and unethical. But that's exactly what every wanna-be hacker dream turns out, so we have the motivation to complete the challenge. From the program's instruction, our goal would be to cause the bank's money to go to zero by either robbing or depositing money from your source. The first option was definitely inappropriate for an undergraduate student, so we had to deposite money. Apparently, at each try we can deposit an integer value of money into the bank, which could not be larger than $1000. This seemed like we can only give money to the bank, until we realize we could enter a negative amount. And thus went the banking system bankrupt as a simple input sequence *"2 -30000"* was enough to get us the (virtual) money and the flag.

Flag: **efiensctf{1nt_0v3r7l0w_c4n_r0b_7h3_b4nk}**

### login 
In this challenge, the code was structured in a much more secure way in comparison with the 3 previous challenges. However, as suggested by the author, we could exploit the *strcmp* function vulnerability to overcome the system. Apparently, *strcmp* would only compare the two string char-by-char until the *\0* character is discovered (or until any mismatched character case happens). Knowing this, we could overcome the system by entering the string *"admin\0"* (to trick the first conditional into receiving the *"admin"* string) followed by a sequence of at least 35 other non-"\0" characters to overflow the *isAdmin* variable. However, the *\0* character is a special character and cannot be typed from the keyboard. From a pwn [source](https://drive.google.com/file/d/1v0fEIRDcWEOwziD-5byPzf0mYv-qJLQR/view) and suggestions from Discord, there were two ways we could achieve this: either by redirection or pipe. As we only wanted to enter a special character, pipe would be a neater choice. We could then use some commands such as an echo
```
echo -e "admin\0 1234567891123456789212345678931234" | nc 34.126.106.179 4400
```
or a python script
```
(python3 -c "print('admin\0'+'1'*35)") | nc 34.126.106.179 4400 
```
Flag: **efiensctf{l0g1n_5y573m_w17h0u7_pa55w0rd_0m3galul}**


## Round 1 Summary
Overall, I got a total of 7502 points from the contest (including all the solved problems, minus 50 points for the two hints in *Slow down*, and the 102 honorary points from the *MISC* section). It was my first ever CTF contest, and with limited knowledge and experience on the subject, I could tell this amount of points was quite decent. There were many regrettable unsolved challenges where I just missed a little more patience and critical thinking, while there were also some lucky guess that got me points faster than expected. It was also notable that I didn't use a lot of self-coding in this contest yet, and it should be desirable to improve this aspect in order to compete for round 2.

