# EfiensCTF-Writeup
> Short write-ups for CTF Challenges from HCMUT Information Security club Efiens

2020's Efiens Member Recruitment Challenge includes 2 stages. This write-ups attempt to summarize the process of solving CTF challenges as well as relevant codes/ scripts used. Unless otherwise stated, all the files included in the repositories are written on the author's behalf. List of references are at the end, while noteworthy help, advice and suggestions are also mentioned in the write-ups. 

The challenges were hosted on Efiens' Website, [Efiens](https://ctf.efiens.com/challenges)

## Round 1
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

### Linux

#### grep
This one is a simple introduction to the *grep* command of Linux which can be powerful in searching for patterns in a file. The provided file *flag.txt* on the site was a long text file with complicated characters, which proves difficulty in finding the flag by hand. 

Using *grep*, one could type
```
grep "efiens" flag.txt
```
to yield the string(s) containing the pattern specified, as well as neighboring characters. This proved to be enough to find the flag hidden in the text.

Flag: **efiensctf{warm_up_challenge}**



#### Hide and Seek
This one was initially named *advanced grep*, which tells all about what you need to get another 300 trivial points. In this problem, the server folder is a complex hierarchy of folders nested inside, each with long and complicated name. This means brute-force searching for a *flag.txt* is unrealistic, therefore we have to adopt a better search method from grep - this time with an additional option *-r* to search for the pattern in every files in the structure. We perform the following command on the top-level folder:
```
grep -r "efiens" CQjctl
```
and obtain the flag **efiensctf{needle_in_a_haystack}**


#### git
The server now introduces a folder containing only one file *flag.c*. However, the string containing the flag in the code is blank. As the title of the challenge suggested, we might think that the file *used to* have the flag, but the user has updated the code and committed the change to git. However, this provides a visible exploitation as we can view the git history (which is what it's known for). A simple command
```
git log -p
```
is enough to review the history of committed code, which reveal what the *flag* string used to be.
Flag: **efiensctf{use_git_for_tracking_changes}**


#### nmap
Once again, the challenge title gives pretty much usable suggestion as to what we should do. The server folder is blank, and the only thing we can explore is the *nmap* command, which scans the locally available (open) ports at the server. These ports can tell us important information about the server, and the user itself. Initially I cannot find any open port outside the default 22 for ssh. Fortunately, the admin was kind and considerate enough to give a (possibly) game-ending suggestion, a suggestion that makes this 800-point challenge looks like a 400-point one. Apparently the usual *nmap* command only scans the first few thousand ports, while the total numbers of ports can go up to 65535. Therefore, we have to run
```
nmap -p- localhost
```
to actually scan all open port. The commands reveal another open port numbered 5041 was available for exploit. We use netcat to connect to this port
```
nc 45.77.254.247 5041
```
to reveal the flag **efiensctf{sc4n_p0rt}**


### Web


#### Treasure Seeker 1
A really simple problem that is also pretty popular amongst high school students about using Inspect Element, this one surprisingly took me hours to solve. As with any web exploitation, we started with viewing the web page source (Ctrl + U). However, I was too distracted to realize the unmissable comment *-- KEY: thisisKEY --* right in the beginning of the source. This is also the password that needs to be typed in the input field on the site. However, we can see the site's input is limited to length 6, which can easily be bypassed (contemporarily) by changing the HTML field of it to any value greater than 10 or smaller than 0 (or just straight up delete it). This proves to be enough to obtain the password, and the flag, which spells **efiensctf{n0thiNg_c4N_sT0p_H4ck3R!!!}**


#### Treasure Seeker 2
A problem with the same point as the first Treasure Seeker. However, this one was more comprehensive and somewhat trickier in hindsight. The website now has two pages, one of which displays a game where upon clicking on a chest, you immediately open a file named *flag* (shown on the browser bar). However, this "flag" is nothing but a funny GIF. Nonetheless, the file name, *flag*, gives us some tips as what to do next - manipulating the extension. And by changing the extension field on the bar, which initially shows *treasure=flag&format=png* to *treasure=flag&format=txt*, we get the exact thing we wanted - a real flag. **efiensctf{Gg_w3lL_Pl4y_!_TH1S_1S_y0ur_Tr34s!!}**


#### Local File Inclusion 101
This one could be a probable advancement from Treasure Seeker 2, where we can explore files and folders available on the site to reveal subtle to substantial truths. The website has a tab named *Flag*, which echoes *You can get the flag.txt in "Root Directory"*. Apparently, the "flag" shown as the image in the bar's file inclusion field(*p=flag.php*) is only a file at the current web folder. The real *flag.txt* is located at the Root Directory, which can be several levels above the current folder. I was not really knowledgable at exploring the hierarchy on website, so I just spammed *../* additionally into the file inclusion field until the real flag appears. This proves to be successful after only three tries, as changing *p=flag.php* to *p=../../../flag.txt* is enough. 
Flag: **efiensctf{l0c4l_f1l3_1nclus10n_1s_b4s1c!}**


#### Guess Flag
> Keywords: PHP, Type juggling

> Hint: PHP Type juggling : strcmp()

In this challenge, the site's source code is partially revealed right on the user interface to give us hints on what to do. As suggested by the hint, we can exploit the exceptions of the function *strcmp* on PHP to return True (even if it's not supposed to be so). After brief searching on Google, I discovered that *strcmp* and *strcasecmp* will return 1 when the compared variable is an array. Therefore, we will use F12 and change the field *name="flag"* in the input into *name="flag[]"*. This makes *strcasecmp* returns 1 along with the desired flag, as well as a useful warning
```
Warning: strcasecmp() expects parameter 1 to be string, array given in /var/www/html/index.php on line 23
```
Flag: **efiensctf{Y0h_gu3ss_1s_s0_fun}**


### Forensics

#### noob keylogger
This is one of the challenges where my ineffective searching strategies costed me valuable points. The file provided by the drive attached was 2GB, which was huge enough to bar anyone from trying to bare-search the flag inside. However, after downloading, I discovered we can try using *grep* to find something useful in the 16 billion bits of dump memory. The command *grep "efiens" noob_keylogger.raw* didn't yield desirable result, however, as it only prints *Binary file matches* in the result. I was discouraged and unintelligent enough to ignore this apparently revealing result and try other ways, not realizing I can just simply modify the *grep* options to print out the matched strings from the binary file. Ultimately, this command works the finest in exploring the keylogged data from the dump:
```
strings noob_keylogger.raw | grep "efiens"
```
Turns out the keylogger records several Google search results involving the flag. I chose the longest matched result and pasted it into the browser to reveal the rightly formatted flag ASCII, which is **efiensctf{n0w_y0u_hav3_kn0wn_ab0ut_k3yl0gg3r}**

#### pro keylogger
It is probable the challenge's author did not expect users to use *grep* or hex editor to solve these forensics challenges (they are both 1000-pointer items), since it just makes the two trivial and similar. The only difference is that now the pattern *"efiens"* seems to be complicated to search for. However, changing the pattern to
```
strings Pro_keylogger.raw | grep "ctf"
```
apparently yields the search result. Again, we use the Google search keylog data to reveal the flag as **efiensctf{k3yl0gg3r_w!th_rand0m_funct!0n}**

### Reverse Engineering

#### Basic Android
This one was a piece of cake for anyone who has known about Android executable binary. The *.apk* extension allows user to reverse engineer using online tools quite easily and can provide valuable source code information if not protected carefully enough. For the provided *.apk* file, I use the online apk_to_java decompiler to produce the Java source code of the project (there are many other tools that can do this, including Visual Studio and even Github). After inspecting *MainActivity.Java*, we can discover the wanted flag.
Flag: **efiensctf{it_is_not_that_hard_right?}**


#### Im so XORry
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


#### doom
This is also a game where you try to kill the opponent by taking over its health. Apparently, this is not the goal of the challenge. Whatever we try to enter will eventually reveal ourselves as a fool. Therefore, knowing a fool I was, I decided to follow suggestions and download Ghidra to inspect the file in a better sense. Ghidra surprisingly performed really well on the binary, detailing a whole *Verify* function to assign the flag. In this function, the 10-element array for the first 10 characters was provided, while a second 10-element array is unknown. We also know that the function will check if the product of each corresponding element from the two array matches. With this knowledge, we can write a short code to find the next 10 elements and print them as characters together to form the passwords inside the brackets.

Flag: **efiensctf{y0u_Kn0w_y0u_w4n7_m3}**
