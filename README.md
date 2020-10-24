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
