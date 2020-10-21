# EfiensCTF-Writeup
> Short write-ups for CTF Challenges from HCMUT Information Security club Efiens

2020's Efiens Member Recruitment Challenge includes 2 stages. This write-ups attempt to summarize the process of solving CTF challenges as well as relevant codes/ scripts used. Unless otherwise stated, all the files included in the repositories are written on the author's behalf. List of references are at the end, while noteworthy help, advice and suggestions are also mentioned in the write-ups. 

The challenges were hosted on Efiens' Website, [Efiens](https://ctf.efiens.com/challenges)

## Round 1
| **Category**      | **Name**                  | **Score**                                                                                                    | **Status**                                                
|--------------|------------------------------|-----------|-----------|     
| Linux | [grep](#grep) | 200 | Solved
| Linux | Hide and Seek | 300 | Solved
| Linux | git | 400 | Solved
| Linux | nmap | 800 | Solved
| Linux | env | 800 | Solved
| Linux | sudo -l | 1000 | Unsolved
| Web | Treasure Seeker 1 | 400 | Solved
| Web | Treasure Seeker 2 | 400 | Solved
| Web | Slow Down | 400 | Solved
| Web | Local File Inclusion 101 | 500 | Solved
| Web | Guess Flag | 600 | Solved
| Web | Dummy HTML Tester | 800 | Unsolved
| Web | Deserialization | 800 | Unsolved
| Web | Cạp Cạp Restaurant | 1000 | Unsolved

### Linux Round 1 Writeups

#### grep
This one is a simple introduction to the *grep* command of Linux which can be powerful in searching for patterns in a file. The provided file *flag.txt* on the site was a long text file with complicated characters, which proves difficulty in finding the flag by hand. 

Using *grep*, one could type
```
grep "efiens" flag.txt
```
to yield the string(s) containing the pattern specified, as well as neighboring characters. This proved to be enough to find the flag hidden in the text.

*Flag*: efiensctf{warm_up_challenge}

