# EfiensCTF-Writeup-Round-2
> Short write-up for CTF Problems from Efiens CTF 2020 Round 2

EfiensCTF 2020, organized and hosted by HCMUT Information Security club [Efiens](https://blog.efiens.com), is the entrance competition for recruiting new members in our university for this year. The CTF includes 2 rounds, which took place on 17/10 and 12/12, respectively. The first round is an online 10-hour introductory-level contest mostly for familiarizing with CTF concepts. The second round is originally an onsite 7-hour jeopary-style CTF, but after that, it was opened for everyone to join and attempt to solve the challenges in around one week. This write-ups attempt to summarize the process of solving the CTF challenges presented in the second round of EfiensCTF 2020.

The challenges were hosted on Efiens' CTF Website, [Efiens](http://45.77.254.247/challenges)

## Introduction

Since this CTF is intended as the recruitment challenge for starters in information security, most round-2 challenges were beginner-to-intermediate problems for familiarizing with the thought process and techniques. There are a total of 19 challenges, in 4 areas: Pwnable, Reverse Engineering, Web Exploitation, and Cryptography. I managed to solve 8 problems during the onsite contest time, and 5 further more (so far) during the open contest. Of course, since the CTF is intended to be fully solved in 6-7 hours, this number is nothing but pathetically rookie. Still, I find the process of thinking and solving the challenges really interesting and helpful, so I would like to present the writeup to anyone who is interested in joining Efiens in the future, or is simply into information security.

## Challenge Set
The following tables lists out the challenges I solved during the contest time. All challenge files and solutions can be found [here](https://github.com/mkbui/EfiensCTF-Writeup/tree/main/round2). Unless otherwise stated, I do not own any of the files included and referenced in this repos, which were created by Efiens' members. List of references are at the end, while noteworthy help, advice and suggestions are also mentioned in the write-ups. 

| **Category**      | **Challege Name**                    |
|-------------------|--------------------------------------|
| Crypto  | [ROT1000](#rot1000)   |
| Crypto  | [Baby RSA](#baby-rsa) |
| Crypto  | [ECBC](#ecbc)         |
| Crypto  | [Four time pad](#four-time-pad) |
| Web     | [Cave of wonder](#cave-of-wonder) |
| Web     | [Tiểu cường học Nodejs](#tiểu-cường-học-nodejs) |
| Web     | [Rapper hub](#rapper-hub) |
| Web     | [Trust bank is back](#trust-bank-is-back) |
| RE      | [Single Byte](#single-byte) |
| RE      | [Easy MIPS](#easy-mips)     |
| Pwn     | [Lottery](#lottery)   |
| Pwn     | [Luck](#luck)         |
| Pwn     | [ROP](#rop)           |

Note that this list only contains problem that I solved, which were not completed. 


## ROT1000

> Source files : [`chall.py`](./crypto/rot1000/chall.py)

The source details the process of encrypting and encoding the flag using a variety of methods.

```python
def rot(s, num):
    return ''.join(ALPHABET[(ALPHABET.index(x) + num) % len(ALPHABET)] if x in ALPHABET else x for x in s)

def encrypt(c):
    cipher = c
    x = random.randint(1, 1000)
    for i in range(x):
        cipher = rot(cipher, random.randint(1,26))
    cipher = b64encode(cipher.encode())

    l = b""
    for i in range(len(cipher)):
        l += bytes([cipher[i] ^ cipher[(i+1)%len(cipher)]])
    return b64encode(l).decode()
```

The process steps are depicted as followed:
1. The plaintext (consisting of all uppercase character and `{`, `}`) is modified by the `rot` function for `x` number of times, where `x` is a randomly generated number between 1 and 1000. Upon inspection of `rot`, we can see that this function performs the same Caesar shift cipher on the message, which the shift key also randomly generated between `1` and `26`. 
2. The resulting ciphertext is then wrapped into a base64 encoding object called `cipher`, which stores the text as an array of base64 characters.
3. The process now encrypts the object into a new byte string as followed: the value of the byte at each position is produced by XORing the two neighboring base64 characters of `cipher` at that position and its next one (for the last character, it is XORed with the first one).
4. The resulting final ciphertext is encoded into base64 form using the `base64encode` object.

As we can see, this is a linear process where each step is independent of each other. Thus, we attempt to reverse the process and decrypt the original message from the last step back to the first one:
1. We obtain the byte string at the beginning of step 4 by wrapping the ciphertext in a `base64decode` object, which is Python's counterpart object for `base64encode`. 
```python
l = b64decode(encrypted)
```

2 and 3. Although the encryption process looks complicated, the property of XOR allows us to recover the whole message provided knowledge of a single correct character in the original message. For example, if we know `cipher[0]`, we can calculate `cipher[1] = l[0] ^ cipher[0]`, `cipher[2] = l[1] ^ cipher[1]`, and so forth. Therefore, we don't actually need to bruteforce every possible combination of the byte string, we just need to bruteforce the first letter of `cipher`. Since the ROT encryption only produces alphabetical uppercase character, we have 26 possibility to try. How to determine which first character is valid? Notice that `cipher` only consists of valid ASCII characters (more specifically, uppercase alphabet and the brackets), which can be safely decoded into an ASCII string by Python. If the first character is wrong, there is very high possibility the resulting reversed byte string will contain non-ASCII byte values. Therefore, we can use exception handling to return just the valid choice of first character:

```python
first = 'A'
while (True):
    guess = first.encode()
    for i in range(len(l)):
        guess += bytes([l[i] ^ guess[i]])

    try:
        cipher = b64decode(guess).decode()
        break
    except:
        pass

    first = chr(ord(first) + 1)
```    

Note that `b64decode(guess).decode()` also does the base64 decoding presented in encryption step `2`.

4. Finally, we need to recover the original plaintext by cryptanalysing Caesar cipher, now in 1000 times. We can easily see no matter how many times `rot` was produced, the resulting cipher will always be shifted with a fixed number for every character in the string. Therefore, we only need a linear 26 tries at most to discover the plaintext. However, we already know the first letter in the plaintext should be `E` in `EFIENSCTF{...}`, which reduces the number of tries to only 1: we just need to call `rot` with a supplied shift as the difference between `E` and the first letter in `cipher`.

```python
print(rot(cipher, (ord('E') - ord(cipher[0])) % len(ALPHABET)))
```

We obtain the flag as `EFIENSCTF{_WARMUP_BABE_:)_ENJOY_THE_CTF_}`.

The message in the challenge flag is more terrifying than the challenge itself.

## Baby RSA

> Source files: [chall.py](./crypto/babyrsa/chall.py)

The challenge shows us the source, which depicts the process of RSA encryption with some additional information.

```python
def leak(x, n=512, rate=0.45):
    cc = list(range(n))
    shuffle(cc)
    cc = cc[:int(rate*n)]
    bit = list(bin(x)[2:].zfill(n))
    for i in cc:
        bit[i] = 'x'
    return '0b' + ''.join(bit)


p = getPrime(512)
q = getPrime(512)
n = p*q
m = bytes_to_long(flag.encode())
c = pow(m, 65537, n)

print(f'n = {n}')
print(f'p = {leak(p)}')
print(f'q = {leak(q)}')
print(f'c = {c}')

# n = 79753459280206880128113574432814937699658173430959080655543409042957247559575129669546574580450020074729891652719995259102247118118129856047047260436761118020607272628218875167846537090248986069614704056782852058656553098641635416733510555297527445944922605886852081480971490040604366056053007281766327844861
# p = 0b1x01x000xx11x01xx0110xxx100xxx1x0xx1x10x010110xx1x1xx0xx0001xx01xx0xxx1xx00xxxx1x0xx0x0x10x11xx100x0xxx10x1x1x01xx00110xx1x1x00xx0x0x11100xx0x11x1x1xxxx1x1xx0x00x01x110xx1001x1x0x1x11xx010x1x100xx0x1x0x1000x0x0x110x1x110x00x01x10001x0x0xxxx000xxx0x1xx011x0x1001x0x0xxx001x1xxx11010xx1xx100x1x00110xx00xx001xx0010xxxx0xxx10110xx1xx1x11xx1x01xx1xxxx00x01x10x1110x1000x0x0xxxx000x0x1110000x1010x1010xxxx1x0xxx0xx0xxx0x111x0x0xxx0x1xxx00x0xxx0xxxx0x11x00x110x00xx1x0x11xxx0x10x110x00xx001111x1x00001xxx01xxx11xxx10x1
# q = 0b1100xx0xxxxx11x0xxxxxx0x1x1x0xxxxx0x100xx01xxx0xxx0xx0x0xx1000xxx0x111x1xxx0x000111x1xx1xx0x1x010011x1x1x10100x1xxx000x10x1xx01xxx1x0000xx10111xxxxxx010xx1x011x10xxxx0001010110x100xxx0111x000x1xxxx00x00011xx1000x0101x0010xxx001xxxxxxxx1x11xxx0xx0xx11x0xxx01xx00011xx0xx1x1x1x100x1x001xx1x100x01111xxxx100x11xx00010x10xx010xx1xx1x1100x00x0x0x0xx1xxxxxx100x1001x01xx010x100x111x111x1xxx1xxx0x01xxx1xx0xx1x110000xx0x00xx10100x111xxx101x1xxxx1001111xxx101xxxxxxx1001x0xxx01x1100001x001x0001xx1x00x0xx0110x01xx0xx01xx
# c = 69798571987059279536020048590380044210697540311399633826675257935676764846459954894967850784513288877022680859815373044798758357399449803892309076689360603234922881853951574595305273158929170599103698971345765935160435747059203310715064910469854375945380312715370629665433775374987617013660468800917779452238

```

From the source, we are provided knowledge of the modulus `n`, the public key `e`, and the ciphertext `c` as usual. However, this time the program also allows a sneak-peek into some parts of the prime components `p` and `q`, which reveals a random 55% bits of each (the remaining 45% unrevealed bits will be denoted by the `x` character, as seen in the `leak` function and the output).

The topic of leaked components cryptanalysis in RSA is pretty popular, and in this case we attempt to fully recover the plaintext with partial knowledge of the factorization of `n`. First, we use the principle of modular arithmetic: 
```
p * q = n   <=>   last_i( last_i(p) * last_i(q) ) = last_i(n)
```
with `last_i` denoting the last `i` trailing bits of the number. 

With this knowledge, we can try to linearly cryptanalyze `p` and `q` by finding possible combinations of the last `i` bits of `p` and `q` which multiplication has the same `i` trailing bits as `n`. `i` is then incremented by 1 each, until we come to the final list of possible full-bit combinations of `p` and `q` that satisfies the condition. Normally, if we have absolutely zero knowledge of the two primes, it would produce `2^bits` combinations (`bits` is the bit length of `p`, which is 512), which is no better than factorizing `n` directly. However, with the leaked bits, the number of possibles combinations significantly decreases - in fact, the resulting list of this problem only has 78 elements in total.

Using the output, we create the list by going from the last bit of `p` and `q` up to the 512th:
```python
n = 79753459280206880128113574432814937699658173430959080655543409042957247559575129669546574580450020074729891652719995259102247118118129856047047260436761118020607272628218875167846537090248986069614704056782852058656553098641635416733510555297527445944922605886852081480971490040604366056053007281766327844861
p = "1x01x000xx11x01xx0110xxx100xxx1x0xx1x10x010110xx1x1xx0xx0001xx01xx0xxx1xx00xxxx1x0xx0x0x10x11xx100x0xxx10x1x1x01xx00110xx1x1x00xx0x0x11100xx0x11x1x1xxxx1x1xx0x00x01x110xx1001x1x0x1x11xx010x1x100xx0x1x0x1000x0x0x110x1x110x00x01x10001x0x0xxxx000xxx0x1xx011x0x1001x0x0xxx001x1xxx11010xx1xx100x1x00110xx00xx001xx0010xxxx0xxx10110xx1xx1x11xx1x01xx1xxxx00x01x10x1110x1000x0x0xxxx000x0x1110000x1010x1010xxxx1x0xxx0xx0xxx0x111x0x0xxx0x1xxx00x0xxx0xxxx0x11x00x110x00xx1x0x11xxx0x10x110x00xx001111x1x00001xxx01xxx11xxx10x1"
q = "1100xx0xxxxx11x0xxxxxx0x1x1x0xxxxx0x100xx01xxx0xxx0xx0x0xx1000xxx0x111x1xxx0x000111x1xx1xx0x1x010011x1x1x10100x1xxx000x10x1xx01xxx1x0000xx10111xxxxxx010xx1x011x10xxxx0001010110x100xxx0111x000x1xxxx00x00011xx1000x0101x0010xxx001xxxxxxxx1x11xxx0xx0xx11x0xxx01xx00011xx0xx1x1x1x100x1x001xx1x100x01111xxxx100x11xx00010x10xx010xx1xx1x1100x00x0x0x0xx1xxxxxx100x1001x01xx010x100x111x111x1xxx1xxx0x01xxx1xx0xx1x110000xx0x00xx10100x111xxx101x1xxxx1001111xxx101xxxxxxx1001x0xxx01x1100001x001x0001xx1x00x0xx0110x01xx0xx01xx"

l = len(p)
possible = [("", "")]
for i in range(len(p)):
  newlist = []
  pguess = ["0", "1"] if p[l-i-1] == "x" else [p[l-i-1]]
  qguess = ["0", "1"] if q[l-i-1] == "x" else [q[l-i-1]]
  
  for ps in pguess:
    for qs in qguess:
      for s in possible:
        pnew = ps + s[0]
        qnew = qs + s[1]
        if (((int(pnew, 2) * int(qnew, 2)) % (1 << i+1)) == (n % (1 << i+1))): newlist += [(pnew, qnew)]

  possible = newlist

print(len(possible)    #78
```

After this, finding which combination actually produces the correct modulus `n` is simple. 

```python
for s in possible:
  ptrue = int(s[0], 2)
  qtrue = int(s[1], 2)
  if ptrue * qtrue == n: 
    totient = (ptrue-1)*(qtrue-1)
    d = inverse(65537, totient)
    print(long_to_bytes(pow(c, d, n)).decode())
    break
```

Flag: `EFIENSCTF{___Basic_RSA_chall_:)___}`

# ECBC

> Source files: [chall.py](./crypto/ecbc/chall.py)

The source file details a web service that encrypts the flag using a combination of `ECB` and `CBC` block cipher modes:

```python
BS = 16

def pad(m):
    if len(m) % BS == 0:
        return m
    return m + bytes(BS - len(m) % BS)

def encrypt(m):
    c = []
    m = pad(m)
    n = bytes_to_long(FLAG)
    for _ in range(len(FLAG) * 8):
        if n & 1:
            c.append(AES.new(os.urandom(BS), AES.MODE_ECB).encrypt(m))
        else:
            c.append(AES.new(os.urandom(BS), AES.MODE_CBC, os.urandom(BS)).encrypt(m))
        n >>= 1
    return c

if __name__ == '__main__':
    message = bytes.fromhex(input())
    for x in encrypt(message):
        print(x.hex())
```

In summary, we need to send a hex message to the oracle, which will be padded to 16-byte blocks. The service oracle then encrypts our messages based on the flag bits. For each bit, if it is `1`, the cipher mode will be `ECB`, else, the cipher mode will be `CBC`. Note that the key and the Init Vector (for `CBC`) are all randomly generated each time. The encrypted message is then sent back to us, again, bit by bit according to the flag bit length.

As we can see, the challenge here is to detect if the ciphertext sent from the server is encrypted using `ECB` or `CBC` mode. This is pretty simple if you already have some knowledge regarding the block cipher mode of operations. In this case, I use an important (and very susceptible) characteristics of `ECB` mode: **the mode separated our message into 16-byte blocks to encrypt each with the provided key, and if two blocks are identical, the resulting 16-byte encrypted blocks will also be identical**. This means if, for example, we send a 32-byte message to the server with the first 16 bytes identical to the last 16 bytes, the resulting message sent back to us will also contain a 32-byte ciphertext with identical parts. For `CBC`, this will not happen for almost every case due to the fact that each next block depends on both the key and the previous block's encrypted result.

We can then simply send a 32-byte message satisfying the condition (I used a hex string with 64 zeroes), then read the result from the server line by line, and assemble the flag bits to get the result.

```python
# run $python -c 'print("0"*64+"\n")' | nc 128.199.234.122 3333 > outcbc.txt

f = open(os.path.join(os.sys.path[0], "outcbc.txt"), "r")

messages = f.readlines()
res = ""
for m in messages:
  if m[:32] == m[32:-1]: res += "1"
  else: res += "0"

print(long_to_bytes(int(res[::-1], 2)))
```

It is possible to use python to automate the server interaction, which you can view in [ecbc_sol.py](./crypto/ecbc/ecbc_sol.py)


# Four time pad

> Source files: [chall.py](#./crypto/fourtimepad/chall.py)

> Hint 1: Hamming distance

> Hint 2: Find my seeds (no need to bruteforce)

The challenge again provides us with the source file of the encryption algorithm.

```python
# flag = b"efiensctf{?????????????????????}"
# seeds = [?,?,?,?]

def twist(random_numbers):
    A,B,C,D = random_numbers
    return (~A) ^ (B & C) ^ (C | D)


if __name__ == "__main__":
    ct = bytes_to_long(flag)

    random_numbers = []

    for seed in seeds:
        assert seed.bit_length() <= 8
        random.seed(seed)
        random_numbers.append(random.getrandbits(500))


    for number in random_numbers:
        ct = ct ^ number


    with open("output.txt","w") as f:
        f.write(f"Magic number: {(twist(random_numbers))} \nEncrypted flag: {ct}")
 
# Magic number: -2366540547707921699196359399704685795692230503857310199630127241713302904294984638188222048954693422933286057485453364955232326575156580931098343765793 
# Encrypted flag: 481730728147477590058623891675498051334529574592495375656331717409768416155349933803891410647003817827440361572464319442970436132820134834740943058323
```

From the source, we gain some basic information:
- The random factors in the code is the four seeds, which is revealed to be 8-bit long each.
- These seeds will be used to generate four random 500-bit numbers, which will then be XORed with our flag one by one. The results is displayed for us.
- There is also a random function that performs an array of bitwise operations, including NOT, OR, AND, among the random numbers and output the result to us as `magic`.
 
 At first glance, it is apparent we have to get something from the `magic` number. I first tried to eliminate the first random, `A`, by simply XORing `magic` with `encrypted` and then with `-1` (The `NOT` operation property makes `A ^ (~A) ^ -1 = 0`). This, however, produces an even more messy calculation:
```
blob = magic ^ enc ^ -1 = ct ^ B ^ C ^ D ^ (B & C) ^ (C | D)
```

Luckily, shortly after the challenge was released, the challenge author provided us with two consecutive hints. The second hints indicate we could recover the seeds without bruteforcing. This hint immediately prompts me to try to bruteforce. There are actually only `256**3` or about 16 million possible combinations of `B`, `C` and `D`, which might be in possible range depending on how desperate we are.

However, as there was plenty of time left and this was my last Crypto challenge, I tried to discover how to solve it the right way. We turn the attention to the first hint, which suggests using *Hamming distance*. Hamming distance basically indicates how different two numbers are, in bit form - more specifically, the number of mismatched respective bits among the two (for example, the Hamming distance between `010` and `011` is `1` due to the last bit difference). We can conveniently calculate the Hamming distance by XORing the two numbers and count the number of `1`s bits - which is also denoted as the *Hamming weight* of a number (we can easily figure out the mathematical explanation behind this).

```python
def hamming(intin):
    count = 0
    while intin > 0:
        if intin & 1: count += 1
        intin //= 2
    return count
```

Using the clue above, I figured `B`, `C`, `D`, or some bitwise combination between them, must have a noticeably higher or lower Hamming distance with our `blob` or `magic`. At the contest time, I was not keen and intelligent enough to work out which exact combination is the mathematically suitable. However, using the *no-bruteforce* suggestion, I tried experimenting with simple single `B` / `C` / `D` cases first by generating my own seeds and magic numbers. Upon some testing, I figure out `blob` has an unusually lower Hamming distance when compared with `B` and `D`. In almost all cases, discovering the two numbers that produced the lowest Hamming weight when XORed with `blob` also means discovering `B` and `D`. 

Using this information, we can easily find `B` and `D` 

```python
min1, s1 = 500, -1
min2, s2 = 500, -1
for i in range(256):
    random.seed(i)
    a = hamming(enc ^ magic ^ -1 ^ random.getrandbits(500))
    if a < min1: 
        min2, s2 = min1, s1
        min1, s1 = a, i
    else:
        if a < min2: min2, s2 = a, i

# s1 = 69, s2 = 135

random.seed(s1)
b = random.getrandbits(500)
random.seed(s2)
d = random.getrandbits(500)
```

The only problem left is a linear bruteforce on `C` to reveal our long-waited flag.
```python
for i in range(256):
    random.seed(i)
    c = random.getrandbits(500)
    a = enc ^ magic ^ -1 ^ b ^ d ^ (b&c) ^ (c|d) ^ c
    try:
        l = long_to_bytes(a)
        print(l.decode())
        break
    except:
        pass
```

Flag: `EFIENSCTF{Kowalski_Analy5isss!!}`

You can also view the bruteforce alternative (attempted after the onsite contest) [here](#./crypto/fourtimepad/chall.py)


# Tiểu Cường học Nodejs  
