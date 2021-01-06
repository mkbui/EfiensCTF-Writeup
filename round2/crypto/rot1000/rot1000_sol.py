import random
from string import ascii_uppercase as ALPHABET
from base64 import b64encode, b64decode, decodebytes


def rot(s, num):
    return ''.join(ALPHABET[(ALPHABET.index(x) + num) % len(ALPHABET)] if x in ALPHABET else x for x in s)

encrypted = "Z1kqFGZqFhoDLSE8VAhpBWVANhIBPQ4wEAgbA2cJDn0db2EKOSECHQNvdBo7CAIwAy0hAWsDDWs="

# Step 1: b64decode back to l
l = b64decode(encrypted)

# Step 2: find original unxored cipher
cipher = ""
first = 'A'
while (True):
    guess = first.encode()
    for i in range(len(l)):
        guess += bytes([l[i] ^ guess[i]])

    try:
        cipher = decodebytes(guess).decode()
        break
    except:
        pass

    first = chr(ord(first) + 1)
    if first == chr(ord('Z') + 1):
        break

# Step 3: find original message before ROTing
print(rot(cipher, (ord('E') - ord(cipher[0])) % len(ALPHABET)))

#EFIENSCTF{_WARMUP_BABE_:)_ENJOY_THE_CTF_}