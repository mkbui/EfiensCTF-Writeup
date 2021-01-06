import random
from string import ascii_uppercase as ALPHABET
from base64 import b64encode


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


flag = open('flag.txt').read()
assert flag.isupper()

print("cipher =", encrypt(flag))

# cipher = Z1kqFGZqFhoDLSE8VAhpBWVANhIBPQ4wEAgbA2cJDn0db2EKOSECHQNvdBo7CAIwAy0hAWsDDWs=
