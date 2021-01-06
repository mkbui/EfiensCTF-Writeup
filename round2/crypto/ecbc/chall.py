from Crypto.Cipher import AES
from Crypto.Util.number import bytes_to_long
import os

BS = 16
FLAG = open('flag.txt').read().encode()


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
