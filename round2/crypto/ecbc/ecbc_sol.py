from Cryptodome.Util.number import long_to_bytes, bytes_to_long
import sys, os
import socket

HOST = "128.199.234.122"
PORT = 3333

def recvall(sock):
    BUFF_SIZE = 1024
    data = b''
    while True:
        part = sock.recv(BUFF_SIZE)
        data += part
        if len(part) == 0:
            break
    return data.decode()

conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
conn.connect((HOST, PORT))
conn.send(b'0'*64+b'\n')
res = ""

messages = [*filter(lambda x: len(x) == 64, recvall(conn).split('\n'))]

for m in messages:
  if m[:32] == m[32:]: res += "1"
  else: res += "0"

print(long_to_bytes(int(res[::-1], 2)).decode())

#EFIENSCTF{Now_you_know_ECB_is_weak_;)_}

'''
# alternative way
# run $python -c 'print("0"*64+"\n")' | nc 128.199.234.122 3333 > outcbc.txt

f = open(os.path.join(os.sys.path[0], "outcbc.txt"), "r")

messages = f.readlines()
res = ""
for m in messages:
  if m[:32] == m[32:-1]: res += "1"
  else: res += "0"

print(long_to_bytes(int(res[::-1], 2)))
'''
