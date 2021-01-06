import socket, requests 

HOST = '128.199.234.122'
PORT = 4100
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
print(s.recv(2048))