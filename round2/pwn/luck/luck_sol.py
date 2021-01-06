from pwn import *

found = False
while not found:
  r = remote('128.199.234.122', 2222)
  money = 69

  while True:
    r.send('1\n0_0_0_0_0_0_0_1\n')
    res = r.recvuntil(b'$').split(b' ')[-2]

    if res == b'win':
      r.recvuntil(b'> ') 
      r.send('2\n')
      print(r.recvuntil(b'}').decode())
      found = True 
      break

    money -= 10
    if money < 1:
      break

#efiensctf{wh4t_1s_th4t_w31rd_numb3r_FeelsWeirdMan}

