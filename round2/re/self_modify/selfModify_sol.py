from functools import reduce
import os, sys 

'''
.data:0000000000201010 ; _BYTE byte_201010[16]
.data:0000000000201010 byte_201010     db 91h, 0EDh, 1Eh, 1Dh, 82h, 0AEh, 0D1h, 9 dup(0)
.data:0000000000201010                                         ; CODE XREF: main+196↑p
.data:0000000000201010                                         ; DATA XREF: main+B8↑o ...
.data:0000000000201020 ; _DWORD dword_201020[5]
.data:0000000000201020 dword_201020    dd 965ABFA7h, 5C10D757h, 0DEADA1CAh, 1994F6EFh, 1D6D2AE0
'''

b10 = [0x91, 0xed, 0x1e, 0x1d, 0x82, 0xae, 0xd1] + [0x0] * 9
d20 = [0x965abfa7, 0x5c10d757, 0xdeada1ca, 0x1994f6ef, 0x1d6d2ae0]

for i in range(7):
  b10[i] ^= 0x10
  b10[i] += 2

for i in range(5):
  d20[i] ^= 0xdeadbeef

byted20 = reduce(lambda ins, d: ins + int.to_bytes(d, length=4, byteorder='little'), d20, b'')


f = open(os.path.join(os.sys.path[0], 'b10.bin'), 'wb')
f.write(bytearray(b10))
f.close()

g = open(os.path.join(os.sys.path[0], 'd20.bin'), 'wb')
g.write(byted20)
g.close()


'''
b10 code:
seg000:0000000000000000                 cmp     edi, 10h
seg000:0000000000000003                 setz    al
seg000:0000000000000006                 retn
seg000:0000000000000006 ; ---------------------------------------------------------------------------
seg000:0000000000000007                 align 10h
seg000:0000000000000007 seg000          ends

d20 code:
seg000:0000000000000000                 add     rdi, rsi
seg000:0000000000000003                 mov     rax, 1F2582BD69h
seg000:000000000000000D                 cmp     rdi, rax
seg000:0000000000000010                 setz    al
seg000:0000000000000013                 retn
'''

'''
  if ( (*(unsigned __int8 (__fastcall **)(_QWORD))byte_201010)(v3)
    && (*(unsigned __int8 (__fastcall **)(_QWORD, unsigned __int64))dword_201020)(*(_QWORD *)v7, 0xCBA0CCE8B74E5506LL)
    && (*(unsigned __int8 (__fastcall **)(_QWORD, unsigned __int64))dword_201020)(*((_QWORD *)v7 + 1), 0xDEDE91A9B32358FBLL) )
  {
    printf("Congratulation, the flag is: efiensctf{%s}\n", s);
  }
'''

def d20inv(rs): return int.to_bytes((0x1F2582BD69 - rs) & 0xffffffffffffffff, length=8, byteorder='little')

context = d20inv(0xCBA0CCE8B74E5506) + d20inv(0xDEDE91A9B32358FB)
print('efiensctf{' + context.decode() + '}')

#efiensctf{ch4n63_4nd_run!!}