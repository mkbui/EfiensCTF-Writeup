import os, sys

# Run ./singleByte > out.txt
f = open(os.path.join(os.sys.path[0], 'out.txt'), 'rb')

bArr = f.readline().split(b': ')[1][:-1]
randval = ord('e') ^ bArr[0]
for b in bArr:
  print(chr(b ^ randval), end='')

#efiensctf{r4nd0m_numb3r5_c4n7_b347_m3!!!}