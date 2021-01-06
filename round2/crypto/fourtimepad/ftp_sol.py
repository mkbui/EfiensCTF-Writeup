from Cryptodome.Util.number import bytes_to_long, long_to_bytes
import random


def hamming(intin):
    count = 0
    while intin > 0:
        #print(intin)
        if intin & 1: count += 1
        intin //= 2
    return count

magic =  -2366540547707921699196359399704685795692230503857310199630127241713302904294984638188222048954693422933286057485453364955232326575156580931098343765793 
enc = 481730728147477590058623891675498051334529574592495375656331717409768416155349933803891410647003817827440361572464319442970436132820134834740943058323

min1, s1 = 500, -1
min2, s2 = 500, -1
for i in range(256):
    random.seed(i)
    a = hamming(enc ^ magic ^ -1 ^ random.getrandbits(500))
    if a < min1: 
        min2, s2 = min1, s1
        min1, s1 = a, i
    else:
        if a < min2: min2, s2 = a, i

# s1 = 69, s2 = 135

random.seed(s1)
b = random.getrandbits(500)
random.seed(s2)
d = random.getrandbits(500)

for i in range(256):
    random.seed(i)
    c = random.getrandbits(500)
    a = enc ^ magic ^ -1 ^ b ^ d ^ (b&c) ^ (c|d) ^ c
    try:
        l = long_to_bytes(a)
        print(l.decode())
        break
    except:
        pass

#EFIENSCTF{Kowalski_Analy5isss!!}
