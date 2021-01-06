from Cryptodome.Util.number import bytes_to_long, long_to_bytes
import random

# flag = b"efiensctf{?????????????????????}"
# seeds = [?,?,?,?]

flag = b"efiensctf{?????????????????????}"
seeds = [111, 57, 35, 75]

def twist(random_numbers):
    A,B,C,D = random_numbers
    return (~A) ^ (B & C) ^ (C | D)

def twist2(random_numbers):
    A,B,C,D = random_numbers
    return (B & C) ^ (C | D)

def hamming(intin):
    count = 0
    while intin > 0:
        #print(intin)
        if intin & 1: count += 1
        intin //= 2
    return count

if __name__ == "__main__":
    ct = bytes_to_long(flag)

    random_numbers = []

    for seed in seeds:
        assert seed.bit_length() <= 8
        random.seed(seed)
        random_numbers.append(random.getrandbits(500))


    for number in random_numbers:
        ct = ct ^ number

    t = twist(random_numbers)
    print(f"Magic number: {(twist(random_numbers))} \nEncrypted flag: {ct}")

    
    #print(ct ^ 123)
    #print(35 | 114)
    #print(97 & 35)
    #print(t)
    
    for i in range(256):
        random.seed(i)
        a =hamming(ct ^ t ^ -1 ^ random.getrandbits(500))
        print(a, i)
        #if a < 230: print(a, i)
    
    ct1 = ct ^ 72
    t1 = t ^ ~72
    print(t1, twist2(random_numbers), sep = '\n')

    print("----")

    b = 57
    d = 75
    c = 35
    random.seed(b)
    bp = random.getrandbits(500)
    random.seed(c)
    cp = random.getrandbits(500)
    random.seed(d)
    dp = random.getrandbits(500)        
    a = ct ^ t ^ -1 ^ bp ^ dp ^ (bp&cp) ^ (cp|dp) ^ cp
    b = ct ^ bp ^ cp ^ dp ^ 111
    #print("BCD: ", bp, cp, dp, sep = '\n')
    print(long_to_bytes(a))
    for i in range(256):
        random.seed(i)
        c = random.getrandbits(500)
        a = ct ^ t ^ -1 ^ b ^ d ^ (b&c) ^ (c|d) ^ c
        try:
            pass#print(long_to_bytes(a))
        except:
            pass    

    random.seed(57)
    b = random.getrandbits(500)
    random.seed(75)
    d = random.getrandbits(500)
    #seed0 = 69
    '''
    for i in range(256):
        random.seed(i)
        c = random.getrandbits(500)
        #if i == 35: print("BCD: ", b, c, d, sep = '\n')
        a = ct ^ t ^ -1 ^ b ^ d ^ (b&c) ^ (c|d) ^ c
        try:
            l = long_to_bytes(a)
            if l[0] == b'e' or i == 35: 
                print(l, i)
                print("YEAH")
        except:
            pass
    '''
    for i in range(256):
        random.seed(i)
        a = hamming(ct1 ^ t1 ^ random.getrandbits(500))
        #print(a)
        #if a < 240: print(a, i)
    
    '''
    mini = 256
    minj = -1
    print(35 | 194, 11 | 35, 11 | 194)
    for i in range(256):
        for j in range(256):
            random.seed(i)
            b = random.getrandbits(500)
            random.seed(j)
            c = random.getrandbits(500)
            a =hamming(ct ^ t ^ (b | c) )
            if a < mini:
                mini = a 
                minj = (i, j)
            #if a < 210: print(a, i)  
    
    print(mini, minj)
    '''


magic =  -2366540547707921699196359399704685795692230503857310199630127241713302904294984638188222048954693422933286057485453364955232326575156580931098343765793 
enc = 481730728147477590058623891675498051334529574592495375656331717409768416155349933803891410647003817827440361572464319442970436132820134834740943058323
'''
encnew = enc ^ -1 ^ magic 
for i in range(256):
    print(hamming(encnew ^ i))
'''

'''
mini = 256
for i in range(256):
    random.seed(i)
    a = hamming(enc ^ magic ^ -1 ^ random.getrandbits(500))
    #print(i, a)
    if a < mini: mini = a 


for i in range(256):
    random.seed(i)
    a = hamming(enc ^ magic ^ -1 ^ random.getrandbits(500))
    if a <= mini+40: print(i, a)

random.seed(69)
b = random.getrandbits(500)
random.seed(135)
d = random.getrandbits(500)
#seed0 = 69

for i in range(256):
    random.seed(i)
    c = random.getrandbits(500)
    a = enc ^ magic ^ -1 ^ b ^ d ^ (b&c) ^ (c|d) ^ c
    try:
        l = long_to_bytes(a)
        print(l)
    except:
        pass
#EFIENSCTF{Kowalski_Analy5isss!!}
'''

'''
for i in range(256):
    for j in range(256):
        random.seed(i)
        b = random.getrandbits(500)
        random.seed(j)
        c = random.getrandbits(500)
        a = hamming(enc ^ magic1 ^ -1 ^ random.getrandbits(500))
        if a < mini: mini = a
'''














