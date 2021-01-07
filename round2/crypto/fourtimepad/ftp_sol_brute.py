from Cryptodome.Util.number import bytes_to_long, long_to_bytes
import random


magic =  -2366540547707921699196359399704685795692230503857310199630127241713302904294984638188222048954693422933286057485453364955232326575156580931098343765793 
enc = 481730728147477590058623891675498051334529574592495375656331717409768416155349933803891410647003817827440361572464319442970436132820134834740943058323

for i in range(256):
  for j in range(256):
    for k in range(256):
      random.seed(i); b = random.getrandbits(500)
      random.seed(j); c = random.getrandbits(500)
      random.seed(k); d = random.getrandbits(500)
      ct = magic ^ enc ^ -1 ^ (b & c) ^ (c | d) ^ b ^ c ^ d 
      ct = long_to_bytes(ct)
      try:
        print(ct.decode())
        break
      except:
        pass
