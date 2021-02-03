s = """
local_1f8[0] = 0x735f5f66;
local_1f8[1] = 0x646c6c65;
local_1f8[2] = 0x6270637b;
local_1f8[3] = 0x6f6f656f;
local_1e8 = 0x666e7564;
local_1e4 = 0x5f73656d;
local_1e0 = 0x7d776965;
local_1dc = 0x6f307767;
local_1d8 = 0x765f7274;
"""

# reverse allocate the check integer to the corresponding 36-element in the lower half of `aiStack432`
a432 = __import__('functools').reduce(lambda lst, x: lst + [x[-j:][:2] for j in range(8, 0, -2)][::-1], s.split(";"), [])[:-4]

# .data extracted from the program memory
data = [0x8, 0x1c, 0x0d, 0x1d, 0x21, 0x19, 0x1f, 0x13, 0x9, 0x6, 0x15, 0x18, 0x11, 0x0, 0x12, 0x17, 0x22, 0x0e, 0x4, 0x1, 0x1b, 0x1a, 0x5, 0x0f, 0x3, 0x2, 0x0a, 0x23, 0x10, 0x0c, 0x0b, 0x1e, 0x7, 0x16, 0x14, 0x20]

# reverse permutation to obtain the correct order of the characters in password
flag = ['']*36
for j in range(36):
  flag[data[j]] = chr(int(a432[j], 16))

[print(f, end = '') for f in flag]