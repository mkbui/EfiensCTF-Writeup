from Crypto.Util.number import bytes_to_long
import random

# flag = b"efiensctf{?????????????????????}"
# seeds = [?,?,?,?]

def twist(random_numbers):
    A,B,C,D = random_numbers
    return (~A) ^ (B & C) ^ (C | D)


if __name__ == "__main__":
    ct = bytes_to_long(flag)

    random_numbers = []

    for seed in seeds:
        assert seed.bit_length() <= 8
        random.seed(seed)
        random_numbers.append(random.getrandbits(500))


    for number in random_numbers:
        ct = ct ^ number


    with open("output.txt","w") as f:
        f.write(f"Magic number: {(twist(random_numbers))} \nEncrypted flag: {ct}")




















