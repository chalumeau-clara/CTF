from pwn import *

target = process("./guessy.txt")

# Print the flag
flag = ''

# First step
payload = b'FCSC{'
flag += payload.decode("utf-8")

target.sendline(payload)
print(target.recvline())

# Second Step
payload = b'e7552cf6'
flag += payload.decode("utf-8")
target.sendline(payload)
print(target.recvline())

# Third Step
s = 104
v3 = 198
v4 = 202
v5 = 100
v6 = 202
v7 = 106
v8 = 194
v9 = 200


def to_chr(number):
    return bytes([number // 2])


payload = to_chr(s) + to_chr(v3) + to_chr(v4) + to_chr(v5) + to_chr(v6) + to_chr(v7) + to_chr(v8) + to_chr(v9)
flag += payload.decode("utf-8")
target.sendline(payload)
print(target.recvline())

# Fourth Step
s = 384
v3 = 784
v4 = 784
v5 = 384
v6 = 456
v7 = 424
v8 = 416
v9 = 816


def to_chr(number):
    return bytes([number // 8])


payload = to_chr(s) + to_chr(v3) + to_chr(v4) + to_chr(v5) + to_chr(v6) + to_chr(v7) + to_chr(v8) + to_chr(v9)
flag += payload.decode("utf-8")

target.sendline(payload)
print(target.recvline())


# Fifth step
def to_num(number):
    return int(number // 8)


final = to_num(s) + to_num(v3) + to_num(v4) + to_num(v5) + to_num(v6) + to_num(v7) + to_num(v8) + to_num(v9)

x = 1 ^ to_num(s)
x1 = 84 ^ to_num(v3)
x2 = 85 ^ to_num(v4)
x5 = 81 ^ to_num(v5)
x6 = 9 ^ to_num(v6)
x7 = 7 ^ to_num(v7)
x8 = 87 ^ to_num(v8)
x9 = to_num(v9)


def to_bytes(number):
    return bytes([number])


payload = to_bytes(x) + to_bytes(x1) + to_bytes(x2) + to_bytes(x5) + to_bytes(x6) + to_bytes(x7) + to_bytes(
    x8) + to_bytes(x9)


flag += payload.decode("utf-8")
target.sendline(payload)
print(target.recvline())

# sixth step
payload = b'}'
flag += payload.decode("utf-8")
target.sendline(payload)
print(target.recvline())

## Print final flag
print("FLAG : " + flag)
for i in range(100):
    print(target.recvline())
