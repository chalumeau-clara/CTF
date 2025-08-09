from pwn import *

target = process("./sloubi.txt")

flag_rev = "4B}mCuCNJmeVhvCzQusFHS7{2gCBCrQW"
flag = [" "] * 32

for i in range(32):
    flag[i] = flag_rev[(17 * i + 51) % 32]

flag = ''.join(flag)
print("FLAG : " + flag)

target.sendline(flag)
print(target.recvline())

for i in range(100):
    print(target.recvline())


