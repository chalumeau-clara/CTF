from pwn import *

pass_enc = bytearray(b"NzTfdvs4Q4ttx1se")

def reverse_transform(data: bytearray):
    """Decrement each byte in the input bytearray until a null byte is encountered."""
    output = bytearray(len(data))
    for i in range(len(pass_enc)):
        output[i] = data[i] - 1
    return output


output = reverse_transform(pass_enc)

print("Reversed:", output)

target = process("./TarteTatin.txt")
target.sendline(output)

for i in range(100):
    print(target.recvline())