from pwn import *

pass_enc = "b87de397e1346bc605be4ed8361a68a3d9748fc9"
def transform(data):
    output = ""
    for i in range(len(pass_enc)):
        output += pass_enc[ (i + 10) % 40]
    return output


output = transform(pass_enc)
print("Reversed:", output)