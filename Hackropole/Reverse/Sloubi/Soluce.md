# Guessy Write-up 

Challenge Source: [Hackropole Sloubi](https://hackropole.fr/fr/challenges/reverse/fcsc2025-reverse-sloubi/) 


# Solution

I use IDA to decompile the challenge and reverse it.

See the script "sloubi.py" to see the solution.

```bash
└─$ python3 sloubi.py 
[+] Starting local process './sloubi.txt': pid 154
FLAG : FCSC{JgeBhrCWQBsmHu7N2mCVCvQz4u}
/mnt/c/Users/chalu/Documents/CTF/Hackropole/sloubi.py:14: BytesWarning: Text is not bytes; assuming ASCII, no guarantees. See https://docs.pwntools.com/#bytes
  target.sendline(flag)
b'Congrats! You can use this flag to validate the challenge.\n'

```

✅ **Answer**: FCSC{JgeBhrCWQBsmHu7N2mCVCvQz4u}