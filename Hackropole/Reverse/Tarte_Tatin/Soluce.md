# Tarte Tatin Write-up 

Challenge Source: [Hackropole Tarte Tatin](https://hackropole.fr/fr/challenges/reverse/fcsc2020-reverse-tarte-tatin/) 


# Solution

I use IDA to decompile the challenge and reverse it.

See the script "tartetatin.py" to get the solution.

```bash
└─$ python3 tartetatin.py 
Reversed: bytearray(b'MySecur3P3ssw0rd')
[+] Starting local process './TarteTatin.txt': pid 191
b'Well done! The flag is: FCSC{83f41431c111062d003dd0213cf824d66f770a0be1305e2813f15dd76503a91d}\n'

```

✅ **Answer**: FCSC{83f41431c111062d003dd0213cf824d66f770a0be1305e2813f15dd76503a91d}