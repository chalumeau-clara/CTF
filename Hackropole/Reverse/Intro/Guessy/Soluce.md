# Guessy Write-up 

Challenge Source: [Hackropole Guessy](https://hackropole.fr/fr/challenges/reverse/fcsc2021-reverse-guessy/) 


# Solution

I use IDA to decompile the challenge and reverse it.

See the script "send.py" to see the solution.

```bash
└─$ python3 send.py 
[+] Starting local process './guessy.txt': pid 260
b'Give me the flag:\n'
b"Ok so I see we have an understanding. Let's begin the difficult part now.\n"
b'Now you can try to guess the next eight characters of the flag.\n'
b"Well done, you can try to guess the next eight characters but it won't be so easy.\n"
b"I see you've got some skills in reversing, but can you guess the next eight ?\n"
b"I must say that I'm impressed but it's not over. Will you be able to guess the next eight characters ?\n"
FLAG : FCSC{e7552cf64ce2e5ad0bb0954f167a02cf}
b"Alright, now let's go to the most difficult part of this challenge.\n"
b'Can you guess the LAST character of the flag ?\n'
b"Congratulations, you've guessed the flag !\n"
```

✅ **Answer**: FCSC{e7552cf64ce2e5ad0bb0954f167a02cf}