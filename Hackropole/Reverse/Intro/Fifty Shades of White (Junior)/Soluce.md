# Fifty Shades of White (Junior)
 Write-up 

Challenge Source: [Hackropole Fifty Shades of White (Junior)
](https://hackropole.fr/fr/challenges/reverse/fcsc2024-reverse-fifty-shades-of-white-1/) 


# Solution

Walter White Junior license decode : 

```
Name: Walter White Junior
Serial: 1d117c5a-297d-4ce6-9186-d4b84fb7f230
Type: 1
```

To transform his license into admin, type has to be set at 1337

**Cyberchef Recipe**: https://gchq.github.io/CyberChef/#recipe=To_Base64('A-Za-z0-9%2B/%3D')&input=TmFtZTogV2FsdGVyIFdoaXRlIEp1bmlvcgpTZXJpYWw6IDFkMTE3YzVhLTI5N2QtNGNlNi05MTg2LWQ0Yjg0ZmI3ZjIzMApUeXBlOiAxMzM3Cg&ieol=CRLF&oeol=CRLF

```bash
└─$ nc localhost 4000
[*] Send empty lines to mark the end of your inputs.
[*] Give me a valid admin license for username: Walter White Junior
----BEGIN WHITE LICENSE----
TmFtZTogV2FsdGVyIFdoaXRlIEp
1bmlvcgpTZXJpYWw6IDFkMTE3Yz
VhLTI5N2QtNGNlNi05MTg2LWQ0Y
jg0ZmI3ZjIzMApUeXBlOiAxMzM3
Cg==
-----END WHITE LICENSE-----

Valid admin license for Walter White Junior!
Well done! Here is the flag for the Junior challenge:
FCSC{2053bb69dff8cf975c1a3e3b803b05e5cc68933923aabdd6179eace1ece0c41a}
```


✅ **Answer**: FCSC{da8ae129af8512620bc6c9a711392395fba426edc6713819c1baffe004024ff2}