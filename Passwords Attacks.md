# Cracking pdf password
```bash
pdf2john Infrastructure.pdf > pdf.hash

john --wordlist=/usr/share/wordlists/rockyou.txt --rules=best64 pdf.hash
```
---
# PPK(Putty Private Key File) to PEM
```bash
puttygen <file.ppk> -O private-openssh -o <file.pem>

ssh -i <file.pem> host@local
```
---
# cpassword(groups.xml)
```bash
# pip install gpp-decrypt
gpp-decrypt -f groups.xml
```
