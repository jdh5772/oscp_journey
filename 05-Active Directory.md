# FPing
```bash
fping -asgq 172.16.5.0/23

sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

# kerbrute
```bash
# jsmith.txt/jsmith2.txt
git clone https://github.com/insidetrust/statistically-likely-usernames

kerbrute userenum -d INLANEFREIGHT.LOCAL --dc 172.16.5.5 jsmith.txt -o valid_ad_users
```

# Responder
```bash
sudo respondr -I tun0 -v
```

# Inveigh
```powershell
.\inveigh.exe

# press ESC and ENTER in Inveigh
GET NTLMV2UNIQUE

GET NTLMV2USERNAMES
```

# password policy
```bash
crackmapexec smb 172.16.5.5 -u avazquez -p Password123 --pass-pol
```
```bash
rpcclient -U "" -N 172.16.5.5

rpcclient $> querydominfo
rpcclient $> getdompwinfo
```
```bash
enum4linux -P 172.16.5.5

enum4linux-ng -P 172.16.5.5 -oA ilfreight
```
```powershell
net use \\DC01\ipc$ "" /u:""
```
```bash
ldapsearch -H 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```
```powershell
net accounts
```
```powershell
import-module .\PowerView.ps1
Get-DomainPolicy
```

# Enumerate Users
```bash
enum4linux -U 172.16.5.5  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"

crackmapexec smb 172.16.5.5 --users

ldapsearch -H 172.16.5.5 -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "

./windapsearch.py --dc-ip 172.16.5.5 -u "" -U

kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt
```
```bash
rpcclient -U "" -N 172.16.5.5

rpcclient $> enumdomusers
```
