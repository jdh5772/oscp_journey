# Reconnaissance and Enumeration

## NMAP
```bash
# 자세한 스캔
nmap -vv <ip>

# 취약점 스캔
sudo nmap --script vuln <ip>

# /etc/hosts에 등록하고 난 뒤에 nmap 한번 더 실행해주기
sudo nmap <ip>

# Ping 테스트가 안되더라도 서버가 열려있을 수 있음
sudo nmap -Pn <ip>

# 네트워크 스캔
sudo nmap -sn 192.168.1.0/24
```
---

## SNMP Enumeration
- 네트워크 장비(라우터, 스위치, 서버, 프린터 등)를 관리 및 모니터링하기 위한 표준 프로토콜

```bash
snmp-check <ip>
```

---

## FTP Enumeration
```bash
# FTP 접속 후
ls -al  # 숨겨진 파일 확인 가능
passive # dir 안될 때 입력해서 만들어주기
```
- 업로드가 가능한지 확인

---

## SMTP User Enumeration
```bash
perl smtp-user-enum.pl -M VRFY -U /home/kali/Desktop/known-users -t 192.168.211.137
```

---

## IMAP Enumeration
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

---

## Squid Proxy
```bash
python3 spose.py --proxy http://10.10.11.131:3128 --target 10.10.11.131
```
- https://github.com/aancw/spose

---

## Redis Enumeration
```bash
redis-cli -h <ip>
```

---

## VNC (Virtual Network Computing)
- 네트워크를 통해 다른 컴퓨터 화면을 공유하고 원격 제어할 수 있는 기술

```bash
vncviewer 192.168.0.10:1
```

---

## Docker Enumeration
```bash
docker images
```

---

## Wireless Network Enumeration
```bash
# 무선 네트워크 인터페이스 정보와 설정을 확인
iw dev
```

---

## FreeBSD Enumeration
```bash
./ident-user-enum.pl 10.0.0.1 21 80 113 443
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
```

---

## Kerbrute
```bash
./kerbrute_linux_amd64 userenum --dc 192.168.133.40 -d haero /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt
```

---

## Important Checks

### 파일 및 디렉토리 확인
- `config` 파일을 먼저 `find`로 모두 찾아본 뒤에 패스워드 혹은 해시가 적혀 있는지 확인
- 사이트 제목 및 내용 확인
- `/var/mail`에 있는 내용 확인
- page source code 확인

### 네트워크 정보 확인
```bash
ip addr       # 네트워크 인터페이스의 IP 주소 확인
ip route      # 라우팅 테이블 확인
```

### 기타 확인 사항
- `curl` 헤더 확인
- password reuse 가능성 체크
- github에서 `"$pass"`로 pass 변수 찾기
