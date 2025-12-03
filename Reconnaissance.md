# Reconnaissance
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
## 🔎 Footprinting

### SSL Certificate 정보 수집
<img width="969" height="759" alt="image" src="https://github.com/user-attachments/assets/9b03c318-cce6-4810-ab5d-0c70a0648c2b" />

```bash
# crt.sh를 이용한 서브도메인 발견
curl -s "https://crt.sh/?q=facebook.com&output=json" | jq -r '.[] | select(.name_value | contains("dev")) | .name_value' | sort -u
```

> **Tip**: SSL 인증서에는 서브도메인 정보가 포함되어 있어 공격 표면 확장에 유용합니다.

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

## 📊 Information Gathering - Web

### 디렉토리 차이점

```
/admin  → 리다이렉션 (301/302)
/admin/ → /admin/index 파일 직접 반환 (200)
```

> **Tip**: 슬래시 유무에 따라 서버 응답이 다를 수 있습니다.

---

## 🔧 FinalRecon

> **⚠️ OSCP 시험에서 사용 불가**

통합 정보 수집 도구입니다.

```bash
# 헤더 및 WHOIS 정보 수집
./finalrecon.py --headers --whois --url http://inlanefreight.com
```
