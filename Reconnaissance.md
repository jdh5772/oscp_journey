# Reconnaissance

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
## 🗺️ Footprinting

### SSL Certificate 정보 수집

SSL/TLS 인증서에는 서브도메인, 조직 정보, 유효 기간 등 귀중한 정보가 포함되어 있습니다.

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

### WHOIS에서 얻을 수 있는 정보:
- **등록자 정보**: 조직명, 연락처 (GDPR로 인해 제한될 수 있음)
- **네임서버**: DNS 서버 정보 → 호스팅 제공자 파악
- **등록일/만료일**: 도메인 수명 추정
- **등록 대행사**: 도메인 관리 업체
- **IP 주소 블록**: WHOIS를 통한 IP 범위 확인

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

### DNS 레코드 타입 설명

| 레코드 타입 | 설명 | 예시 |
|------------|------|------|
| A | IPv4 주소 | `example.com → 93.184.216.34` |
| AAAA | IPv6 주소 | `example.com → 2606:2800:220:1:248:1893:25c8:1946` |
| CNAME | 별칭 (Canonical Name) | `www.example.com → example.com` |
| MX | 메일 서버 | `example.com → mail.example.com` |
| NS | 네임서버 | `example.com → ns1.example.com` |
| TXT | 텍스트 정보 | SPF, DKIM, DMARC 레코드 |
| PTR | 역방향 DNS | `34.216.184.93.in-addr.arpa → example.com` |

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

# 응답 크기 필터링 (False Positive 제거)
ffuf -w wordlist.txt -H 'Host: FUZZ.target.com' -u http://target.com -fs 1234
```

### VHOST vs Subdomain

| 구분 | VHOST | Subdomain |
|------|-------|-----------|
| DNS 등록 | 불필요 | 필요 |
| 접근 방식 | Host 헤더 조작 | DNS 쿼리 |
| 발견 방법 | 브루트포스 | DNS 조회 |

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

### 주요 HTTP 헤더 분석

| 헤더 | 의미 | 예시 |
|------|------|------|
| Server | 웹 서버 소프트웨어 | `Apache/2.4.41` |
| X-Powered-By | 백엔드 기술 | `PHP/7.4.3` |
| X-AspNet-Version | ASP.NET 버전 | `4.0.30319` |
| X-Generator | CMS 정보 | `WordPress 5.8` |

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

### 크롤링 시 주의사항
- **robots.txt 확인**: 크롤링 제한 규칙 파악
- **Rate Limiting**: 요청 속도 제한 (서버 부하 방지)
- **User-Agent 설정**: 봇 차단 회피

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

### 주요 Well-Known URIs

| URI | 용도 |
|-----|------|
| `/security.txt` | 보안 연락처, 버그 바운티 정보 |
| `/change-password` | 비밀번호 변경 페이지 |
| `/openid-configuration` | OpenID Connect 설정 |
| `/assetlinks.json` | Android App Links |
| `/apple-app-site-association` | iOS Universal Links |

> **Use Case**: `security.txt`를 통해 버그 바운티 프로그램이나 보안 연락처를 찾을 수 있습니다.

---

## 🕰️ Wayback Machine

Internet Archive의 Wayback Machine을 통해 과거 웹사이트 스냅샷을 확인할 수 있습니다.

**URL**: https://web.archive.org/

### 활용 방법
- 삭제된 페이지 확인
- 과거 코드나 설정 파일 발견
- 도메인 소유권 변경 이력 추적
- 오래된 취약점 식별 (패치되지 않은 경우)

### waybackurls 도구 사용
```bash
# waybackurls 설치
go install github.com/tomnomnom/waybackurls@latest

# 사용법
echo "target.com" | waybackurls
```

---

## 📊 Information Gathering - Web

### 디렉토리 차이점

```
/admin  → 리다이렉션 (301/302)
/admin/ → /admin/index 파일 직접 반환 (200)
```

> **Tip**: 슬래시 유무에 따라 서버 응답이 다를 수 있습니다. 브루트포싱 시 두 가지 모두 시도하는 것이 좋습니다.

---

## 🔧 FinalRecon

> **⚠️ OSCP 시험에서 사용 불가**

통합 정보 수집 도구입니다.

```bash
# 헤더 및 WHOIS 정보 수집
./finalrecon.py --headers --whois --url http://inlanefreight.com

# 전체 정보 수집
./finalrecon.py --full --url http://inlanefreight.com
```

---

## 📝 Reconnaissance Checklist

정찰 단계에서 확인해야 할 항목들:

- [ ] WHOIS 정보 수집 완료
- [ ] DNS 레코드 조회 (A, AAAA, MX, NS, TXT)
- [ ] Zone Transfer 시도
- [ ] 서브도메인 열거 (brute-force, certificate transparency)
- [ ] Virtual Host 발견
- [ ] 웹 기술 스택 식별
- [ ] WAF/IPS 존재 여부 확인
- [ ] robots.txt, sitemap.xml 확인
- [ ] Well-known URIs 조회
- [ ] SSL/TLS 인증서 정보 수집
- [ ] Wayback Machine 아카이브 확인
- [ ] 소셜 미디어 프로필 검색 (LinkedIn, GitHub)
