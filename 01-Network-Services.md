# Network Services

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
### NTLM Relay Attack
```bash
impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.220.146 -c '<payload>'
```

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

## 📧 SMTP Enumeration

**포트**: 25 (SMTP), 465 (SMTPS), 587 (Submission)

```bash
# SMTP 사용자 열거
smtp-user-enum -M VRFY -U footprinting-wordlist.txt -t 10.129.42.195 -w 20 -v

smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7

smtp-user-enum -M EXPN -U userlist.txt -D inlanefreight.htb -t 10.129.203.7
```
```bash
hydra -l 'marlin@inlanefreight.htb' -P pws.list smtp://10.129.203.12
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
```powershell
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```bash
xfreerdp /v:10.10.10.132 /u:administrator /p:'Password0@' /drive:linux,/home/plaintext/htb/academy/filetransfer
```

**포트**: 3389

### 체크리스트

침투 테스트 시 RDP 접근 후 확인할 사항:

- ✅ 특정 프로그램을 관리자 권한으로 실행 가능한지 확인
- ✅ `cmd.exe` 또는 `powershell.exe`를 관리자로 실행 가능한지 테스트
