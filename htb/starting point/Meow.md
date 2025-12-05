# Hack the Box/Starting Point/Meow

## 1. 정찰(Reconnaissance)

```bash
sudo nmap -p 23 -sC -sV -oA mew 10.129.1.17
```
<img width="1100" height="206" alt="image" src="https://github.com/user-attachments/assets/02f2ddd0-5bd2-4582-b8af-00a9e7b32377" />

- 23번 포트에서 Telnet 서비스 실행 중 확인
---
## 2. 열거(Enumeration)
### Telnet
- Linux/Unix 시스템에서 원격 접속을 위한 프로토콜
- 사용법 : `telnet <ip> <port>`

---
## 3. 공격(Exploitation)
### Telnet 접속 시도

```bash
telnet 10.129.1.17 23
```
<img width="1100" height="235" alt="image" src="https://github.com/user-attachments/assets/e8db2047-d4e5-48c6-90e2-e35a0ed0e670" />

### 로그인 시도
- 대부분의 Linux 시스템에서 관리자 계정 이름은 `root`
- 먼저 `root` 계정으로 로그인 시도
- root 계정으로 패스워드 없이 로그인 성공!
- 시스템에 대한 완전한 관리자 권한 획득
<img width="1100" height="315" alt="image" src="https://github.com/user-attachments/assets/a39aaff2-0af4-46cc-a3fc-625764e2f3cc" />
