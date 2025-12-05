# Fawn - HackTheBox StartingPoint
- Hack The Box/Starting Point/Fawn
## 1. 정찰(Reconnaissance)
```bash
sudo nmap -p 21 -sC -sV -oA fawn 10.129.1.14
```
<img width="1100" height="369" alt="image" src="https://github.com/user-attachments/assets/46eb2a3c-19ee-4bd6-b91b-6799781d43ca" />

## 2. 열거(Enumeration)
### FTP(21)
- anonymous 로그인 허용

## 3. 공격(Exploitation)
### FTP anonymous 로그인 시도
```bash
ftp 10.129.1.14
```
<img width="1100" height="325" alt="image" src="https://github.com/user-attachments/assets/5483a1d6-1905-4d02-81f0-de1b0db3e4cb" />

### FTP file Download
- `get` 명령어를 통해서 FTP로부터 파일 다운로드
<img width="1100" height="170" alt="image" src="https://github.com/user-attachments/assets/2a101e14-c19c-4e6e-b331-fa52bcb59349" />


