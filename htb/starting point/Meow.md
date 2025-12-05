# Hack the Box/Starting Point/Meow
## 정찰(Reconnaissance)
sudo nmap -p 23 -sC -sV -oA mew 10.129.1.17
<img width="1100" height="206" alt="image" src="https://github.com/user-attachments/assets/02f2ddd0-5bd2-4582-b8af-00a9e7b32377" />

## 열거(Enumeration)
- telnet : linux에서 원격 접속하여 명령어를 실행할 수 있도록 하는 프로그램.
- `telnet <ip> <port>`로 접속할 수 있음.

## 공격(Exploitation)
telnet 10.129.1.17 23
<img width="1100" height="235" alt="image" src="https://github.com/user-attachments/assets/e8db2047-d4e5-48c6-90e2-e35a0ed0e670" />

대부분의 리눅스의 관리자 계정의 id는 root다.

어떤 계정으로 로그인이 되는지는 확실하게 모르지만, 일단 root로 시도해본다.

root 계정으로 로그인 성공하여 flag.txt를 확인할 수 있다.
<img width="1100" height="315" alt="image" src="https://github.com/user-attachments/assets/a39aaff2-0af4-46cc-a3fc-625764e2f3cc" />
