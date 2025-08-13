# exiftool

```bash
# PDF 파일의 모든(exiftool이 아는 한) 메타데이터를 최대한 상세히 출력
exiftool -a -u brochure.pdf
```

- `exiftool` : 이미지/문서/영상 파일의 메타데이터를 조회·수정하는 도구  
- `-a` (*allow duplicates*) : 중복 키가 있어도 모두 표시  
- `-u` (*unknown*) : 표준에 없는(알 수 없는) 태그까지 표시  
- `brochure.pdf` : 대상 파일

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
