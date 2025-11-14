# Scripting and Development

## Bash Script

### basename
```bash
name=$(basename "$file")
# basename : 파일 경로에서 파일 이름만 추출
# basename /home/nicolas/bin/.bashrc -> .bashrc
```

### 문자열 패턴 제거
```bash
clean="${name#.}"
# ${variable#pattern} : 변수의 앞쪽에서 pattern과 일치하는 부분 제거
# var=".example"
# echo "${example#.}" -> example
```

### 조건문에서 변수 사용
```bash
if [[ "$DB_PASS" == "$USER_PASS" ]]
# " "를 붙이지 않으면 공백/특수문자/빈 값을 넣을 수가 있음
```

---

## Python3

### Base64 인코딩/디코딩
```python3
import base64

test = 'ping 192.168.45.154'

# str -> bytes (base64는 bytes로 받아야 해서 bytes로 변환해줘야함)
test = test.encode()

# bytes -> str
result = base64.b64encode(test).decode()

print(result)
```

### Python SSL Requests Error
- `verify=False`를 요청에다가 추가해주기

---

## Git

### Git 서버와 Git 저장소 구조

#### `git-server` 디렉토리 이름
- `git-server`는 **Git에서 강제한 이름이 아님**
- 보통 "여기가 Git 서버 저장소다"라는 의미로 관례적으로 붙이는 것
- 다른 이름이어도 전혀 상관 없음
  - 예: `/srv/git/`, `/opt/repos/`, `/home/git/repositories/`

#### Git이 저장소를 구분하는 기준
- **디렉토리 이름**이 아니라, 내부 **구조**를 보고 판단함
- Git 저장소에는 다음과 같은 파일/디렉토리가 존재:
  ```
  HEAD
  config
  description
  hooks/
  info/
  objects/
  refs/
  ```
- 특히 `objects/`, `refs/`가 있으면 Git 저장소일 가능성이 매우 높음

#### 클론 가능한지 확인하는 방법
```bash
git clone file:///path/to/repo.git
```
- 정상적으로 복제된다면 Git 저장소가 맞음
- bare repo가 아니면 clone 시 에러가 발생할 수도 있음

#### Bare 저장소 vs 일반 저장소
- **일반 저장소**:
  - 소스 코드 작업 디렉토리 + `.git/` 디렉토리 포함
  - 개발자가 직접 사용하는 형태
- **Bare 저장소**:
  - 작업 디렉토리 없이 `.git` 구조만 존재
  - 중앙 서버용으로 사용됨
  - 보통 `.git` 확장자를 붙여 관리:
    ```
    /srv/git/myproject.git/
    ```

### GIT_SSH_COMMAND
```bash
GIT_SSH_COMMAND='ssh -i id_rsa -p 43022' git clone git@192.168.120.204:/git-server
git config --global user.name "kali"
git config --global user.email "kali@kali.(none)"
git add -A
git commit -m "pwn"
git push origin main
```

**설명:**
- `GIT_SSH_COMMAND=...` : `GIT_SSH_COMMAND` 환경변수를 지정하면, Git이 사용할 SSH 명령어를 직접 정의할 수 있음
- 다른 포트로만 접속 가능한 경우 사용
- `--global` : 현재 사용자 계정 전체에 적용

---

## SSH

### SSH 옵션
```bash
ssh -i root -o IdentitiesOnly=true root@localhost
```
- `-o IdentitiesOnly=true` : 저장되어 있는 다른 키들을 같이 전송하기 때문에 해당하는 키만으로 인증하는 방법
