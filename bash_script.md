```bash
name=$(basename "$file")
# basename : 파일 경로에서 파일 이름만 추출
# basename /home/nicolas/bin/.bashrc` -> `.bashrc

clean="${name#.}"
# ${variable#pattern} : 변수의 앞쪽에서 pattern과 일치하는 부분 제거
# var=".example"
# echo "${example#.}" -> example
```
