# OSCP Journey

A collection of OSCP commands and techniques tailored to my taste

## 📚 Contents

이 저장소는 OSCP 준비를 위한 보안 관련 명령어와 기법들을 체계적으로 정리한 것입니다.

### 📂 File Structure

1. **01_Reconnaissance_and_Enumeration.md**
   - NMAP, SMB, LDAP, SNMP, FTP 등 정보 수집
   - 각종 스캐닝 도구 및 기법

2. **02_Web_Application_Attacks.md**
   - SQL Injection (MSSQL, MySQL, PostgreSQL)
   - LFI/RFI, Directory Traversal
   - File Upload Vulnerabilities
   - Command Injection
   - PHP Wrappers

3. **03_Windows_Privilege_Escalation.md**
   - Service Binary Hijacking
   - Unquoted Service Paths
   - Token Impersonation
   - AlwaysInstallElevated
   - SeBackupPrivilege, SeRestore, SeManageVolume
   - Server Operators Group

4. **04_Linux_Privilege_Escalation.md**
   - SUID/SGID 파일 악용
   - Disk Group 권한 상승
   - Sudo 권한 악용
   - Wildcard Exploits
   - 공유 라이브러리 취약점

5. **05_Active_Directory_Attacks.md**
   - AS-REP Roasting
   - Kerberoasting
   - Silver Tickets
   - Domain Controller Synchronization
   - BloodHound Enumeration
   - Azure AD Connect

6. **06_Password_Attacks.md**
   - NTLM Hash Cracking
   - Net-NTLMv2 Cracking & Relaying
   - KeePass Password Cracking
   - SSH Private Key Cracking
   - Hydra, John the Ripper, Hashcat

7. **07_Network_Tunneling_and_Pivoting.md**
   - SSH Port Forwarding (Local, Remote, Dynamic)
   - Socat
   - Chisel
   - Plink
   - Netsh
   - sshuttle

8. **08_Exploitation_Tools.md**
   - msfvenom
   - Netcat
   - exiftool
   - curl, wget
   - GCC Cross Compilation

9. **09_Platform_Specific_Exploits.md**
   - Mantis, Jenkins, Grafana
   - PRTG, Apache Tomcat
   - Redis, GlassFish

10. **10_Scripting_and_Development.md**
    - Bash Scripting
    - Python3
    - Git

## 🎯 Usage

각 파일은 독립적으로 읽을 수 있도록 구성되어 있습니다. 필요한 주제를 찾아 해당 파일을 참조하세요.

## ⚠️ Disclaimer

이 자료는 **교육 목적**으로만 사용되어야 합니다. 승인받지 않은 시스템에 대한 공격은 불법입니다.
