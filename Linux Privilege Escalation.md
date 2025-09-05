```bash
# OS정보 확인
cat /etc/issue

cat /etc/os-release

uname -a
```
```bash
# 프로세스 및 네트워크 상태 확인
ps aux

ifconfig

routel

ss -anp

cat /etc/iptables/rules.v4
- IPv4 iptables 방화벽 규칙 확인.
```
```bash
ls -al /etc/cron*
sudo crontab -l
```
```bash
# 패키지 목록 조회
dpkg -l
```
```bash
find / -writable -type d 2>/dev/null

find /etc -writable -type f 2>/dev/null

find /usr -writable -type f 2>/dev/null

find /var -writable -type f 2>/dev/null
```
```bash
# 마운트 및 디스크 정보 조회
cat /etc/fstab
- 부팅 시 자동 마운트되는 파일 시스템 정보 확인.

mount

lsblk
- 블록 디바이스(디스크, 파티션) 정보 출력.
```
```bash
# 커널 모듈 정보
lsmod
- 현재 로드된 커널 모듈 목록 표시.

/sbin/modinfo libata
- 특정 커널 모듈(`libata`)의 상세 정보 확인.
```
```bash
find / -perm -4000 -type f 2>/dev/null
```
```bash
/usr/sbin/getcap -r / 2>/dev/null
```
```bash
sudo -l
```
---
# Linux Exploit Suggester
- https://github.com/The-Z-Labs/linux-exploit-suggester
- 예전 버전 리눅스 취약점 발견에 용이
---

# disk group privilege escalation
- https://www.hackingarticles.in/disk-group-privilege-escalation/
- `disk` 그룹은 **로우 블록 디바이스**(예: `/dev/sda`, `/dev/nvme0n1p2`)에 접근할 수 있습니다.  
```bash
df -h
- 현재 마운트된 파일시스템의 디스크 사용량을 사람이 읽기 쉬운 형태로 출력합니다.
```
<img width="689" height="248" alt="image" src="https://github.com/user-attachments/assets/96e0cff6-b9f2-4624-9c36-417a71ddac0c" />
---
```bash
debugfs /dev/sda3
- 파일시스템의 내부 구조를 조작하거나 디버깅할 수 있는 저수준 파일시스템 디버거 실행

mkdir test
- readonly로 설정되어 있으면 아래 코드 실행

cat /root/.ssh/id_rsa
```
# sudo group
```bash
sudo su
```
---
# rpc.py
- https://github.com/abersheeran/rpc.py
- https://www.exploit-db.com/exploits/50983
---
# makefile privesc
<img width="706" height="636" alt="image" src="https://github.com/user-attachments/assets/553e10b6-f5d7-4494-b3da-94c3167651d4" />
- https://medium.com/@adamforsythebartlett/makefile-privilege-escalation-oscp-62ea2c666d23
