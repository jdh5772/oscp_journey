# Dancing - HackTheBox StartingPoint
## 1. 정찰(Reconnaissance)
```bash
sudo nmap -p 135,139,445,5985 -sC -sV -vv -oA dancing 10.129.1.12
```
<img width="858" height="475" alt="image" src="https://github.com/user-attachments/assets/33b240ab-5ea2-41b8-aac7-2b88c0fa3aad" />

## 2.  열거(Enumeration)
### SMB
- `guest`로 로그인 시도 및 탐색

### winrm
-  수집된 credential로 로그인 시도

## 3.  공격(Exploitation)
### SMB
```bash
smbmap -u 'guest' -p '' -H 10.129.1.12
```
<img width="943" height="156" alt="image" src="https://github.com/user-attachments/assets/c95a3ac4-80b9-49e7-ac93-adeee1d1ac9c" />

- `IPC$`를 제외하고 `WorkShares`폴더 탐색
```bash
smbclient //10.129.1.12/WorkShares
```
<img width="943" height="237" alt="image" src="https://github.com/user-attachments/assets/e5209818-38e9-4dc0-a999-e5ba41dc52f8" />

- `james.p` 폴더에서 `flag.txt`발견 및 다운로드
<img width="1022" height="332" alt="image" src="https://github.com/user-attachments/assets/eb9c5da2-8395-404b-96ad-2a56c5f85458" />



