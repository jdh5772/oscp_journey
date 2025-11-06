# base64 error
```python3
import base64;

test = 'ping 192.168.45.154'

# str -> bytes(base64는 bytes로 받아야 해서 bytes로 변환해줘야함.)
test = test.encode();

# bytes -> str
result = base64.b64encode(test).decode();

print(result);
```
