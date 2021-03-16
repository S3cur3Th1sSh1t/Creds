$credential = New-Object System.Management.Automation.PsCredential("DOMAIN\Username", (ConvertTo-SecureString "Password" -AsPlainText -Force))
