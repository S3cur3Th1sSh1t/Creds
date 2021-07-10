<#
.SYNOPSIS 
    Use to build an anonymous SMB file server.
    Author: 3gstudent
    License: BSD 3-Clause
.DESCRIPTION 
Use to build an anonymous SMB file server.
This is useful for testing CVE-2021-1675 and CVE-2021-34527.
Test is successful on the following system:
- Windows 7
- Windows 8
- Windows 10
- Windows Server 2012
- Windows Server 2012 R2
- Windows Server 2016
.PARAMETER Path
The folder path to use.
.PARAMETER Mode
Enable or Disable the anonymous SMB file server.
.EXAMPLE 
PS > Invoke-BuildAnonymousSMBServer -Path c:\share -Mode Enable
PS > Invoke-BuildAnonymousSMBServer -Path c:\share -Mode Disable
#>

function Invoke-BuildAnonymousSMBServer
{
    [CmdletBinding()]
    param 
    (
        [Parameter(Mandatory = $True)]
        [string] $Path,
        [Parameter(Mandatory = $True)]
        [string] $Mode   
    )
    if ($Mode -eq "Enable")
    {
        EnableAnonymousSMBServer($Path)
    }

    elseif ($Mode -eq "Disable")
    {
        DisableAnonymousSMBServer($Path)
    }
    
    else
    {
        Write-Host "[!] Wrong input"
    }
} 
function EnableAnonymousSMBServer($Path)
{
    Write-Host "[+] Enable the Anonymous SMB Server "
    
    Write-Host "[1] Add permissions for the target path: " $Path
    icacls $Path /T /grant Everyone:r

    Write-Host "[2] Create the net share for the target path: " $Path
    $ShareName = "smb"
    $CommandNetshare = "net share sharename=" + $Path + " /grant:everyone,full"
    CMD.EXE /C $CommandNetshare

    Write-Host "[3] Enable the Guest account"
    net user guest /active:yes

    Write-Host "[4] Set the share that can be accessed anonymously"
    REG ADD "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /t REG_MULTI_SZ /d $ShareName /f

    Write-Host "[5] Let Everyone permissions apply to anonymous users"
    REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 1 /f

    Write-Host "[6] Remove the Guest account from `"Deny access to this computer from the network`""
    Write-Host "[*] export the security settings"
    Write-Host "    save as gp.inf"
    secedit /export /cfg gp.inf /quiet
    Write-Host "[*] modify the security settings"
    (Get-Content gp.inf) -replace "SeDenyNetworkLogonRight = Guest","SeDenyNetworkLogonRight = " | Set-Content "gp.inf"
    Write-Host "[*] reimport the security settings"
    secedit /configure /db gp.sdb /cfg gp.inf /quiet
    Write-Host "[*] update the security settings"
    CMD.EXE /C "gpupdate/force"
    Write-Host "[*] cleanup the file gp.inf and gp.sdb"
    CMD.EXE /C "del gp.inf"
    CMD.EXE /C "del gp.sdb"
 
    Write-Host "[+] All done." 
    Write-Host "    Anonymous SMB Server: //<server ip>/$ShareName"
        
} 


function DisableAnonymousSMBServer($Path)
{
    Write-Host "[+] Disable the Anonymous SMB Server "
   
    Write-Host "[1] Remove the permissions for the target path: " $Path
    icacls $Path /remove Everyone
    
    Write-Host "[2] Delete the net share for the target path: " $Path
    $ShareName = "smb"
    $CommandNetshare = "net share " + $Path + " /del /y"
    CMD.EXE /C $CommandNetshare   
    
    Write-Host "[3] Disable the Guest account"
    net user guest /active:no
    
    Write-Host "[4] Remove the share that can be accessed anonymously"
    REG DELETE "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v NullSessionShares /f

    Write-Host "[5] Disable `"Let Everyone permissions apply to anonymous users`""
    REG ADD "HKLM\System\CurrentControlSet\Control\Lsa" /v EveryoneIncludesAnonymous /t REG_DWORD /d 0 /f   
    
    Write-Host "[6] Add the Guest account back to `"Deny access to this computer from the network`""
    Write-Host "[*] export the security settings"
    Write-Host "    save as gp.inf"
    secedit /export /cfg gp.inf /quiet
    Write-Host "[*] modify the security settings"
    (Get-Content gp.inf) -replace "SeDenyInteractiveLogonRight = Guest","SeDenyNetworkLogonRight = Guest`r`nSeDenyInteractiveLogonRight = Guest" | Set-Content "gp.inf"
    Write-Host "[*] reimport the security settings"
    secedit /configure /db gp.sdb /cfg gp.inf /quiet
    Write-Host "[*] update the security settings"
    CMD.EXE /C "gpupdate/force"
    Write-Host "[*] cleanup the file gp.inf and gp.sdb"
    CMD.EXE /C "del gp.inf"
    CMD.EXE /C "del gp.sdb"
    
    Write-Host "[+] All done." 


} 
