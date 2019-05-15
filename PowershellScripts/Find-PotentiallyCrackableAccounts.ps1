<#
    Author: Matan Hart (@machosec)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Find-PotentiallyCrackableAccounts
{
<#
    .SYNOPSIS
        Reveals juicy information about user accounts associated with SPN

        Author: Matan Hart (@machosec)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION
        This function queries the Active Directory and retreive information about user accounts associated with SPN.
        This infromation could detremine if a service account is potentially crackable.
        User accounts associated with SPN are vulnerable to offline brute-forceing and they are often (by defualt)
        configured with weak password and encryption (RC4-HMAC).  
        Requires Active Directory authentication (domain user is enough). 

    .PARAMETER Domain
        The name of the domain to query. "Current" for the user's current domain. Defualts to the entire forest. 

    .PARAMETER AddGroups
        Add additional groups to consider as sensitive 

    .PARAMETER Sensitive
        Show only sensitive accounts.

    .PARAMETER Stealth
        Do not check service/server connectivity
    .PARAMETER GetSPNs
        Show SPNs instead of user's data

    .PARAMETER FullData
        Show more user data

    .EXAMPLE 
        Get-PotentiallyCrackableAccounts -Domain "IT.company.com"
        Returns all user accounts associated with SPN in the IT.company.com domain.

    .EXAMPLE
        Get-PotentiallyCrackableAccounts -FullData -Verbose
        Returns detailed information about all user accounts associated with SPN in the forest. Enable verbose mode 

    .EXAMPLE
        Get-PotentiallyCrackableAccounts -AddGroups "Remote Desktop Users" -Sensitive -Stealth -GetSPNs
        Returns all SPNs of sensitive user account in the forest. Consider "Remote Desktop Users" group as sensitive and do not check connectivity.
    #>

    [CmdletBinding()]
    param
    (
        [string]$Domain,
        [array]$AddGroups,
        [switch]$Sensitive,
        [switch]$Stealth,
        [switch]$GetSPNs,
        [switch]$FullData
    )

    #recursivly get nested groups of a group object
    function Get-NestedGroups
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$True, ValueFromPipeline=$True)]
            [ValidateNotNullOrEmpty()]
            [string]$DN
        )

        $GroubObj = [adsi]"LDAP://$DN"
        #if the object is a group
        if ($GroubObj.Properties.samaccounttype -match '536870912' -or $GroubObj.Properties.samaccounttype -match '268435456')
        {
            #Searching for group objects that are member of the group
            foreach ($Member in $GroubObj.Properties.member)
            {
                #get group objects inside this group object
                Get-NestedGroups -DN $Member
            }
            return $GroubObj.Properties.distinguishedname
        }
    }

#========================================================================= Creating ADSI Searcher =========================================================================
    
    $SearchList = @()
    if($Domain)
    {
        if ($Domain -eq "Current") {
            $SearchScope = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        else
        {
            try {
                $TargetDomain = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
                $SearchScope = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($TargetDomain)
            }
            catch {
                Write-Error "Could not communicate with the foreigen domain: $Domain"
                return
            } 
        }
        if ($SearchScope.DomainMode.value__ -lt 4 -and $ChildDomain.DomainMode.value__ -ne -1) {
            Write-Warning "The function level of domain: $($SearchScope.Name) is lower than 2008 - Some stuff may not work"
        }
        $SearchList += 'LDAP://DC=' + ($SearchScope.Name -Replace ("\.",',DC='))
        Write-Verbose "Searching the domain: $($SearchScope.name)"
    }
    else 
    {
        $SearchScope = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
        foreach ($ChildDomain in $($SearchScope.Domains)) {
            if ($ChildDomain.DomainMode.value__ -lt 4 -and $ChildDomain.DomainMode.value__ -ne -1) {
                Write-Warning "The function level of domain: $($ChildDomain.Name) is lower than 2008 - Some stuff may not work"
            }
            $SearchList += 'LDAP://DC=' + ($ChildDomain.Name -Replace ("\.",',DC='))
        }
        Write-Verbose "Searching the forest: $($SearchScope.name)"    
    }

    #creating ADSI searcher 
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.PageSize = 500
    $Searcher.PropertiesToLoad.Add("distinguishedname") | Out-Null

#========================================================================= Gathering Sensitive Groups =========================================================================

    #list of built-in sensitive groups (Administratos group conatins domain and enterprise admins) - did I missed a group?
    $SensitiveGroups = @("Administrators", "Account Operators", "Backup Operators", "Print Operators", "Server Operators", "Group Policy Creator Owners", "Schema Admins")
    if ($AddGroups) {
        Write-Verbose "Adding $AddGroups to the list of senstivie groups"
        $SensitiveGroups += $AddGroups
    }
    $AllSensitiveGroups = @()
    Write-Verbose "Gathering sensitive groups"
    foreach ($Path in $SearchList) {
        Write-Verbose "Searching Sensitive groups in domain: $($Path -replace "LDAP://DC=" -replace ",DC=", ".")"
        $Searcher.SearchRoot = $Path
        foreach ($GroupName in $SensitiveGroups) {
            #filter group objects with specific name
            $Searcher.Filter = "(&(|(samAccountType=536870912)(samAccountType=268435456))(|(samAccountName=$GroupName)(name=$GroupName)))"
            try {
                $GroupObjects = $Searcher.FindAll()
            }
            catch {
                Write-Warning "Could not communicate with the domain: $($Path -replace "LDAP://DC=" -replace ",DC=", ".")"
            }
            if ($GroupObjects)
            {
                foreach ($GroupObject in $GroupObjects) {
                    #recursivly get all nested groups inherited from sensitive groups - don't trust AdminCount=1 
                    $AllSensitiveGroups += Get-NestedGroups -DN $GroupObject.Properties.distinguishedname
                }
            }
            else {Write-Warning "Could not find group: $Group"}     
        }
    }
    Write-Verbose "Number of sensitive groups found: $($AllSensitiveGroups.Count)"

#========================================================================= Gathering users with SPN =========================================================================
  
    Write-Verbose "Gathering user accounts associated with SPN"
    #list of properties to retreive from AD
    $Properies = "msDS-UserPasswordExpiryTimeComputed", "msDS-AllowedToDelegateTo", "msDS-SupportedEncryptionTypes", "samaccountname", "userprincipalname", "useraccountcontrol", "displayname", "memberof", "serviceprincipalname", "pwdlastset", "description"
    foreach ($Property in $Properies) {
        $Searcher.PropertiesToLoad.Add($Property) | Out-Null
    }
    #filter user accounts with SPN except krbtgt account
    $Searcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!(samAccountName=krbtgt)))"
    $UsersWithSPN = @()
    foreach ($Path in $SearchList) {
        $Searcher.SearchRoot = $Path
        try {
            $UsersWithSPN += $Searcher.FindAll()
        }
        catch {
            Write-Warning "Could not communicate with the domain: $($Path -replace "LDAP://DC=" -replace ",DC=", ".") - Does it have trust?"
        }
    }
    Write-Verbose "Number of users that contain SPN: $($UsersWithSPN.Count)"
    
# ========================================================================= Gathering info about users =========================================================================

    $CurrentDate = Get-Date
    $AllData = @()
    foreach ($User in $UsersWithSPN) {
        Write-Verbose "Gathering info about the user: $($User.Properties.displayname)"
        
        #----------------------------------- Time stuff -----------------------------------
        
        $CrackWindow = "N/A"
        #if the user's password has expiration date (works with FGPP) - https://msdn.microsoft.com/en-us/library/cc223410.aspx
        if ($user.Properties.'msds-userpasswordexpirytimecomputed' -ne 9223372036854775807) # 0x7FFFFFFFFFFFFFFF
        {
            $PasswordExpiryDate = [datetime]::FromFileTime([string]$User.Properties.'msds-userpasswordexpirytimecomputed')
            Write-Verbose "$($User.Properties.displayname)'s password will expire on $PasswordExpiryDate"
            $CrackWindow = $PasswordExpiryDate.Subtract($CurrentDate).Days
            Write-Verbose "Which means it has crack window of $CrackWindow days"
        }
        $PasswordLastSet = [datetime]::FromFileTime([string]$User.Properties.pwdlastset)
        $PasswordAge = $CurrentDate.Subtract($PasswordLastSet).Days

        #----------------------------------- UAC stuff -----------------------------------
        
        #reading UAC attributes using bitmask - https://support.microsoft.com/en-us/kb/305144
        [int32]$UAC = [string]$User.Properties.useraccountcontrol
        $IsEnabled = $true
        #if the user is disabled or lockedout
        if (($UAC -band 2) -eq 2 -or ($UAC -band 16) -eq 16) {$IsEnabled = $false} # 0x0002 / 0x0010
        $IsPasswordExpires = $true
        #if the user password never expires
        if (($UAC -band 65536) -eq 65536) # 0x10000
        {
            $IsPasswordExpires = $false
            $CrackWindow = "Indefinitely"
        } 
        $Delegation = $false
        $TargetServices = "None"
        #if the user is trusted for Kerberos unconstrained delegation
        if (($UAC -band 524288) -eq 524288) # 0x80000
        {
            $Delegation = "Unconstrained"
            $TargetServices = "Any"
        } 
        #if the user is trusted for Kerberos constrained delegation
        elseif ($User.Properties.'msds-allowedtodelegateto')
        {
            $Delegation = "Constrained" 
            #if the user is trusted for Kerberos constrained delegation with protocol transition
            if (($UAC -band 16777216) -eq 16777216) {$Delegation = "Protocol Transition"} # 0x1000000
            $TargetServices = [array]$User.Properties.'msds-allowedtodelegateto'
        }
        $EncType = "RC4-HMAC"
        [int32]$eType = [string]$User.Properties.'msds-supportedencryptiontypes'
        #if the user supports AES encryptions (MS-KILE 2.2.6) - https://msdn.microsoft.com/en-us/library/cc220375.aspx
        if ($eType)
        {
            if (($eType -band 16) -eq 16) {$EncType = "AES256-HMAC"} # 0x10
            elseif (($eType -band 8) -eq 8) {$EncType = "AES128-HMAC"} # 0x08
        }
        else 
        {
            #if the UF_USE_DES_KEY_ONLY bit is set (account can only use DES in Kerberos authentication)
            if (($UAC -band 2097152) -eq 2097152) {$EncType = "DES"} #0x200000
        }

        #----------------------------------- SPN stuff -----------------------------------
        
        $AccountRunUnder = @()
        #arranging SPNs to <service>/<server> format - https://technet.microsoft.com/en-us/library/cc961723.aspx
        [array]$SPNs = $User.Properties.serviceprincipalname -replace ":.*"  | Get-Unique 
        foreach ($SPN in $SPNs)
        {
            #splitting SPN to service type and instance name 
            $SPN = $SPN -split("/")
            #TODO: More services and ports, take the port from the SPN
            [array]$Service = switch -Wildcard ([string]$SPN[0])
            {
                "MSSQL*"    {"MS SQL",@(1433)}
                "HTTP"      {"Web",@(80,443,8080)}
                "WWW"       {"Web",@(80,443,8080)}
                "TERMSRV"   {"Terminal Services",@(3389)}
                "MONGO*"    {"MongoDB Enterprise"}
                "HOST"      {"Computer services"}
                "WSMAN"     {"WinRM",@(5985,5986)}
                "FTP"       {"File Transfer",@(22)}
                default     {$SPN[0]}
            }
            $RunUnder = New-Object -TypeName psobject -Property @{
                Service = $Service[0]
                Server  = $SPN[1] 
                IsAccessible = "N/A"
            } | select Service,Server,IsAccessible
            if (!$Stealth)
            {
                #if the service contains default ports
                if ($Service[1])
                {
                    $Socket = New-Object System.Net.Sockets.TcpClient
                    $RunUnder.IsAccessible = "No"
                    #testing if the service default ports are open on the server 
                    foreach ($Port in $Service[1]) {
                        Write-Verbose "Checking connectivity to server: $($RunUnder.Server) on port $Port"
                        try {
                            $Socket.Connect($RunUnder.Server,$Port)
                            $RunUnder.IsAccessible = "Yes"
                            break
                        }
                        catch {
                            Write-Verbose "Port $Port is not accessiable on server: $($RunUnder.Server)"
                        }
                    }
                }
                else
                {
                    Write-Verbose "Checking connectivity to server: $($RunUnder.Server)"
                    #if the server answers to one ping
                    if (Test-Connection -ComputerName $RunUnder.Server -Quiet -Count 1)
                    {
                        $RunUnder.IsAccessible = "Yes"
                    }
                    else
                    {
                        Write-Verbose "The server: $($RunUnder.Server) is not accessiable - Is it exist?"
                        $RunUnder.IsAccessible = "No"
                    }
                }
            }
            $AccountRunUnder += $RunUnder
        }  
        if ($User.Properties.memberof)
        {
            #get sensitive groups that the user is a memberof
            $UserSensitiveGroups = (@(Compare-Object $AllSensitiveGroups $([array]$User.Properties.memberof) -IncludeEqual -ExcludeDifferent)).InputObject
        }
        $IsSensitive = $false
        #if the user is a member of a sensitive group or is allowed for Kerberos unconstrained or S4U2Self delegation
        if ($UserSensitiveGroups -or $Delegation)
        {
            Write-Verbose "$($User.Properties.displayname) is sensitive"
            $IsSensitive = $true 
        }
        $UserData = New-Object psobject -Property @{
            UserName        = [string]$User.Properties.samaccountname
            DomainName      = [string]$User.Properties.userprincipalname -replace ".*@"
            IsSensitive     = $IsSensitive
            EncType         = $EncType
            Description     = [string]$User.Properties.description
            IsEnabled       = $IsEnabled
            IsPwdExpires    = $IsPasswordExpires
            PwdAge          = $PasswordAge
            CrackWindow     = $CrackWindow
            SensitiveGroups = $UserSensitiveGroups -replace "CN=" -replace ",.*"
            MemberOf        = $User.Properties.memberof -replace "CN=" -replace ",.*"
            DelegationType  = $Delegation
            TargetServices  = $TargetServices
            NumofServers    = ($AccountRunUnder.Server | select -Unique).Count
            RunsUnder       = $AccountRunUnder
            AssociatedSPNs  = [array]$User.Properties.serviceprincipalname   
        } | select UserName,DomainName,IsSensitive,EncType,Description,IsEnabled,IsPwdExpires,PwdAge,CrackWindow,SensitiveGroups,MemberOf,DelegationType,TargetServices,NumofServers,RunsUnder,AssociatedSPNs
        $AllData += $UserData 
    }
    if ($Sensitive)
    {
       Write-Verbose "Removing non-sensitive users from the list"
       $AllData = $AllData | ? {$_.IsSensitive}
    }  
    Write-Verbose "Number of users included in the list: $($AllData.UserName.Count)"
    if ($GetSPNs) {return @($AllData.AssociatedSPNs)}
    elseif ($FullData) {return $AllData}
    else {return $AllData | ? {$_.IsEnabled} | Select-Object UserName,DomainName,IsSensitive,EncType,Description,PwdAge,CrackWindow,RunsUnder}        
}
