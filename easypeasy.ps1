<#
    Author: Lavi Lazarovitz
    Contact: cyberark.labs@cyberark.com
    License: GNU v3
#>
   


    function EasyPeasy
    {

     <#
    .SYNOPSIS
        Scan for EasyPeasy passwords in Active Directory

    .DESCRIPTION
        The function first scans for domain accounts with local admininstrator privileges across connected machines in the network.
        The account's NTLM hash is then extracted from Active Directory using a privilegd account and password replication process.
        In case a common password is found, the function outputs the user name and password to the screen (no output file is created).


    .PARAMETER All
        Allows the scan to check all domain accounts. In case the all switch is chosen, the scan extract all NTLM hashes from Active
        Directory. THe scan is much quicker than the partial privileged accounts scan.

    .PARAMETER Details
        Allows the scan to check where the accounts with common passwords have access to and on what machines those accounts 
        currently have open sessions.
        The 'Details' will be presented only if the -All switch is off.

    .PARAMETER Hash_File
        Use your own dictionary CSV file. The path should be full and include the clear text password in column 1 and the corresponding
        hash in column 2 ( see the ntlmHashes.csv file for reference). 

    .EXAMPLE 
        EasyPeasy
        Returns all user names with common passwords, where those accounts have privileged access and where those accounts currently have
        active sessions (where the accounts' hashes could be found).
        
    .EXAMPLE
        EasyPeasy -All
        Returns all domain accounts with easy passwords.

       #>
    

    [CmdletBinding()]
    param
    (
        [switch]$All,
        [switch]$Details,
        [string]$Hash_File
    )
        
        if ($PSVersionTable.PSVersion.Major -ge 3){
        $path = $PSScriptRoot
        }

        else{$path = '.'}
        if(-not $All){
            Write-host "Getting a list of machines connected to the network" -ForegroundColor Green       
            $comps = Get-DomainComps

            try{
            . $path\invoke-parallel.ps1
            . $path\Invoke-DCsync.ps1
            Import-Module $path\Recon\Recon.psm1
            }catch{
                write-host "Some files seem to be missing. If Powershell version is 2, execute the module inside Easy-Peasy directory."
                break}

           write-host "Getting a list of all privileged accounts" -ForegroundColor Green
#======================================================= Handling Privileged Accounts ===================================================
    
          $results = $comps | Invoke-Parallel -Throttle 200  -ErrorAction SilentlyContinue -RunspaceTimeout 5 -ScriptBlock{
            
                
                #. .\easypeasy.ps1.
                $localadmins = Get-NetLocalGroup -ComputerName $_ -Recurse -WarningAction SilentlyContinue -ErrorAction Ignore 
                $admins_array = New-Object System.Collections.ArrayList
                foreach ($admin in $localadmins)
                {
                    if ($admin -and -not $admin.IsGroup -and $admin.IsDomain -and -not $admins_array.Contains($admin.AccountName)){$admins_array.add($admin.AccountName) > $null}

                }
            
            
                if ($admins_array){Write-Output ($_ + " @@=@@ " + $admins_array + ';') }
            
            

            } | Out-String


            Write-Host "Processing privileged accounts" -ForegroundColor Green
            $parsed_results = $results -split ';' 
            $priv_accounts = @{}
            foreach($line in $parsed_results){$mach,$accs = $line -split '@@=@@';if ($mach -and $accs){$priv_accounts.Add($mach.trim(), $accs.trim())}}
            $priv_accounts | Out-File .\privileged_accounts.txt

            [System.Collections.ArrayList]$accts_dcsync = @()
            foreach($item in $priv_accounts.GetEnumerator()){foreach($acct in $item.Value.split(" ")){$accts_dcsync.Add($acct.split('/')[1]) > $null}}
            #Write-Output $accts_dcsync
        }
        try{
        write-host "Retrieving privileged accounts passwords hashes" -ForegroundColor Green

#======================================================= Extracting Hashes ===================================================

        if(-not $All){
        $hashes = Invoke-DCSync -Users $accts_dcsync
        }else{
        $hashes = Invoke-DCSync
        }
           
        } catch{
            write-host "There was some problem retrieving the passwords from active directory. Please make sure the tool runs with replication privileges." -ForegroundColor Red
            break
        }
        Write-Host "Processing list of common passwords" -ForegroundColor Green

#======================================================= Loading list of Common Passwords ===================================================
        if(-not $Hash_File){
        $file = Import-Csv -Path $path\ntlmHashes.csv -Header "column1","column2"
        }else{$file = Import-Csv -Path $Hash_File -Header "column1","column2"}
        $hashTable = @{}
        foreach($row in $file){ $hashTable[$row.column2] = $row.column1}
        #$hashtable
#======================================================= Compraing Passwords Against DB ===================================================
        Write-Host "Comparing retrieved password against the common passwords list" -ForegroundColor Green
        [System.Collections.ArrayList]$proccessed_accts = @()
        foreach($acct in $hashes){
            if ($proccessed_accts -notcontains $acct.user -and $hashTable.ContainsKey($acct.hash)){
                $proccessed_accts.Add($acct.user) > $null
                write-host "----------------------------------------------------------------------------------------------------------"
                write-host "The account"  $acct.user  " has a weak password: "  $hashTable[$acct.hash] -ForegroundColor Red
                if(-not $All -and $Details){
                    $user_name = $acct.domain + '/' + $acct.user
                    [System.Collections.ArrayList]$machine_list = @()
                    foreach($item in $priv_accounts.GetEnumerator()){
                        if($item.Value.split(" ") -contains $user_name){
                            $machine_list.Add($item.Key) > $null
                        }
                    }
                
                    Write-Host "The account has admin access on the following machines: " $machine_list -ForegroundColor DarkYellow
                
                    $online_sessions = Invoke-UserHunter -UserName $acct.user
                    if($online_sessions){
                        Write-Host "The account has active session on the folloiwng machines:" -ForegroundColor DarkYellow
                        $online_sessions | select computername | Write-Host -ForegroundColor DarkYellow
                
                
                    }
                }
   
                
            }

                
        }  
   } 
#======================================================= Retreiving Machines ===================================================
       function Get-DomainComps
    {
        Import-Module $path\Recon\Recon.psm1
        $comps = Get-NetComputer | Out-String
        $parsed_comps = $comps -split '[\r\n]'
        $parsed_comps = $parsed_comps | ? {$_}
        return $parsed_comps
    }

