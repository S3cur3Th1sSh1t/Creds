function Discover-PSInterestingServices
{

<#
.SYNOPSIS
This script is used to discover network servers with interesting services without port scanning.
Service discovery in the Active Directory Forest is performed by querying an Active Directory Gloabl Catalog via LDAP.
The script can also provide additional computer information such as OS and last bootup time.

PowerSploit Function: Discover-PSInterestingServices
Author: Sean Metcalf, Twitter: @PyroTek3
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

Version: 1.5

.DESCRIPTION
This script is used to discover network servers with interesting services without port scanning.
Service discovery in the Active Directory Forest is performed by querying an Active Directory Gloabl Catalog via ADSI.

REQUIRES: Active Directory user authentication. Standard user access is fine - admin access is not necessary.

Currently, the script performs the following actions:
    * Queries a Global Catalog in the Active Directory root domain for all SPNs in the forest
    * Identifies interesting services running on computers (if a port is identified in the SPN, it is shown in the report as SPN.port)

A description of SPN Service Types can be found here:
http://adsecurity.org/?page_id=183 


.PARAMETER StandardSPNServiceFilter
Array of Strings: Standard list of SPN Services Reported: ("ADAM","AGPM","bo","CESREMOTE","Dfs","DNS","Exchange","FIMService","ftp","http","IMAP","ipp","iSCSITarget","kadmin","ldap","MS","sql","nfs","secshd","sip","SMTP","SoftGrid","TERMSRV","Virtual","vmrc","vnc","vpn","vssrvc","WSMAN","xmpp")
It is best to remove from this list if needed. Use the OptionalSPNServiceFilter parameter for adding SPN Services to the report.

.PARAMETER OptionalSPNServiceFilter
Array of Strings: Provide additonal SPN service types desired in the report.
Multiple values are acceptable.

.EXAMPLE
Discover-PSInterestingServices
Perform discovery on servers running interesting services via ADSI returning results in a custom PowerShell object.
Discovers the following SPNs: ("ADAM","AGPM","bo","CESREMOTE","Dfs","DNS","Exchange","FIMService","ftp","http","IMAP","ipp","iSCSITarget","kadmin","ldap","MS","sql","nfs","secshd","sip","SMTP","SoftGrid","TERMSRV","Virtual","vmrc","vnc","vpn","vssrvc","WSMAN","xmpp")

Discover-PSInterestingServices -GetAllForestSPNs
Perform discovery of ALL SPN typs in Active Directory in order to discover servers running interesting services via ADSI returning results in a custom PowerShell object.

Discover-PSInterestingServices -OptionalSPNServiceFilter ("Microsoft Virtual Console Service","Dfsr")
Perform discovery on servers running interesting services (adding Hyper-V hosts and domain DFS servers) via ADSI returning results in a custom PowerShell object.

.NOTES
This script is used to discover computers with interesting services without port scanning.

.LINK
Blog: http://www.ADSecurity.org
Github repo: https://github.com/PyroTek3/PowerShell-AD-Recon

#>


Param
    (
        [switch] $GetAllForestSPNs,
        [String[]] $StandardSPNServiceFilter = ("ADAM","AGPM","bo","CESREMOTE","Dfs","DNS","Exchange","FIMService","ftp","http","IMAP","ipp","iSCSITarget","kadmin","ldap","MS","sql","nfs","secshd","sip","SMTP","SoftGrid","TERMSRV","Virtual","vmrc","vnc","vpn","vssrvc","WSMAN","xmpp"),
        [String[]] $OptionalSPNServiceFilter
    )

IF ($OptionalSPNServiceFilter)
    { [array]$SPNServiceFilter = $StandardSPNServiceFilter + $OptionalSPNServiceFilter } 
 ELSE
    { [array]$SPNServiceFilter = $StandardSPNServiceFilter }

Write-verbose "Build SPN searcher based on Standard and Optional "
[string]$ADSearcherSPNTypes = "(|"
ForEach ($SPNServiceFilterItem in $SPNServiceFilter)
    { [string]$ADSearcherSPNTypes += "(serviceprincipalname=*$SPNServiceFilterItem*)" }
[string]$ADSearcherSPNTypes += " )"

Write-Verbose "Get current Active Directory domain... "
$ADForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$ADForestInfoRootDomain = $ADForestInfo.RootDomain
$ADForestInfoRootDomainArray = $ADForestInfoRootDomain -Split("\.")
$ADForestInfoRootDomainDN = "DC=" + $ADForestInfoRootDomain -Replace("\.",',DC=')

$ADDomainInfoLGCDN = 'GC://' + $ADForestInfoRootDomainDN

Write-Verbose "Discovering Interesting Services in the AD Forest $ADForestInfoRootDomainDN "
$root = [ADSI]$ADDomainInfoLGCDN 

IF ($GetAllForestSPNs -eq $True)
    { $ADSearcher = new-Object System.DirectoryServices.DirectorySearcher($root,"(serviceprincipalname=*)")  } 
  ELSE
    { $ADSearcher = new-Object System.DirectoryServices.DirectorySearcher($root,"$ADSearcherSPNTypes") }

$ADSearcher.PageSize = 1000
$AllForestSPNs = $ADSearcher.FindAll() 

#$AllForestSPNsCount = $AllForestSPNs.Count

$AllInterestingSPNs = $NULL
$AllSPNs = $NULL
$AllSPNTypes = $NULL
$AllInterestingSPNHashTable =@{}
$AllInterestingSPNReverseHashTable =@{}
ForEach ($AllForestSPNsItem in $AllForestSPNs)
    {
        $AllForestSPNsItemPath = $AllForestSPNsItem.Path
        Write-Verbose "Reviewing SPN for $AllForestSPNsItemPath "
        $AllForestSPNsItemDomainName = $NULL
        [array]$AllForestSPNsItemArray = $AllForestSPNsItem.Path -Split(",DC=")
        [int]$DomainNameFECount = 0
        ForEach ($AllForestSPNsItemArrayItem in $AllForestSPNsItemArray)
            {
                IF ($DomainNameFECount -gt 0)
                { [string]$AllForestSPNsItemDomainName += $AllForestSPNsItemArrayItem + "." }
                $DomainNameFECount++
            }
        $AllForestSPNsItemDomainName = $AllForestSPNsItemDomainName.Substring(0,$AllForestSPNsItemDomainName.Length-1)

        ForEach ($FSPNItemSPNItem in $AllForestSPNsItem.properties.serviceprincipalname)
            {
                Write-Verbose "Reviewing SPN Data: $FSPNItemSPNItem " 
                [string]$FSPNItemSPNItemSPNType = ( $FSPNItemSPNItem -Split("/") )[0]
                [array]$AllSPNTypes += ( $FSPNItemSPNItem -Split("/") )[0]

                IF ( ($FSPNItemSPNItemSPNType -like "*kadmin*") -AND ($AllForestSPNsItem -like "*krbtgt*") )
                    { 
                        $AllInterestingSPNHashTable.Set_Item("krbtgt ($AllForestSPNsItemDomainName)",$FSPNItemSPNItem) 
                        $AllInterestingSPNReverseHashTableData = $AllInterestingSPNReverseHashTable.Get_Item($FSPNItemSPNItem)
                        IF ($AllInterestingSPNReverseHashTableData)
                            {
                                $AllInterestingSPNReverseHashTableDataUpdate = $AllInterestingSPNReverseHashTableData + ";" + "krbtgt ($AllForestSPNsItemDomainName)" 
                                $AllInterestingSPNReverseHashTable.Set_Item($FSPNItemSPNItem,$AllInterestingSPNReverseHashTableDataUpdate)
                            }
                        IF (!$AllInterestingSPNReverseHashTableData)
                            { $AllInterestingSPNReverseHashTable.Set_Item($FSPNItemSPNItem,"krbtgt ($AllForestSPNsItemDomainName)") }
                    }
                 ELSE
                    {
                        $FSPNItemSPNItemServerFQDN = ( ( ( $FSPNItemSPNItem -Split("/") )[1] )-Split(":") )[0]
                        IF ($FSPNItemSPNItemServerFQDN -notlike "*$AllForestSPNsItemDomainName*" )
                            { $FSPNItemSPNItemServerFQDN = $FSPNItemSPNItemServerFQDN + "." + $AllForestSPNsItemDomainName }
                        [string]$FSPNItemSPNItemServerPort = ( ( ( $FSPNItemSPNItem -Split("/") )[1] )-Split(":") )[1]

                        $AllInterestingSPNReverseHashTableData = $AllInterestingSPNReverseHashTable.Get_Item($FSPNItemSPNItemSPNType)
                        IF ( ($AllInterestingSPNReverseHashTableData) -AND ($AllInterestingSPNReverseHashTableData -notlike "*$FSPNItemSPNItemServerFQDN*") )
                            {
                                $AllInterestingSPNReverseHashTableDataUpdate = $AllInterestingSPNReverseHashTableData + ";" + $FSPNItemSPNItemServerFQDN 
                                $AllInterestingSPNReverseHashTable.Set_Item($FSPNItemSPNItemSPNType,$AllInterestingSPNReverseHashTableDataUpdate)
                            }
                        IF (!$AllInterestingSPNReverseHashTableData)
                            { $AllInterestingSPNReverseHashTable.Set_Item($FSPNItemSPNItemSPNType,$FSPNItemSPNItemServerFQDN) } 

                        IF ( ($FSPNItemSPNItemServerPort) -AND ($FSPNItemSPNItemServerPort -match "^[\d\.]+$") )
                            { $FSPNItemSPNItemSPNType = $FSPNItemSPNItemSPNType + "." + $FSPNItemSPNItemServerPort }
                
                        ForEach ($SPNServiceFilterItem in $SPNServiceFilter)
                            {
                                IF ($FSPNItemSPNItemSPNType -like "*$SPNServiceFilterItem*")
                                    { 
                                        Write-Verbose "SPNServiceFilterItem is $SPNServiceFilterItem "
                                        $AllInterestingSPNsData = $AllInterestingSPNHashTable.Get_Item($FSPNItemSPNItemServerFQDN)
                                        IF ( ($AllInterestingSPNsData) -AND ($AllInterestingSPNsData -notlike "*$SPNServiceFilterItem*") )
                                            {
                                                $AllInterestingSPNsDataUpdate = $AllInterestingSPNsData + ";" + $FSPNItemSPNItemSPNType
                                                $AllInterestingSPNHashTable.Set_Item($FSPNItemSPNItemServerFQDN,$AllInterestingSPNsDataUpdate) 
                                                Write-Verbose "Updating AllInterestingSPNHashTable with $FSPNItemSPNItemServerFQDN : $AllInterestingSPNsDataUpdate " 
                                            }
                                        IF (!$AllInterestingSPNsData) 
                                            { 
                                                $AllInterestingSPNHashTable.Set_Item($FSPNItemSPNItemServerFQDN,$FSPNItemSPNItemSPNType) 
                                                Write-Verbose "Updating AllInterestingSPNHashTable with new data $FSPNItemSPNItemServerFQDN : $FSPNItemSPNItemSPNType " 
                                            }    
                                    }
                            }
                    }
            }
    }


    $ALLIntServerServicesReport = @()
        
    ForEach ($AllInterestingSPNHashTableItem in $AllInterestingSPNHashTable.GetEnumerator() )
    {
        $AllServerInterstingSPNServiceList = $NULL
        $AllInterestingSPNHashTableItemServerDomainName = $NULL
        $AllInterestingSPNHashTableItemServerDomainDN = $NULL

        $AllInterestingSPNHashTableItemServerFQDN =  $AllInterestingSPNHashTableItem.Name
        [array]$AllServerInterstingSPNArray = ($AllInterestingSPNHashTableItem.Value) -split(";")
        [array]$AllServerInterstingSPNArraySorted = $AllServerInterstingSPNArray | sort-Object

        ForEach ($AllServerInterstingSPNArraySortedItem in $AllServerInterstingSPNArraySorted)
            { [string]$AllServerInterstingSPNServiceList += $AllServerInterstingSPNArraySortedItem + ";" }
        $AllServerInterstingSPNServiceList = $AllServerInterstingSPNServiceList.Substring(0,$AllServerInterstingSPNServiceList.Length-1)

        $AllInterestingSPNHashTableItemServerFQDNArray = $AllInterestingSPNHashTableItemServerFQDN -Split('\.')
        [int]$FQDNArrayFECount = 0
        ForEach ($AllInterestingSPNHashTableItemServerFQDNArrayItem in $AllInterestingSPNHashTableItemServerFQDNArray)
            {
                IF ($FQDNArrayFECount -ge 1)
                    { 
                        [string]$AllInterestingSPNHashTableItemServerDomainName += $AllInterestingSPNHashTableItemServerFQDNArrayItem + "." 
                        [string]$AllInterestingSPNHashTableItemServerDomainDN += "DC=" + $AllInterestingSPNHashTableItemServerFQDNArrayItem + "," 
                    }
                $FQDNArrayFECount++
            }

        $AllInterestingSPNHashTableItemServerDomainName = $AllInterestingSPNHashTableItemServerDomainName.Substring(0,$AllInterestingSPNHashTableItemServerDomainName.Length-1)
        $AllInterestingSPNHashTableItemServerDomainDN = $AllInterestingSPNHashTableItemServerDomainDN.Substring(0,$AllInterestingSPNHashTableItemServerDomainDN.Length-1)
        $AllInterestingSPNHashTableItemServerDomainLDAPDN = "LDAP://$AllInterestingSPNHashTableItemServerDomainDN"

        $AllInterestingSPNHashTableItemServerName = $AllInterestingSPNHashTableItemServerFQDN -Replace(("."+$AllInterestingSPNHashTableItemServerDomainName),"")

        IF ($AllInterestingSPNHashTableItemServerFQDN -like "*changepw*") 
            { $AllInterestingSPNHashTableItemServerFQDN = $AllInterestingSPNHashTableItemServerDomainName + "\krbgt" }

        IF ($AllInterestingSPNHashTableItemServerFQDN -like "*_msdcs*")
            { 
                $AllInterestingSPNHashTableItemServerFQDN = $AllInterestingSPNHashTableItemServerDomainName + "\DNSzone" 
                $AllInterestingSPNHashTableItemServerName = $NULL 
            } 
 
        TRY
            {
                $ADComputerSearch = New-Object DirectoryServices.DirectorySearcher([ADSI]"")
                $ADComputerSearch.SearchRoot = $AllInterestingSPNHashTableItemServerDomainLDAPDN
                $ADComputerSearch.PageSize = 500
                $ADComputerSearch.Filter = "(&(objectCategory=Computer)(name=$AllInterestingSPNHashTableItemServerName))"
                $ComputerADInfo = $ADComputerSearch.FindAll()

                [string]$ComputerADInfoLastLogonTimestamp = ($ComputerADInfo[0].properties.lastlogontimestamp)
                TRY { [datetime]$ComputerADInfoLLT = [datetime]::FromFileTime($ComputerADInfoLastLogonTimestamp) }
                    CATCH { $ComputerADInfoLLT = $Null }
            }
            CATCH
            { Write-Warning "Unable to gather property data for computer $AllInterestingSPNHashTableItemServerName " }
                
        $ComputerADInfoShortOS = $Null
        $ComputerADInfoShortOSArray = $ComputerADInfoOperatingSystem -split(" ")
        ForEach ($ComputerADInfoShortOSArrayItem in $ComputerADInfoShortOSArray ) 
            {
                IF ($ComputerADInfoShortOSArrayItem -eq "Windows")
                    { [string] $ComputerADInfoShortOS += "Win" }
                                
                IF ($ComputerADInfoShortOSArrayItem -eq "Server")
                    { }

                IF ($ComputerADInfoShortOSArrayItem -match "\d")
                    { [string] $ComputerADInfoShortOS += $ComputerADInfoShortOSArrayItem }  
            }

        $IntServerServicesReport = New-Object -TypeName System.Object 
        $IntServerServicesReport | Add-Member -MemberType NoteProperty -Name Domain -Value $AllInterestingSPNHashTableItemServerDomainName
        $IntServerServicesReport | Add-Member -MemberType NoteProperty -Name ServerName -Value $AllInterestingSPNHashTableItemServerFQDN   
        $IntServerServicesReport | Add-Member -MemberType NoteProperty -Name SPNServices -Value $AllServerInterstingSPNServiceList     
        $IntServerServicesReport | Add-Member -MemberType NoteProperty -Name OperatingSystem -Value ($ComputerADInfo[0].properties.operatingsystem)
        $IntServerServicesReport | Add-Member -MemberType NoteProperty -Name OSServicePack -Value ($ComputerADInfo[0].properties.operatingsystemservicepack) 
        $IntServerServicesReport | Add-Member -MemberType NoteProperty -Name LastBootup -Value $ComputerADInfoLLT  
        $IntServerServicesReport | Add-Member -MemberType NoteProperty -Name OSVersion -Value ($ComputerADInfo[0].properties.operatingsystemversion)
        $IntServerServicesReport | Add-Member -MemberType NoteProperty -Name Description -Value ($ComputerADInfo[0].properties.description)

        [array]$ALLIntServerServicesReport += $IntServerServicesReport
    }

return $ALLIntServerServicesReport 
} 
