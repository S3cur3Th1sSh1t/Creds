function ShadowHound-DS() {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'The domain controller to query.')]
        [string]$Server,

        [Parameter(Mandatory = $false, HelpMessage = 'Path to the output file where results will be saved.')]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFile,

        [Parameter(Mandatory = $false, HelpMessage = 'LDAP filter to customize the search.')]
        [string]$LdapFilter = '(ObjectGuid=*)',

        [Parameter(Mandatory = $false, HelpMessage = 'The base DN for the search.')]
        [string]$SearchBase,

        [Parameter(Mandatory = $false, HelpMessage = 'PSCredential object for alternate credentials.')]
        [pscredential]$Credential,

        [Parameter(Mandatory = $false, HelpMessage = 'Enumerate certificates.')]
        [switch]$Certificates,

        [Parameter(Mandatory = $false, HelpMessage = 'Display help information.')]
        [switch]$Help
    )

    if ($Help) {
        Print-Help
        return
    }

    if (-not $OutputFile) {
        Write-Output '[-] -OutputFile is required.'
        return
    }

    Print-Logo

    Write-Output '[+] Executing with the following parameters:'
    if ($Server) { Write-Output "   - Server: $Server" }
    Write-Output "   - OutputFile: $OutputFile"
    if ($LdapFilter) { Write-Output "   - LdapFilter: $LdapFilter" }
    if ($SearchBase) { Write-Output "   - SearchBase: $SearchBase" }
    if ($Credential) { Write-Output "   - Credential: $($Credential.UserName)" }
    if ($Certificates) { Write-Output '   - Enumerating certificates' }

    if ($Certificates) {
        # Enumerate certificates
        Write-Output '[*] Getting Configuration Naming Context...'

        try {
            if ($Server) {
                if ($Credential) {
                    $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/RootDSE", $Credential.UserName, $Credential.GetNetworkCredential().Password)
                } else {
                    $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$Server/RootDSE")
                }
            } else {
                if ($Credential) {
                    $rootDSE = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE', $Credential.UserName, $Credential.GetNetworkCredential().Password)
                } else {
                    $rootDSE = New-Object System.DirectoryServices.DirectoryEntry('LDAP://RootDSE')
                }
            }
            $configContext = $rootDSE.Properties['configurationNamingContext'][0]
        } catch {
            Write-Output "[-] Failed to retrieve ConfigurationNamingContext: $_"
            return
        }

        if ($null -eq $configContext) {
            Write-Output '[-] ConfigurationNamingContext is null.'
            return
        }

        Write-Output "[*] Enumerating PKI objects under $configContext..."

        $ldapFilters = @(
            '(objectClass=pKIEnrollmentService)',
            '(objectClass=pKICertificateTemplate)',
            '(objectClass=certificationAuthority)',
            '(objectclass=msPKI-Enterprise-Oid)'
        )

        $count = 0
        $streamWriter = New-Object System.IO.StreamWriter($OutputFile, $true, [System.Text.Encoding]::UTF8)
        try {
            
            foreach ($ldapFilter in $ldapFilters) {
                Write-Output "  [*] Searching with filter: $ldapFilter"
            
                if ($Server) {
                    $ldapPath = "LDAP://$Server/$configContext"
                } else {
                    $ldapPath = "LDAP://$configContext"
                }
            
                if ($Credential) {
                    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
                } else {
                    $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
                }
            
                $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)
                $searcher.Filter = $ldapFilter
                $searcher.PageSize = 1000
                $silenceofthezero = $searcher.PropertiesToLoad.Add('*')
                $searcher.SecurityMasks = 'Dacl,Group,Owner'
            
                try {
                    $searchResults = $searcher.FindAll()
                } catch {
                    Write-Output "   [!!] Error during search with filter $ldapFilter`: $_"
                    continue
                }
            
                foreach ($searchResult in $searchResults) {
                    Process-AdObject -SearchResult $searchResult -StreamWriter $streamWriter
                    $count++
                    if ($count % 1000 -eq 0) {
                        Write-Output "    [*] $count objects processed..."
                        $streamWriter.Flush()
                    }
                }
            }
            
            $streamWriter.WriteLine("Retrieved $count results total")

        } finally {
            $streamWriter.Flush()
            $streamWriter.Close()
        }
    

        Write-Output "Objects have been processed and written to $OutputFile"
        Write-Output "Retrieved $count results total"
        return
    }

    # If not enumerating certificates, proceed as usual
    if ($SearchBase) {
        $ldapPath = 'LDAP://'
        if ($Server) {
            $ldapPath += "$Server/"
        }
        $ldapPath += "$SearchBase"
    } elseif ($Server) {
        $ldapPath = "LDAP://$Server"
    } else {
        $ldapPath = 'LDAP://RootDSE'
    }

    if ($Credential) {
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath, $Credential.UserName, $Credential.GetNetworkCredential().Password)
    } else {
        $directoryEntry = New-Object System.DirectoryServices.DirectoryEntry($ldapPath)
    }

    $searcher = New-Object System.DirectoryServices.DirectorySearcher($directoryEntry)

    if ($LdapFilter) {
        $searcher.Filter = $LdapFilter
    } else {
        $searcher.Filter = '(objectGuid=*)'
    }

    $searcher.PageSize = 1000

    $searcher.PropertiesToLoad.Add('*')
    $searcher.SecurityMasks = 'Dacl,Group,Owner'

    $count = 0

    $streamWriter = New-Object System.IO.StreamWriter($OutputFile, $true, [System.Text.Encoding]::UTF8)

    try {
        $searchResults = $searcher.FindAll()
    } catch {
        Write-Output "Error during search: $_"
        $streamWriter.Flush()
        $streamWriter.Close()
        return
    }

    foreach ($searchResult in $searchResults) {
        Process-AdObject -SearchResult $searchResult -StreamWriter $streamWriter
        $count++
        if ($count % 1000 -eq 0) {
            Write-Output "    [*] $count objects processed..."
            $streamWriter.Flush()
        }
    }

    $streamWriter.WriteLine("Retrieved $count results total")
    $streamWriter.Flush()
    $streamWriter.Close()

    Write-Output "Objects have been processed and written to $OutputFile"
    Write-Output "Retrieved $count results total"
}


function Process-AdObject {
    param (
        [System.DirectoryServices.SearchResult]$SearchResult,
        [System.IO.StreamWriter]$StreamWriter
    )

    if ($null -eq $SearchResult) {
        Write-Output '[-] Search result is null.'
        return
    }

    $propertiesList = @()
    $propertiesList += '--------------------'

    foreach ($name in $SearchResult.Properties.PropertyNames) {
        $valueCollection = $SearchResult.Properties[$name]

        if ($null -eq $valueCollection -or $valueCollection.Count -eq 0 -or $name -in $ignoredValues ) {
            continue
        }

        # Handle nTSecurityDescriptor
        if ($name -eq 'nTSecurityDescriptor') {
            $entry = $SearchResult.GetDirectoryEntry()
            $securityDescriptor = $entry.ObjectSecurity

            if ($null -ne $securityDescriptor) {
                $binaryForm = $securityDescriptor.GetSecurityDescriptorBinaryForm()
                $base64Value = [System.Convert]::ToBase64String($binaryForm)
                $propertiesList += "$name`: $base64Value"
            }
        } elseif ($valueCollection[0] -is [DateTime]) {
            foreach ($value in $valueCollection) {
                $formattedValue = $value.ToUniversalTime().ToString('yyyyMMddHHmmss.0Z')
                $propertiesList += "$name`: $formattedValue"
            }
        } elseif ($name -eq 'objectClass') {
            $values = $valueCollection | ForEach-Object { $_.ToString() }

            if ($objectClassMapping.ContainsKey($values[0])) {
                $formattedObjectClass = $objectClassMapping[$values[0]]
            } else {
                $formattedObjectClass = ($values -join ', ')
            }

            $propertiesList += "$name`: $formattedObjectClass"
        } elseif ($valueCollection.Count -gt 1) {
            if ($name -eq 'dSCorePropagationData') {
                $latestDate = ($valueCollection | Where-Object { $_ -is [datetime] } | Sort-Object { $_.ToUniversalTime() } -Descending | Select-Object -First 1)
                if ($null -ne $latestDate) {
                    $formattedDate = $latestDate.ToUniversalTime().ToString('yyyyMMddHHmmss.0Z')
                    $propertiesList += "$name`: $formattedDate"
                }
            } elseif ($name -eq 'cACertificate') {
                $value = $valueCollection[0]
                $propertiesList += "$name`: " + ([Convert]::ToBase64String($value))
            } elseif ($name -eq 'authorityRevocationList') {
                $propertiesList += "$name`: $null"
            } elseif ($name -eq 'userCertificate') {
                $value = $valueCollection[0]
                $propertiesList += "$name`: " + ([Convert]::ToBase64String($value))
            } else {
                $values = $valueCollection | ForEach-Object { $_.ToString() }
                $propertiesList += "$name`: " + ($values -join ', ')
            }
        } elseif ($valueCollection[0] -is [byte[]]) {
            $value = $valueCollection[0]
            $base64Value = [System.Convert]::ToBase64String($value)
            $propertiesList += "$name`: $base64Value"
        } elseif ($valueCollection[0] -is [Guid]) {
            $value = $valueCollection[0]
            $propertiesList += "$name`: $value"
        } else {
            $value = $valueCollection[0]
            $propertiesList += "$name`: $value"
        }
    }

    $StreamWriter.WriteLine([string]::Join("`n", $propertiesList))
    $StreamWriter.WriteLine('') # Add an empty line between objects
}

$ignoredValues = @('CanonicalName', 'PropertyNames', 'AddedProperties', 
    'RemovedProperties', 'ModifiedProperties', 'PropertyCount', 
    'repsTo', 'ProtectedFromAccidentalDeletion', 'sDRightsEffective', 
    'modifyTimeStamp', 'Modified', 'createTimeStamp', 
    'Created', 'userCertificate')

$objectClassMapping = @{
    'applicationSettings'                  = 'top, applicationSettings, nTFRSSettings'
    'builtinDomain'                        = 'top, builtinDomain'
    'classStore'                           = 'top, classStore'
    'container'                            = 'top, container'
    'groupPolicyContainer'                 = 'top, container, groupPolicyContainer'
    'msImaging-PSPs'                       = 'top, container, msImaging-PSPs'
    'rpcContainer'                         = 'top, container, rpcContainer'
    'dfsConfiguration'                     = 'top, dfsConfiguration'
    'dnsNode'                              = 'top, dnsNode'
    'dnsZone'                              = 'top, dnsZone'
    'domainDNS'                            = 'top, domain, domainDNS'
    'fileLinkTracking'                     = 'top, fileLinkTracking'
    'linkTrackObjectMoveTable'             = 'top, fileLinkTracking, linkTrackObjectMoveTable'
    'linkTrackVolumeTable'                 = 'top, fileLinkTracking, linkTrackVolumeTable'
    'foreignSecurityPrincipal'             = 'top, foreignSecurityPrincipal'
    'group'                                = 'top, group'
    'infrastructureUpdate'                 = 'top, infrastructureUpdate'
    'ipsecFilter'                          = 'top, ipsecBase, ipsecFilter'
    'ipsecISAKMPPolicy'                    = 'top, ipsecBase, ipsecISAKMPPolicy'
    'ipsecNegotiationPolicy'               = 'top, ipsecBase, ipsecNegotiationPolicy'
    'ipsecNFA'                             = 'top, ipsecBase, ipsecNFA'
    'ipsecPolicy'                          = 'top, ipsecBase, ipsecPolicy'
    'domainPolicy'                         = 'top, leaf, domainPolicy'
    'secret'                               = 'top, leaf, secret'
    'trustedDomain'                        = 'top, leaf, trustedDomain'
    'lostAndFound'                         = 'top, lostAndFound'
    'msDFSR-Content'                       = 'top, msDFSR-Content'
    'msDFSR-ContentSet'                    = 'top, msDFSR-ContentSet'
    'msDFSR-GlobalSettings'                = 'top, msDFSR-GlobalSettings'
    'msDFSR-LocalSettings'                 = 'top, msDFSR-LocalSettings'
    'msDFSR-Member'                        = 'top, msDFSR-Member'
    'msDFSR-ReplicationGroup'              = 'top, msDFSR-ReplicationGroup'
    'msDFSR-Subscriber'                    = 'top, msDFSR-Subscriber'
    'msDFSR-Subscription'                  = 'top, msDFSR-Subscription'
    'msDFSR-Topology'                      = 'top, msDFSR-Topology'
    'msDS-PasswordSettingsContainer'       = 'top, msDS-PasswordSettingsContainer'
    'msDS-QuotaContainer'                  = 'top, msDS-QuotaContainer'
    'msTPM-InformationObjectsContainer'    = 'top, msTPM-InformationObjectsContainer'
    'organizationalUnit'                   = 'top, organizationalUnit'
    'contact'                              = 'top, person, organizationalPerson, contact'
    'user'                                 = 'top, person, organizationalPerson, user'
    'computer'                             = 'top, person, organizationalPerson, user, computer'
    'rIDManager'                           = 'top, rIDManager'
    'rIDSet'                               = 'top, rIDSet'
    'samServer'                            = 'top, securityObject, samServer'
    'msExchSystemObjectsContainer'         = 'top, container, msExchSystemObjectsContainer'
    'msRTCSIP-ApplicationContacts'         = 'top, container, msRTCSIP-ApplicationContacts'
    'msRTCSIP-ArchivingServer'             = 'top, container, msRTCSIP-ArchivingServer'
    'msRTCSIP-ConferenceDirectories'       = 'top, container, msRTCSIP-ConferenceDirectories'
    'msRTCSIP-ConferenceDirectory'         = 'top, container, msRTCSIP-ConferenceDirectory'
    'msRTCSIP-Domain'                      = 'top, container, msRTCSIP-Domain'
    'msRTCSIP-EdgeProxy'                   = 'top, container, msRTCSIP-EdgeProxy'
    'msRTCSIP-GlobalContainer'             = 'top, container, msRTCSIP-GlobalContainer'
    'msRTCSIP-GlobalTopologySetting'       = 'top, container, msRTCSIP-GlobalTopologySetting'
    'msRTCSIP-GlobalTopologySettings'      = 'top, container, msRTCSIP-GlobalTopologySettings'
    'msRTCSIP-GlobalUserPolicy'            = 'top, container, msRTCSIP-GlobalUserPolicy'
    'msRTCSIP-LocalNormalization'          = 'top, container, msRTCSIP-LocalNormalization'
    'msRTCSIP-LocalNormalizations'         = 'top, container, msRTCSIP-LocalNormalizations'
    'msRTCSIP-LocationContactMapping'      = 'top, container, msRTCSIP-LocationContactMapping'
    'msRTCSIP-LocationContactMappings'     = 'top, container, msRTCSIP-LocationContactMappings'
    'msRTCSIP-LocationProfile'             = 'top, container, msRTCSIP-LocationProfile'
    'msRTCSIP-LocationProfiles'            = 'top, container, msRTCSIP-LocationProfiles'
    'msRTCSIP-MCUFactories'                = 'top, container, msRTCSIP-MCUFactories'
    'msRTCSIP-MCUFactory'                  = 'top, container, msRTCSIP-MCUFactory'
    'msRTCSIP-MonitoringServer'            = 'top, container, msRTCSIP-MonitoringServer'
    'msRTCSIP-PhoneRoute'                  = 'top, container, msRTCSIP-PhoneRoute'
    'msRTCSIP-PhoneRoutes'                 = 'top, container, msRTCSIP-PhoneRoutes'
    'msRTCSIP-Policies'                    = 'top, container, msRTCSIP-Policies'
    'msRTCSIP-Pool'                        = 'top, container, msRTCSIP-Pool'
    'msRTCSIP-Pools'                       = 'top, container, msRTCSIP-Pools'
    'msRTCSIP-RouteUsage'                  = 'top, container, msRTCSIP-RouteUsage'
    'msRTCSIP-RouteUsages'                 = 'top, container, msRTCSIP-RouteUsages'
    'msRTCSIP-TrustedMCU'                  = 'top, container, msRTCSIP-TrustedMCU'
    'msRTCSIP-TrustedMCUs'                 = 'top, container, msRTCSIP-TrustedMCUs'
    'msRTCSIP-TrustedProxies'              = 'top, container, msRTCSIP-TrustedProxies'
    'msRTCSIP-TrustedServer'               = 'top, container, msRTCSIP-TrustedServer'
    'msRTCSIP-TrustedService'              = 'top, container, msRTCSIP-TrustedService'
    'msRTCSIP-TrustedServices'             = 'top, container, msRTCSIP-TrustedServices'
    'msRTCSIP-TrustedWebComponentsServer'  = 'top, container, msRTCSIP-TrustedWebComponentsServer'
    'msRTCSIP-TrustedWebComponentsServers' = 'top, container, msRTCSIP-TrustedWebComponentsServers'
    'msWMI-Som'                            = 'top, msWMI-Som'
    'nTFRSReplicaSet'                      = 'top, nTFRSReplicaSet'
    'packageRegistration'                  = 'top, packageRegistration'
    'msDS-GroupManagedServiceAccount'      = 'top, person, organizationalPerson, user, computer, msDS-GroupManagedServiceAccount'
    'pKIEnrollmentService'                 = 'top, pKIEnrollmentService'
    'nTFRSSettings'                        = 'top, applicationSettings, nTFRSSettings'
    'rpcServer'                            = 'top, leaf, connectionPoint, rpcEntry, rpcServer'
    'rpcServerElement'                     = 'top, leaf, connectionPoint, rpcEntry, rpcServerElement'
    'serviceConnectionPoint'               = 'top, leaf, connectionPoint, serviceConnectionPoint'
    'msRTCSIP-ApplicationServerService'    = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-ApplicationServerService'
    'msRTCSIP-MCUFactoryService'           = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-MCUFactoryService'
    'msRTCSIP-PoolService'                 = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-PoolService'
    'msRTCSIP-Service'                     = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-Service'
    'msRTCSIP-WebComponentsService'        = 'top, leaf, connectionPoint, serviceConnectionPoint, msRTCSIP-WebComponentsService'
    'pKICertificateTemplate'               = 'top, pKICertificateTemplate'
    'certificationAuthority'               = 'top, certificationAuthority'
    'msPKI-Enterprise-Oid'                 = 'top, msPKI-Enterprise-Oid'
}

function Print-Help {
    Print-Logo
    $helpMessage = '
ShadowHound-DS Help

SYNTAX:
ShadowHound-DS [-Server <string>] -OutputFile <string> [-LdapFilter <string>] [-SearchBase <string>] [-Credential <pscredential>] [-Certificates] [-Help]

PARAMETERS:
-Help
    Display this help information.

-Server <string> [Optional]
    The domain controller to query. If not specified, the default DC is used.

-OutputFile <string> [Required]
    The path to the output file where results will be saved.

-LdapFilter <string> [Optional]
    LDAP filter to customize the search.
    Defaults to (objectGuid=*).

-SearchBase <string> [Optional]
    The base DN for the search.

-Credential <pscredential> [Optional]
    PSCredential object for alternate credentials.

-Certificates [Optional]
    Enumerate certificate-related objects.

EXAMPLES:
# Example 1: Basic usage with required parameter
ShadowHound-DS -OutputFile "C:\Results\ldap_output.txt"

# Example 2: Specify a domain controller
ShadowHound-DS -Server "dc.domain.local" -OutputFile "C:\Results\ldap_output.txt"

# Example 3: Use a custom LDAP filter
ShadowHound-DS -OutputFile "C:\Results\ldap_output.txt" -LdapFilter "(objectClass=computer)"

# Example 4: Specify a search base
ShadowHound-DS -OutputFile "C:\Results\ldap_output.txt" -SearchBase "DC=domain,DC=local"

# Example 5: Enumerate certificate-related objects
ShadowHound-DS -OutputFile "C:\Results\cert_output.txt" -Certificates

# Example 6: Use alternate credentials
$cred = Get-Credential
ShadowHound-DS -OutputFile "C:\Results\ldap_output.txt" -Credential $cred
'
    Write-Output $helpMessage
    return
}


function Print-Logo {
    $logo = @'
·········································································
:  ____  _               _               _   _                       _  :
: / ___|| |__   __ _  __| | _____      _| | | | ___  _   _ _ __   __| | :
: \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |_| |/ _ \| | | | '_ \ / _` | :
:  ___) | | | | (_| | (_| | (_) \ V  V /|  _  | (_) | |_| | | | | (_| | :
: |____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_| |_|\___/ \__,_|_| |_|\__,_| :
:                                                                       :
:   Author: Yehuda Smirnov (X: @yudasm_ BlueSky: @yudasm.bsky.social)   :
·········································································
'@
    Write-Output $logo
}

