function ShadowHound-ADM {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false, HelpMessage = 'The domain controller to query.')]
        [string]$Server,

        [Parameter(Mandatory = $false, HelpMessage = 'Path to the output file where results will be saved.')]
        [ValidateNotNullOrEmpty()]
        [string]$OutputFilePath,

        [Parameter(Mandatory = $false, HelpMessage = 'LDAP filter to customize the search.')]
        [string]$LdapFilter = '(ObjectGuid=*)',

        [Parameter(Mandatory = $false, HelpMessage = 'The base DN for the search.')]
        [string]$SearchBase,

        [Parameter(Mandatory = $false, HelpMessage = 'The number of objects to include in one page for paging LDAP searches.')]
        [int]$PageSize = 1000,

        [Parameter(Mandatory = $false, HelpMessage = 'PSCredential object for alternate credentials.')]
        [pscredential]$Credential,

        [Parameter(Mandatory = $false, HelpMessage = 'Splits the search across top-level containers to handle large domains.')]
        [switch]$SplitSearch,

        [Parameter(Mandatory = $false, HelpMessage = 'Splits the search by first letter of CN to handle large domains, if the query fails, will also split the letter.')]
        [switch]$LetterSplitSearch,

        [Parameter(Mandatory = $false, HelpMessage = 'Path to a file containing a list of parsed containers.')]
        [string]$ParsedContainers,

        [Parameter(Mandatory = $false, HelpMessage = 'Recursively process containers that fail.')]
        [switch]$Recurse,

        [Parameter(Mandatory = $false, HelpMessage = 'Enumerate certificates.')]
        [switch]$Certificates,

        [Parameter(Mandatory = $false, HelpMessage = 'Display help information.')]
        [switch]$Help
    )

    if ($Help) {
        Print-Help
        return
    }

    if ($Certificates -and ($SplitSearch -or $LetterSplitSearch -or $Recurse -or $ParsedContainers -or $SearchBase)) { 
        Write-Error '[!] Certificate enumeration is done seprately from the rest of the enumeration.'
        return
    }

    if (-not $OutputFilePath) {
        Write-Error '[!] -OutputFilePath is required.'
        return
    }

    if ($ParsedContainers -and -not $SplitSearch) {
        Write-Error '[!] Cannot parse containers if -SplitSearch is not provided.'
        return
    }

    if ($Recurse -and -not $SplitSearch) {
        Write-Error '[!] Cannot recurse if -SplitSearch is not provided.'
        return
    }

    if ($ParsedContainers -and -not (Test-Path -Path $ParsedContainers)) {
        Write-Error '[!] -ParsedContainers path not found, provide a valid path.'
        return
    }


    Print-Logo
    Write-Output '[+] Executing with the following parameters:'
    if ($server) { Write-Output "   - Server: $Server" }
    Write-Output "   - OutputFilePath: $OutputFilePath"
    if ($LdapFilter) { Write-Output "   - LdapFilter: $LdapFilter" }
    if ($SearchBase) { Write-Output "   - SearchBase: $SearchBase" }
    if ($SplitSearch) { Write-Output '   - SplitSearch enabled' }
    if ($LetterSplitSearch) { Write-Output '   - LetterSplitSearch enabled' }
    if ($Recurse) { Write-Output '   - Recurse enabled' }
    if ($Credential) { Write-Output "   - Credential: $($Credential.UserName)" }
    if ($ParsedContainers) { Write-Output "   - ParsedContainers: $ParsedContainers" }
    if ($Certificates) { Write-Output '   - Enumerating certificates' }


    $count = [ref]0
    $printingThreshold = 1000

    # Prepare Get-ADObject parameters
    $getAdObjectParams = @{
        Server     = $Server
        Properties = '*'
        LdapFilter = $LdapFilter
    }

    if ($SearchBase) { $getAdObjectParams['SearchBase'] = $SearchBase }
    if ($Credential) { $getAdObjectParams['Credential'] = $Credential }
    if ($PageSize) { $getAdObjectParams['ResultPageSize'] = $PageSize }

    # Open StreamWriter
    $streamWriter = New-Object System.IO.StreamWriter($OutputFilePath, $true, [System.Text.Encoding]::UTF8)
    try {
        $streamWriter.WriteLine('--------------------')
        if ($Certificates) {

            Write-Output '[*] Getting Configuration Naming Context...'
            $configEnumParams = @{
                Server     = $Server
                Credential = $Credential
            }
            $configContext = (Get-ADRootDSE @configEnumParams).ConfigurationNamingContext
            if ($null -eq $configContext) {
                Write-Error '[-] Failed to retrieve ConfigurationNamingContext.'
                return
            }

            Write-Output "[*] Enumerating PKI objects under $configContext..."
            $getAdObjectParams['SearchBase'] = $configContext

            $getAdObjectParams['LdapFilter'] = '(objectClass=pKIEnrollmentService)'
            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

            $getAdObjectParams['LdapFilter'] = '(objectClass=pKICertificateTemplate)'
            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

            $getAdObjectParams['LdapFilter'] = '(objectClass=certificationAuthority)'
            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

            $getAdObjectParams['LdapFilter'] = '(objectclass=msPKI-Enterprise-Oid)'
            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

        } elseif ($SplitSearch -eq $false -and $LetterSplitSearch -eq $false) {

            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold

        } elseif ($SplitSearch -eq $true) {
            # Get top-level containers
            Write-Output "[*] Discovering top level containers for $Server..."
            $topLevelContainers = Get-TopLevelContainers -Params $getAdObjectParams
            if ($null -eq $topLevelContainers) {
                Write-Error '[-] Something went wrong, no top-level containers found.'
                return
            }

            # We also need to query specifically the domain object
            $dcSearchParams = @{
                Server     = $Server
                Credential = $Credential
                Properties = '*'
                LdapFilter = '(objectClass=domain)'
            }
            Perform-ADQuery -SearchParams $dcSearchParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                        
            # In letter split search we need to make sure the top level containers are included
            if ($LetterSplitSearch -eq $true) {
                $topLevelContainers | ForEach-Object {
                    Process-AdObject -AdObject $_ -StreamWriter $streamWriter
                    $count.Value++
                    if ($count.Value % $printingThreshold -eq 0) {
                        Write-Output "[+] Queried $($Count.Value) objects so far..."
                        $streamWriter.Flush()
                    }
                }


            }


            Write-Output "[+] Found $($topLevelContainers.Count) top-level containers."

            $processedContainers = @()
            $unprocessedContainers = @()

            if ($ParsedContainers) {
                $ParsedContainersList = Get-Content -Path $ParsedContainers
            } else {
                $ParsedContainersList = @()
            }

            # process them containers
            foreach ($container in $topLevelContainers) {
                $containerDN = $container.DistinguishedName

                if ($ParsedContainersList -contains $containerDN) {
                    Write-Output "[+] Encountered already parsed container $containerDN, skipping..."
                    $processedContainers += $containerDN
                    continue
                }

                $containerSearchParams = $getAdObjectParams.Clone()
                $containerSearchParams['SearchBase'] = $containerDN

                Write-Output "[*] Processing container ($($processedContainers.Count + $unprocessedContainers.Count + 1)/$($topLevelContainers.Count)): $containerDN"

                if ($LetterSplitSearch -eq $false) {
                    try {
                        # Process the container
                        Perform-ADQuery -SearchParams $containerSearchParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                        $processedContainers += $containerDN
                    } catch {
                        Write-Error "[-] Error processing container '$containerDN': $_"
                        $unprocessedContainers += $containerDN
                        continue
                    }
                } elseif ($LetterSplitSearch -eq $true) {

                    # Split the search by first letter
                    $charset = ([char[]](97..122) + [char[]](48..57) + '!', '_', '@', '$', '{', '}')
                    $OriginalFilter = $containerSearchParams['LdapFilter']
                    foreach ($char in $charset) {
                        Write-Output "  [*] Querying $containerDN for objects with CN starting with '$char'"
                        $containerSearchParams['LdapFilter'] = "(&$OriginalFilter(cn=$char**))"

                        try {
                            Perform-ADQuery -SearchParams $containerSearchParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                        } catch {
                            Write-Output "   [!!] Error processing CN=$char* for container '$containerDN': $_`nTrying to split each letter again..."
                            foreach ($subChar in $charset) {
                                try {
                                    Write-Output "  [*] Querying $containerDN for objects with CN starting with '$char$subChar'"
                                    $containerSearchParams['LdapFilter'] = "(&$OriginalFilter(cn=$char$subChar**))"
                                    Perform-ADQuery -SearchParams $containerSearchParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                                } catch {
                                    Write-Output "   [-] Failed to process (CN=$char$subChar*) for container '$containerDN': $_`nMoving to the next sub letter..."
                                    continue
                                }
                            }
                        }
                    }

                    $processedContainers += $containerDN
                }
            }

            # Output summary
            Write-Output "Processed $($count.Value) objects in total."
            if ($processedContainers.Count -gt 0) {
                Write-Output '[+] Successfully processed containers:'
                $processedContainers | ForEach-Object { Write-Output "  - $_" }
            }
            if ($unprocessedContainers.Count -gt 0) {
                Write-Output "`n[-] Failed to process containers:"
                $unprocessedContainers | ForEach-Object { Write-Output "    - $_" }
            }
        } elseif ($LetterSplitSearch -eq $true -and $SplitSearch -eq $false) {
            $charset = ([char[]](97..122) + [char[]](48..57) + '!', '_', '@', '$', '{', '}')
            $OriginalFilter = $getAdObjectParams['LdapFilter']
            foreach ($char in $charset) {
                Write-Output "  [*] Querying for objects with CN starting with '$char'"
                $getAdObjectParams['LdapFilter'] = "(&$OriginalFilter(cn=$char**))"

                try {
                    Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                } catch {
                    Write-Output "   [!!] Error processing character '$char*': $_"
                    Write-Output '        Trying to split each letter again...'
                    foreach ($subChar in $charset) {
                        try {
                            Write-Output "  [*] Querying for objects with CN starting with '$char$subChar'"
                            $getAdObjectParams['LdapFilter'] = "(&$OriginalFilter(cn=$char$subChar**))"
                            Perform-ADQuery -SearchParams $getAdObjectParams -StreamWriter $streamWriter -Count $count -PrintingThreshold $printingThreshold
                        } catch {
                            Write-Output "   [-] Failed to process (CN=$char$subChar*): $_"
                            Write-Output '       Moving to the next sub letter...'
                            continue
                        }
                    }
                }
            }
        }


        $summaryLine = "Retrieved $($count.Value) results total"
        $streamWriter.WriteLine($summaryLine)
    } finally {
        $streamWriter.Flush()
        $streamWriter.Close()
    }

    Write-Output "Objects have been processed and written to $OutputFilePath"
    Write-Output $summaryLine
    Write-Output '==================================================='

    # Handle recursion if necessary
    if ($Recurse -and $unprocessedContainers.Count -gt 0) {
        Write-Output "[*] Current SearchBase is $SearchBase"
        Write-Output "[*] Attempting to recurse $($unprocessedContainers.Count) failed containers/OUs:"
        foreach ($failedContainer in $unprocessedContainers) {
            Write-Output $failedContainer

            $recurseParams = @{
                Server           = $Server
                OutputFilePath   = "$($failedContainer.Split(',')[0].Split('=')[1])_$OutputFilePath"
                LdapFilter       = $LdapFilter
                Credential       = $Credential
                ParsedContainers = $ParsedContainers
                SearchBase       = $failedContainer
                SplitSearch      = $true
                Recurse          = $true
            }

            if ($LetterSplitSearch) {
                $recurseParams['LetterSplitSearch'] = $true
            }

            Write-Output "[+] Attempting to recurse $failedContainer"
            ShadowHound-ADM @recurseParams
        }
    }
}

function Print-Logo {
    $logo = @'
.........................................................................
:  ____  _               _               _   _                       _  :
: / ___|| |__   __ _  __| | _____      _| | | | ___  _   _ _ __   __| | :
: \___ \| '_ \ / _` |/ _` |/ _ \ \ /\ / / |_| |/ _ \| | | | '_ \ / _` | :
:  ___) | | | | (_| | (_| | (_) \ V  V /|  _  | (_) | |_| | | | | (_| | :
: |____/|_| |_|\__,_|\__,_|\___/ \_/\_/ |_| |_|\___/ \__,_|_| |_|\__,_| :
:                                                                       :
:   Author: Yehuda Smirnov (X: @yudasm_ BlueSky: @yudasm.bsky.social)   :
.........................................................................
'@
    Write-Output $logo
}

function Print-Help {
    Print-Logo
    $helpMessage = '
ShadowHound-ADM Help

SYNTAX:
    ShadowHound-ADM [-Server <string>] -OutputFilePath <string> [-LdapFilter <string>] [-SearchBase <string>] [-PageSize <int>] [-Credential <pscredential>] [-SplitSearch] [-LetterSplitSearch] [-ParsedContainers <string>] [-Recurse] [-Help]

PARAMETERS:
    -Help
        Display help information.

    -Server <string> [Optional]
        The domain controller to query, e.g., domain.local or 192.168.10.10.

    -OutputFilePath <string> [Required]
        The path to the output file where results will be saved.

    -LdapFilter <string> [Optional]
        LDAP filter to customize the search.
        Defaults to (objectGuid=*).

    -SearchBase <string> [Optional]
        The base DN for the search, e.g., CN=top,CN=level,DC=domain,DC=local.
        Defaults to the root of the domain.

    -PageSize <int> [Optional]
        The number of objects to include in one page for paging LDAP searches.

    -Credential <pscredential> [Optional]
        PSCredential object for alternate credentials.

    -SplitSearch [Optional]
        Splits the search across top-level containers to handle large domains.

    -LetterSplitSearch [Optional]
        Splits the search by first letter of CN to handle large domains; if the query fails, will also split the letter.

    -ParsedContainers <string> [Optional]
        Path to a file containing a newline-separated list of Distinguished Names of parsed containers (exact match required).

    -Certificates [Optional]
        Enumerate certificates.

    -Recurse [Optional]
        Recursively process containers that fail.

EXAMPLES:
    # Example 1: Basic usage with required parameter
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt"

    # Example 2: Specify a domain controller and custom LDAP filter
    ShadowHound-ADM -Server "dc.domain.local" -OutputFilePath "C:\Results\output.txt" -LdapFilter "(objectClass=user)"

    # Example 3: Use alternate credentials and specify a search base
    $cred = Get-Credential
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt" -Credential $cred -SearchBase "DC=domain,DC=local"

    # Example 4: Split the search across top-level containers with split letter search
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt" -SplitSearch -LetterSplitSearch

    # Example 5: Enumerate certificates
    ShadowHound-ADM -OutputFilePath "C:\Results\output.txt" -Certificates
'
    Write-Host $helpMessage
    return
}

function Process-AdObject {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [Microsoft.ActiveDirectory.Management.ADObject]$AdObject,

        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$StreamWriter
    )

    # Define ignored properties
    $ignoredValues = @(
        'CanonicalName', 'PropertyNames', 'AddedProperties', 'RemovedProperties',
        'ModifiedProperties', 'PropertyCount', 'repsTo', 'ProtectedFromAccidentalDeletion',
        'sDRightsEffective', 'modifyTimeStamp', 'Modified', 'createTimeStamp',
        'Created', 'userCertificate'
    )

    # Map object classes
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

    if ($null -eq $AdObject) {
        Write-Error 'AdObject is null'
        return
    }

    $outputLines = New-Object System.Collections.Generic.List[string]
    $outputLines.Add('--------------------')

    foreach ($property in $AdObject.PSObject.Properties) {
        $name = $property.Name
        $value = $property.Value

        # Skip properties with empty values and unwanted properties
        if ($null -eq $value -or ($value -is [string] -and [string]::IsNullOrWhiteSpace($value)) -or $ignoredValues -contains $name) {
            continue
        }

        # Cache type checks
        $isDateTime = $value -is [datetime]
        $isByteArray = $value -is [byte[]]
        $isGuid = $value -is [guid]
        $isCollection = $value -is [Microsoft.ActiveDirectory.Management.ADPropertyValueCollection]

        switch ($name) {
            'nTSecurityDescriptor' {
                if ($null -ne $value) {
                    $binaryForm = $value.GetSecurityDescriptorBinaryForm()
                    if ($binaryForm.Length -gt 0) {
                        $base64Value = [System.Convert]::ToBase64String($binaryForm)
                        $outputLines.Add("$name`: $base64Value")
                    }
                }
                break
            }
            'objectClass' {
                if ($objectClassMapping.ContainsKey($value)) {
                    $formattedObjectClass = $objectClassMapping[$value]
                } else {
                    $formattedObjectClass = ($value -join ', ')
                }
                $outputLines.Add("$name`: $formattedObjectClass")
                break
            }
            default {
                if ($isDateTime) {
                    # Format date/time attributes in LDAP time format
                    $formattedValue = '{0:yyyyMMddHHmmss.0Z}' -f $value.ToUniversalTime()
                    $outputLines.Add("$name`: $formattedValue")
                } elseif ($isByteArray) {
                    # Base64 encode byte arrays
                    if ($value.Length -gt 0) {
                        $base64Value = [System.Convert]::ToBase64String($value)
                        $outputLines.Add("$name`: $base64Value")
                    }
                } elseif ($isGuid) {
                    $outputLines.Add("$name`: $value")
                } elseif ($isCollection) {
                    switch ($name) {
                        'dSCorePropagationData' {
                            # Efficiently find the latest date
                            $latestDate = $null
                            foreach ($date in $value) {
                                if ($date -is [datetime]) {
                                    if ($null -eq $latestDate -or $date -gt $latestDate) {
                                        $latestDate = $date
                                    }
                                }
                            }
                            if ($null -ne $latestDate) {
                                $formattedDate = '{0:yyyyMMddHHmmss.0Z}' -f $latestDate.ToUniversalTime()
                                $outputLines.Add("$name`: $formattedDate")
                            }
                            break
                        }
                        'cACertificate' {
                            if ($value.Count -gt 0 -and $value[0].Length -gt 0) {
                                $base64Value = [System.Convert]::ToBase64String($value[0])
                                $outputLines.Add("$name`: $base64Value")
                            }
                            break
                        }
                        'userCertificate' {
                            if ($value.Count -gt 0 -and $value[0].Length -gt 0) {
                                $base64Value = [System.Convert]::ToBase64String($value[0])
                                $outputLines.Add("$name`: $base64Value")
                            }
                            break
                        }
                        'authorityRevocationList' {
                            $outputLines.Add("$name`: $null")
                            break
                        }
                        default {
                            $joinedValues = ($value | ForEach-Object { $_.ToString() }) -join ', '
                            $outputLines.Add("$name`: $joinedValues")
                            break
                        }
                    }
                } else {
                    # General handling for other types
                    $outputLines.Add("$name`: $value")
                }
                break
            }
        }
    }

    # Write the formatted content to the file using StreamWriter
    foreach ($line in $outputLines) {
        $StreamWriter.WriteLine($line)
    }
}

function Perform-ADQuery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$SearchParams,

        [Parameter(Mandatory = $true)]
        [System.IO.StreamWriter]$StreamWriter,

        [Parameter(Mandatory = $true)]
        [ref]$Count,

        [Parameter(Mandatory = $false)]
        [int]$PrintingThreshold = 1000
    )

    # Process the objects
    Get-ADObject @SearchParams | ForEach-Object {
        Process-AdObject -AdObject $_ -StreamWriter $StreamWriter
        $Count.Value++
        if ($Count.Value % $PrintingThreshold -eq 0) {
            Write-Output "      [**] Queried $($Count.Value) objects so far..."
            $StreamWriter.Flush()
        }
    }
}

function Get-TopLevelContainers {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$Params
    )

    try {
        $topLevelParams = $Params.Clone()
        $topLevelParams['SearchScope'] = 'OneLevel'
        $TopLevelContainers = Get-ADObject @topLevelParams 
        return $TopLevelContainers
    } catch {
        Write-Error "Failed to retrieve top-level containers: $_"
        return $null
    }
}
