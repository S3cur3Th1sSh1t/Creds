function Invoke-ThreadedFunction
{
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory = $false)]
        [String[]]$ComputerName,
        [String[]]$VulnLinks,
        [Parameter(Position = 1, Mandatory = $True)]
        [System.Management.Automation.ScriptBlock]$ScriptBlock,
        [Parameter(Position = 2)]
        [Hashtable]$ScriptParameters,
        [Int]$Threads = 20,
        [Int]$Timeout = 100,
        [Int]$Hostcount
    )
    
    begin
    {
        
        if ($PSBoundParameters['Debug'])
        {
            $DebugPreference = 'Continue'
        }
        if ($ComputerName)
        {
        Write-Verbose "[*] Total number of hosts: $($ComputerName.count)"
        }
        elseif ($VulnLinks)
        {
        Write-Verbose "[*] Total number of URL's: $($VulnLinks.count*$Hostcount)"
        }


        # Adapted from:
        #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
        $SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
        $SessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
        
        # threading adapted from
        # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
        #   Thanks Carlos!
        # create a pool of maxThread runspaces
        $Pool = [runspacefactory]::CreateRunspacePool(1, $Threads, $SessionState, $Host)
        $Pool.Open()
        
        $Jobs = @()
        $PS = @()
        $Wait = @()
        
        $Counter = 0
    }
    
    process
    {
        
        if ($ComputerName)
        {
            ForEach ($Computer in $ComputerName)
            {
            
                # make sure we get a server name
                if ($Computer -ne '')
                {
                
                    While ($($Pool.GetAvailableRunspaces()) -le 0)
                    {
                        Start-Sleep -MilliSeconds $Timeout
                    }
                
                    # create a "powershell pipeline runner"
                    $PS += [powershell]::create()
                    $PS[$Counter].runspacepool = $Pool
                
                    # add the script block + arguments
                    $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter('ComputerName', $Computer)
                    if ($ScriptParameters)
                    {
                        ForEach ($Param in $ScriptParameters.GetEnumerator())
                        {
                            $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                        }
                    }
                
                    # start job
                    $Jobs += $PS[$Counter].BeginInvoke();
                
                    # store wait handles for WaitForAll call
                    $Wait += $Jobs[$Counter].AsyncWaitHandle
                }
                $Counter = $Counter + 1
            }
        }
        elseif ($VulnLinks)
        {
            ForEach ($testlink in $VulnLinks)
            {
                # make sure we get a server name
                if ($testlink -ne '')
                {
                
                    While ($($Pool.GetAvailableRunspaces()) -le 0)
                    {
                        Start-Sleep -MilliSeconds $Timeout
                    }
                
                    # create a "powershell pipeline runner"
                    $PS += [powershell]::create()
                    $PS[$Counter].runspacepool = $Pool
                
                    # add the script block + arguments
                    $Null = $PS[$Counter].AddScript($ScriptBlock).AddParameter('VulnLinks', $testlink)
                    if ($ScriptParameters)
                    {
                        ForEach ($Param in $ScriptParameters.GetEnumerator())
                        {
                            $Null = $PS[$Counter].AddParameter($Param.Name, $Param.Value)
                        }
                    }
                
                    # start job
                    $Jobs += $PS[$Counter].BeginInvoke();
                
                    # store wait handles for WaitForAll call
                    $Wait += $Jobs[$Counter].AsyncWaitHandle
                }
                $Counter = $Counter + 1
            }
        }
    }
    
    end
    {
        
        Write-Verbose "Waiting for scanning threads to finish..."
        $WaitTimeout = Get-Date
        
        # set a 60 second timeout for the scanning threads
        while ($($Jobs | Where-Object { $_.IsCompleted -eq $False }).count -gt 0 -or $($($(Get-Date) - $WaitTimeout).totalSeconds) -gt 60)
        {
            Start-Sleep -MilliSeconds $Timeout
        }
        
        # end async call
        for ($y = 0; $y -lt $Counter; $y++)
        {
            
            try
            {
                # complete async job
                $PS[$y].EndInvoke($Jobs[$y])
                
            }
            catch
            {
                Write-Warning "error: $_"
            }
            finally
            {
                $PS[$y].Dispose()
            }
        }
        
        $Pool.Dispose()
        Write-Verbose "All threads completed!"
    }
}

function Find-Fruit 

{

<#
.SYNOPSIS

Search for "low hanging fruit".
.DESCRIPTION

A script to find potentially easily exploitable web servers on a target network.

.PARAMETER Rhosts

Targets in CIDR or comma separated format.

.PARAMETER Port

Specifies the port to connect to.

.PARAMETER Path

Path to custom dictionary.

.PARAMETER Timeout

Timeout for each connection in milliseconds.

.PARAMETER UseSSL

Use an SSL connection.

.PARAMETER Threads

The maximum concurrent threads to execute..


.EXAMPLE

C:\PS> Find-Fruit -Rhosts 192.168.1.0/24 -Port 8080 
C:\PS> Find-Fruit -Rhosts 192.168.1.0/24 -Path dictionary.txt -Port 8443 -UseSSL


.NOTES
Credits to mattifestation for Get-HttpStatus
HTTP Status Codes: 100 - Informational * 200 - Success * 300 - Redirection * 400 - Client Error * 500 - Server Error
    

#>
    
[CmdletBinding()]

param (
    [Parameter(Mandatory = $True)]
    [String]$Rhosts,
    [Int]$Port,
    [String]$Path,
    [Int]$Timeout = 110,
    [Switch]$UseSSL,
    [ValidateRange(1, 100)]
    [Int]$Threads
)
    
    begin {   
        $hostList = New-Object System.Collections.ArrayList
        
        $iHosts = $Rhosts -split ","
        
        foreach ($iHost in $iHosts) {
            $iHost = $iHost.Replace(" ", "")
            
            if (!$iHost) {
                continue
            }
            
            if ($iHost.contains("/")) {
                $netPart = $iHost.split("/")[0]
                [uint32]$maskPart = $iHost.split("/")[1]
                
                $address = [System.Net.IPAddress]::Parse($netPart)
                if ($maskPart -ge $address.GetAddressBytes().Length * 8) {
                    throw "Bad host mask"
                }
                
                $numhosts = [System.math]::Pow(2, (($address.GetAddressBytes().Length * 8) - $maskPart))
                
                $startaddress = $address.GetAddressBytes()
                [array]::Reverse($startaddress)
                
                $startaddress = [System.BitConverter]::ToUInt32($startaddress, 0)
                [uint32]$startMask = ([System.math]::Pow(2, $maskPart) - 1) * ([System.Math]::Pow(2, (32 - $maskPart)))
                $startAddress = $startAddress -band $startMask
                #in powershell 2.0 there are 4 0 bytes padded, so the [0..3] is necessary
                $startAddress = [System.BitConverter]::GetBytes($startaddress)[0..3]
                [array]::Reverse($startaddress)
                $address = [System.Net.IPAddress][byte[]]$startAddress
                
                $Null = $hostList.Add($address.IPAddressToString)
                
                for ($i = 0; $i -lt $numhosts - 1; $i++) {
                    $nextAddress = $address.GetAddressBytes()
                    [array]::Reverse($nextAddress)
                    $nextAddress = [System.BitConverter]::ToUInt32($nextAddress, 0)
                    $nextAddress++
                    $nextAddress = [System.BitConverter]::GetBytes($nextAddress)[0..3]
                    [array]::Reverse($nextAddress)
                    $address = [System.Net.IPAddress][byte[]]$nextAddress
                    $Null = $hostList.Add($address.IPAddressToString)       
                }
                
            }
            else {
                $Null = $hostList.Add($iHost) 
            }
        }
            
        $HostEnumBlock = {
            param($ComputerName, $UseSSL, $Port, $Path, $Timeout)
            
            if ($UseSSL -and $Port -eq 0) {
                # Default to 443 if SSL is specified but no port is specified
                $Port = 443
            }
            elseif ($Port -eq 0) {
                # Default to port 80 if no port is specified
                $Port = 80
            }
            
            
            if ($UseSSL) {
                $SSL = 's'
                # Ignore invalid SSL certificates
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }
            }
            else {
                $SSL = ''
            }
            
            if (($Port -eq 80) -or ($Port -eq 443)) {
                $PortNum = ''
            }
            else {
                $PortNum = ":$Port"
            }
            
            if ($Path) {
                if (!(Test-Path -Path $Path)) { Throw "File doesnt exist" }
                $VulnLinks = @()
                foreach ($Link in Get-Content $Path) {
                    $VulnLinks = $VulnLinks + $Link
                }
            }
            else {
                $VulnLinks = @()
                $VulnLinks = $VulnLinks + "jmx-console/" # Jboss
                $VulnLinks = $VulnLinks + "web-console/ServerInfo.jsp" # Jboss
                $VulnLinks = $VulnLinks + "invoker/JMXInvokerServlet" # Jboss
                $VulnLinks = $VulnLinks + "system/console" # OSGi console
                $VulnLinks = $VulnLinks + "axis2/axis2-admin/" # Apache Axis2
                $VulnLinks = $VulnLinks + "manager/html/" # Tomcat
                $VulnLinks = $VulnLinks + "tomcat/manager/html/" # Tomcat
                $VulnLinks = $VulnLinks + "wp-admin" # Wordpress
                $VulnLinks = $VulnLinks + "workorder/FileDownload.jsp" #Manage Engine
                $VulnLinks = $VulnLinks + "ibm/console/logon.jsp?action=OK" # WebSphere
                $VulnLinks = $VulnLinks + "data/login" # Dell iDrac
                $VulnLinks = $VulnLinks + "script/" # Jenkins Script Conosle
                $VulnLinks = $VulnLinks + "opennms/" # OpenNMS
                $VulnLinks = $VulnLinks + "RDWeb/Pages/en-US/Default.aspx" #RDS Remote Desktop
            }
            
            # Check Http status for each entry in the host
            foreach ($Target in $ComputerName) {
                                
                
                foreach ($Item in $Vulnlinks) {
                    $WebTarget = "http$($SSL)://$($Target)$($PortNum)/$($Item)"
                    $URI = New-Object Uri($WebTarget)
                    
                    try {
                        $WebRequest = [System.Net.WebRequest]::Create($URI)
                        $WebRequest.Headers.Add('UserAgent', $UserAgent)
                        $WebResponse = $WebRequest.Timeout = $Timeout
                        $WebResponse = $WebRequest.GetResponse()
                        $WebStatus = $WebResponse.StatusCode
                        $ResultObject += $ScanObject
                        $WebResponse.Close()
                    }
                    catch {
                        $WebStatus = $Error[0].Exception.InnerException.Response.StatusCode 
                        if ($WebStatus -eq $null) {
                            # Not every exception returns a StatusCode.
                            # If that is the case, return the Status.
                            $WebStatus = $Error[0].Exception.InnerException.Status
                        }
                    }

                    $Result = @{
                        Status = $WebStatus;
                        URL = $WebTarget
                    }
                    
                    New-Object -TypeName PSObject -Property $Result | Where-Object {$_.Status -eq 'OK'}
                   
                }
            }
        }
    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"

            # if we're using threading, kick off the script block with Invoke-ThreadedFunction
            $ScriptParams = @{
                'UseSSL' = $UseSSL
                'Port' = $Port
                'Path' = $Path
                'Timeout' = $Timeout
                'UserAgent' = $UserAgent
            }

            # kick off the threaded script block + arguments
            Invoke-ThreadedFunction -ComputerName $hostList -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $HostList, $UseSSL, $Port, $Path, $Timeout, $UserAgent 
        }
    }
}



function Brute-Fruit

{

<#
.SYNOPSIS
Search for web directories and files at scale across multiple web servers. Think "Dirbusting across a broad range of hosts".

.DESCRIPTION
A script to find directories and files across multiple web servers.

.PARAMETER Dictionary
Path to custom dictionary of files or directories. 
Here's a good place to start: 
https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content
https://github.com/DanMcInerney/pentest-machine/blob/master/wordlists/dirs-files-6000.list

.PARAMATER UrlList
List of URL's to scan. These should be one per line in the format of "http://domain.com", "https://domain.com:8443", etc...

.PARAMETER Timeout
Timeout for each connection in milliseconds.

.PARAMETER Threads
The maximum concurrent threads to execute.

.PARAMETER FoundOnly
Only display found URI's


.EXAMPLE
C:\PS> Brute-Fruit -Dictionary C:\temp\dictionary-of-files-to-test.txt -UrlList C:\temp\list-of-hosts.txt -Timeout 3000

C:\PS> Brute-Fruit -Dictionary C:\temp\dictionary-of-files-to-test.txt -UrlList C:\temp\list-of-hosts.txt -Timeout 3000 -Threads 10 -FoundOnly -Verbose

.NOTES
Credits to mattifestation for Get-HttpStatus
HTTP Status Codes: 100 - Informational * 200 - Success * 300 - Redirection * 400 - Client Error * 500 - Server Error
#>
    
[CmdletBinding()]

param (
    [Parameter(Mandatory = $false)]
    [String]$Dictionary,
    [Int]$Timeout = 110,
    [ValidateRange(1, 100)]
    [Int]$Threads,
    [Switch]$FoundOnly,
    [String]$UrlList
)
    
    begin
    {   
    if (!(Test-Path -Path $UrlList)) { Throw "File doesn't exist" }
        $hostlist = @()
        $hostlist
        foreach ($hostobject in Get-Content $UrlList)
        {
            $hostlist += $hostobject
        }

    if (!(Test-Path -Path $Dictionary)) { Throw "Dictionary file doesn't exist" }
        $VulnLinks = @()
        foreach ($Link in Get-Content $Dictionary)
        {
            $VulnLinks = $VulnLinks + $Link
        }
            

        $HostEnumBlock = {
            param($ComputerName, $Dictionary, $Timeout, $FoundOnly, $VulnLinks)
      
            foreach ($Item in $Vulnlinks)
            {
               
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $True }
                foreach ($Target in $ComputerName)
                {

                    $WebTarget = "$Target/$Item"
                    $URI = New-Object Uri($WebTarget)
                    
                    try
                    {
                        $WebRequest = [System.Net.WebRequest]::Create($URI)
                        $WebResponse = $WebRequest.Timeout = $Timeout
                        $WebResponse = $WebRequest.GetResponse()
                        $WebStatus = $WebResponse.StatusCode
                        $Stream = $WebResponse.GetResponseStream()
                        $Reader = New-Object IO.StreamReader($Stream)
                        $html = $reader.ReadToEnd()
                        $WebSize = $html.Length
                        $ResultObject += $ScanObject
                        $WebResponse.Close()
                    }
                    catch
                    {
                        $WebStatus = $Error[0].Exception.InnerException.Response.StatusCode
                        
                        if ($WebStatus -eq $null)
                        {
                            # Not every exception returns a StatusCode.
                            # If that is the case, return the Status.
                            $WebStatus = $Error[0].Exception.InnerException.Status
                        }
                    }

                    $Result = @{
                        Status = $WebStatus;
                        URL = $WebTarget
                        Size = $WebSize
                    }
                    
                    if ($FoundOnly) {
                        New-Object -TypeName PSObject -Property $Result | Where-Object {$_.Status -eq 'OK'}
                                          
                    } else {
                        New-Object -TypeName PSObject -Property $Result
                    }
                    
                }
            }
        }
    }

    process {

        if($Threads) {
            Write-Verbose "Using threading with threads = $Threads"

            # if we're using threading, kick off the script block with Invoke-ThreadedFunction
            $ScriptParams = @{
                'UseSSL' = $UseSSL
                'Port' = $Port
                'Dictionary' = $Dictionary
                'Timeout' = $Timeout
                'FoundOnly' = $FoundOnly
                'ComputerName' = $hostlist
                
                
            }

            # kick off the threaded script block + arguments           
            $Hostcount = $hostlist.count
            Invoke-ThreadedFunction -VulnLinks $VulnLinks -HostCount $Hostcount -ScriptBlock $HostEnumBlock -ScriptParameters $ScriptParams
        }

        else {
            Invoke-Command -ScriptBlock $HostEnumBlock -ArgumentList $HostList, $Dictionary, $Timeout, $FoundOnly, $VulnLinks
        }
    }
}
