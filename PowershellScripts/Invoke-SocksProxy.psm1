<#
.SYNOPSIS
 
Powershell Socks5 Proxy
 
Author: p3nt4 (https://twitter.com/xP3nt4)
License: MIT
 
.DESCRIPTION
 
Creates a Socks proxy using powershell.
 
Supports both Socks4 and Socks5 connections.

This is only a subset of the Socks 4 and 5 protocols: It does not support authentication, It does not support UDP or bind requests.
 
New features will be implemented in the future. PRs are welcome.
 
 
.EXAMPLE
 
Create a Socks proxy on port 1234:
Invoke-SocksProxy -bindPort 1234
 
Create a simple tcp port forward:
Invoke-PortFwd -bindPort 33389 -destHost 127.0.0.1 -destPort 3389
 
 
#>
 
 
[ScriptBlock]$TcpConnectionMgr = {
    param($vars)
    $srvConnection=$vars.srvConnection
    $cliConnection=$vars.cliConnection
    $Script = {
           param($vars)
        $vars.inStream.CopyToAsync($vars.outStream)   
    }
    $cliStream = $cliConnection.GetStream()
    $srvStream = $srvConnection.GetStream() 
    $vars2 = [PSCustomObject]@{"inStream"=$cliStream;"outStream"=$srvStream}
    $PS = [PowerShell]::Create()
    $PS.AddScript($Script).AddArgument($vars2) | Out-Null
    [System.IAsyncResult]$AsyncJobResult = $null
 
    $vars3 = [PSCustomObject]@{"inStream"=$srvStream;"outStream"=$cliStream}
    $PS2 = [PowerShell]::Create()
    $PS2.AddScript($Script).AddArgument($vars3) | Out-Null
    [System.IAsyncResult]$AsyncJobResult2 = $null
 
    try
    {
        $AsyncJobResult = $PS.BeginInvoke()
        $AsyncJobResult2 = $PS2.BeginInvoke()
        while($cliConnection.Connected -and $srvConnection.Connected){
            sleep -m 100;
        }
    }
    catch {
    }
    finally {
        if ($cliConnection -ne $null) {
            $cliConnection.Close()
            $cliConnection.Dispose()
            $cliConnection = $null
        }
        if ($srvConnection -ne $null) {
            $srvConnection.Close()
            $srvConnection.Dispose()
            $srvConnection = $null
        }
        if ($PS -ne $null -and $AsyncJobResult -ne $null) {
            $PS.EndInvoke($AsyncJobResult) | Out-Null
            $PS.Dispose()
        }
        if ($PS2 -ne $null -and $AsyncJobResult2 -ne $null) {
            $PS2.EndInvoke($AsyncJobResult2) | Out-Null
            $PS2.Dispose()
        }
    }
}
 
[ScriptBlock]$SocksConnectionMgr = {
    param($vars)
    function Get-IpAddress{
        param($ip)
        IF ($ip -as [ipaddress]){
            return $ip
        }else{
            $ip2 = [System.Net.Dns]::GetHostAddresses($ip)[0].IPAddressToString;
        }
        return $ip2
    }
    $client=$vars.cliConnection
    $TcpConnectionMgr=$vars.TcpConnectionMgr
    $buffer = New-Object System.Byte[] 32
    try
    {
        $cliStream = $client.GetStream()
        $cliStream.Read($buffer,0,2) | Out-Null
        $socksVer=$buffer[0]
        if ($socksVer -eq 5){
            $cliStream.Read($buffer,2,$buffer[1]) | Out-Null
            for ($i=2; $i -le $buffer[1]+1; $i++) {
                if ($buffer[$i] -eq 0) {break}
            }
            if ($buffer[$i] -ne 0){
                $buffer[1]=255
                $cliStream.Write($buffer,0,2)
            }else{
                $buffer[1]=0
                $cliStream.Write($buffer,0,2)
            }
            $cliStream.Read($buffer,0,4) | Out-Null
            $cmd = $buffer[1]
            $atyp = $buffer[3]
            if($cmd -ne 1){
                $buffer[1] = 7
                $cliStream.Write($buffer,0,2)
                throw "Not a connect"
            }
            if($atyp -eq 1){
                $ipv4 = New-Object System.Byte[] 4
                $cliStream.Read($ipv4,0,4) | Out-Null
                $ipAddress = New-Object System.Net.IPAddress(,$ipv4)
                $hostName = $ipAddress.ToString()
            }elseif($atyp -eq 3){
                $cliStream.Read($buffer,4,1) | Out-Null
                $hostBuff = New-Object System.Byte[] $buffer[4]
                $cliStream.Read($hostBuff,0,$buffer[4]) | Out-Null
                $hostName = [System.Text.Encoding]::ASCII.GetString($hostBuff)
            }
            else{
                $buffer[1] = 8
                $cliStream.Write($buffer,0,2)
                throw "Not a valid destination address"
            }
            $cliStream.Read($buffer,4,2) | Out-Null
            $destPort = $buffer[4]*256 + $buffer[5]
            $destHost = Get-IpAddress($hostName)
            if($destHost -eq $null){
                $buffer[1]=4
                $cliStream.Write($buffer,0,2)
                throw "Cant resolve destination address"
            }
            $tmpServ = New-Object System.Net.Sockets.TcpClient($destHost, $destPort)
            if($tmpServ.Connected){
                $buffer[1]=0
                $buffer[3]=1
                $buffer[4]=0
                $buffer[5]=0
                $cliStream.Write($buffer,0,10)
                $cliStream.Flush()
                $vars = [PSCustomObject]@{"cliConnection"=$client;"srvConnection"= $tmpServ}
                $PS3 = [PowerShell]::Create()
                $PS3.AddScript($TcpConnectionMgr).AddArgument($vars) | Out-Null
                [System.IAsyncResult]$AsyncJobResult3 = $null
                $AsyncJobResult3 = $PS3.BeginInvoke()
                while($client.Connected -and $tmpServ.Connected){
                    sleep -m 100;
                }
            }
            else{
                $buffer[1]=4
                $cliStream.Write($buffer,0,2)
                throw "Cant connect to host"
            }
       }elseif($socksVer -eq 4){
            $cmd = $buffer[1]
            if($cmd -ne 1){
                $buffer[0] = 0
                $buffer[1] = 91
                $cliStream.Write($buffer,0,2)
                throw "Not a connect"
            }
            $cliStream.Read($buffer,2,2) | Out-Null
            $destPort = $buffer[2]*256 + $buffer[3]
            $ipv4 = New-Object System.Byte[] 4
            $cliStream.Read($ipv4,0,4) | Out-Null
            $destHost = New-Object System.Net.IPAddress(,$ipv4)
            $buffer[0]=1
            while ($buffer[0] -ne 0){
                $cliStream.Read($buffer,0,1)
            }
            $tmpServ = New-Object System.Net.Sockets.TcpClient($destHost, $destPort)
            if($tmpServ.Connected){
                $buffer[0]=0
                $buffer[1]=90
                $buffer[2]=0
                $buffer[3]=0
                $cliStream.Write($buffer,0,8)
                $cliStream.Flush()
                $vars = [PSCustomObject]@{"cliConnection"=$client;"srvConnection"= $tmpServ}
                $PS3 = [PowerShell]::Create()
                $PS3.AddScript($TcpConnectionMgr).AddArgument($vars) | Out-Null
                [System.IAsyncResult]$AsyncJobResult3 = $null
                $AsyncJobResult3 = $PS3.BeginInvoke()
                while($client.Connected -and $tmpServ.Connected){
                    sleep -m 100;
                }
            }
       }else{
            throw "Unknown socks version"
       }
    }
    catch {
    }
    finally {
        if ($client -ne $null) {
            $client.Close()
            $client.Dispose()
            $client = $null
        }
        if ($PS3 -ne $null -and $AsyncJobResult3 -ne $null) {
            $PS3.EndInvoke($AsyncJobResult3) | Out-Null
            $PS3.Dispose()
        }
    }
}
 
function Invoke-SocksProxy{
    param (
 
            [String]$bindIP = "0.0.0.0",
 
            [Int]$bindPort = 1080
 
     )
    try{
        $listener = new-object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($bindIP), $bindPort)
        $listener.start()
        write-host "Listening on port $bindPort..."
        while($true){
            $client = $listener.AcceptTcpClient()
            Write-Host "New Connection from " $client.Client.RemoteEndPoint
            $vars = [PSCustomObject]@{"cliConnection"=$client;"TcpConnectionMgr"=$TcpConnectionMgr}
            $PS3 = [PowerShell]::Create()
            $PS3.AddScript($SocksConnectionMgr).AddArgument($vars) | Out-Null
            [System.IAsyncResult]$AsyncJobResult3 = $null
            $AsyncJobResult3 = $PS3.BeginInvoke()
        }
     }
    catch{
        write-host $_.Exception.Message
    }
    finally{
        write-host "Server closed."
        if ($listener -ne $null) {
                  $listener.Stop()
           }
        if ($client -ne $null) {
            $client.Close()
            $client.Dispose()
            $client = $null
        }
        if ($PS3 -ne $null -and $AsyncJobResult3 -ne $null) {
            $PS3.EndInvoke($AsyncJobResult3) | Out-Null
            $PS3.Dispose()
        }
    }
}
 
function Invoke-PortFwd{
    param (
 
            [String]$destHost,
 
            [Int]$destPort,
 
            [String]$bindIP = "0.0.0.0",
 
            [Int]$bindPort
 
     )
    $destIp = Get-IpAddress $destHost
    $listener = new-object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Parse($bindIP), $bindPort)
    $listener.start()
    write-host "Listening on port $bindPort..."
    while($true){
        $client = $listener.AcceptTcpClient()
        Write-Host "New Connection"
        $serv = New-Object System.Net.Sockets.TcpClient($destIp, $destPort)
        $vars = [PSCustomObject]@{"cliConnection"=$client;"srvConnection"= $serv}
        $PS3 = [PowerShell]::Create()
        $PS3.AddScript($TcpConnectionMgr).AddArgument($vars) | Out-Null
        [System.IAsyncResult]$AsyncJobResult3 = $null
        $AsyncJobResult3 = $PS3.BeginInvoke()
    }
    if ($listener -ne $null) {
              $listener.Stop()
       }
    if ($PS3 -ne $null -and $AsyncJobResult3 -ne $null) {
        $PS3.EndInvoke($AsyncJobResult3) | Out-Null
        $PS3.Dispose()
    }
    write-host "Connection closed."
}
 
function Get-IpAddress{
    param($ip)
    IF ($ip -as [ipaddress]){
        return $ip
    }else{
        $ip2 = [System.Net.Dns]::GetHostAddresses($ip)[0].IPAddressToString;
        Write-Host "$ip resolved to $ip2"
    }
    return $ip2
}
export-modulemember -function Invoke-SocksProxy
export-modulemember -function Invoke-PortFwd
