

function Get-SecConnectionInfo{
<#
.Synopsis
  Retrieves current tcp connections and returns the remote IP addresses, location of those addresses, and connection state as a custom object 


.EXAMPLE
  Show all connections outside the United States
  PS C:\> Get-SecConnectionInfo | Where-Object{$_.Location -notmatch "United States"}

 .Link
        https://github.com/organizations/PoshSec

#>

[CmdletBinding()]

$global = [System.net.networkInformation.IPGlobalProperties]::GetIPGlobalProperties()


$connects = $global.GetActiveTcpConnections()

$custobjs = @()

foreach($i in $connects){

if(($i.RemoteEndPoint.Address -ne "127.0.0.1") -and ($i.RemoteEndPoint.Address -ne "::1") ){
$rhost = $i.RemoteEndPoint.Address
$state = $i.State

$webreq = (Invoke-WebRequest "http://iplocation.truevue.org/$rhost.html").toString() 

$startstring = $webreq.IndexOf("title:") + 7
$endstring = $webreq.IndexOf("});")
$diff = $endstring - $startstring - 11

$custobj = New-Object System.Object
$custobj | Add-Member -MemberType NoteProperty -Name RemoteAddress -Value $rhost
$custobj | Add-Member -MemberType NoteProperty -Name Location -Value $webreq.substring($startstring, $diff)
$custobj | Add-Member -MemberType NoteProperty -Name State -Value $state
$custobjs += $custobj


}

}

return $custobjs

}

