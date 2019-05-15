function Add-PuttyDynamicPortForward {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]
    $SessionName,

    # IP to bind to
    [Parameter(Mandatory=$false)]
    [System.Net.IPAddress]
    $IpAddress = '127.0.0.1',

    [Parameter(Mandatory=$true)]
    [int]
    [ValidateRange(1,65535)]
    $Port,

    [Parameter(Mandatory=$false)]
    [string]
    $PuttyRegKey = 'HKCU:\SOFTWARE\SimonTatham\PuTTY',

    [switch]
    $Force
    )

    if(Test-Path $PuttyRegKey -ErrorAction SilentlyContinue) {
        if(Test-Path "$($PuttyRegKey)\Sessions\$($SessionName)" -ErrorAction SilentlyContinue) {
            $ExistingPortForwards = (Get-ItemProperty -Path "$($PuttyRegKey)\Sessions\$($SessionName)" -Name PortForwardings -ErrorAction SilentlyContinue).PortForwardings

            Write-Verbose "Existing port forward string: '$($ExistingPortForwards)'"

            if($ExistingPortForwards) {
                $NewPortForward = $ExistingPortForwards + ",D$($IpAddress):$($Port)="
            } else {
                $NewPortForward = "D$($IpAddress):$($Port)="
            }

            Set-ItemProperty -Force:$force -Path "$($PuttyRegKey)\Sessions\$($SessionName)" -Name PortForwardings -Value $NewPortForward

        } else {
            Write-Error "The PuTTY session '$($SessionName)' does not exist"
        }
    } else {
        Write-Error "The PuTTY registry key '$($PuttyRegKey)' does not exist"
    }
}

function Enable-PuttyConnectionSharing {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]
    $SessionName,

    [Parameter(Mandatory=$false)]
    [string]
    $PuttyRegKey = 'HKCU:\SOFTWARE\SimonTatham\PuTTY',

    [switch]
    $Force
    )

    if(Test-Path $PuttyRegKey -ErrorAction SilentlyContinue) {
        if(Test-Path "$($PuttyRegKey)\Sessions\$($SessionName)" -ErrorAction SilentlyContinue) {
            $ConnectionSharing = (Get-ItemProperty -Path "$($PuttyRegKey)\Sessions\$($SessionName)" -Name ConnectionSharing -ErrorAction SilentlyContinue).ConnectionSharing

            Write-Verbose "Existing ConnectionSharing value: '$($ConnectionSharing)'"

            Set-ItemProperty -Force:$Force -Path "$($PuttyRegKey)\Sessions\$($SessionName)" -Name ConnectionSharing -Value 1

        } else {
            Write-Error "The PuTTY session '$($SessionName)' does not exist"
        }
    } else {
        Write-Error "The PuTTY registry key '$($PuttyRegKey)' does not exist"
    }
}

function Disable-PuttyConnectionSharing {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]
    $SessionName,

    [Parameter(Mandatory=$false)]
    [string]
    $PuttyRegKey = 'HKCU:\SOFTWARE\SimonTatham\PuTTY',

    [switch]
    $Force
    )

    if(Test-Path $PuttyRegKey -ErrorAction SilentlyContinue) {
        if(Test-Path "$($PuttyRegKey)\Sessions\$($SessionName)" -ErrorAction SilentlyContinue) {
            $ConnectionSharing = (Get-ItemProperty -Path "$($PuttyRegKey)\Sessions\$($SessionName)" -Name ConnectionSharing -ErrorAction SilentlyContinue).ConnectionSharing

            Write-Verbose "Existing ConnectionSharing value: '$($ConnectionSharing)'"

            Set-ItemProperty -Force:$Force -Path "$($PuttyRegKey)\Sessions\$($SessionName)" -Name ConnectionSharing -Value 0

        } else {
            Write-Error "The PuTTY session '$($SessionName)' does not exist"
        }
    } else {
        Write-Error "The PuTTY registry key '$($PuttyRegKey)' does not exist"
    }
}

function Test-PuttyConnectionSharing {
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$true)]
    [string]
    $SessionName,

    [Parameter(Mandatory=$false)]
    [string]
    $PuttyRegKey = 'HKCU:\SOFTWARE\SimonTatham\PuTTY',

    [switch]
    $Force
    )

    if(Test-Path $PuttyRegKey -ErrorAction SilentlyContinue) {
        if(Test-Path "$($PuttyRegKey)\Sessions\$($SessionName)" -ErrorAction SilentlyContinue) {
            $ConnectionSharing = (Get-ItemProperty -Path "$($PuttyRegKey)\Sessions\$($SessionName)" -Name ConnectionSharing -ErrorAction SilentlyContinue).ConnectionSharing

            if($ConnectionSharing) {
                [bool]$ConnectionSharing
            } else {
                $false
            }
        } else {
            Write-Error "The PuTTY session '$($SessionName)' does not exist"
        }
    } else {
        Write-Error "The PuTTY registry key '$($PuttyRegKey)' does not exist"
    }
}

function Get-PuttyConfiguration {
    [CmdletBinding()]
    Param (
        [switch]
        $ReturnHashtables
    )

    $UserSidMap = @{}; 
    Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | ForEach-Object { 
        $UserSidMap[$_.PSChildName] = $_.GetValue('ProfileImagePath') 
    }

    $null = New-PSDrive -Name HKU -PSProvider Registry -Root Registry::HKEY_USERS

    #Attempt to enumerate the servers for all users
    $Users = Get-ChildItem -Path "HKU:\" -ErrorAction SilentlyContinue
    foreach ($UserSid in ($Users | Select-Object -ExpandProperty PSChildName))
    {
        $PuttyKeyPath = "HKU:\$($UserSid)\SOFTWARE\SimonTatham\Putty"

        if(Test-Path -ErrorAction SilentlyContinue $PuttyKeyPath) {
            Write-Verbose "Putty registry key is present"

            $Output = @{}
            
            try {
                $SIDObj = New-Object System.Security.Principal.SecurityIdentifier($UserSid)
                $Output["User"] = ($SIDObj.Translate([System.Security.Principal.NTAccount])).Value
            } catch {
                $Output["User"] = $UserSid
            }

            # 1) Saved jump list
            $Output["JumpList"] = (Get-ItemProperty "$($PuttyKeyPath)\Jumplist" -Name 'Recent Sessions' -ErrorAction SilentlyContinue).'Recent sessions'
        
            # 2) Session configs
            $Sessions = Get-ChildItem "$($PuttyKeyPath)\Sessions" -ErrorAction SilentlyContinue
            
            if($Sessions) {
                $Output["Sessions"] = @{}
            
                foreach($Session in $Sessions) {
                    $SessionData = @{}
                    $SessionName = $Session.PSChildName

                    $Session.GetValueNames() | ForEach-Object {
                        $SessionData["$_"] = $Session.GetValue($_)
                    }

                    if($ReturnHashtables) {
                        $Output.Sessions["$SessionName"] = $SessionData
                    } else {
                        $Output.Sessions["$SessionName"] = New-Object PSObject -Property $SessionData                        
                    }

                }
            }

            # 3) Known hosts
            $HostKeysRegKey = Get-Item "$($PuttyKeyPath)\SshHostKeys" -ErrorAction SilentlyContinue

            if($HostKeysRegKey) {
                $HostKeys = @{}
                foreach($HostName in ($HostKeysRegKey.GetValueNames())) {
                    $HostKeys["$HostName"] = $HostKeysRegKey.GetValue($HostName)
                }

                $Output["HostKeys"] = $HostKeys
            }

            if($Output["JumpList"] -or $Output["Sessions"] -or $Output["HostKeys"]) {
                if($ReturnHashtables) {
                    $Output
                } else {
                    New-Object PSObject -Property $Output
                }
            }
        }
    }

    $null = Remove-PSDrive -Name HKU
}
