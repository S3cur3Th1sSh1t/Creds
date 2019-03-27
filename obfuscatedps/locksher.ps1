

$FhEJPlq9tJYHeGu:ExploitTable = $null

function Get-FileVersionInfo ($ecWAIOEhbhXrDJF) {

    $SPvpoe9tY9a99Cm = (Get-Item $ecWAIOEhbhXrDJF).VersionInfo
    $ExFiYEgvzXOq9oA = ( "{0}.{1}.{2}.{3}" -f $SPvpoe9tY9a99Cm.FileMajorPart, $SPvpoe9tY9a99Cm.FileMinorPart, $SPvpoe9tY9a99Cm.FileBuildPart, $SPvpoe9tY9a99Cm.FilePrivatePart )
        
    return $ExFiYEgvzXOq9oA

}

function Get-InstalledSoftware($AMVZzQ99jytZ9ir) {

    $Xxt9RmvxndpKhjk = Get-WmiObject -Class Win32_Product | Where { $_.Name -eq $AMVZzQ99jytZ9ir } | Select-Object Version
    $Xxt9RmvxndpKhjk = $Xxt9RmvxndpKhjk.Version  # I have no idea what I'm doing
    
    return $Xxt9RmvxndpKhjk

}


function rites {


    $LdaQHCNMttyjb9r = (Get-WmiObject Win32_OperatingSystem).OSArchitecture


    $xVqtZfrSOTxYy9X = $env:PROCESSOR_ARCHITECTURE

    return $LdaQHCNMttyjb9r, $xVqtZfrSOTxYy9X

}

function bolls {


    $FhEJPlq9tJYHeGu:ExploitTable = New-Object System.Data.DataTable


    $FhEJPlq9tJYHeGu:ExploitTable.Columns.Add("Title")
    $FhEJPlq9tJYHeGu:ExploitTable.Columns.Add("MSBulletin")
    $FhEJPlq9tJYHeGu:ExploitTable.Columns.Add("CVEID")
    $FhEJPlq9tJYHeGu:ExploitTable.Columns.Add("Link")
    $FhEJPlq9tJYHeGu:ExploitTable.Columns.Add("VulnStatus")




    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("User Mode to Ring (KiTrap0D)","MS10-015","2010-0232","https://www.exploit-db.com/exploits/11199/")
    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("Task Scheduler .XML","MS10-092","2010-3338, 2010-3888","https://www.exploit-db.com/exploits/19930/")

    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("NTUserMessageCall Win32k Kernel Pool Overflow","MS13-053","2013-1300","https://www.exploit-db.com/exploits/33213/")
    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("TrackPopupMenuEx Win32k NULL Page","MS13-081","2013-3881","https://www.exploit-db.com/exploits/31576/")

    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("TrackPopupMenu Win32k Null Pointer Dereference","MS14-058","2014-4113","https://www.exploit-db.com/exploits/35101/")

    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("ClientCopyImage Win32k","MS15-051","2015-1701, 2015-2433","https://www.exploit-db.com/exploits/37367/")
    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("Font Driver Buffer Overflow","MS15-078","2015-2426, 2015-2433","https://www.exploit-db.com/exploits/38222/")

    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("'mrxdav.sys' WebDAV","MS16-016","2016-0051","https://www.exploit-db.com/exploits/40085/")
    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("Secondary Logon Handle","MS16-032","2016-0099","https://www.exploit-db.com/exploits/39719/")

    $FhEJPlq9tJYHeGu:ExploitTable.Rows.Add("Nessus Agent 6.6.2 - 6.10.3","N/A","2017-7199","https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html")

}

function Set-ExploitTable ($UDyBfjEpHarJgnZ, $WcWpwEEIPVIeLpK) {

    if ( $UDyBfjEpHarJgnZ -like "MS*" ) {

        $FhEJPlq9tJYHeGu:ExploitTable | Where { $_.MSBulletin -eq $UDyBfjEpHarJgnZ

        } | ForEach-Object {

            $_.VulnStatus = $WcWpwEEIPVIeLpK

        }

    } else {


    $FhEJPlq9tJYHeGu:ExploitTable | Where { $_.CVEID -eq $UDyBfjEpHarJgnZ

        } | ForEach-Object {

            $_.VulnStatus = $WcWpwEEIPVIeLpK

        }

    }

}

function earthiest {

    $FhEJPlq9tJYHeGu:ExploitTable

}

function proportioned {

    if ( !$FhEJPlq9tJYHeGu:ExploitTable ) {

        $null = bolls
    
    }

        unsteadier
        fringing
        shipmates
        splendidest
        rarefying
        Louisianian
        crag
        Max
        Irtish
        bookkeeping

        earthiest

}

function unsteadier {


    $UDyBfjEpHarJgnZ = "MS10-015"


    $Dm9gypTBjGMYeOQ = rites


    if ( $Dm9gypTBjGMYeOQ[0] -eq "64-bit" ) {

        $WcWpwEEIPVIeLpK = "Not supported on 64-bit systems"

    } Else {


        $Path = $env:windir + "\system32\ntoskrnl.exe"
        $SPvpoe9tY9a99Cm = Get-FileVersionInfo($Path)


        $SPvpoe9tY9a99Cm = $SPvpoe9tY9a99Cm.Split(".")


        $Build = $SPvpoe9tY9a99Cm[2]
        $ymrF9YaDzWNXCYW = $SPvpoe9tY9a99Cm[3].Split(" ")[0] # Drop the junk


        switch ( $Build ) {

            7600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "20591" ] }
            default { $WcWpwEEIPVIeLpK = "Not Vulnerable" }

        }

    }


    Set-ExploitTable $UDyBfjEpHarJgnZ $WcWpwEEIPVIeLpK

}

function fringing {


    $UDyBfjEpHarJgnZ = "MS10-092"


    $Dm9gypTBjGMYeOQ = rites


    if ( $Dm9gypTBjGMYeOQ[1] -eq "AMD64" -or $Dm9gypTBjGMYeOQ[0] -eq "32-bit" ) {


        $Path = $env:windir + "\system32\schedsvc.dll"
        $SPvpoe9tY9a99Cm = Get-FileVersionInfo($Path)


        $SPvpoe9tY9a99Cm = $SPvpoe9tY9a99Cm.Split(".")


        $Build = $SPvpoe9tY9a99Cm[2]
        $ymrF9YaDzWNXCYW = $SPvpoe9tY9a99Cm[3].Split(" ")[0] # Drop the junk


        switch ( $Build ) {

            7600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "20830" ] }
            default { $WcWpwEEIPVIeLpK = "Not Vulnerable" }

        }
        
    } ElseIf ( $Dm9gypTBjGMYeOQ[0] -eq "64-bit" -and $Dm9gypTBjGMYeOQ[1] -eq "x86" ) {

        $WcWpwEEIPVIeLpK = "Migrate to a 64-bit process to avoid WOW64 Filesystem Redirection shenanigans"

    }


    Set-ExploitTable $UDyBfjEpHarJgnZ $WcWpwEEIPVIeLpK

}

function shipmates {


    $UDyBfjEpHarJgnZ = "MS13-053"


    $Dm9gypTBjGMYeOQ = rites


    if ( $Dm9gypTBjGMYeOQ[0] -eq "64-bit" ) {

        $WcWpwEEIPVIeLpK = "Not supported on 64-bit systems"

    } Else {


        $Path = $env:windir + "\system32\win32k.sys"
        $SPvpoe9tY9a99Cm = Get-FileVersionInfo($Path)


        $SPvpoe9tY9a99Cm = $SPvpoe9tY9a99Cm.Split(".")


        $Build = $SPvpoe9tY9a99Cm[2]
        $ymrF9YaDzWNXCYW = $SPvpoe9tY9a99Cm[3].Split(" ")[0] # Drop the junk


        switch ( $Build ) {

            7600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -ge "17000" ] }
            7601 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "22348" ] }
            9200 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "20732" ] }
            default { $WcWpwEEIPVIeLpK = "Not Vulnerable" }

        }

    }


    Set-ExploitTable $UDyBfjEpHarJgnZ $WcWpwEEIPVIeLpK

}

function splendidest {


    $UDyBfjEpHarJgnZ = "MS13-081"


    $Dm9gypTBjGMYeOQ = rites


    if ( $Dm9gypTBjGMYeOQ[0] -eq "64-bit" ) {

        $WcWpwEEIPVIeLpK = "Not supported on 64-bit systems"

    } Else {


        $Path = $env:windir + "\system32\win32k.sys"
        $SPvpoe9tY9a99Cm = Get-FileVersionInfo($Path)


        $SPvpoe9tY9a99Cm = $SPvpoe9tY9a99Cm.Split(".")


        $Build = $SPvpoe9tY9a99Cm[2]
        $ymrF9YaDzWNXCYW = $SPvpoe9tY9a99Cm[3].Split(" ")[0] # Drop the junk


        switch ( $Build ) {

            7600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -ge "18000" ] }
            7601 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "22435" ] }
            9200 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "20807" ] }
            default { $WcWpwEEIPVIeLpK = "Not Vulnerable" }

        }

    }


    Set-ExploitTable $UDyBfjEpHarJgnZ $WcWpwEEIPVIeLpK

}

function rarefying {


    $UDyBfjEpHarJgnZ = "MS14-058"


    $Dm9gypTBjGMYeOQ = rites


    if ( $Dm9gypTBjGMYeOQ[1] -eq "AMD64" -or $Dm9gypTBjGMYeOQ[0] -eq "32-bit" ) {


        $Path = $env:windir + "\system32\win32k.sys"
        $SPvpoe9tY9a99Cm = Get-FileVersionInfo($Path)


        $SPvpoe9tY9a99Cm = $SPvpoe9tY9a99Cm.Split(".")


        $Build = $SPvpoe9tY9a99Cm[2]
        $ymrF9YaDzWNXCYW = $SPvpoe9tY9a99Cm[3].Split(" ")[0] # Drop the junk


        switch ( $Build ) {

            7600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -ge "18000" ] }
            7601 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "22823" ] }
            9200 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "21247" ] }
            9600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "17353" ] }
            default { $WcWpwEEIPVIeLpK = "Not Vulnerable" }

        }

        } ElseIf ( $Dm9gypTBjGMYeOQ[0] -eq "64-bit" -and $Dm9gypTBjGMYeOQ[1] -eq "x86" ) {

            $WcWpwEEIPVIeLpK = "Migrate to a 64-bit process to avoid WOW64 Filesystem Redirection shenanigans"

        }


    Set-ExploitTable $UDyBfjEpHarJgnZ $WcWpwEEIPVIeLpK

}

function Louisianian {


    $UDyBfjEpHarJgnZ = "MS15-051"


    $Dm9gypTBjGMYeOQ = rites


    if ( $Dm9gypTBjGMYeOQ[1] -eq "AMD64" -or $Dm9gypTBjGMYeOQ[0] -eq "32-bit" ) {


        $Path = $env:windir + "\system32\win32k.sys"
        $SPvpoe9tY9a99Cm = Get-FileVersionInfo($Path)


        $SPvpoe9tY9a99Cm = $SPvpoe9tY9a99Cm.Split(".")


        $Build = $SPvpoe9tY9a99Cm[2]
        $ymrF9YaDzWNXCYW = $SPvpoe9tY9a99Cm[3].Split(" ")[0] # Drop the junk


        switch ( $Build ) {

            7600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -ge "18000" ] }
            7601 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "22823" ] }
            9200 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "21247" ] }
            9600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "17353" ] }
            default { $WcWpwEEIPVIeLpK = "Not Vulnerable" }

        }

    } ElseIf ( $Dm9gypTBjGMYeOQ[0] -eq "64-bit" -and $Dm9gypTBjGMYeOQ[1] -eq "x86" ) {

        $WcWpwEEIPVIeLpK = "Migrate to a 64-bit process to avoid WOW64 Filesystem Redirection shenanigans"

    }


    Set-ExploitTable $UDyBfjEpHarJgnZ $WcWpwEEIPVIeLpK

}

function crag {


    $UDyBfjEpHarJgnZ = "MS15-078"


    $Path = $env:windir + "\system32\atmfd.dll"
    $SPvpoe9tY9a99Cm = Get-FileVersionInfo($Path)


    $SPvpoe9tY9a99Cm = $SPvpoe9tY9a99Cm.Split(" ")


    $ymrF9YaDzWNXCYW = $SPvpoe9tY9a99Cm[2]


    switch ( $ymrF9YaDzWNXCYW ) {

        243 { $WcWpwEEIPVIeLpK = "Appears Vulnerable" }
        default { $WcWpwEEIPVIeLpK = "Not Vulnerable" }

    }


    Set-ExploitTable $UDyBfjEpHarJgnZ $WcWpwEEIPVIeLpK

}

function Max {


    $UDyBfjEpHarJgnZ = "MS16-016"


    $Dm9gypTBjGMYeOQ = rites


    if ( $Dm9gypTBjGMYeOQ[0] -eq "64-bit" ) {

        $WcWpwEEIPVIeLpK = "Not supported on 64-bit systems"

    } Else {


        $Path = $env:windir + "\system32\drivers\mrxdav.sys"
        $SPvpoe9tY9a99Cm = Get-FileVersionInfo($Path)


        $SPvpoe9tY9a99Cm = $SPvpoe9tY9a99Cm.Split(".")


        $Build = $SPvpoe9tY9a99Cm[2]
        $ymrF9YaDzWNXCYW = $SPvpoe9tY9a99Cm[3].Split(" ")[0] # Drop the junk


        switch ( $Build ) {

            7600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -ge "16000" ] }
            7601 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "23317" ] }
            9200 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "21738" ] }
            9600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "18189" ] }
            10240 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "16683" ] }
            10586 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le "103" ] }
            default { $WcWpwEEIPVIeLpK = "Not Vulnerable" }

        }

    }


    Set-ExploitTable $UDyBfjEpHarJgnZ $WcWpwEEIPVIeLpK

}

function Irtish {


    $UDyBfjEpHarJgnZ = "MS16-032"


    $Dm9gypTBjGMYeOQ = rites


    if ( $Dm9gypTBjGMYeOQ[1] -eq "AMD64" -or $Dm9gypTBjGMYeOQ[0] -eq "32-bit" ) {


        $Path = $env:windir + "\system32\seclogon.dll"
        $SPvpoe9tY9a99Cm = Get-FileVersionInfo($Path)


        $SPvpoe9tY9a99Cm = $SPvpoe9tY9a99Cm.Split(".")


        $Build = [int]$SPvpoe9tY9a99Cm[2]
        $ymrF9YaDzWNXCYW = [int]$SPvpoe9tY9a99Cm[3].Split(" ")[0] # Drop the junk

        switch ( $Build ) {
            6002 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $9CghsEs9JicoDRu -lt 19598 -Or ( $ymrF9YaDzWNXCYW -ge 23000 -And $ymrF9YaDzWNXCYW -le 23909 ) ] } # Confirmed for Windows 2008
            7600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -ge 16000 ] } # Not sure about 7 RTM
            7601 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -lt 19148 -Or ( $ymrF9YaDzWNXCYW -ge 23000 -And $ymrF9YaDzWNXCYW -le 23347 ) ] } # Confirmed for Windows 7 and 2008R2
            9200 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $9CghsEs9JicoDRu -lt 17649 -Or ( $ymrF9YaDzWNXCYW -ge 21000 -And $ymrF9YaDzWNXCYW -le 21767 ) ] } # Confirmed for Windows 2012
            9600 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $9CghsEs9JicoDRu -lt 18230 ] } # Confirmed for Windows 8.1 and 2012R2
            10240 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -lt 16724 ] } # Confirmed for Windows 10
            10586 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $ymrF9YaDzWNXCYW -le 161 ] } # Confirmed for Windows 10 1151
            default { $WcWpwEEIPVIeLpK = "Not Vulnerable" } # If no match

        }

    } ElseIf ( $Dm9gypTBjGMYeOQ[0] -eq "64-bit" -and $Dm9gypTBjGMYeOQ[1] -eq "x86" ) {

        $WcWpwEEIPVIeLpK = "Migrate to a 64-bit process to avoid WOW64 Filesystem Redirection shenanigans"

    }


    Set-ExploitTable $UDyBfjEpHarJgnZ $WcWpwEEIPVIeLpK

}

function bookkeeping {


    $CVEID = "2017-7199"


    $Xxt9RmvxndpKhjk = Get-InstalledSoftware "Nessus Agent"
    
    if ( !$Xxt9RmvxndpKhjk ) {

        $WcWpwEEIPVIeLpK = "Not Vulnerable"

    } else {


        $Xxt9RmvxndpKhjk = $Xxt9RmvxndpKhjk.Split(".")


        $Major = [int]$Xxt9RmvxndpKhjk[0]
        $Minor = [int]$Xxt9RmvxndpKhjk[1]
        $Build = [int]$Xxt9RmvxndpKhjk[2]


        switch( $Major ) {

        6 { $WcWpwEEIPVIeLpK = @("Not Vulnerable","Appears Vulnerable")[ $Minor -eq 10 -and $Build -le 3 -Or ( $Minor -eq 6 -and $Build -le 2 ) -Or ( $Minor -le 9 -and $Minor -ge 7 ) ] } # 6.6.2 - 6.10.3
        default { $WcWpwEEIPVIeLpK = "Not Vulnerable" }

        }

    }


    Set-ExploitTable $CVEID $WcWpwEEIPVIeLpK

}