<#
    Author: Matan Hart (@machosec)
    License: GNU v3
    Required Dependencies: Find-PotentiallyCrackableAccounts
    Optional Dependencies: None
#>


function Export-PotentiallyCrackableAccounts
{
     <#
    .SYNOPSIS
        Report juicy information about user accounts associated with SPN
        
        Author: Matan Hart (@machosec)
        License: GNU v3
        Required Dependencies: Find-PotentiallyCrackableAccounts
        Optional Dependencies: None 

    .DESCRIPTION
        This function queries the Active Directory and retreive information about user accounts associated with SPN.
        This infromation could detremine if a service account is potentially crackable.
        User accounts associated with SPN are vulnerable to offline brute-forceing and they are often (by defualt)
        configured with weak password and encryption (RC4-HMAC).  
        Requires Active Directory authentication (domain user is enough).
         
    .PARAMETER Type
        The format of the report file. The default is CSV 

    .PARAMETER Path
        The path to store the file. The default is the user's "Documents" folder

    .PARAMETER Name
        The name of the report. The default is "Report" 

    .PARAMETER Summary
        Report minimial information

    .PARAMETER DoNotOpen
        Do not open the report

    .EXAMPLE 
        Report-PotentiallyCrackableAccounts 
        Report all user accounts associated with SPN in entire forest. Save and open the report in CSV format in Documents folder 

    .EXAMPLE
        Report-PotentiallyCrackableAccounts -Type XML -Path C:\Report -DoNotOpen
        Report all user accounts associated with SPN in entire forest. Save the report in XML format in C:\Report folder  

    #>
    [CmdletBinding()]
    param
    (
        [ValidateSet("CSV", "XML", "HTML", "TXT")]
        [String]$Type = "CSV",
        [String]$Path = "$env:USERPROFILE\Documents",
        [String]$Name = "Report",
        [Switch]$Summary,
        [Switch]$DoNotOpen
    )

    # Credits for Boe Prox from TechNet - https://gallery.technet.microsoft.com/scriptcenter/Convert-OutoutForCSV
    Function Convert-Output
    {
        [cmdletbinding()]
        Param (
            [parameter(ValueFromPipeline=$true)]
            [psobject]$InputObject
        )
        Begin {
            $PSBoundParameters.GetEnumerator() | ForEach {
                Write-Verbose "$($_)"
            }
            $FirstRun = $True
        }
        Process {
            If ($FirstRun) {
                $OutputOrder = $InputObject.psobject.properties.name
                $FirstRun = $False
                #Get properties to process
                $Properties = Get-Member -InputObject $InputObject -MemberType *Property
                #Get properties that hold a collection
                $Properties_Collection = @(($Properties | Where-Object {
                    $_.Definition -match "Collection|\[\]"
                }).Name)
                #Get properties that do not hold a collection
                $Properties_NoCollection = @(($Properties | Where-Object {
                    $_.Definition -notmatch "Collection|\[\]"
                }).Name)
            }
 
            $InputObject | ForEach {
                $Line = $_
                $stringBuilder = New-Object Text.StringBuilder
                $Null = $stringBuilder.AppendLine("[pscustomobject] @{")
                $OutputOrder | ForEach {
                        $Null = $stringBuilder.AppendLine("`"$($_)`" = `"$(($line.$($_) | Out-String).Trim())`"")
                    }
                }
                $Null = $stringBuilder.AppendLine("}")
                Invoke-Expression $stringBuilder.ToString()
            }
        End {}
    }

    $FilePath = "$Path\$Name.$($Type.ToLower())"
    $Report = Find-PotentiallyCrackableAccounts -FullData
    if ($Summary) {
       $Report = $Report | Select-Object UserName,DomainName,IsSensitive,PwdAge,CrackWindow,RunsUnder
    }
    if ($Type -eq "CSV" ) {$Report | Convert-Output | Export-Csv $FilePath -Encoding UTF8 -NoTypeInformation}
    elseif ($Type -eq "XML") {$Report | Export-Clixml $FilePath -Encoding UTF8}
    elseif ($Type -eq "HTML") {$Report |  Convert-Output | ConvertTo-Html | Out-File $FilePath -Encoding utf8}
    elseif ($Type -eq "TXT") {$Report |  Convert-Output | Out-File $FilePath -Encoding utf8}  
    Write-Host "$Type file saved in: $FilePath"
    if (!$DoNotOpen) {
        Invoke-Item $FilePath
    }    
}
