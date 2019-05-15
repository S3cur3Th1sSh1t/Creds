<#
.SYNOPSIS
	    

.DESCRIPTION
The main features included in this version are:

	    Return a huge number of attributes on computers, users, containers/OUs, groups, ACL, etc...
	    Search for locked accounts, expired password, no password policy, etc...
	    Return a list of all privileged account in domain. (The script search in SID value instead in a group name)
	    Return a list of group’s modification (Users added/deleted for a specific group, etc...)
	    Multi-Threading support
	    Plugin Support
     
    VOYEUR can be used in two ways scenarios:
        Able for using on local or remote computer
        Able for using on joined machine or workgroup machine

    With VOYEUR, there is also support for exporting data driven to popular formats like CSV, XML or JSON.

    Office Support
        Support for exporting data driven to EXCEL format. The tool also support table style modification, chart creation, company logo or independent language support. At the moment only Office Excel 2010 and Office Excel 2013 are supported by the tool.
	
.NOTES
	Author		: Juan Garrido (http://windowstips.wordpress.com)
    Twitter		: @tr1ana
    Company		: https://www.nccgroup.trust
    File Name	: voyeur.ps1

.LINK

https://www.blackhat.com/us-16/arsenal.html#juan-garrido

.EXAMPLE
	.\voyeur.ps1 -ExportTo PRINT

This example retrieve information of an Active Directory and print results. If no credential passed, the script will try to connect using the token for logged user
	
.EXAMPLE
	.\voyeur.ps1 -ExportTo CSV,JSON,XML

This example retrieve information of an Active Directory and export data driven to CSV, JSON and XML format into Reports folder. If no credential passed, the script will try to connect using the token for logged user
	
.EXAMPLE
	.\voyeur.ps1 -Domain "test.example.local" -AlternateCredential -ExportTo CSV

This example retrieve information of an Active Directory for a specific domain with explicit credentials and export results to CSV format. 
	
.EXAMPLE
	.\voyeur.ps1 -Domain "test.example.local" -ExportACL -ExportOU -ExportTo JSON

This example retrieve information of an Active Directory for a specific domain. Also, retrieve Organizational Unit information and ACL values. Next, export all data driven to JSON format. 

.EXAMPLE
	.\voyeur.ps1 -Domain "test.example.local" -SearchRoot "OU=NCCGroup,DC=test,DC=example,DC=local" -ExportACL -ExportOU -ExportTo XML

This example retrieve information of an Active Directory for a specific domain and for specific Organizational Unit (OU). Also, retrieve Organizational Unit information and ACL values. Next, export all data driven to XML format. 
	
.EXAMPLE
	.\voyeur.ps1 -Domain "test.example.local" -UseSSL -ExportTo CSV

This example retrieve information of an Active Directory through SSL and export data driven to CSV. 
Note: You must first make sure that LDAP over SSL (also known as LDAPS or LDAP over TLS) is enabled on Active Directory server and you have imported imported a CA certificate for Active Directory server to your machine.
	
.PARAMETER Domain
	Collect data from the specified domain.

.PARAMETER SearchRoot
	Collect data from specified Organizational Unit.

.PARAMETER UseSSL
	For SSL connection an valid username/password and domain passed is neccesary to passed

.PARAMETER ExportTo
	Export all data to multiple formats. Supported XML, JSON, CSV, EXCEL

.PARAMETER AlternateCredential
	Run Voyeur with alternate credential

.PARAMETER ExportACL
	Export ACL information from Organizational Units

.PARAMETER AdminSDHolder
	Collect data from AdminSDHolder object.

.PARAMETER AuditorName
	Sets the name of security auditor. Used for Excel report
#>

[CmdletBinding()] 
param
(	
	[Parameter(Mandatory=$false)]
	[String] $DomainName= $null,

    [Parameter(Mandatory=$false, HelpMessage="Prompt for alternate credentials")]
    [switch]
    $AlternateCredential,

    [Parameter(Mandatory=$false, HelpMessage="Export ACL from Organizational Units")]
    [switch]
    $ExportACL,

    [Parameter(Mandatory=$false, HelpMessage="Export Organizational Units from Domain")]
    [switch]
    $ExportOU,

    [Parameter(ValueFromPipelineByPropertyName=$true, Mandatory=$false, HelpMessage="Export AdminSDHolder ACL")]
    [switch]
    $AdminSDHolder,

    [Parameter(Mandatory=$false, HelpMessage="Get Organizational Unit Volumetry")]
	[Switch] $OUVolumetry,

    [Parameter(Mandatory=$false)]
	[String] $SearchRoot = $null,

    [Parameter(Mandatory=$false, HelpMessage="Name of auditor")]
	[String] $AuditorName = $env:username,
	
	[Parameter(Mandatory=$false, HelpMessage="User/Password and Domain required")]
	[Switch] $UseSSL,

    [parameter(ValueFromPipelineByPropertyName=$true, Mandatory= $false, HelpMessage= "Export data to multiple formats")]
    [ValidateSet("CSV","JSON","XML","PRINT","EXCEL")]
    [Array]$ExportTo=@()
)

$MyParams = $PSBoundParameters

#Export voyeur data to multiple formats
Function Export-ResultQuery{
    Param (
        [parameter(ValueFromPipeline = $True,ValueFromPipeLineByPropertyName = $True)]
        [Object]$Dataset,

        [parameter()]
        [ValidateSet("CSV","JSON","XML","Print","EXCEL")]
        [String]$ExportTo="CSV"

        )

    #Export data
    switch ($ExportTo) { 
        'CSV'
        {
            Generate-CSV -ServerObject $AllVoyeurData -RootPath $Report
        }
        'JSON'
        {
            Generate-Json -ServerObject $AllVoyeurData -RootPath $Report
        }
        'XML'
        {
            Generate-XML -ServerObject $AllVoyeurData -RootPath $Report
        }
        'EXCEL'
        {
            Generate-Excel -ServerObject $AllVoyeurData -Settings $ExcelSettings `
                           -Formatting $TableFormatting -HeaderStyle $HeaderStyle -RootPath $Report
        }
        'Print'
        {
            $AllVoyeurData | %{
                foreach ($node in $_.psobject.Properties){
                    [pscustomobject]@{$node.Name=$node.Value.Data}
                }
            }
        }
     }    
}

#Function to create new ADObject
Function New-VoyeurADObject{
    try{
        #Create and return a new PsObject
        $ObjectData = New-Object -TypeName PSCustomObject
        $ObjectData | Add-Member -type NoteProperty -name Forest -value $Global:Forest
        $ObjectData | Add-Member -type NoteProperty -name Credential -value $Global:credential
        $ObjectData | Add-Member -type NoteProperty -name Domain -value $Global:AllDomainData
        $ObjectData | Add-Member -type NoteProperty -name DomainSID -value $Global:DomainSID
        $ObjectData | Add-Member -type NoteProperty -name UseCredentials -value $Global:UseCredentials
        $ObjectData | Add-Member -type NoteProperty -name SearchRoot -value $Global:SearchRoot
        $ObjectData | Add-Member -type NoteProperty -name UseSSL -value $Global:UseSSL
        $ObjectData | Add-Member -type NoteProperty -name InactiveDays -value $InactiveDays
        $ObjectData | Add-Member -type NoteProperty -name KerberosEncType -value $Global:KerberosEncType
        $ObjectData | Add-Member -type NoteProperty -name Report -value @()
        return $ObjectData
    }
    catch{
        throw ("{0}: {1}" -f "Unable to create new object",$_.Exception.Message)
    }
}

#Region Import Modules
#---------------------------------------------------
# Import Modules
#---------------------------------------------------	
$ScriptPath = $PWD.Path #Split-Path $MyInvocation.MyCommand.Path -Parent
. $ScriptPath\Common\Domain.ps1
. $ScriptPath\Common\Runspace.ps1
. $ScriptPath\Common\getconfig.ps1
. $ScriptPath\Common\Functions.ps1
. $ScriptPath\Common\Vars.ps1
. $ScriptPath\Common\Office\Excel\ExcelObject.ps1
. $ScriptPath\Utils\CsvReport.ps1
. $ScriptPath\Utils\JsonReport.ps1
. $ScriptPath\Utils\XmlReport.ps1
. $ScriptPath\Utils\ExcelReport.ps1


#Load Plugins and config file
$Plugins = Get-ChildItem "$ScriptPath\Plugins\*.ps1" | Select-Object FullName
$appConfig = Get-VoyeurConf -path "$($ScriptPath)\Config\Voyeur.config" -Node "filterSettings"
$appConfig+= Get-VoyeurConf -path "$($ScriptPath)\Config\Voyeur.config" -Node "eventSettings"
$ExcelSettings = Get-VoyeurConf -path "$($ScriptPath)\Config\Voyeur.config" -Node "excelSettings"
$TableFormatting = Get-VoyeurConf -path "$($ScriptPath)\Config\Voyeur.config" -Node "tableFormatting"
$HeaderStyle = Get-VoyeurConf -path "$($ScriptPath)\Config\Voyeur.config" -Node "HeaderStyle"

#Set-Variable credential -Value (Get-Credential) -Scope Global
#Set-Variable UseCredentials -Value $true -Scope Global

#EndRegion
#Start Time
$starttimer = Get-Date
#End Start Time
#Main Vars
Set-Variable MyPath -Value $ScriptPath -Scope Global
Set-Variable isConnected -Value $false -Scope Global
Set-Variable Domain -Value $false -Scope Global
Set-Variable DomainName -Value $DomainName -Scope Global
Set-Variable UseSSL -Value $UseSSL -Scope Global
Set-Variable SearchRoot -Value $SearchRoot -Scope Global
Set-Variable AuditorName -Value $AuditorName -Scope Global
Set-Variable KerberosEncType -Value ([System.DirectoryServices.AuthenticationTypes]::Sealing -bor [System.DirectoryServices.AuthenticationTypes]::Secure) -Scope Global
#Region Main

    if($MyParams['AlternateCredential']){
        Set-Variable credential -Value (Get-Credential) -Scope Global
        Set-Variable UseCredentials -Value $true -Scope Global
    }
    else{
        Set-Variable UseCredentials -Value $false -Scope Global
    }
    $AllDomainData = Get-DomainInfo
    #$AllDomainData | fl
    Set-Variable AllDomainData -Value $AllDomainData -Scope Global
    #Get Identifiers from Domain
    if ($Global:AllDomainData.Name){
        Set-Variable -Name Forest -Value (Get-CurrentForest) -Scope Global 
        Set-Variable -Name DomainSID -Value (Get-DomainSID) -Scope Global

        $ObjectData = New-VoyeurADObject
        $AllData = New-Object -TypeName PSCustomObject

        #Add filter data to Users and Computers queries
        if($appConfig["UsersFilter"]){
            $ObjectData | Add-Member -type NoteProperty -name UsersFilter -value $appConfig["UsersFilter"]  
        }
        if($appConfig["ComputersFilter"]){
            $ObjectData | Add-Member -type NoteProperty -name ComputersFilter -value $appConfig["ComputersFilter"]  
        }
        if($appConfig["GroupFilter"]){
            $ObjectData | Add-Member -type NoteProperty -name GroupFilter -value $appConfig["GroupFilter"]  
        }
        #Populate jobs with plugins
        $AllData = Get-RunSpaceADObject -Plugins $Plugins -ADObject $ObjectData

        if($MyParams['ExportOU']){
            #Create New object 
            $MyPlugin = Get-ChildItem "$ScriptPath\Plugins\ACL.ps1" | Select-Object FullName
            $OUExtract = New-Object -TypeName PSCustomObject
            $OUExtract | Add-Member -type NoteProperty -name Name -value "OrganizationalUnit"
            $OUExtract | Add-Member -type NoteProperty -name Query -value $appConfig["OU"]
            $OUExtract | Add-Member -type NoteProperty -name FullACL -value $false
            #Send object to plugin
            $NewObjectData = New-VoyeurADObject
            $NewObjectData | Add-Member -type NoteProperty -name OUExtract -value $OUExtract -Force  
            #Send Unit plugin
            $OUExport = Get-RunSpaceADObject -Plugins $MyPlugin -ADObject $NewObjectData
            #Add new values to PsObject
            $CustomReportFields = $AllData.Report
            $Data = $OUExport.OrganizationalUnit
            if($Data){
                $NewCustomReportFields = [array]$CustomReportFields+="OrganizationalUnit"
                $AllData | Add-Member -type NoteProperty -name Report -value $NewCustomReportFields -Force
                $AllData | Add-Member -type NoteProperty -name OrganizationalUnit -value $Data -Force
            }
            
        }
        if($MyParams['ExportACL']){
            #Create New object
            $MyPlugin = Get-ChildItem "$ScriptPath\Plugins\ACL.ps1" | Select-Object FullName
            $OUExtract = New-Object -TypeName PSCustomObject
            $OUExtract | Add-Member -type NoteProperty -name Name -value "FullOrganizationalUnit"
            $OUExtract | Add-Member -type NoteProperty -name Query -value $appConfig["OU"]
            $OUExtract | Add-Member -type NoteProperty -name FullACL -value $true
            #Send object to plugin
            $NewObjectData = New-VoyeurADObject
            $NewObjectData | Add-Member -type NoteProperty -name OUExtract -value $OUExtract -Force
            #Send Unit plugin
            $ACLExport = Get-RunSpaceADObject -Plugins $MyPlugin -ADObject $NewObjectData
            #Add data to psObject
            $CustomReportFields = $AllData.Report
            $Data = $ACLExport.FullOrganizationalUnit
            if($Data){
                $NewCustomReportFields = [array]$CustomReportFields+="FullOrganizationalUnit"
                $AllData | Add-Member -type NoteProperty -name Report -value $NewCustomReportFields -Force
                $AllData | Add-Member -type NoteProperty -name FullOrganizationalUnit -value $Data -Force
            }
            
        }
        if($MyParams['SearchRoot']){
            $ObjectData | Add-Member -type NoteProperty -name SearchRoot -value $SearchRoot -Force
        }
        if($MyParams['AdminSDHolder']){
            #Create New object
            $MyPlugin = Get-ChildItem "$ScriptPath\Plugins\ACL.ps1"  | Select-Object FullName 
            $OUExtract = New-Object -TypeName PSCustomObject
            $OUExtract | Add-Member -type NoteProperty -name Name -value "AdminSDHolder"
            $OUExtract | Add-Member -type NoteProperty -name Query -value $appConfig["AdminSDHolder"]
            $OUExtract | Add-Member -type NoteProperty -name FullACL -value $true
            #Send object to plugin
            $NewObjectData = New-VoyeurADObject
            $NewObjectData | Add-Member -type NoteProperty -name OUExtract -value $OUExtract -Force
            #Send Unit plugin
            $AdminSDHolderExport = Get-RunSpaceADObject -Plugins $MyPlugin -ADObject $NewObjectData
            #Add data to PSObject
            $CustomReportFields = $AllData.Report
            $Data = $AdminSDHolderExport.AdminSDHolder
            if($Data){
                $NewCustomReportFields = [array]$CustomReportFields+="AdminSDHolder"
                $AllData | Add-Member -type NoteProperty -name Report -value $NewCustomReportFields -Force
                $AllData | Add-Member -type NoteProperty -name AdminSDHolder -value $Data -Force
            }
        }
        if($MyParams['OUVolumetry']){
            #Try to extract OU Volumetry
            $AllUsers = $AllData.DomainUsers.Data
            $AllOU = $AllData.OrganizationalUnit.Data
            if($AllUsers -and $AllOU){
                $VolumetryACL = Get-OUVolumetry -ACL $AllOU -Users $AllUsers
                $CustomReportFields = $AllData.Report
                $NewCustomReportFields = [array]$CustomReportFields+="OUVolumetry"
                $AllData | Add-Member -type NoteProperty -name Report -value $NewCustomReportFields -Force
                $AllData | Add-Member -type NoteProperty -name OUVolumetry -value $VolumetryACL -Force
            }
        }
        #Remove unnecessary data
        $excludes = @("Report","UsersStatus")
        $AllVoyeurData = New-Object -TypeName PSCustomObject
        $AllData.psobject.Properties| %{`
            foreach ($exclude in $excludes){
                if ($_.Name -eq $exclude){
                    return}
            }
            $AllVoyeurData | Add-Member -type NoteProperty -name $_.Name -value $_.Value
        }

        #Prepare data and export results to multiple formats
        if($MyParams['ExportTo']){
            if($AllVoyeurData){
                if($ExportTo -ne "print"){
                    Write-Host "Create report folder...." -ForegroundColor Green
			        $ReportPath = New-Report $ScriptPath $Domain.name
			        Set-Variable -Name Report -Value $ReportPath -Scope Global
			        Write-Host "Report folder created in $Report..." -ForegroundColor Green
                }
                $ExportTo | %{$Output = $_.split(",");
                              Export-ResultQuery -Dataset $AllVoyeurData -ExportTo $Output[0]
                }                
            }
        }       
        
    }
    else{
        throw "Unable to connect..."
    }

    #End main script. Remove Vars
    try{
        remove-item -Path "variable:Report" -Force -ErrorAction SilentlyContinue
        remove-item -Path "variable:DomainName" -Force -ErrorAction SilentlyContinue
        remove-item -Path "variable:Forest" -Force -ErrorAction SilentlyContinue
        remove-item -Path "variable:DomainSID" -Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:RootDomainSID" -Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:credential" -Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:Domain" -Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:UseCredentials" -Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:isConnected" -Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:AllDomainData" -Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:SearchRoot" -Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:UseSSL"-Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:MyPath"-Force -ErrorAction SilentlyContinue
        remove-item -Path "Variable:AuditorName"-Force -ErrorAction SilentlyContinue
        $ObjectData = $null
        $AllData = $null
    }
    catch{
        #Nothing to do here
    }
    #Stop timer
    $stoptimer = Get-Date
    "Total time for JOBs: {0} Minutes" -f [math]::round(($stoptimer – $starttimer).TotalMinutes , 2) 

#}

<#        
Catch
	{
		Write-Host "Voyeur problem...$($_.Exception)" -ForegroundColor Red
	}
#>