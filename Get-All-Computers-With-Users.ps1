<#
.SYNOPSIS
  Get list of all computers and currently logged on users.
.DESCRIPTION
  This script will query AD for a list of all computers(customizable by $OU variable), then pull currently logged on user from each one using WMI.
  Final output is a table with computer names, creation date and current user.
  Table is exported as CSV in current folder.
.NOTES
  Version:            1.0
  Author:             Daniel Allen
  Last Modified Date: 16.08.2016
.EXAMPLE
  ./Get-All-Computers-With-Users.ps1
#>

$ErrorActionPreference = "SilentlyContinue"

$OU = "OU=Computers,DC=YOUR,DC=DOMAIN,DC=NAME" # OU with computers

$Computers = Get-ADComputer -SearchBase $OU -Filter * -Properties Created

$Array = @()

$Counter = 0

ForEach ($Computer in $Computers) {

  $Counter++

  Write-Progress -Activity "[Processing $Counter of $($Computers.Count)]" -Status "Querying $($Computer.Name)" -PercentComplete (($Counter/$Computers.Count) * 100) -CurrentOperation "$([math]::Round(($Counter/$Computers.Count) * 100))% complete"

  $Username = (Get-WMIObject Win32_ComputerSystem -ComputerName $Computer.Name).UserName

  $Obj = New-Object PSObject
  $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $Computer.Name
  $Obj | Add-Member -MemberType NoteProperty -Name "Created Date" -Value $Computer.Created
  $Obj | Add-Member -MemberType NoteProperty -Name "User" -Value $Username

  $Array += $Obj
}

$Array | Sort-Object -Property Name | Out-GridView

$Array | Sort-Object -Property Name | Export-CSV -Path "All-Computers-With-Users.csv" -NoTypeInformation
