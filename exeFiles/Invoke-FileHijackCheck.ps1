$ErrorActionPreference= 'silentlycontinue'
#$ErrorActionPreference= 'continue'

# https://stackoverflow.com/a/24992975
function Test-FileWriteLock {
  param (
    [parameter(Mandatory=$true)][string]$Path
  )

  $oFile = New-Object System.IO.FileInfo $Path

  if ((Test-Path -Path $Path) -eq $false) {
    return $false
  }

  try {
    $oStream = $oFile.Open([System.IO.FileMode]::Open, [System.IO.FileAccess]::ReadWrite, [System.IO.FileShare]::None)

    if ($oStream) {
      $oStream.Close()
    }
    $false
  } catch {
    # file is locked by a process.
    return $true
  }
}

function Test-FileOpenLock() {
    param (
    [parameter(Mandatory=$true)]
    [string]
    $Path
    )

    $relativePath = (split-path -noq $Path).substring(1)
    $res = $(.\handle.exe -nobanner $relativePath)
    if ($res -eq "No matching handles found.") {
        return $false
    }

    return $true
}

function CheckFile() {
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Identity,

        [Parameter(Position = 1, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    $acls = $(acl $Path) | select -ExpandProperty access

    if ($acls) {
        $builtin_users = $(acl $Path | select -ExpandProperty access | Where-Object {$_.identityreference -eq $Identity})
        foreach ($perm in $builtin_users.FileSystemRights) {
            if (($perm -like "*FullControl*") -or
                ($perm -like "*Delete*") -or
                ($perm -like "*Modify*")) {
                return $perm
            }
        }
    }

    return 0
}

function CheckDirectory() {
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Identity,

        [Parameter(Position = 1, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path
    )

    $acls = $(acl $Path) | select -ExpandProperty access

    if ($acls) {
        $builtin_users = $(acl $Path | select -ExpandProperty access | Where-Object {$_.identityreference -eq $Identity})
        foreach ($perm in $builtin_users.FileSystemRights) {
        if (($perm -like "*FullControl*") -or
            ($perm -like "*Write*") -or
            ($perm -like "*CreateFiles*") -or
            ($perm -like "*Modify*")) {
                return $perm
            }
        }
    }

    return 0
}

function Invoke-FileHijackCheck() {
<#

.SYNOPSIS

Simple function to analyze ProcMon CSV output checking for potential Symlink File Hijack to SYSTEM Impersonation Attacks 

Author: Francesco Soncina (phra)
License: BSD 3-Clause

.DESCRIPTION

Simple function to analyze ProcMon CSV output checking for potential Symlink File Hijack to SYSTEM Impersonation Attacks.
It needs "Handle.exe" from SysInternals in the same directory of this script.
To export data from ProcMon, save it in CSV format. (filter by Operation:WriteFile + User:NT AUTHORITY\SYSTEM)

.PARAMETER Csv

The CSV file to read.

.EXAMPLE

Invoke-FileHijackCheck .\Logfile.csv

Analyze CSV file Logfile.csv in the current directory

#>
    [CMDLetBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Csv,

        [switch]
        $ShowOnlyVulnerable
    )

    $paths = type $Csv | convertfrom-csv | Sort-Object -prop path -unique
    $usersToCheck = "NT AUTHORITY\INTERACTIVE",
        "BUILTIN\Users",
        "NT AUTHORITY\Authenticated Users",
        "NT AUTHORITY\LOCAL SERVICE",
        "Everyone",
        $(whoami)

    foreach ($path in $paths) {
        $acls = $(acl $path.Path) | select -ExpandProperty access
        foreach ($user in $usersToCheck) {
            $res = $(CheckFile $user $path.Path)

            if ($res -ne 0) {
                $parent = Split-Path -path $path.Path
                $res2 = $(CheckDirectory $user $parent)
                if ($res2 -ne 0) {
                    if (Test-FileOpenLock $path.Path) {
                        if (-not $ShowOnlyVulnerable) {
                            write-host -nonewline $user " => " $path.Path
                            write-host -ForegroundColor green " [LOCKED]"
                        }
                    } else {
                        write-host -nonewline $user " => " $path.Path
                        write-host -ForegroundColor red " [VULNERABLE!]"
                    }
                }
            }
        }
    }
}
