function Start-ProcessAsUser {
<#
.SYNOPSIS

Executes a command using a specified set of credentials.

Author: Matthew Graeber (@mattifestation) with modifications by Lee Christensen (@tifkin_)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

A simple wrapper for advapi32!CreateProcessWithLogonW.  The invoker can perform a normal 
logon or use the NetOnly flag create the process using the LOGON_NETCREDENTIALS_ONLY 
flag. Script is a modified version of Matt Graeber's New-HoneyHash cmdlet.

.PARAMETER Domain

Specifies the domain.

.PARAMETER Username

Specifies the user name.

.PARAMETER Password

Specifies the Password

.PARAMETER Cmd

Specifies the command to execute

.PARAMETER NetOnly

Start the process using the LOGON_NETCREDENTIALS_ONLY flag (equivalent of running "runas.exe /netonly")

.EXAMPLE

Start-ProcessAsUser -Domain corpwest.local -Username itadmin -Password MyPassword -Cmd "powershell.exe -noexit -C get-process"

.EXAMPLE

Start-ProcessAsUser -Domain linux.org -Username root -Password MyPassword -Cmd cmd.exe -NetOnly

.LINK

https://gist.github.com/mattifestation/9c342622f5e23c59fda9

#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $True, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Parameter(Mandatory = $True, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Username,

        [Parameter(Mandatory = $True, Position = 2)]
        [String]
        $Password,

        [Parameter(Mandatory = $True, Position = 3)]
        [String]
        $Cmd,

        [Parameter(Mandatory = $False)]
        [Switch]
        $NetOnly
    )

    $SystemModule = [Microsoft.Win32.IntranetZoneCredentialPolicy].Module
    $NativeMethods = $SystemModule.GetType('Microsoft.Win32.NativeMethods')
    $SafeNativeMethods = $SystemModule.GetType('Microsoft.Win32.SafeNativeMethods')
    $CreateProcessWithLogonW = $NativeMethods.GetMethod('CreateProcessWithLogonW', [Reflection.BindingFlags] 'NonPublic, Static')
    $LogonFlags = $NativeMethods.GetNestedType('LogonFlags', [Reflection.BindingFlags] 'NonPublic')
    $StartupInfo = $NativeMethods.GetNestedType('STARTUPINFO', [Reflection.BindingFlags] 'NonPublic')
    $ProcessInformation = $SafeNativeMethods.GetNestedType('PROCESS_INFORMATION', [Reflection.BindingFlags] 'NonPublic')

    $Flags = [Activator]::CreateInstance($LogonFlags)

    if($NetOnly) {
        $Flags.value__ = 2 # LOGON_NETCREDENTIALS_ONLY
    } else {
        $Flags.value__ = 0
    }

    $StartInfo = [Activator]::CreateInstance($StartupInfo)
    $ProcInfo = [Activator]::CreateInstance($ProcessInformation)

    $PasswordStr = ConvertTo-SecureString $Password -AsPlainText -Force
    $PasswordPtr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($PasswordStr)
    $StrBuilder = New-Object System.Text.StringBuilder
    $null = $StrBuilder.Append($Cmd)

    $Result = $CreateProcessWithLogonW.Invoke($null, @([String] $UserName,
                                             [String] $Domain,
                                             [IntPtr] $PasswordPtr,
                                             ($Flags -as $LogonFlags),     # LOGON_NETCREDENTIALS_ONLY 
                                             $null,
                                             [Text.StringBuilder] $StrBuilder,
                                             0x08000000, # Don't display a window
                                             $null,
                                             $null,
                                             $StartInfo,
                                             $ProcInfo))

    if (-not $Result) {
        throw 'Unable to create process as user.'
    }

    Write-Verbose 'Process created successfully!'
}
