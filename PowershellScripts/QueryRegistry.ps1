function Get-SubfoldersWithProtectValue {
    param (
        [string]$registryPath
    )

    $key = Get-Item -LiteralPath $registryPath

    foreach ($subkeyName in $key.GetSubKeyNames()) {
        $subkeyPath = Join-Path $registryPath $subkeyName
        $subkey = Get-Item -LiteralPath $subkeyPath

        $protectValue = $subkey.GetValue("Protect", $null)

        if ($protectValue -ne $null -and $protectValue -eq 0) {
            Write-Output "Subfolder: $subkeyName"
        }

        # Recursively call the function for subkeys
        Get-SubfoldersWithProtectValue -registryPath $subkeyPath
    }
}

# Specify the registry path
$registryPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'

# Call the function
Get-SubfoldersWithProtectValue -registryPath $registryPath
