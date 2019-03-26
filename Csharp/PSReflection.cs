// Author: Lee Christensen
// License: BSD 3-Clause

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;

namespace RandomCSharp
{
    public class Program
    {
        public static MethodInfo GetMethod(MethodInfo[] methods, string Name)
        {
            foreach (var method in methods)
            {
                if (method.Name == Name)
                {
                    return method;
                }
            }
            return null;
        }

        public static void Main(string[] args)
        {
            Console.WriteLine("PID: " + Process.GetCurrentProcess().Id);
            string command = @"[System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms'); [System.Windows.Forms.MessageBox]::Show('Pop pop!');";

            var AutomationDllByets = File.ReadAllBytes(@"C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0__31bf3856ad364e35\System.Management.Automation.dll");
            var AutomationAssembly = Assembly.Load(AutomationDllByets);

            Type PowerShellClassType = AutomationAssembly.GetType("System.Management.Automation.PowerShell");
            var PublicStaticMethods = PowerShellClassType.GetMethods((BindingFlags.Public | BindingFlags.Static));
            var PublicMethods = PowerShellClassType.GetMethods((BindingFlags.Public | BindingFlags.Instance));

            var CreateMethod = GetMethod(PublicStaticMethods, "Create");
            var AddScriptMethod = GetMethod(PublicMethods, "AddScript");
            var InvokeMethod = GetMethod(PublicMethods, "Invoke");

            var PowerShellInstance = CreateMethod.Invoke(PowerShellClassType, new object[] { });

            AddScriptMethod.Invoke(PowerShellInstance, new object[] { command });
            InvokeMethod.Invoke(PowerShellInstance, new object[] { });
        }
    }
}
