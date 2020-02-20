$parser = @"
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Diagnostics.Eventing.Reader;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.Security.Principal;
using System.IO;

namespace EventLogParser
{
    public class EventLogHelpers
    {

        #region Static Variable Definitions

        static string[] powershellLogs = { "Microsoft-Windows-PowerShell/Operational", "Windows PowerShell" };
        public static Dictionary<string, Delegate> supportedEventIds = new Dictionary<string, Delegate>()
        {
            { "4104", new Action<string, string>(Parse4104Events) },
            { "4103", new Action(Parse4103Events) },
            { "4688", new Action(Parse4688Events) },
        };

        #endregion

        #region Regex Definitions

        static Regex[] powershellRegex =
        {
            new Regex(@"(New-Object.*System.Management.Automation.PSCredential.*)", RegexOptions.IgnoreCase & RegexOptions.Multiline),
            new Regex(@"(net(.exe)? user.*)", RegexOptions.IgnoreCase & RegexOptions.Multiline),
            new Regex(@"(ConvertTo-SecureString.*AsPlainText.*)", RegexOptions.IgnoreCase & RegexOptions.Multiline),
            new Regex(@"(cmdkey(.exe)?.*/pass:.*)", RegexOptions.IgnoreCase & RegexOptions.Multiline),
            new Regex(@"(ssh(.exe)?.*-i .*)", RegexOptions.IgnoreCase & RegexOptions.Multiline)
        };

        static Regex[] processCmdLineRegex =
        {
            new Regex(@"(net(.exe)? user.*)", RegexOptions.IgnoreCase),
            new Regex(@"(cmdkey(.exe)?.*/pass:.*)", RegexOptions.IgnoreCase),
            new Regex(@"(ssh(.exe)?.*-i .*)", RegexOptions.IgnoreCase)
        };
        #endregion

        #region Helper Functions

        static EventLogQuery GetEventLog(string logName, int eventId, PathType pathType=PathType.LogName)
        {
            string query = String.Format("*[System/EventID={0}]", eventId);
            EventLogQuery eventLogQuery = new EventLogQuery(logName, pathType, query);
            eventLogQuery.ReverseDirection = true;
            return eventLogQuery;
        }

        public static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }

        #endregion

        #region Event Log Parsing Functions

        public static void Parse4104Events(string outFile = "", string context = "")
        {
            if (context != "")
            {
                int result = 0;
                int.TryParse(context, out result);
                if (result == 0)
                {
                    Console.WriteLine("[X] Error: Could not parse context given: {0}", context);
                    Console.WriteLine("[X] Exiting.");
                    Environment.Exit(1);
                }
                Parse4104Events(outFile, int.Parse(context));
            }
            Parse4104Events(outFile, int.Parse(context));
        }

        public static void Parse4104Events(string outFile = "", int context = 3)
        {
            // Properties[2] contains the scriptblock
            int eventId = 4104;
            Console.WriteLine("[*] Parsing PowerShell {0} event logs...", eventId);
            System.IO.StreamWriter streamWriter = null;
            if (outFile != "")
            {
                try
                {
                    streamWriter = new System.IO.StreamWriter(outFile);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[X] Error: Could not open {0} for writing.", outFile);
                    Console.WriteLine("[X] Reason: {0}", ex.Message);
                }
            }
            foreach (string logName in powershellLogs)
            {
                EventLogQuery eventLogQuery = GetEventLog(logName, eventId);
                EventLogReader logReader = new EventLogReader(eventLogQuery);
                for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                {
                    string scriptBlock = eventdetail.Properties[2].Value.ToString();
                    foreach (Regex reg in powershellRegex)
                    {
                        Match m = reg.Match(scriptBlock);
                        if (m.Success)
                        {
                            Console.WriteLine();
                            Console.WriteLine("[+] Regex Match: {0}", m.Value);
                            if (streamWriter != null)
                            {
                                streamWriter.WriteLine(scriptBlock);
                            }
                            string[] scriptBlockParts = scriptBlock.Split('\n');
                            for (int i = 0; i < scriptBlockParts.Length; i++)
                            {
                                if (scriptBlockParts[i].Contains(m.Value))
                                {
                                    Console.WriteLine("[+] Regex Context:");
                                    int printed = 0;
                                    for (int j = 1; i - j > 0 && printed < context; j++)
                                    {
                                        if (scriptBlockParts[i - j].Trim() != "")
                                        {
                                            Console.WriteLine("\t{0}", scriptBlockParts[i - j].Trim());
                                            printed++;
                                        }
                                    }
                                    printed = 0;
                                    Console.WriteLine("\t{0}", m.Value.Trim());
                                    for (int j = 1; printed < context && i + j < scriptBlockParts.Length; j++)
                                    {
                                        if (scriptBlockParts[i + j].Trim() != "")
                                        {
                                            Console.WriteLine("\t{0}", scriptBlockParts[i + j].Trim());
                                            printed++;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Cleanup
            if (streamWriter != null)
            {
                streamWriter.Close();
                Console.WriteLine("[*] Wrote all script blocks to {0}", outFile);
            }
        }

        public static void Parse4103Events()
        {
            int eventId = 4103;
            char[] separator = { '=' };
            Dictionary<string, HashSet<string>> results = new Dictionary<string, HashSet<string>>();
            Console.WriteLine("[*] Parsing PowerShell {0} event logs...", eventId);
            foreach (string logName in powershellLogs)
            {
                EventLogQuery eventLogQuery = GetEventLog(logName, eventId);
                EventLogReader logReader = new EventLogReader(eventLogQuery);
                for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
                {
                    string[] eventAttributeLines = eventdetail.Properties[0].Value.ToString().Split('\n');
                    string username = "";
                    string scriptName = "";
                    foreach (string attr in eventAttributeLines)
                    {
                        if (attr.Contains("Script Name ="))
                        {
                            scriptName = attr.Split(separator, 2)[1].Trim();
                        }
                        else if (attr.Contains("User =") && !attr.Contains("Connected User ="))
                        {
                            username = attr.Split(separator, 2)[1].Trim();
                        }
                        if (username != "" && scriptName != "")
                        {
                            break;
                        }
                    }
                    if (!results.ContainsKey(username))
                    {
                        results[username] = new HashSet<string>();
                    }
                    results[username].Add(scriptName);
                }
            }
            foreach (string username in results.Keys)
            {
                if (results[username].Count > 0)
                {
                    Console.WriteLine("[+] {0} loaded modules:", username);
                    foreach (string script in results[username])
                    {
                        Console.WriteLine("\t{0}", script);
                    }
                }
            }
        }

        public static void Parse4688Events()
        {
            if (!IsHighIntegrity())
            {
                Console.WriteLine("[X] Error: To parse 4688 Event Logs, you need to be in high integrity.");
                Console.WriteLine("[X] Exiting.");
                Environment.Exit(1);
            }
            int eventId = 4688;
            Console.WriteLine("[*] Parsing {0} Process Creation event logs...", eventId);
            string logName = "Security";
            HashSet<string> results = new HashSet<string>();
            EventLogQuery eventLogQuery = GetEventLog(logName, eventId);
            EventLogReader logReader = new EventLogReader(eventLogQuery);
            for (EventRecord eventdetail = logReader.ReadEvent(); eventdetail != null; eventdetail = logReader.ReadEvent())
            {
                // Properties[8]
                string commandLine = eventdetail.Properties[8].Value.ToString().Trim();
                if (commandLine != "")
                {
                    Console.WriteLine(commandLine);
                    foreach (Regex reg in processCmdLineRegex)
                    {
                        Match m = reg.Match(commandLine);
                        if (m.Success)
                        {
                            results.Add(commandLine);
                        }
                    }
                }
            }

            foreach(string cmd in results)
            {
                Console.WriteLine("[+] {0}", cmd);
            }
        }

        #endregion
    }
}
"@

Add-Type -TypeDefinition $parser -Language CSharp
