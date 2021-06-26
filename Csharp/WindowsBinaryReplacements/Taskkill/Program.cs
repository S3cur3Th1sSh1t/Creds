using System;
using System.Diagnostics;
using System.ComponentModel;
using System.Linq;

namespace Taskkill
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("WinBinReplacements: taskkill.exe <ProcessName|PID> [ProcessName|PID] [ProcessName|PID] ...");
                return;
            }
            foreach(string arg in args)
            {
                int.TryParse(arg, out int pid); // who thought it was a good idea to put the output variable as an input parameter
                if(pid != 0)
                {
                    Process process = null;
                    try
                    {
                        process = Process.GetProcessById(pid);
                    }
                    catch(ArgumentException)
                    {
                        Console.WriteLine("[!] Error: No processes running with PID: " + arg);
                        continue;
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine("[!] Error: unhandled exception getting handle on PID: " + arg);
                        Console.WriteLine(e);
                        continue;
                    }

                    try
                    {
                        process.Kill();
                        Console.WriteLine("[*] Killed process " + process.Id + " (" + process.ProcessName + ")");
                    }
                    catch(Win32Exception)
                    {
                        Console.WriteLine("Error: could not kill process by process ID: " + pid + " (" + process.ProcessName + "). You probably don't have permission.");
                        continue;
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine("Error: unhandled exception killing process by process ID: " + pid + " (Name: " + process.ProcessName + ")");
                        Console.WriteLine(e);
                        continue;
                    }
                }
                else // process(es) by name
                {
                    string name = arg;
                    if(arg.EndsWith(".exe"))
                    {
                        name = String.Concat(arg.Reverse().Skip(4).Reverse()); // just wanna remove the .exe at the end :(
                    }
                    Process[] processes = Process.GetProcessesByName(name);
                    if(processes.Length == 0)
                    {
                        Console.WriteLine("[!] Error: no process exists with name: " + arg);
                        continue;
                    }
                    foreach(Process process in processes)
                    {
                        try
                        {
                            process.Kill();
                            Console.WriteLine("[*] Killed process " + process.Id + " (" + process.ProcessName + ")");
                        }
                        catch(Win32Exception)
                        {
                            Console.WriteLine("[!] Error: could not kill process by name: " + process.ProcessName + " (PID: " + process.Id + "). You might not have permission.");
                            continue;
                        }
                        catch(Exception e)
                        {
                            Console.WriteLine("Error: unhandled exception killing process by name: " + process.ProcessName + " (PID: " + process.Id + ")");
                            Console.WriteLine(e);
                            continue;
                        }
                    }
                }
            }
        }
    }
}
