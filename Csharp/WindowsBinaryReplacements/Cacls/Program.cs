using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Principal;

namespace Cacls
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("WinBinReplacements: cacls.exe <file> [file2] [file3] ...");
                return;
            }
            foreach(string arg in args)
            {
                string fullPath = Path.GetFullPath(arg); // if the user specifies a path with bad chars here they can go fuck themself. No try catch for you.
                AuthorizationRuleCollection authRules = null;
                if (Directory.Exists(fullPath))
                {
                    try
                    {
                        DirectorySecurity securityInfo = Directory.GetAccessControl(fullPath);
                        authRules = securityInfo.GetAccessRules(true, true, typeof(NTAccount));
                    }
                    catch(UnauthorizedAccessException)
                    {
                        Console.WriteLine("[!] Error: unauthorized to read permissions of: " + fullPath);
                        continue;
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine("[!] Error: unhandled exception trying to read permissions of: " + fullPath);
                        Console.WriteLine(e);
                        continue;
                    }
                }

                else if(File.Exists(fullPath))
                {
                    try
                    {
                        FileSecurity securityInfo = File.GetAccessControl(fullPath);
                        authRules = securityInfo.GetAccessRules(true, true, typeof(NTAccount));
                    }
                    catch(UnauthorizedAccessException)
                    {
                        Console.WriteLine("[!] Error: unauthorized to read permissions of: " + fullPath);
                        continue;
                    }
                    catch(Exception e)
                    {
                        Console.WriteLine("[!] Error: unhandled exception trying to read permissions of: " + fullPath);
                        Console.WriteLine(e);
                        continue;
                    }
                }

                else
                {
                    Console.WriteLine("[!] Error: file/dir does not exist: " + fullPath);
                    continue; // Go next if the current file doesn't exist
                }

                int longest = 0;
                foreach (AuthorizationRule authRule in authRules)
                {
                    if(authRule.IdentityReference.Value.Length > longest)
                    {
                        longest = authRule.IdentityReference.Value.Length;
                    }
                }

                Console.WriteLine("\nPermissions of: " + fullPath);
                Console.WriteLine(new string('=', fullPath.Length + 16));

                foreach (AuthorizationRule authRule in authRules)
                {
                    int userLen = authRule.IdentityReference.Value.Length;
                    FileSystemAccessRule accessRule = authRule as FileSystemAccessRule;
                    Console.WriteLine(authRule.IdentityReference.Value + new string(' ', longest - userLen + 3) + accessRule.FileSystemRights);
                }
            }
        }
    }
}
