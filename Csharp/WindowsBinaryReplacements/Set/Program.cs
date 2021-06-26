using System;
using System.Collections;
using System.Security;

namespace Set
{
    public class Program
    {
       public static void Main(string[] args)
        {
            if ((args.Length > 2) || (args.Length == 1 || args.Length == 2) && (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help"))
            {
                Console.WriteLine("WinBinReplacements: set.exe [variable] [value]");
                return;
            }
            if(args.Length == 0) // We just list the current environment variables then exit
            {
                int longest = 0;
                IDictionary envars = Environment.GetEnvironmentVariables();
                foreach(DictionaryEntry envar in envars)
                {
                    if(envar.Key.ToString().Length > longest)
                    {
                        longest = envar.Key.ToString().Length;
                    }
                }
                Console.WriteLine("Environment Variable" + new string(' ', longest - 17) + "Variable Value");
                Console.WriteLine(new string('=', longest + 17));
                foreach (DictionaryEntry envar in envars)
                {
                    int length = envar.Key.ToString().Length;
                    Console.WriteLine(envar.Key + new string(' ', longest + 3 - length) + envar.Value);
                }
                return;
            }
            else if(args.Length == 1) // Get just a specific environment variable
            {
                string envar = null;
                try
                {
                    envar = Environment.GetEnvironmentVariable(args[0]);
                }
                catch(SecurityException)
                {
                    Console.WriteLine("[!] Error: security exception trying to access variable: " + args[0]);
                    return;
                }
                catch(Exception e)
                {
                    Console.WriteLine("[!] Error: unhandled exception trying to read variable: " + args[0]);
                    Console.WriteLine(e);
                    return;
                }
                if(envar == null)
                {
                    Console.WriteLine("[*] Variable \"" + args[0] + "\" is not set and does not have a value");
                }
                else
                {
                    Console.WriteLine(envar);
                }
            }
            else // Set a variable with new value
            {
                try
                {
                    Environment.SetEnvironmentVariable(args[0], args[1]);
                    Console.WriteLine("[*] Environment variable \"" + args[0] + "\" successfully updated/created (current process only)");
                }
                catch(Exception e)
                {
                    Console.WriteLine("[!] Error: unhandled exception trying to write/create variable: " + args[0]);
                    Console.WriteLine(e);
                }
            }
        }
    }
}
