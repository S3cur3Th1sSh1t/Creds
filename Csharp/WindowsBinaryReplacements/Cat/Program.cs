using System;
using System.IO;
using System.Security;
using System.Collections;

namespace Cat
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if(args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("WinBinReplacements: cat.exe <file> [file2] [file3] ...");
                return;
            }

            ArrayList fileTexts = new ArrayList();
            foreach(string file in args)
            {
                try
                {
                    fileTexts.Add(File.ReadAllText(file));
                }
                catch(FileNotFoundException)
                {
                    Console.WriteLine("[!] Error: file not found: " + file);
                }
                catch(SecurityException)
                {
                    Console.WriteLine("[!] Error: no permissions to read file: " + file);
                }
                catch(IOException)
                {
                    Console.WriteLine("[!] Error: file could not be read: " + file);
                }
                catch(Exception e)
                {
                    Console.WriteLine("[!] Error: Unexpected error reading file: " + file);
                    Console.WriteLine(e);
                }
            }
            if(fileTexts.Count != 0)
            {
                foreach(string fileText in fileTexts)
                {
                    Console.WriteLine(fileText);
                }
            }
            return;
        }
    }
}
