using System;
using System.IO;

namespace Mkdir
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("WinBinReplacements: mkdir.exe <dir>[/subdir1/subdir2/...] [dir2] [dir3] ...");
                return;
            }
            
            foreach(string arg in args)
            {
                string fullPath = Path.GetFullPath(arg);
                try
                {
                    Directory.CreateDirectory(fullPath);
                }
                catch(UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Error: unauthorized to create directory " + fullPath);
                    continue;
                }
                catch(IOException)
                {
                    Console.WriteLine("[!] Error: IOException when trying to create directory " + fullPath);
                    continue;
                }
                catch(Exception e)
                {
                    Console.WriteLine("[!] Error: unhandled exception when trying to create directory " + fullPath);
                    Console.Write(e);
                    continue;
                }
                // too easy. it practically writes itself.
            }
        }
    }
}
