using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Rm
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("WinBinReplacements: rm.exe <item1> [item2] [item3] ...");
                return;
            }
            foreach (string arg in args)
            {
                string fileOrDir = Path.GetFullPath(arg);
                if (Directory.Exists(fileOrDir))
                {
                    try
                    {
                        DirectoryInfo dir = new DirectoryInfo(fileOrDir);
                        setAttributesNormal(dir);
                        Directory.Delete(fileOrDir, recursive: true);
                        Console.WriteLine("[*] Removed all child items and deleted directory: " + fileOrDir);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("[!] Error: access denied - could not delete directory: " + fileOrDir);
                    }
                    catch (IOException)
                    {
                        Console.WriteLine("[!] Error: IOException - could not delete directory: " + fileOrDir);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Error: Unexpected exception deleting directory: " + fileOrDir);
                        Console.WriteLine(e);
                    }

                }
                else if (File.Exists(fileOrDir))
                {
                    try
                    {
                        // prevent some files from resisting deletion
                        File.SetAttributes(fileOrDir, FileAttributes.Normal);
                        File.Delete(fileOrDir);
                        Console.WriteLine("[*] Deleted file: " + fileOrDir);
                    }
                    catch (UnauthorizedAccessException)
                    {
                        Console.WriteLine("[!] Error: access denied - could not delete file: " + fileOrDir);
                    }
                    catch (IOException)
                    {
                        Console.WriteLine("[!] Error: IOException - could not delete file: " + fileOrDir);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("[!] Error: Unexpected exception deleting file: " + fileOrDir);
                        Console.WriteLine(e);
                    }
                }
                else
                {
                    Console.WriteLine("[!] Error: file or directory does not exist: " + fileOrDir);
                    return;
                }
            }
        }
        private static void setAttributesNormal(DirectoryInfo dir)
        {
            foreach (DirectoryInfo subDir in dir.GetDirectories())
            {
                setAttributesNormal(subDir);
            }
            foreach (FileInfo file in dir.GetFiles())
            {
                file.Attributes = FileAttributes.Normal;
            }
        }
    }
}
