using System;
using System.IO;
using System.Linq;

namespace Ls
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if(args.Length > 1)
            {
                Console.WriteLine("WinBinReplacements: ls.exe [path]");
                return;
            }
            else if(args.Length == 1 && (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help"))
            {
                Console.WriteLine("WinBinReplacements: ls.exe [path]");
                return;
            }

            string dir = Directory.GetCurrentDirectory();
            string[] files = null;
            string[] subdirs = null;
            long biggestFileSize = 0;
            int sizeCharLength = 4; //Minimum size of "Size" column is 4 since must be at least as long as "Size "
            int biggestOwnerSize = 9; // "<Unknown>" is 9 chars
            if (args.Length == 1)
            {
                dir = args[0];
            }
            try
            {
                files = Directory.GetFiles(dir);
                subdirs = Directory.GetDirectories(dir);
                Console.WriteLine("\n  Directory listing of " + dir + "\n");
            }
            catch(DirectoryNotFoundException)
            {
                Console.WriteLine("[!] Error: directory does not exist: " + dir);
                return;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Error: no permissions to read directory: " + dir);
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error: unhandled exception listing directory: " + dir);
                Console.WriteLine(e);
                return;
            }

            string[] dirContents = files.Concat(subdirs).ToArray();
            Array.Sort(dirContents);
            if (dirContents == null)
            {
                Console.WriteLine("[*] The directory " + dir + " is empty!");
            }
            else
            {
                //Getting sizes of strings that need to be printed so the data can be formatted in a neat table
                foreach(string file in files)
                {
                    long fileSize = new FileInfo(file).Length;
                    if (fileSize > biggestFileSize)
                    {
                        biggestFileSize = fileSize;
                    }
                    if(sizeCharLength < biggestFileSize.ToString().Length)
                    {
                        sizeCharLength = biggestFileSize.ToString().Length;
                    } 
                }
                foreach(string item in dirContents)
                {
                    try
                    {
                        if (File.GetAccessControl(item).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString().Length > biggestOwnerSize)
                        {
                            biggestOwnerSize = File.GetAccessControl(item).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString().Length;
                        }
                    }
                    catch { }

                }

                Console.WriteLine("Last Modify      Type     " + "Owner" + new string(' ', biggestOwnerSize - 5) + "   Size" + new string(' ', sizeCharLength - 4) + "   File/Dir Name");
                Console.WriteLine("==============   ======   " + new string('=', biggestOwnerSize) + "   " + new string('=', sizeCharLength) + "   =============");
                foreach (string item in dirContents)
                {
                    string relativepath = Path.GetFileName(item);
                    DateTime lastWriteDate = File.GetLastWriteTime(item);
                    string lastWrite = String.Format("{0:MM/dd/yy HH:mm}", lastWriteDate);
                    string owner;
                    try
                    {
                        owner = File.GetAccessControl(item).GetOwner(typeof(System.Security.Principal.NTAccount)).ToString();
                    }
                    catch
                    {
                        owner = "<Unknown>";
                    }

                    if (files.Contains(item)) // item is a file
                    {
                        var fileSize = new FileInfo(item).Length;
                        Console.WriteLine(lastWrite + "   <File>   " + owner + new string(' ', biggestOwnerSize - owner.ToString().Length) + "   " + fileSize + new string(' ', sizeCharLength - fileSize.ToString().Length) + "   " + relativepath);
                    }
                    else // item is a directory
                    {
                        Console.WriteLine(lastWrite + "   <Dir>    " + owner + new string(' ', biggestOwnerSize - owner.ToString().Length) + "   " + new string('.', sizeCharLength) + "   " + relativepath);
                    }
                    
                }
            }
            return;
        }
    }
}
