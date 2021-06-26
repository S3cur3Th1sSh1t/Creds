using System;
using System.IO;

namespace Cp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length != 2 || (args.Length == 2 && (args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")))
            {
                Console.WriteLine("WinBinReplacements: cp.exe <source> <destination>");
                return;
            }

            // Handle errors such as file doesn't exist or no permissions
            string source = Path.GetFullPath(args[0]);
            string dest = Path.GetFullPath(args[1]);
            bool overwrite = false;
            if(!CheckParams(source, dest))
            {
                return;
            }

            if (Directory.Exists(dest))
            {
                // User specified <file> <directory> so we need to append the file name to the dest directory
                dest = Path.Combine(dest, Path.GetFileName(source));
            }
            if (Directory.Exists(source))
            {
                if(DirectoryCopy(source, dest, copySubDirs: true))
                {
                    Console.WriteLine("[*] Copied directory " + source + " and all contents to " + dest);
                }
                return;
            }

            if (File.Exists(dest))
            {
                overwrite = true;
            }
            try
            {
                File.Copy(source, dest, overwrite: true);
                if(overwrite == true)
                {
                    Console.WriteLine("[*] Overwriting the destination file: " + dest);
                }
                Console.WriteLine("[*] File successfully copied from " + source + " to " + dest);
            }
            catch(UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Error: permission denied during copy operation");
            }
            catch(Exception e)
            {
                Console.WriteLine("[!] Error: Unexpected exception during copy");
                Console.WriteLine(e);
            }
        }
        private static bool CheckParams(string s, string d)
        {
            string source = Path.GetFullPath(s);
            string dest = Path.GetFullPath(d);
            FileAttributes fatributes;
            try
            {
                fatributes = File.GetAttributes(source);
            }
            catch (FileNotFoundException)
            {
                Console.WriteLine("[!] Error: source file not found: " + source);
                return false;
            }
            catch (DirectoryNotFoundException)
            {
                Console.WriteLine("[!] Error: source directory not found: " + source);
                return false;
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Error: not authorized to access: " + source);
                return false;
            }
            catch (IOException)
            {
                Console.WriteLine("[!] Error: the source file is locked by another process: " + source);
                return false;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error: unexpected exception with source: " + source);
                Console.WriteLine(e);
                return false;
            }
            return true;
        }
        // Taken from MSDN (https://docs.microsoft.com/en-us/dotnet/standard/io/how-to-copy-directories?redirectedfrom=MSDN)
        private static bool DirectoryCopy(string sourceDirName, string destDirName, bool copySubDirs)
        {
            // Get the subdirectories for the specified directory.
            DirectoryInfo dir = new DirectoryInfo(sourceDirName);

            if (!dir.Exists)
            {
                throw new DirectoryNotFoundException("[!] Error: source directory does not exist or could not be found: " + sourceDirName);
            }

            DirectoryInfo[] dirs = dir.GetDirectories();
            // If the destination directory doesn't exist, create it.
            if (!Directory.Exists(destDirName))
            {
                try
                {
                    Directory.CreateDirectory(destDirName);
                }
                catch(UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Error: unauthorized to create destination directory: " + destDirName);
                    return false;
                }
            }

            // Get the files in the directory and copy them to the new location.
            FileInfo[] files = dir.GetFiles();
            foreach (FileInfo file in files)
            {
                string temppath = Path.Combine(destDirName, file.Name);
                try
                {
                    file.CopyTo(temppath, overwrite: true);
                }
                catch(UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Error: unauthorized to copy file " + file.Name + " to destination");
                }
                catch(Exception e)
                {
                    Console.WriteLine("[!] Error: unexpected exception when copying file: " + file.Name);
                    Console.WriteLine(e);
                }
                
            }

            // If copying subdirectories, copy them and their contents to new location.
            if (copySubDirs)
            {
                foreach (DirectoryInfo subdir in dirs)
                {
                    string temppath = Path.Combine(destDirName, subdir.Name);
                    DirectoryCopy(subdir.FullName, temppath, copySubDirs);
                }
            }
            return true;
        }
    }
}
