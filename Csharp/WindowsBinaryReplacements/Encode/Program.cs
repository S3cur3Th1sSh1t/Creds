using System;
using System.IO;
using System.Linq;

namespace Encode
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length == 0 || args.Length > 3 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("WinBinReplacements: encode.exe <file> [-o outfile]");
                return;
            }
            string outfile = null;
            string infile = null;
            string encodedData = null;

            if(args.Contains("-o"))
            {
                try
                {
                    outfile = args[Array.FindIndex(args, x => x.Contains("-o")) + 1]; // next item after the -o
                }
                catch
                {
                    Console.WriteLine("[!] Error: no output file specified");
                    return;
                }
            }
            foreach(string arg in args)
            {

                if(arg != "-o" && arg != outfile)
                {
                    infile = arg; //it's the other arg that isn't one of the 2 above
                }
            }
            if (infile == null)
            {
                Console.WriteLine("[!] Error: no input file specified");
                return;
            }
            string fullpath = Path.GetFullPath(infile);
            if (!File.Exists(fullpath))
            {
                Console.WriteLine("[!] Error: input file does not exist: " + fullpath);
                return;
            }
            byte[] data;
            try
            {
                data = File.ReadAllBytes(fullpath);    
            }
            catch(UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Error: unauthorized to read file: " + fullpath);
                return;
            }
            catch(Exception e)
            {
                Console.WriteLine("[!] Error: unhandled exception trying to read file: " + fullpath);
                Console.WriteLine(e);
                return;
            }
            if(outfile != null)
            {
                string outFileFull = Path.GetFullPath(outfile);
                try
                {
                    encodedData = Convert.ToBase64String(data);
                    File.WriteAllText(outFileFull, encodedData);
                    Console.WriteLine("[*] Encoded data written to output file: " + outFileFull);
                }
                catch(UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Error: unauthorized to write to file: " + outFileFull);
                    return;
                }
                catch(Exception e)
                {
                    Console.WriteLine("[!] Error: unhandled exception trying to write to file: " + outFileFull);
                    Console.WriteLine(e);
                    return;
                }
            }
            else
            {
                try
                {
                    encodedData = Convert.ToBase64String(data);
                    Console.WriteLine(encodedData);
                }
                catch
                {
                    Console.WriteLine("[!] Error: could not encode the data inside " + fullpath);
                }
            }
        }
    }
}
