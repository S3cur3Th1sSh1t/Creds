using System;
using System.IO;
using System.Linq;

namespace Decode
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length == 0 || args.Length > 3 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("WinBinReplacements: decode.exe <file> [-o outfile]");
                return;
            }
            string outfile = null;
            string infile = null;
            string decodedText = null;
            string text;
            byte[] data = null;
            char[] cArray;

            if (args.Contains("-o"))
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
            foreach (string arg in args)
            {
                if (arg != "-o" && arg != outfile)
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
            try
            {
                text = File.ReadAllText(fullpath);
            }
            catch (UnauthorizedAccessException)
            {
                Console.WriteLine("[!] Error: unauthorized to read file: " + fullpath);
                return;
            }
            catch (Exception e)
            {
                Console.WriteLine("[!] Error: unhandled exception trying to read file: " + fullpath);
                Console.WriteLine(e);
                return;
            }
            if (outfile != null)
            {
                string outFileFull = Path.GetFullPath(outfile);
                try
                {
                    data = Convert.FromBase64String(text);
                    File.WriteAllBytes(outFileFull, data);
                    Console.WriteLine("[*] Decoded data written to output file: " + outFileFull);
                }
                catch (UnauthorizedAccessException)
                {
                    Console.WriteLine("[!] Error: unauthorized to write to file: " + outFileFull);
                    return;
                }
                catch (Exception e)
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
                    data = Convert.FromBase64String(text);
                }
                catch
                {
                    Console.WriteLine("[!] Error: data inside file is not valid base64: " + fullpath);
                    return;
                }
                try
                {
                    cArray = System.Text.Encoding.UTF8.GetChars(data);
                    decodedText = new string(cArray);
                    Console.WriteLine(decodedText);
                }
                catch
                {
                    try
                    {
                        cArray = System.Text.Encoding.Unicode.GetChars(data);
                        decodedText = new string(cArray);
                        Console.WriteLine(decodedText);
                    }
                    catch
                    {
                        Console.WriteLine("[*] Decoded data is binary - not displaying to console");
                    }
                }
            }
        }
    }
}
