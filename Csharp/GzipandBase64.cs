//Use to generate the KatzCompressed string in PELoaderofMimikatz.cs
//Complie:
//C:\Windows\Microsoft.NET\Framework64\v3.5\csc.exe GzipandBase64.cs
//or
//C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe GzipandBase64.cs
using System;
using System.IO;
using System.IO.Compression;
namespace GzipandBase64
{
    class Program
    {
	static byte[] Compress(byte[] raw)
        {
            using (MemoryStream memory = new MemoryStream())
            {
                using (GZipStream gzip = new GZipStream(memory,
                CompressionMode.Compress, true))
                {
                    gzip.Write(raw, 0, raw.Length);
                }
                return memory.ToArray();
            }
        }        
	static void Main(string[] args)
        {
            byte[] AsBytes = File.ReadAllBytes(@"mimikatz.exe");
            byte[] compress = Compress(AsBytes);

            String AsBase64String = Convert.ToBase64String(compress);
            StreamWriter sw = new StreamWriter(@"base64.txt");
            sw.Write(AsBase64String);
            sw.Close();
        }
    }
}
