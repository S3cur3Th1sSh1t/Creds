function gzipcompress
{

Param
    (
        [string]
        $inputfile,
	    [switch]
        $folder
)
$gzip = @"
using System;
using System.IO;
using System.IO.Compression;

namespace gzbase64
{
    public class Program
    {
        public static byte[] Compress(byte[] data)
        {
            using (var compressedStream = new MemoryStream())
            using (var zipStream = new GZipStream(compressedStream, CompressionMode.Compress))
            {
                zipStream.Write(data, 0, data.Length);
                zipStream.Close();
                return compressedStream.ToArray();
            }
        }

        public static string base64_encode(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            return Convert.ToBase64String(data);
        }

        public static void Main(string[] args)
        {
            if (args == null || args.Length == 0 || args.Length > 1)
            {
                Console.WriteLine("Usage: " + System.AppDomain.CurrentDomain.FriendlyName + " <path/to/file>");
            }
            else
            {
                string fileName = args[0];
                byte[] file = File.ReadAllBytes(fileName);
                byte[] compress = Compress(file);
                string encoded = base64_encode(compress);
                Console.WriteLine(encoded);
            }
        }
    }
}

"@
Add-Type -TypeDefinition $gzip -Language CSharp

if ($folder)
{
    $Files = Get-Childitem -Path $inputfile -File
    $fullname = $Files.FullName
    foreach($file in $fullname)
    {
        Write-Host "Encrypting $file"
        $outfile = $File + "gzipbase64.txt"

        $OldConsoleOut = [Console]::Out
        $StringWriter = New-Object IO.StringWriter
        [Console]::SetOut($StringWriter)
        
        [gzbase64.Program]::Main("$file")
    
        [Console]::SetOut($OldConsoleOut)
        $Results = $StringWriter.ToString()
        $Results | out-file $outfile
     
    }
    Write-Host "Check."
    Write-Host -ForegroundColor yellow "Results Written to the same folder"
}
else
{
    Write-Host "Encrypting $inputfile"
    $outfile = $inputfile + "gzipbase64.txt"
    
    $OldConsoleOut = [Console]::Out
    $StringWriter = New-Object IO.StringWriter
    [Console]::SetOut($StringWriter) 
    
    [gzbase64.Program]::Main("$inputfile")

    [Console]::SetOut($OldConsoleOut)
    $Results = $StringWriter.ToString()
    $Results | out-file $outfile
    Write-Host "Result Written to $outfile"
}

}

