using System;
using System.Runtime.InteropServices;

using WORD = System.UInt16;
using LONG = System.UInt32;
using DWORD = System.UInt32;
using QWORD = System.UInt64;
using ULONGLONG = System.UInt64;
using LARGE_INTEGER = System.UInt64;

using PSID = System.IntPtr;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;
using SIZE_T = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    sealed class Winnt
    {
        //Token 
        //http://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
        public const DWORD STANDARD_RIGHTS_REQUIRED = 0x000F0000;
        public const DWORD STANDARD_RIGHTS_READ = 0x00020000;
        public const DWORD TOKEN_ASSIGN_PRIMARY = 0x0001;
        public const DWORD TOKEN_DUPLICATE = 0x0002;
        public const DWORD TOKEN_IMPERSONATE = 0x0004;
        public const DWORD TOKEN_QUERY = 0x0008;
        public const DWORD TOKEN_QUERY_SOURCE = 0x0010;
        public const DWORD TOKEN_ADJUST_PRIVILEGES = 0x0020;
        public const DWORD TOKEN_ADJUST_GROUPS = 0x0040;
        public const DWORD TOKEN_ADJUST_DEFAULT = 0x0080;
        public const DWORD TOKEN_ADJUST_SESSIONID = 0x0100;
        public const DWORD TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        public const DWORD TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
            TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
            TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
            TOKEN_ADJUST_SESSIONID);
        public const DWORD TOKEN_ALT = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);

        //TOKEN_PRIVILEGES
        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
        public const DWORD SE_PRIVILEGE_ENABLED = 0x2;
        public const DWORD SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1;
        public const DWORD SE_PRIVILEGE_REMOVED = 0x4;
        public const DWORD SE_PRIVILEGE_USED_FOR_ACCESS = 0x3;

        public const Int32 ANYSIZE_ARRAY = 1;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446619(v=vs.85).aspx
        public const String SE_ASSIGNPRIMARYTOKEN_NAME = "SeAssignPrimaryTokenPrivilege";
        public const String SE_BACKUP_NAME = "SeBackupPrivilege";
        public const String SE_DEBUG_NAME = "SeDebugPrivilege";
        public const String SE_INCREASE_QUOTA_NAME = "SeIncreaseQuotaPrivilege";
        public const String SE_TCB_NAME = "SeTcbPrivilege";

        public const QWORD SE_GROUP_ENABLED = 0x00000004L;
        public const QWORD SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
        public const QWORD SE_GROUP_INTEGRITY = 0x00000020L;
        public const QWORD SE_GROUP_INTEGRITY_32 = 0x00000020;
        public const QWORD SE_GROUP_INTEGRITY_ENABLED = 0x00000040L;
        public const QWORD SE_GROUP_LOGON_ID = 0xC0000000L;
        public const QWORD SE_GROUP_MANDATORY = 0x00000001L;
        public const QWORD SE_GROUP_OWNER = 0x00000008L;
        public const QWORD SE_GROUP_RESOURCE = 0x20000000L;
        public const QWORD SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010L;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446583%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        public const DWORD DISABLE_MAX_PRIVILEGE = 0x1;
        public const DWORD SANDBOX_INERT = 0x2;
        public const DWORD LUA_TOKEN = 0x4;
        public const DWORD WRITE_RESTRICTED = 0x8;

        private const DWORD EXCEPTION_MAXIMUM_PARAMETERS = 15;

        [Flags]
        // https://msdn.microsoft.com/en-us/library/windows/desktop/aa366786(v=vs.85).aspx
        public enum MEMORY_PROTECTION_CONSTANTS : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
            PAGE_TARGETS_INVALID = 0x40000000,
            PAGE_TARGETS_NO_UPDATE = 0x40000000
        }

        [Flags]
        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630(v=vs.85).aspx
        public enum TokenPrivileges : uint
        {
            SE_PRIVILEGE_NONE = 0x0,
            SE_PRIVILEGE_ENABLED_BY_DEFAULT = 0x1,
            SE_PRIVILEGE_ENABLED = 0x2,
            SE_PRIVILEGE_REMOVED = 0x4,
            SE_PRIVILEGE_USED_FOR_ACCESS = 0x3
        }

        [Flags]
        public enum ACCESS_MASK : uint
        {
            DELETE = 0x00010000,
            READ_CONTROL = 0x00020000,
            WRITE_DAC = 0x00040000,
            WRITE_OWNER = 0x00080000,
            SYNCHRONIZE = 0x00100000,
            STANDARD_RIGHTS_REQUIRED = 0x000F0000,
            STANDARD_RIGHTS_READ = 0x00020000,
            STANDARD_RIGHTS_WRITE = 0x00020000,
            STANDARD_RIGHTS_EXECUTE = 0x00020000,
            STANDARD_RIGHTS_ALL = 0x001F0000,
            SPECIFIC_RIGHTS_ALL = 0x0000FFF,
            ACCESS_SYSTEM_SECURITY = 0x01000000,
            MAXIMUM_ALLOWED = 0x02000000,
            GENERIC_READ = 0x80000000,
            GENERIC_WRITE = 0x40000000,
            GENERIC_EXECUTE = 0x20000000,
            GENERIC_ALL = 0x10000000,
            DESKTOP_READOBJECTS = 0x00000001,
            DESKTOP_CREATEWINDOW = 0x00000002,
            DESKTOP_CREATEMENU = 0x00000004,
            DESKTOP_HOOKCONTROL = 0x00000008,
            DESKTOP_JOURNALRECORD = 0x00000010,
            DESKTOP_JOURNALPLAYBACK = 0x00000020,
            DESKTOP_ENUMERATE = 0x00000040,
            DESKTOP_WRITEOBJECTS = 0x00000080,
            DESKTOP_SWITCHDESKTOP = 0x00000100,
            WINSTA_ENUMDESKTOPS = 0x00000001,
            WINSTA_READATTRIBUTES = 0x00000002,
            WINSTA_ACCESSCLIPBOARD = 0x00000004,
            WINSTA_CREATEDESKTOP = 0x00000008,
            WINSTA_WRITEATTRIBUTES = 0x00000010,
            WINSTA_ACCESSGLOBALATOMS = 0x00000020,
            WINSTA_EXITWINDOWS = 0x00000040,
            WINSTA_ENUMERATE = 0x00000100,
            WINSTA_READSCREEN = 0x00000200,
            WINSTA_ALL_ACCESS = 0x0000037F
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT
        {
            public CONTEXT_FLAGS ContextFlags;
            // Retrieved by CONTEXT_DEBUG_REGISTERS 
            public uint Dr0;
            public uint Dr1;
            public uint Dr2;
            public uint Dr3;
            public uint Dr6;
            public uint Dr7;
            // Retrieved by CONTEXT_FLOATING_POINT 
            public _FLOATING_SAVE_AREA FloatSave;
            // Retrieved by CONTEXT_SEGMENTS 
            public uint SegGs;
            public uint SegFs;
            public uint SegEs;
            public uint SegDs;
            // Retrieved by CONTEXT_INTEGER 
            public uint Edi;
            public uint Esi;
            public uint Ebx;
            public uint Edx;
            public uint Ecx;
            public uint Eax;
            // Retrieved by CONTEXT_CONTROL 
            public uint Ebp;
            public uint Eip;
            public uint SegCs;
            public uint EFlags;
            public uint Esp;
            public uint SegSs;
            // Retrieved by CONTEXT_EXTENDED_REGISTERS 
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
            public byte[] ExtendedRegisters;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct CONTEXT64
        {
            public ulong P1Home;
            public ulong P2Home;
            public ulong P3Home;
            public ulong P4Home;
            public ulong P5Home;
            public ulong P6Home;

            public CONTEXT_FLAGS64 ContextFlags;
            public uint MxCsr;

            public ushort SegCs;
            public ushort SegDs;
            public ushort SegEs;
            public ushort SegFs;
            public ushort SegGs;
            public ushort SegSs;
            public uint EFlags;

            public ulong Dr0;
            public ulong Dr1;
            public ulong Dr2;
            public ulong Dr3;
            public ulong Dr6;
            public ulong Dr7;

            public ulong Rax;
            public ulong Rcx;
            public ulong Rdx;
            public ulong Rbx;
            public ulong Rsp;
            public ulong Rbp;
            public ulong Rsi;
            public ulong Rdi;
            public ulong R8;
            public ulong R9;
            public ulong R10;
            public ulong R11;
            public ulong R12;
            public ulong R13;
            public ulong R14;
            public ulong R15;

            public ulong Rip;

            public _XMM_SAVE_AREA32 FltSave;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 26)]
            public _M128A[] VectorRegister;
            public ulong VectorControl;

            public ulong DebugControl;
            public ulong LastBranchToRip;
            public ulong LastBranchFromRip;
            public ulong LastExceptionToRip;
            public ulong LastExceptionFromRip;
        }

        [Flags]
        public enum CONTEXT_FLAGS : uint
        {
            CONTEXT_i386 = 0x10000,
            CONTEXT_i486 = 0x10000,   //  same as i386
            CONTEXT_CONTROL = CONTEXT_i386 | 0x0001, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_i386 | 0x0002, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_i386 | 0x0004, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_i386 | 0x0008, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_i386 | 0x0010, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_i386 | 0x0020, // cpu specific extensions
            CONTEXT_FULL = 65543,//CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = 65599//CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        [Flags]
        public enum CONTEXT_FLAGS64 : uint
        {
            CONTEXT_AMD64 = 0x100000,
            CONTEXT_CONTROL = CONTEXT_AMD64 | 0x01, // SS:SP, CS:IP, FLAGS, BP
            CONTEXT_INTEGER = CONTEXT_AMD64 | 0x02, // AX, BX, CX, DX, SI, DI
            CONTEXT_SEGMENTS = CONTEXT_AMD64 | 0x04, // DS, ES, FS, GS
            CONTEXT_FLOATING_POINT = CONTEXT_AMD64 | 0x08, // 387 state
            CONTEXT_DEBUG_REGISTERS = CONTEXT_AMD64 | 0x10, // DB 0-3,6,7
            CONTEXT_EXTENDED_REGISTERS = CONTEXT_AMD64 | 0x20, // cpu specific extensions
            CONTEXT_FULL = 1048587,//CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS,
            CONTEXT_ALL = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS | CONTEXT_EXTENDED_REGISTERS
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _EXCEPTION_POINTERS
        {
            public System.IntPtr ExceptionRecord;
            public System.IntPtr ContextRecord;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _EXCEPTION_RECORD
        {
            public DWORD ExceptionCode;
            public DWORD ExceptionFlags;
            public System.IntPtr hExceptionRecord;
            public PVOID ExceptionAddress;
            public DWORD NumberParameters;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 15)]
            public DWORD[] ExceptionInformation;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _FLOATING_SAVE_AREA
        {
            public DWORD ControlWord;
            public DWORD StatusWord;
            public DWORD TagWord;
            public DWORD ErrorOffset;
            public DWORD ErrorSelector;
            public DWORD DataOffset;
            public DWORD DataSelector;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 80)]
            public byte[] RegisterArea;
            public DWORD Cr0NpxState;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_BASE_RELOCATION
        {
            public DWORD VirtualAdress;
            public DWORD SizeOfBlock;
        }

        [Flags]
        public enum TypeOffset : ushort
        {
            IMAGE_REL_BASED_ABSOLUTE = 0,
            IMAGE_REL_BASED_HIGH = 1,
            IMAGE_REL_BASED_LOW = 2,
            IMAGE_REL_BASED_HIGHLOW = 3,
            IMAGE_REL_BASED_HIGHADJ = 4,
            IMAGE_REL_BASED_MIPS_JMPADDR = 5,
            IMAGE_REL_BASED_ARM_MOV32A = 5,
            IMAGE_REL_BASED_ARM_MOV32 = 5,
            IMAGE_REL_BASED_SECTION = 6,
            IMAGE_REL_BASED_REL = 7,
            IMAGE_REL_BASED_ARM_MOV32T = 7,
            IMAGE_REL_BASED_THUMB_MOV32 = 7,
            IMAGE_REL_BASED_MIPS_JMPADDR16 = 9,
            IMAGE_REL_BASED_IA64_IMM64 = 9,
            IMAGE_REL_BASED_DIR64 = 10,
            IMAGE_REL_BASED_HIGH3ADJ = 11
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_DATA_DIRECTORY
        {
            public DWORD VirtualAddress;
            public DWORD Size;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        //https://www.nirsoft.net/kernel_struct/vista/IMAGE_DOS_HEADER.html
        public struct _IMAGE_DOS_HEADER
        {
            public WORD e_magic;
            public WORD e_cblp;
            public WORD e_cp;
            public WORD e_crlc;
            public WORD e_cparhdr;
            public WORD e_minalloc;
            public WORD e_maxalloc;
            public WORD e_ss;
            public WORD e_sp;
            public WORD e_csum;
            public WORD e_ip;
            public WORD e_cs;
            public WORD e_lfarlc;
            public WORD e_ovno;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public WORD[] e_res;
            public WORD e_oemid;
            public WORD e_oeminfo;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            public WORD[] e_res2;
            public LONG e_lfanew;
        };

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        //https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_nt_headers
        public struct _IMAGE_NT_HEADERS
        {
            public DWORD Signature;
            public _IMAGE_FILE_HEADER FileHeader;
            public _IMAGE_OPTIONAL_HEADER OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_NT_HEADERS64
        {
            public DWORD Signature;
            public _IMAGE_FILE_HEADER FileHeader;
            public _IMAGE_OPTIONAL_HEADER64 OptionalHeader;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        //https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_file_header
        public struct _IMAGE_FILE_HEADER
        {
            public IMAGE_FILE_MACHINE Machine;
            public WORD NumberOfSections;
            public DWORD TimeDateStamp;
            public DWORD PointerToSymbolTable;
            public DWORD NumberOfSymbols;
            public WORD SizeOfOptionalHeader;
            public CHARACTERISTICS Characteristics;
        }

        [Flags]
        public enum IMAGE_FILE_MACHINE : ushort
        {
            IMAGE_FILE_MACHINE_I386 = 0x014c,
            IMAGE_FILE_MACHINE_IA64 = 0x0200,
            IMAGE_FILE_MACHINE_AMD64 = 0x8664,
        }

        [Flags]
        public enum CHARACTERISTICS : ushort
        {
            IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
            IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
            IMAGE_FILE_LINE_NUMS_STRIPPED = 0x0004,
            IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x0008,
            IMAGE_FILE_AGGRESIVE_WS_TRIM = 0x0010,
            IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
            IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
            IMAGE_FILE_32BIT_MACHINE = 0x0100,
            IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
            IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0400,
            IMAGE_FILE_NET_RUN_FROM_SWAP = 0x0800,
            IMAGE_FILE_SYSTEM = 0x1000,
            IMAGE_FILE_DLL = 0x2000,
            IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
            IMAGE_FILE_BYTES_REVERSED_HI = 0x8000
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        //https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_optional_header
        public struct _IMAGE_OPTIONAL_HEADER
        {
            public MAGIC Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public DWORD SizeOfCode;
            public DWORD SizeOfInitializedData;
            public DWORD SizeOfUninitializedData;
            public DWORD AddressOfEntryPoint;
            public DWORD BaseOfCode;
            public DWORD BaseOfData;
            public DWORD ImageBase;
            public DWORD SectionAlignment;
            public DWORD FileAlignment;
            public WORD MajorOperatingSystemVersion;
            public WORD MinorOperatingSystemVersion;
            public WORD MajorImageVersion;
            public WORD MinorImageVersion;
            public WORD MajorSubsystemVersion;
            public WORD MinorSubsystemVersion;
            public DWORD Win32VersionValue;
            public DWORD SizeOfImage;
            public DWORD SizeOfHeaders;
            public DWORD CheckSum;
            public SUBSYSTEM Subsystem;
            public DLL_CHARACTERISTICS DllCharacteristics;
            public DWORD SizeOfStackReserve;
            public DWORD SizeOfStackCommit;
            public DWORD SizeOfHeapReserve;
            public DWORD SizeOfHeapCommit;
            public DWORD LoaderFlags;
            public DWORD NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public Winnt._IMAGE_DATA_DIRECTORY[] ImageDataDirectory;
        };

        //https://docs.microsoft.com/en-us/windows/desktop/api/winnt/ns-winnt-_image_optional_header
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_OPTIONAL_HEADER64
        {
            public MAGIC Magic;
            public Byte MajorLinkerVersion;
            public Byte MinorLinkerVersion;
            public DWORD SizeOfCode;
            public DWORD SizeOfInitializedData;
            public DWORD SizeOfUninitializedData;
            public DWORD AddressOfEntryPoint;
            public DWORD BaseOfCode;
            public ULONGLONG ImageBase;
            public DWORD SectionAlignment;
            public DWORD FileAlignment;
            public WORD MajorOperatingSystemVersion;
            public WORD MinorOperatingSystemVersion;
            public WORD MajorImageVersion;
            public WORD MinorImageVersion;
            public WORD MajorSubsystemVersion;
            public WORD MinorSubsystemVersion;
            public DWORD Win32VersionValue;
            public DWORD SizeOfImage;
            public DWORD SizeOfHeaders;
            public DWORD CheckSum;
            public SUBSYSTEM Subsystem;
            public DLL_CHARACTERISTICS DllCharacteristics;
            public ULONGLONG SizeOfStackReserve;
            public ULONGLONG SizeOfStackCommit;
            public ULONGLONG SizeOfHeapReserve;
            public ULONGLONG SizeOfHeapCommit;
            public DWORD LoaderFlags;
            public DWORD NumberOfRvaAndSizes;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public Winnt._IMAGE_DATA_DIRECTORY[] ImageDataDirectory;
        };

        [Flags]
        public enum MAGIC : ushort
        {
            IMAGE_NT_OPTIONAL_HDR_MAGIC = 0x00,
            IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
            IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b,
            IMAGE_ROM_OPTIONAL_HDR_MAGIC = 0x107
        }

        [Flags]
        public enum SUBSYSTEM : ushort
        {
            //IMAGE_SUBSYSTEM_UNKNOWN = 0,
            IMAGE_SUBSYSTEM_NATIVE = 1,
            IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
            IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
            IMAGE_SUBSYSTEM_OS2_CUI = 5,
            IMAGE_SUBSYSTEM_POSIX_CUI = 7,
            IMAGE_SUBSYSTEM_WINDOWS_CE_GUI = 9,
            IMAGE_SUBSYSTEM_EFI_APPLICATION = 10,
            IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER = 11,
            IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER = 12,
            IMAGE_SUBSYSTEM_EFI_ROM = 13,
            IMAGE_SUBSYSTEM_XBOX = 14,
            IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION = 16
        }

        [Flags]
        public enum DLL_CHARACTERISTICS : ushort
        {
            Reserved1 = 0x0001,
            Reserved2 = 0x0002,
            Reserved4 = 0x0004,
            Reserved8 = 0x0008,
            IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE = 0x0040,
            IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
            IMAGE_DLLCHARACTERISTICS_NX_COMPAT = 0x0100,
            IMAGE_DLLCHARACTERISTICS_NO_ISOLATION = 0x0200,
            IMAGE_DLLCHARACTERISTICS_NO_SEH = 0x0400,
            IMAGE_DLLCHARACTERISTICS_NO_BIND = 0x0800,
            Reserved1000 = 0x1000,
            IMAGE_DLLCHARACTERISTICS_WDM_DRIVER = 0x2000,
            Reserved4000 = 0x4000,
            IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _IMAGE_SECTION_HEADER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public Char[] Name;
            public DWORD VirtualSize;
            public DWORD VirtualAddress;
            public DWORD SizeOfRawData;
            public DWORD PointerToRawData;
            public DWORD PointerToRelocations;
            public DWORD PointerToLinenumbers;
            public WORD NumberOfRelocations;
            public WORD NumberOfLinenumbers;
            public DWORD Characteristics;
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct _LUID
        {
            public DWORD LowPart;
            public DWORD HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LUID_AND_ATTRIBUTES
        {
            public _LUID Luid;
            public DWORD Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _M128A
        {
            public UInt64 High;
            public Int64 Low;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _MEMORY_BASIC_INFORMATION
        {
            public DWORD BaseAddress;
            public DWORD AllocationBase;
            public DWORD AllocationProtect;
            public DWORD RegionSize;
            public DWORD State;
            public DWORD Protect;
            public DWORD Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _MEMORY_BASIC_INFORMATION64
        {
            public ULONGLONG BaseAddress;
            public ULONGLONG AllocationBase;
            public DWORD AllocationProtect;
            public DWORD __alignment1;
            public ULONGLONG RegionSize;
            public DWORD State;
            public MEMORY_PROTECTION_CONSTANTS Protect;
            public DWORD Type;
            public DWORD __alignment2;
        }

        //https://msdn.microsoft.com/en-us/library/ms809762.aspx
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct _IMAGE_IMPORT_DESCRIPTOR
        {
            public DWORD Characteristics;
            public DWORD TimeDateStamp;
            public DWORD ForwarderChain;
            public DWORD Name;
            public DWORD FirstThunk;
        }

        public const Int32 PRIVILEGE_SET_ALL_NECESSARY = 1;

        [StructLayout(LayoutKind.Sequential)]
        public struct _PRIVILEGE_SET
        {
            public DWORD PrivilegeCount;
            public DWORD Control;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = (Int32)ANYSIZE_ARRAY)]
            public _LUID_AND_ATTRIBUTES[] Privilege;
        }
        //PRIVILEGE_SET, * PPRIVILEGE_SET


        [StructLayout(LayoutKind.Sequential)]
        public struct _SID_AND_ATTRIBUTES
        {
            public PSID Sid;
            public DWORD Attributes;
        }
        //SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES


        [StructLayout(LayoutKind.Sequential)]
        public struct _SID_AND_ATTRIBUTES_MIDL
        {
            public Ntifs._SID Sid;
            public DWORD Attributes;
        }
        //SID_AND_ATTRIBUTES, *PSID_AND_ATTRIBUTES

        [Flags]
        public enum _SECURITY_IMPERSONATION_LEVEL : int
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3
        };

        [StructLayout(LayoutKind.Sequential)]
        public struct _SID_IDENTIFIER_AUTHORITY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 6, ArraySubType = UnmanagedType.I1)]
            public Byte[] Value;
        }

        [Flags]
        public enum _SID_NAME_USE
        {
            SidTypeUser = 1,
            SidTypeGroup,
            SidTypeDomain,
            SidTypeAlias,
            SidTypeWellKnownGroup,
            SidTypeDeletedAccount,
            SidTypeInvalid,
            SidTypeUnknown,
            SidTypeComputer,
            SidTypeLabel
        }

        [Flags]
        public enum TOKEN_ELEVATION_TYPE
        {
            TokenElevationTypeDefault = 1,
            TokenElevationTypeFull,
            TokenElevationTypeLimited
        }

        [Flags]
        public enum _TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            MaxTokenInfoClass
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_MANDATORY_LABEL
        {
            public _SID_AND_ATTRIBUTES Label;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_PRIVILEGES
        {
            public UInt32 PrivilegeCount;
            public _LUID_AND_ATTRIBUTES Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_PRIVILEGES_ARRAY
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
            public _LUID_AND_ATTRIBUTES[] Privileges;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct _TOKEN_STATISTICS
        {
            public Winnt._LUID TokenId;
            public Winnt._LUID AuthenticationId;
            public LARGE_INTEGER ExpirationTime;
            public _TOKEN_TYPE TokenType;
            public _SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
            public DWORD DynamicCharged;
            public DWORD DynamicAvailable;
            public DWORD GroupCount;
            public DWORD PrivilegeCount;
            public Winnt._LUID ModifiedId;
        }

        [Flags]
        public enum _TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _XMM_SAVE_AREA32
        {
            public WORD ControlWord;
            public WORD StatusWord;
            public byte TagWord;
            public byte Reserved1;
            public WORD ErrorOpcode;
            public DWORD ErrorOffset;
            public WORD ErrorSelector;
            public WORD Reserved2;
            public DWORD DataOffset;
            public WORD DataSelector;
            public WORD Reserved3;
            public WORD MxCsr;
            public WORD MxCsr_Mask;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public _M128A[] FloatRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public _M128A[] XmmRegisters;

            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 96)]
            public byte[] Reserved4;
        }
    }
}