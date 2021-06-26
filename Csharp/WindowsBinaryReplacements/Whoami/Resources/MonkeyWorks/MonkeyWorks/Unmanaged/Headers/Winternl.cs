using System;
using System.Runtime.InteropServices;

using BYTE = System.Byte;
using BOOL = System.Boolean;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using ULONG = System.UInt32;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    sealed class Winternl
    {
        [StructLayout(LayoutKind.Explicit, Size = 8)]
        public struct LARGE_INTEGER
        {
            [FieldOffset(0)]
            public Int64 QuadPart;
            [FieldOffset(0)]
            public UInt32 LowPart;
            [FieldOffset(4)]
            public Int32 HighPart;
        }

        [StructLayout(LayoutKind.Sequential, Pack=1)]
        public struct _LDR_DATA_TABLE_ENTRY
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            PVOID Reserved1;
            _LIST_ENTRY InMemoryOrderLinks;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            PVOID Reserved2;
            PVOID DllBase;
            PVOID EntryPoint;
            PVOID Reserved3;
            Subauth._LSA_UNICODE_STRING FullDllName;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            BYTE Reserved4;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            PVOID Reserved5;
            ULONG CheckSum;
            PVOID Reserved6;
            ULONG TimeDateStamp;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _LIST_ENTRY
        {
            IntPtr Flink;
            IntPtr Blink;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PEB32
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 2)]
            public Byte Reserved1;
            public Byte BeingDebugged;
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 1)]
            public Byte Reserved2;
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 2)]
            public IntPtr Reserved3;
            public IntPtr Ldr; /*_PEB_LDR_DATA*/
            public IntPtr ProcessParameters; /*_RTL_USER_PROCESS_PARAMETERS*/
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 104)]
            public Byte Reserved4;
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 52)]
            public IntPtr Reserved5;
            public IntPtr PostProcessInitRoutine; /*_PS_POST_PROCESS_INIT_ROUTINE*/
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 128)]
            public Byte Reserved6;
            [MarshalAs(UnmanagedType.LPArray, SizeConst = 1)]
            public IntPtr Reserved7;
            public UInt32 SessionId;
        }

        //http://bytepointer.com/resources/peb64.htm
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PEB64
        {
            public BYTE InheritedAddressSpace;
            public BYTE ReadImageFileExecOptions;
            public BYTE BeingDebugged;
            public BYTE BitField;

            public UInt32 Reserved3;
            public IntPtr Mutant;
            public IntPtr ImageBaseAddress;
            public IntPtr Ldr;
            public IntPtr ProcessParameters;
            public IntPtr SubSystemData;
            public IntPtr ProcessHeap;
            public IntPtr FastPebLock;

            public IntPtr AtlThunkSListPtr;
            public IntPtr IFEOKey;
            public UInt64 CrossProcessFlags;
            public IntPtr KernelCallbackTable;

            //public  QWORD UserSharedInfoPtr;
            public UInt32 SystemReserved;
            public UInt32 AtlThunkSListPtr32;
            public IntPtr ApiSetMap;
            public UInt32 TlsExpansionCounter;
            public IntPtr TlsBitmap;
            [MarshalAs(UnmanagedType.U4, SizeConst = 2)]
            public UInt32 TlsBitmapBits;
            public IntPtr ReadOnlySharedMemoryBase;
            public IntPtr HotpatchInformation;
            public IntPtr ReadOnlyStaticServerData;
            public IntPtr AnsiCodePageData;
            public IntPtr OemCodePageData;
            public IntPtr UnicodeCaseTableData;
            public UInt32 NumberOfProcessors;
            public UInt32 NtGlobalFlag;
            //public  DWORD dummy02;
            public Int64 /*LARGE_INTEGER*/ CriticalSectionTimeout;
            public QWORD HeapSegmentReserve;
            public QWORD HeapSegmentCommit;
            public QWORD HeapDeCommitTotalFreeThreshold;
            public QWORD HeapDeCommitFreeBlockThreshold;
            public DWORD NumberOfHeaps;
            public DWORD MaximumNumberOfHeaps;
            public QWORD ProcessHeaps;
            public QWORD GdiSharedHandleTable;
            public QWORD ProcessStarterHelper;
            public QWORD GdiDCAttributeList;
            public QWORD LoaderLock;
            public DWORD OSMajorVersion;
            public DWORD OSMinorVersion;
            public WORD OSBuildNumber;
            public WORD OSCSDVersion;
            public DWORD OSPlatformId;
            public DWORD ImageSubsystem;
            public DWORD ImageSubsystemMajorVersion;
            public QWORD ImageSubsystemMinorVersion;
            public QWORD ImageProcessAffinityMask;
            public QWORD ActiveProcessAffinityMask;
            [MarshalAs(UnmanagedType.U8, SizeConst = 30)]
            public QWORD GdiHandleBuffer;
            public QWORD PostProcessInitRoutine;
            public QWORD TlsExpansionBitmap;
            [MarshalAs(UnmanagedType.U4, SizeConst = 32)]
            public DWORD TlsExpansionBitmapBits;
            public QWORD SessionId;
            public UInt64 /*ULARGE_INTEGER*/ AppCompatFlags;
            public UInt64 /*ULARGE_INTEGER*/ AppCompatFlagsUser;
            public QWORD pShimData;
            public QWORD AppCompatInfo;
            public Subauth._LSA_UNICODE_STRING CSDVersion;
            public QWORD ActivationContextData;
            public QWORD ProcessAssemblyStorageMap;
            public QWORD SystemDefaultActivationContextData;
            public QWORD SystemAssemblyStorageMap;
            public QWORD MinimumStackCommit;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct _PEB_LDR_DATA
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            Byte Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 3)]
            IntPtr Reserved2;
            _LIST_ENTRY InMemoryOrderModuleList;
        }

        [StructLayout(LayoutKind.Sequential, Pack=1)]
        public struct _RTL_USER_PROCESS_PARAMETERS
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            BYTE Reserved1;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)]
            PVOID Reserved2;
            Subauth._LSA_UNICODE_STRING ImagePathName;
            Subauth._LSA_UNICODE_STRING CommandLine;
        }
    }
}