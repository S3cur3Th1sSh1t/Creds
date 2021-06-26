using System;
using System.Runtime.InteropServices;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

using ULONG = System.UInt32;
using ULONG32 = System.UInt32;
using ULONG64 = System.UInt64;

using BOOL = System.Boolean;

namespace MonkeyWorks.Unmanaged.Headers
{
    sealed class Minidumpapiset
    {
        [Flags]
        public enum _MINIDUMP_TYPE
        {
            MiniDumpNormal = 0x00000000,
            MiniDumpWithDataSegs = 0x00000001,
            MiniDumpWithFullMemory = 0x00000002,
            MiniDumpWithHandleData = 0x00000004,
            MiniDumpFilterMemory = 0x00000008,
            MiniDumpScanMemory = 0x00000010,
            MiniDumpWithUnloadedModules = 0x00000020,
            MiniDumpWithIndirectlyReferencedMemory = 0x00000040,
            MiniDumpFilterModulePaths = 0x00000080,
            MiniDumpWithProcessThreadData = 0x00000100,
            MiniDumpWithPrivateReadWriteMemory = 0x00000200,
            MiniDumpWithoutOptionalData = 0x00000400,
            MiniDumpWithFullMemoryInfo = 0x00000800,
            MiniDumpWithThreadInfo = 0x00001000,
            MiniDumpWithCodeSegs = 0x00002000,
            MiniDumpWithoutAuxiliaryState = 0x00004000,
            MiniDumpWithFullAuxiliaryState = 0x00008000,
            MiniDumpWithPrivateWriteCopyMemory = 0x00010000,
            MiniDumpIgnoreInaccessibleMemory = 0x00020000,
            MiniDumpWithTokenInformation = 0x00040000,
            MiniDumpWithModuleHeaders = 0x00080000,
            MiniDumpFilterTriage = 0x00100000,
            MiniDumpValidTypeFlags = 0x001fffff
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _MINIDUMP_CALLBACK_INFORMATION
        {
            public bool CallbackRoutine;
            public PVOID CallbackParam;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _MINIDUMP_EXCEPTION_INFORMATION
        {
            public DWORD ThreadId;
            public System.IntPtr ExceptionPointers;
            public BOOL ClientPointers;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _MINIDUMP_USER_STREAM
        {
            public ULONG32 Type;
            public ULONG BufferSize;
            public PVOID Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _MINIDUMP_USER_STREAM_INFORMATION
        {
            public ULONG UserStreamCount;
            public _MINIDUMP_USER_STREAM UserStreamArray;
        }
    }
}