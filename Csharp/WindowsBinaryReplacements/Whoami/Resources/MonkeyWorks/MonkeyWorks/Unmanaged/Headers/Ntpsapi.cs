using System;
using System.Runtime.InteropServices;

using USHORT = System.UInt16;
using WORD = System.UInt16;

using DWORD = System.UInt32;
using ULONG = System.UInt32;

using QWORD = System.UInt64;
using ULONGLONG = System.UInt64;
using LARGE_INTEGER = System.UInt64;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;
using SIZE_T = System.IntPtr;
using PWSTR = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    class ntpsapi
    {
        //Process Security and Access Rights
        //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        internal const DWORD PROCESS_ALL_ACCESS = 0;
        internal const DWORD PROCESS_CREATE_PROCESS = 0x0080;
        internal const DWORD PROCESS_CREATE_THREAD = 0x0002;
        internal const DWORD PROCESS_DUP_HANDLE = 0x0040;
        internal const DWORD PROCESS_QUERY_INFORMATION = 0x0400;
        internal const DWORD PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
        internal const DWORD PROCESS_SET_INFORMATION = 0x0200;
        internal const DWORD PROCESS_SET_QUOTA = 0x0100;
        internal const DWORD PROCESS_SUSPEND_RESUME = 0x0800;
        internal const DWORD PROCESS_TERMINATE = 0x0001;
        internal const DWORD PROCESS_VM_OPERATION = 0x0008;
        internal const DWORD PROCESS_VM_READ = 0x0010;
        internal const DWORD PROCESS_VM_WRITE = 0x0020;
        internal const DWORD SYNCHRONIZE = 0x00100000;
    }
}