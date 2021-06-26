using System.Runtime.InteropServices;

using DWORD = System.UInt32;

using PVOID = System.IntPtr;
using HANDLE = System.IntPtr;
using ULONG_PTR = System.UIntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    class MinWinBase
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _OVERLAPPED
        {
            public ULONG_PTR Internal;
            public ULONG_PTR InternalHigh;
            public DWORD Offset;
            public DWORD OffsetHigh;
            public PVOID Pointer;
            public HANDLE hEvent;
        }
    }
}
