using System.Runtime.InteropServices;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;
using ULONGLONG = System.UInt64;

using LPCWSTR = System.String;

using HWND = System.IntPtr;
using BYTE = System.IntPtr;
using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;
using SIZE_T = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    sealed class Wincrypt
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _CRYPTOAPI_BLOB 
        {
            public DWORD cbData;
            public BYTE pbData;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _CRYPTPROTECT_PROMPTSTRUCT
        {
            public  DWORD cbSize;
            public  DWORD dwPromptFlags;
            public  HWND hwndApp;
            public  LPCWSTR szPrompt;
        } 
    }
}