using System;
using System.Runtime.InteropServices;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using LPCTSTR = System.String;
using LPWSTR = System.Text.StringBuilder;

using PVOID = System.IntPtr;
using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries
{
    sealed class crypt32
    {
        public const UInt32 CRYPTPROTECT_UI_FORBIDDEN = 0x1;
        public const UInt32 CRYPTPROTECT_LOCAL_MACHINE = 0x4;

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CryptStringToBinary(
            LPCTSTR pszString,
            DWORD cchString,
            DWORD dwFlags,
            out IntPtr pbBinary,
            ref DWORD pcbBinary,
            out DWORD pdwSkip,
            out DWORD pdwFlags
        );

        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CryptUnprotectData(
            ref Wincrypt._CRYPTOAPI_BLOB pDataIn,
            LPWSTR ppszDataDescr,
            ref Wincrypt._CRYPTOAPI_BLOB pOptionalEntropy,
            PVOID pvReserved,
            ref Wincrypt._CRYPTPROTECT_PROMPTSTRUCT pPromptStruct,
            DWORD dwFlag,
            ref Wincrypt._CRYPTOAPI_BLOB pDataOut
        );
        
        [DllImport("crypt32.dll", SetLastError = true)]
        public static extern bool CryptUnprotectData(
            ref Wincrypt._CRYPTOAPI_BLOB pDataIn,
            LPWSTR ppszDataDescr,
            IntPtr pOptionalEntropy,
            PVOID pvReserved,
            IntPtr pPromptStruct,
            DWORD dwFlag,
            ref Wincrypt._CRYPTOAPI_BLOB pDataOut
        );
    }
}