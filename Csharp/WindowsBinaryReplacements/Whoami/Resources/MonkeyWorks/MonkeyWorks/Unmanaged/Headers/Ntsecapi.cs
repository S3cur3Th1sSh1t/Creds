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
    class ntsecapi
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _LSA_UNICODE_STRING
        {
            public USHORT Length;
            public USHORT MaximumLength;
            public PWSTR Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _LSA_LAST_INTER_LOGON_INFO
        {
            public LARGE_INTEGER LastSuccessfulLogon;
            public LARGE_INTEGER LastFailedLogon;
            public ULONG FailedAttemptCountSinceLastSuccessfulLogon;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _SECURITY_LOGON_SESSION_DATA
        {
            public ULONG Size;
            public Winnt._LUID LogonId;
            public _LSA_UNICODE_STRING UserName;
            public _LSA_UNICODE_STRING LogonDomain;
            public _LSA_UNICODE_STRING AuthenticationPackage;
            public ULONG LogonType;
            public ULONG Session;
            public IntPtr Sid;
            public LARGE_INTEGER LogonTime;
            public _LSA_UNICODE_STRING LogonServer;
            public _LSA_UNICODE_STRING DnsDomainName;
            public _LSA_UNICODE_STRING Upn;
            /*
            public ULONG UserFlags;
            public _LSA_LAST_INTER_LOGON_INFO LastLogonInfo;
            public _LSA_UNICODE_STRING LogonScript;
            public _LSA_UNICODE_STRING ProfilePath;
            public _LSA_UNICODE_STRING HomeDirectory;
            public _LSA_UNICODE_STRING HomeDirectoryDrive;
            public LARGE_INTEGER LogoffTime;
            public LARGE_INTEGER KickOffTime;
            public LARGE_INTEGER PasswordLastSet;
            public LARGE_INTEGER PasswordCanChange;
            public LARGE_INTEGER PasswordMustChange;
            */ 
        }
    }
}