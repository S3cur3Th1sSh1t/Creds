using System.Runtime.InteropServices;

using PSID = System.IntPtr;

using UCHAR = System.Byte;
using ULONG = System.Int32;

//https://blogs.technet.microsoft.com/fabricem_blogs/2009/07/21/active-directory-maximum-limits-scalability/

namespace MonkeyWorks.Unmanaged.Headers
{
    class Ntifs
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _SID
        {
            public UCHAR Revision;
            public UCHAR SubAuthorityCount;
            public Winnt._SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public ULONG[] SubAuthority;
        }
        //SID, *PISID


        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_GROUPS
        {
            public ULONG GroupCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 230)]
            public Winnt._SID_AND_ATTRIBUTES[] Groups;
        }
        //TOKEN_GROUPS, *PTOKEN_GROUPS


        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_OWNER
        {
            public PSID Owner;
        }
        //TOKEN_OWNER, *PTOKEN_OWNER


        [StructLayout(LayoutKind.Sequential)]
        public struct _TOKEN_USER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public Winnt._SID_AND_ATTRIBUTES[] User;
        } 
        //TOKEN_USER, *PTOKEN_USER
    }
}