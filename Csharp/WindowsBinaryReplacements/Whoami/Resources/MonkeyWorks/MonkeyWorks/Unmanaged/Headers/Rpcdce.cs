using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Headers
{
    class Rpcdce
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct _GUID
        {
            internal Int32 Data1;
            internal Int16 Data2;
            internal Int16 Data3;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            internal Byte[] Data4;
        }
    }
}