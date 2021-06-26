using System;
using System.Runtime.InteropServices;

using LONG = System.Int32;

namespace MonkeyWorks.Unmanaged.Headers
{
    sealed class Windef
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct tagPOINT
        {
            public LONG x;
            public LONG y;
        }
    }
}