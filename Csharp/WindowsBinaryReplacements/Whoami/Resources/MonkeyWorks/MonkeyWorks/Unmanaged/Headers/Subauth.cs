using System.Runtime.InteropServices;

using USHORT = System.UInt16;

using PWSTR = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    sealed class Subauth
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct _LSA_UNICODE_STRING
        {
            public USHORT Length;
            public USHORT MaximumLength;
            public PWSTR Buffer;
        }
    }
}