using System;
using System.Runtime.InteropServices;

namespace MonkeyWorks.Unmanaged.Libraries
{
    class secur32
    {
        [DllImport("secur32.dll")]
        public static extern UInt32 LsaGetLogonSessionData(
            IntPtr LogonId,
            out IntPtr ppLogonSessionData
        );
    }
}