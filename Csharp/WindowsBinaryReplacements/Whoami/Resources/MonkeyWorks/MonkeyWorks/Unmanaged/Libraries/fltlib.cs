using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries
{
    class fltlib
    {
        [DllImport("FltLib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern UInt32 FilterDetach(String lpFilterName, String lpVolumeName, String lpInstanceName);

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterInstanceFindClose(IntPtr hFilterInstanceFind);

        [DllImport("FltLib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern UInt32 FilterInstanceFindFirst(
            String lpFilterName,
            FltUserStructures._INSTANCE_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            ref UInt32 lpBytesReturned,
            ref IntPtr lpFilterInstanceFind
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterInstanceFindNext(
            IntPtr hFilterInstanceFind,
            FltUserStructures._INSTANCE_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            ref UInt32 lpBytesReturned
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterFindClose(IntPtr hFilterFind);

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterFindFirst(
            FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            ref UInt32 lpBytesReturned,
            ref IntPtr lpFilterFind
        );

        [DllImport("FltLib.dll", SetLastError = true)]
        public static extern UInt32 FilterFindNext(
            IntPtr hFilterFind,
            FltUserStructures._FILTER_INFORMATION_CLASS dwInformationClass,
            IntPtr lpBuffer,
            UInt32 dwBufferSize,
            out UInt32 lpBytesReturned
        );

        [DllImport("FltLib.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern UInt32 FilterUnload(String lpFilterName);
    }
}
