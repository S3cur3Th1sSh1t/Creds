// see https://www.mdsec.co.uk/2020/08/massaging-your-clr-preventing-environment-exit-in-in-process-net-assemblies/
using System;
using System.Reflection;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace test
{
    public class Program
    {        
        public struct MEMORY_BASIC_INFORMATION
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public AllocationProtectEnum AllocationProtect;
            public IntPtr RegionSize;
            public StateEnum State;
            public AllocationProtectEnum Protect;
            public TypeEnum Type;
        }

        public enum AllocationProtectEnum : uint
        {
            PAGE_EXECUTE = 0x00000010,
            PAGE_EXECUTE_READ = 0x00000020,
            PAGE_EXECUTE_READWRITE = 0x00000040,
            PAGE_EXECUTE_WRITECOPY = 0x00000080,
            PAGE_NOACCESS = 0x00000001,
            PAGE_READONLY = 0x00000002,
            PAGE_READWRITE = 0x00000004,
            PAGE_WRITECOPY = 0x00000008,
            PAGE_GUARD = 0x00000100,
            PAGE_NOCACHE = 0x00000200,
            PAGE_WRITECOMBINE = 0x00000400
        }

        public enum StateEnum : uint
        {
            MEM_COMMIT = 0x1000,
            MEM_FREE = 0x10000,
            MEM_RESERVE = 0x2000
        }

        public enum TypeEnum : uint
        {
            MEM_IMAGE = 0x1000000,
            MEM_MAPPED = 0x40000,
            MEM_PRIVATE = 0x20000
        }

        [DllImport("kernel32.dll")]
        static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, IntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        public static void Main(string[] args)
        {
            var methods = new List<MethodInfo>(typeof(Environment).GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic));
            var exitMethod = methods.Find((MethodInfo mi) => mi.Name == "Exit");

            RuntimeHelpers.PrepareMethod(exitMethod.MethodHandle);
            var exitMethodPtr = exitMethod.MethodHandle.GetFunctionPointer();

            Console.ReadKey();

            unsafe
            {
                IntPtr target = exitMethod.MethodHandle.GetFunctionPointer();

                MEMORY_BASIC_INFORMATION mbi;

                if (VirtualQueryEx((IntPtr)(-1), target, out mbi, (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION))) != 0)
                {
                    if (mbi.Protect == AllocationProtectEnum.PAGE_EXECUTE_READ)
                    {
                        // seems to be executable code
                        uint flOldProtect;

                        if (VirtualProtectEx((IntPtr)(-1), (IntPtr)target, (IntPtr)1, (uint)AllocationProtectEnum.PAGE_EXECUTE_READWRITE, out flOldProtect))
                        {
                            *(byte*)target = 0xc3; // ret

                            VirtualProtectEx((IntPtr)(-1), (IntPtr)target, (IntPtr)1, flOldProtect, out flOldProtect);
                        }
                    }
                }
            }
        // original code with Environment.Exit(0) here
    }
}
