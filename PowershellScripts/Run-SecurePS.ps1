function Run-SecurePS
{

Param
    (
        [string]
        $argument
    )

$PPIDSpoofBlock = @"
    using System;
    using System.Diagnostics;
    using System.Runtime.InteropServices;
    
    namespace PleaseNo
    {
        public class EDRBlocks
        {
            public static void Main(params string[] args)
            {
                var startInfoEx = new Win32.STARTUPINFOEX();
                var processInfo = new Win32.PROCESS_INFORMATION();
                
                startInfoEx.StartupInfo.cb = (uint)Marshal.SizeOf(startInfoEx);
    
                var lpValue = Marshal.AllocHGlobal(IntPtr.Size);
    
                try
                {
                    var processSecurity = new Win32.SECURITY_ATTRIBUTES();
                    var threadSecurity = new Win32.SECURITY_ATTRIBUTES();
                    processSecurity.nLength = Marshal.SizeOf(processSecurity);
                    threadSecurity.nLength = Marshal.SizeOf(threadSecurity);
    
                    var lpSize = IntPtr.Zero;
                    Win32.InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref lpSize);
                    startInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                    Win32.InitializeProcThreadAttributeList(startInfoEx.lpAttributeList, 2, 0, ref lpSize);
    
                    Marshal.WriteIntPtr(lpValue, new IntPtr((long)Win32.BinarySignaturePolicy.BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON));
    
                    Win32.UpdateProcThreadAttribute(
                        startInfoEx.lpAttributeList,
                        0,
                        (IntPtr)Win32.ProcThreadAttribute.MITIGATION_POLICY,
                        lpValue,
                        (IntPtr)IntPtr.Size,
                        IntPtr.Zero,
                        IntPtr.Zero
                        );
    
                    Win32.CreateProcess(
                        args[0],
                        args[1],
                        ref processSecurity,
                        ref threadSecurity,
                        false,
                        Win32.CreationFlags.ExtendedStartupInfoPresent | Win32.CreationFlags.CreateNewConsole,
                        IntPtr.Zero,
                        null,
                        ref startInfoEx,
                        out processInfo
                        );
                }
                catch (Exception e)
                {
                    Console.Error.WriteLine(e.StackTrace);
                }
                finally
                {
                    Win32.DeleteProcThreadAttributeList(startInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(startInfoEx.lpAttributeList);
                    Marshal.FreeHGlobal(lpValue);
    
                    Console.WriteLine("New PowerShell with PID {0} started.", processInfo.dwProcessId);
                }
            }
        }
    
        class Win32
        {
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
    
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);
    
            [DllImport("kernel32.dll")]
            public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, CreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
    
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern bool DeleteProcThreadAttributeList(IntPtr lpAttributeList);
    
            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            public struct STARTUPINFO
            {
                public uint cb;
                public IntPtr lpReserved;
                public IntPtr lpDesktop;
                public IntPtr lpTitle;
                public uint dwX;
                public uint dwY;
                public uint dwXSize;
                public uint dwYSize;
                public uint dwXCountChars;
                public uint dwYCountChars;
                public uint dwFillAttributes;
                public uint dwFlags;
                public ushort wShowWindow;
                public ushort cbReserved;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdErr;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            public struct STARTUPINFOEX
            {
                public STARTUPINFO StartupInfo;
                public IntPtr lpAttributeList;
            }
    
            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public IntPtr lpSecurityDescriptor;
                public int bInheritHandle;
            }
    
            [Flags]
            public enum ProcThreadAttribute : int
            {
                MITIGATION_POLICY = 0x20007,
                PARENT_PROCESS = 0x00020000
            }
    
            [Flags]
            public enum BinarySignaturePolicy : ulong
            {
                BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON = 0x100000000000,
                BLOCK_NON_MICROSOFT_BINARIES_ALLOW_STORE = 0x300000000000
            }
    
            [Flags]
            public enum CreationFlags : uint
            {
                CreateSuspended = 0x00000004,
                DetachedProcess = 0x00000008,
                CreateNoWindow = 0x08000000,
                ExtendedStartupInfoPresent = 0x00080000,
                CreateNewConsole = 0x00000010
            }
        }
    }
"@

Add-Type -TypeDefinition $PPIDSpoofBlock
[PleaseNo.EDRBlocks]::Main("C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe","$argument")

}
