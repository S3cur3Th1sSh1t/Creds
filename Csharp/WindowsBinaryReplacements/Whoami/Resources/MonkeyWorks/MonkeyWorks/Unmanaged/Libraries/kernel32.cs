using System;
using System.Runtime.InteropServices;
using System.Text;

using MonkeyWorks.Unmanaged.Headers;

namespace MonkeyWorks.Unmanaged.Libraries
{
    sealed class kernel32
    {
        public const UInt32 PROCESS_CREATE_THREAD = 0x0002;
        public const UInt32 PROCESS_QUERY_INFORMATION = 0x0400;
        public const UInt32 PROCESS_VM_OPERATION = 0x0008;
        public const UInt32 PROCESS_VM_WRITE = 0x0020;
        public const UInt32 PROCESS_VM_READ = 0x0010;
        public const UInt32 PROCESS_ALL_ACCESS = 0x1F0FFF;

        public const UInt32 MEM_COMMIT = 0x00001000;
        public const UInt32 MEM_RESERVE = 0x00002000;

        ////////////////////////////////////////////////////////////////////////////////
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean CloseHandle(IntPtr hProcess);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean ConnectNamedPipe(
            IntPtr hNamedPipe,
            MinWinBase._OVERLAPPED lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean ConnectNamedPipe(
            IntPtr hNamedPipe,
            IntPtr lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean CreateProcess(
            String lpApplicationName,
            String lpCommandLine, 
            ref Winbase._SECURITY_ATTRIBUTES lpProcessAttributes,
            ref Winbase._SECURITY_ATTRIBUTES lpThreadAttributes,
            Boolean bInheritHandles,
            Winbase.CREATION_FLAGS dwCreationFlags,
            IntPtr lpEnvironment,
            String lpCurrentDirectory,
            ref Winbase._STARTUPINFO lpStartupInfo,
            out Winbase._PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateNamedPipeA(
            String lpName,
            Winbase.OPEN_MODE dwOpenMode,
            Winbase.PIPE_MODE dwPipeMode,
            UInt32 nMaxInstances,
            UInt32 nOutBufferSize,
            UInt32 nInBufferSize,
            UInt32 nDefaultTimeOut,
            Winbase._SECURITY_ATTRIBUTES lpSecurityAttributes
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateNamedPipeA(
            String lpName,
            Winbase.OPEN_MODE dwOpenMode,
            Winbase.PIPE_MODE dwPipeMode,
            UInt32 nMaxInstances,
            UInt32 nOutBufferSize,
            UInt32 nInBufferSize,
            UInt32 nDefaultTimeOut,
            IntPtr lpSecurityAttributes
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateRemoteThread(IntPtr hHandle, IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UInt32 dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, UInt32 dwCreationFlags, ref UInt32 lpThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateToolhelp32Snapshot(UInt32 dwFlags, UInt32 th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean DisconnectNamedPipe(IntPtr hNamedPipe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentThread();

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void GetNativeSystemInfo(out Winbase._SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern Int32 GetPrivateProfileString(String lpAppName, String lpKeyName, String lpDefault, StringBuilder lpReturnedString, UInt32 nSize, String lpFileName);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern void GetSystemInfo(out Winbase._SYSTEM_INFO lpSystemInfo);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean GetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean GetThreadContext(IntPtr hThread, ref Winnt.CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 GlobalSize(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean IsWow64Process(IntPtr hProcess, out Boolean Wow64Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Module32First(IntPtr hSnapshot, ref TiHelp32.tagMODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Module32Next(IntPtr hSnapshot, ref TiHelp32.tagMODULEENTRY32 lpme);

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        public static extern IntPtr LoadLibrary(string lpFileName);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Process32First(IntPtr hSnapshot, ref TiHelp32.tagPROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Process32Next(IntPtr hSnapshot, ref TiHelp32.tagPROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Boolean bInheritHandle, UInt32 dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessThreadsApi.ProcessSecurityRights dwDesiredAccess, Boolean bInheritHandle, UInt32 dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean OpenProcessToken(IntPtr hProcess, UInt32 dwDesiredAccess, out IntPtr hToken);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenThread(ProcessThreadsApi.ThreadSecurityRights dwDesiredAccess, Boolean bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean OpenThreadToken(IntPtr ThreadHandle, UInt32 DesiredAccess, Boolean OpenAsSelf, ref IntPtr TokenHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean ReadFile(
            IntPtr hFile,
            Byte[] lpBuffer,
            UInt32 nNumberOfBytesToRead,
            ref UInt32 lpNumberOfBytesRead,
            IntPtr lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean ReadFile(
            IntPtr hFile,
            Byte[] lpBuffer,
            UInt32 nNumberOfBytesToRead,
            ref UInt32 lpNumberOfBytesRead,
            ref MinWinBase._OVERLAPPED lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean ReadFile(
            IntPtr hFile,
            Byte[] lpBuffer,
            UInt32 nNumberOfBytesToRead,
            ref UInt32 lpNumberOfBytesRead,
            ref System.Threading.NativeOverlapped lpOverlapped
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "ReadProcessMemory")]
        public static extern Boolean ReadProcessMemory64(IntPtr hProcess, UInt64 lpBaseAddress, IntPtr lpBuffer, UInt64 nSize, ref UInt32 lpNumberOfBytesRead);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern UInt32 SearchPath(String lpPath, String lpFileName, String lpExtension, UInt32 nBufferLength, StringBuilder lpBuffer, ref IntPtr lpFilePart);

        public delegate Boolean HandlerRoutine(Wincon.CtrlType CtrlType);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean SetConsoleCtrlHandler(HandlerRoutine HandlerRoutine, Boolean Add);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean SetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean SetThreadContext(IntPtr hThread, ref Winnt.CONTEXT64 lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean TerminateProcess(IntPtr hProcess, UInt32 uExitCode);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Thread32First(IntPtr hSnapshot, ref TiHelp32.tagTHREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Thread32Next(IntPtr hSnapshot, ref TiHelp32.tagTHREADENTRY32 lpte);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, Winnt.MEMORY_PROTECTION_CONSTANTS flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr VirtualAllocEx(IntPtr hHandle, IntPtr lpAddress, UInt32 dwSize, UInt32 flAllocationType, Winnt.MEMORY_PROTECTION_CONSTANTS flProtect);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        public static extern Boolean VirtualProtect(IntPtr lpAddress, UInt32 dwSize, Winnt.MEMORY_PROTECTION_CONSTANTS flNewProtect, ref Winnt.MEMORY_PROTECTION_CONSTANTS lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean VirtualProtectEx(IntPtr hHandle, IntPtr lpAddress, UInt32 dwSize, Winnt.MEMORY_PROTECTION_CONSTANTS flNewProtect, ref Winnt.MEMORY_PROTECTION_CONSTANTS lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="VirtualQueryEx")]
        public static extern Int32 VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out Winnt._MEMORY_BASIC_INFORMATION lpBuffer, UInt32 dwLength);

        [DllImport("kernel32.dll", SetLastError = true, EntryPoint="VirtualQueryEx")]
        public static extern Int32 VirtualQueryEx64(IntPtr hProcess, IntPtr lpAddress, out Winnt._MEMORY_BASIC_INFORMATION64 lpBuffer, UInt32 dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean WaitForSingleObject(IntPtr hProcess, UInt32 nSize);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern UInt32 WaitForSingleObjectEx(IntPtr hProcess, IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Wow64GetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Wow64GetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Wow64SetThreadContext(IntPtr hThread, IntPtr lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean Wow64SetThreadContext(IntPtr hThread, ref Winnt.CONTEXT lpContext);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, IntPtr lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, Byte[] lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref UInt32 lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Boolean WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, ref UInt64 lpBuffer, UInt32 nSize, ref UInt32 lpNumberOfBytesWritten);
    }
}