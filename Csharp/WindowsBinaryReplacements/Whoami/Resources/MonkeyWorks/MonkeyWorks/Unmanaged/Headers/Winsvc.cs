using System;
using System.Runtime.InteropServices;

using WORD = System.UInt16;
using DWORD = System.UInt32;
using QWORD = System.UInt64;

using LPVOID = System.IntPtr;
using DWORD_PTR = System.IntPtr;

namespace MonkeyWorks.Unmanaged.Headers
{
    sealed class Winsvc
    {
        [Flags]
        public enum dwControl : uint
        {
            SERVICE_CONTROL_STOP = 0x00000001,
            SERVICE_CONTROL_PAUSE = 0x00000002,
            SERVICE_CONTROL_CONTINUE = 0x00000003,
            SERVICE_CONTROL_INTERROGATE = 0x00000004,
            SERVICE_CONTROL_PARAMCHANGE = 0x00000006,
            SERVICE_CONTROL_NETBINDADD = 0x00000007,
            SERVICE_CONTROL_NETBINDREMOVE = 0x00000008,
            SERVICE_CONTROL_NETBINDENABLE = 0x00000009,
            SERVICE_CONTROL_NETBINDDISABLE = 0x0000000A
        }

        [Flags]
        public enum dwControlsAccepted : uint
        {
            SERVICE_ACCEPT_STOP = 0x00000001,
            SERVICE_ACCEPT_PAUSE_CONTINUE = 0x00000002,
            SERVICE_ACCEPT_SHUTDOWN = 0x00000004,
            SERVICE_ACCEPT_PARAMCHANGE = 0x00000008,
            SERVICE_ACCEPT_NETBINDCHANGE = 0x00000010,
            SERVICE_ACCEPT_PRESHUTDOWN = 0x00000100,

            SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020,
            SERVICE_ACCEPT_POWEREVENT = 0x00000040,
            SERVICE_ACCEPT_SESSIONCHANGE = 0x00000080,
            SERVICE_ACCEPT_TIMECHANGE = 0x00000200,
            SERVICE_ACCEPT_TRIGGEREVENT = 0x00000400,
            SERVICE_ACCEPT_USERMODEREBOOT = 0x00000800
        }

        [Flags]
        public enum dwCurrentState : uint
        {
            SERVICE_STOPPED = 0x00000001,
            SERVICE_START_PENDING = 0x00000002,
            SERVICE_STOP_PENDING = 0x00000003,
            SERVICE_RUNNING = 0x00000004,
            SERVICE_CONTINUE_PENDING = 0x00000005,
            SERVICE_PAUSE_PENDING = 0x00000006,
            SERVICE_PAUSED = 0x00000007
        }

        [Flags]
        public enum dwDesiredAccess : uint
        {
            SERVICE_QUERY_CONFIG = 0x0001,
            SERVICE_CHANGE_CONFIG = 0x0002,
            SERVICE_QUERY_STATUS = 0x0004,
            SERVICE_ENUMERATE_DEPENDENTS = 0x0008,
            SERVICE_START = 0x0010,
            SERVICE_STOP = 0x0020,
            SERVICE_PAUSE_CONTINUE = 0x0040,
            SERVICE_INTERROGATE = 0x0080,
            SERVICE_USER_DEFINED_CONTROL = 0x0100,
            SERVICE_ALL_ACCESS = 0xF01FF
        }

        [Flags]
        public enum dwErrorControl : uint
        {
            SERVICE_ERROR_IGNORE = 0x00000000,
            SERVICE_ERROR_NORMAL = 0x00000001,
            SERVICE_ERROR_SEVERE = 0x00000002,
            SERVICE_ERROR_CRITICAL = 0x00000003
        }

        [Flags]
        public enum dwSCManagerDesiredAccess : uint
        {
            SC_MANAGER_ALL_ACCESS = 0xF003F,
            SC_MANAGER_CREATE_SERVICE = 0x0002,
            SC_MANAGER_CONNECT = 0x0001,
            SC_MANAGER_ENUMERATE_SERVICE = 0x0004,
            SC_MANAGER_LOCK = 0x0008,
            SC_MANAGER_MODIFY_BOOT_CONFIG = 0x0020,
            SC_MANAGER_QUERY_LOCK_STATUS = 0x0010
        }

        [Flags]
        public enum dwServiceType : uint
        {
            SERVICE_KERNEL_DRIVER = 0x00000001,
            SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
            SERVICE_ADAPTER = 0x00000004,
            SERVICE_RECOGNIZER_DRIVER = 0x00000008,
            SERVICE_WIN32_OWN_PROCESS = 0x00000010,
            SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
            SERVICE_USER_OWN_PROCESS = 0x00000050,
            SERVICE_USER_SHARE_PROCESS = 0x00000060,
            SERVICE_INTERACTIVE_PROCESS = 0x00000100
        }

        [Flags]
        public enum dwStartType : uint
        {
            SERVICE_BOOT_START = 0x00000000,
            SERVICE_SYSTEM_START = 0x00000001,
            SERVICE_AUTO_START = 0x00000002,
            SERVICE_DEMAND_START = 0x00000003,
            SERVICE_DISABLED = 0x00000004
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _SERVICE_STATUS
        {
            public dwServiceType dwServiceType;
            public dwCurrentState dwCurrentState;
            public dwControlsAccepted dwControlsAccepted;
            public DWORD dwWin32ExitCode;
            public DWORD dwServiceSpecificExitCode;
            public DWORD dwCheckPoint;
            public DWORD dwWaitHint;
        }
    }
}