using System;
using System.Linq;
using System.Runtime.InteropServices;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator
{
    sealed class PSExec : IDisposable
    {
        String serviceName;
        IntPtr hServiceManager;
        IntPtr hSCObject;

        Boolean disposed;

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public PSExec(String serviceName)
        {
            this.serviceName = serviceName;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public PSExec()
        {
            this.serviceName = GenerateUuid(12);
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        ~PSExec()
        {
            Dispose();
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public void Dispose()
        {
            if (!disposed)
            {
                Delete();
            }
            disposed = true;
            if (IntPtr.Zero != hSCObject)
            {
                advapi32.CloseServiceHandle(hSCObject);
            }

            if (IntPtr.Zero != hServiceManager)
            {
                kernel32.CloseHandle(hServiceManager);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal Boolean Connect(String machineName)
        {
            hServiceManager = advapi32.OpenSCManager(
                machineName, null, Winsvc.dwSCManagerDesiredAccess.SC_MANAGER_CONNECT | Winsvc.dwSCManagerDesiredAccess.SC_MANAGER_CREATE_SERVICE
            );

            if (IntPtr.Zero == hServiceManager)
            {
                Console.WriteLine("[-] Failed to connect service controller {0}", machineName);
                return false;
            }

            Console.WriteLine("[+] Connected to {0}", machineName);
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Creates a service
        ////////////////////////////////////////////////////////////////////////////////
        internal Boolean Create(String lpBinaryPathName)
        {
            Console.WriteLine("[*] Creating service {0}", serviceName);
            //Console.WriteLine(lpBinaryPathName);
            IntPtr hSCObject = advapi32.CreateService(
                hServiceManager,
                serviceName, serviceName,
                Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS,
                Winsvc.dwServiceType.SERVICE_WIN32_OWN_PROCESS,
                Winsvc.dwStartType.SERVICE_DEMAND_START,
                Winsvc.dwErrorControl.SERVICE_ERROR_IGNORE,
                lpBinaryPathName,
                String.Empty, null, String.Empty, null, null
            );

            if (IntPtr.Zero == hSCObject)
            {
                Console.WriteLine("[-] Failed to create service");
                Console.WriteLine(Marshal.GetLastWin32Error());
                return false;
            }

            advapi32.CloseServiceHandle(hSCObject);
            Console.WriteLine("[+] Created service {0}", serviceName);
            return true;
        }

        ///////////////////////////////////////////////////////////////////////////////
        // Opens a handle to a service
        ///////////////////////////////////////////////////////////////////////////////
        internal Boolean Open()
        {
            hSCObject = advapi32.OpenService(hServiceManager, serviceName, Winsvc.dwDesiredAccess.SERVICE_ALL_ACCESS);

            if (IntPtr.Zero == hSCObject)
            {
                Console.WriteLine("[-] Failed to open service");
                Console.WriteLine(Marshal.GetLastWin32Error());
                return false;
            }

            Console.WriteLine("[+] Opened service");
            return true;
        }

        ///////////////////////////////////////////////////////////////////////////////
        // Starts the service, if there is a start timeout error, return true
        ///////////////////////////////////////////////////////////////////////////////
        internal Boolean Start()
        {
            if (!advapi32.StartService(hSCObject, 0, null))
            {
                Int32 error = Marshal.GetLastWin32Error();
                if (1053 != error)
                {
                    Console.WriteLine("[-] Failed to start service");
                    Console.WriteLine(new System.ComponentModel.Win32Exception(error).Message);
                    return false;
                }
            }
            Console.WriteLine("[+] Started Service");
            return true;
        }

        ///////////////////////////////////////////////////////////////////////////////
        // Stops the service, if service is already stopped returns true
        ///////////////////////////////////////////////////////////////////////////////
        internal Boolean Stop()
        {
            Winsvc._SERVICE_STATUS serviceStatus;
            IntPtr hControlService = advapi32.ControlService(hSCObject, Winsvc.dwControl.SERVICE_CONTROL_STOP, out serviceStatus);

            if (IntPtr.Zero == hControlService)
            {
                Int32 error = Marshal.GetLastWin32Error();
                if (1062 != error)
                {
                    Console.WriteLine("[-] Failed to stop service");
                    Console.WriteLine(new System.ComponentModel.Win32Exception(error).Message);
                    return false;
                }
            }
            Console.WriteLine("[+] Stopped Service");
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Deletes the service
        ////////////////////////////////////////////////////////////////////////////////
        internal Boolean Delete()
        {
            if (!advapi32.DeleteService(hSCObject))
            {
                Console.WriteLine("[-] Failed to delete service");
                Console.WriteLine(new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
                return false;
            }
            Console.WriteLine("[+] Deleted service");
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        internal static String GenerateUuid(int length)
        {
            Random random = new Random();
            const String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            return new String(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }
}