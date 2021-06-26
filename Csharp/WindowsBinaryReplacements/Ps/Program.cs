using System;
using System.Collections;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace Ps
{
    public class Program
    {
        [DllImport("kernel32.dll")]
        static extern bool ProcessIdToSessionId(uint dwProcessId, out uint pSessionId);
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.Winapi)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool IsWow64Process([In] IntPtr process, [Out] out bool wow64Process);

        [DllImport("user32.dll", ExactSpelling = true, CharSet = CharSet.Auto)]
        public static extern IntPtr GetParent(IntPtr hWnd);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern int GetProcessId(IntPtr hProcess);

        /// <summary>
        /// A utility class to determine a process parent.
        /// </summary>
        [StructLayout(LayoutKind.Sequential)]
        public struct ParentProcessUtilities
        {
            // These members must match PROCESS_BASIC_INFORMATION
            internal IntPtr Reserved1;
            internal IntPtr PebBaseAddress;
            internal IntPtr Reserved2_0;
            internal IntPtr Reserved2_1;
            internal IntPtr UniqueProcessId;
            internal IntPtr InheritedFromUniqueProcessId;

            [DllImport("ntdll.dll")]
            private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref ParentProcessUtilities processInformation, int processInformationLength, out int returnLength);

            /// <summary>
            /// Gets the parent process of the current process.
            /// </summary>
            /// <returns>An instance of the Process class.</returns>
            public static Process GetParentProcess()
            {
                return GetParentProcess(Process.GetCurrentProcess().Handle);
            }

            /// <summary>
            /// Gets the parent process of specified process.
            /// </summary>
            /// <param name="id">The process id.</param>
            /// <returns>An instance of the Process class.</returns>
            public static Process GetParentProcess(int id)
            {
                Process process = Process.GetProcessById(id);
                return GetParentProcess(process.Handle);
            }

            /// <summary>
            /// Gets the parent process of a specified process.
            /// </summary>
            /// <param name="handle">The process handle.</param>
            /// <returns>An instance of the Process class.</returns>
            public static Process GetParentProcess(IntPtr handle)
            {
                ParentProcessUtilities pbi = new ParentProcessUtilities();
                int returnLength;
                int status = NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out returnLength);
                if (status != 0)
                    throw new Win32Exception(status);

                try
                {
                    return Process.GetProcessById(pbi.InheritedFromUniqueProcessId.ToInt32());
                }
                catch (ArgumentException)
                {
                    // not found
                    return null;
                }
            }
        }
        private static bool IsHighIntegrity()
        {
            // returns true if the current process is running with adminstrative privs in a high integrity context
            WindowsIdentity identity = WindowsIdentity.GetCurrent();
            WindowsPrincipal principal = new WindowsPrincipal(identity);
            return principal.IsInRole(WindowsBuiltInRole.Administrator);
        }
        private static bool IsWin64Emulator(Process process)
        {
            if((Environment.OSVersion.Version.Major > 5) || ((Environment.OSVersion.Version.Major == 5) && (Environment.OSVersion.Version.Minor >= 1)))
            {
                bool retVal;
                return IsWow64Process(process.Handle, out retVal) && retVal;
            }
            return false; // not on 64-bit Windows Emulator
        }
        public static void Main(string[] args)
        {
            ManagementScope scope = new System.Management.ManagementScope(@"\\.\root\cimv2");
            scope.Connect();
            ObjectQuery query = new ObjectQuery("SELECT * FROM Win32_Process");
            ManagementObjectSearcher objectSearcher = new ManagementObjectSearcher(scope, query);
            ManagementObjectCollection objectCollection = objectSearcher.Get();

            Dictionary<Int32, String> owners = new Dictionary<Int32, String>();
            int biggestOwnerSize = 5; // Column must be at least (but possibly greater) than 5 chars wide: O W N E R
            foreach (ManagementObject managementObject in objectCollection)
            {
                String[] owner = new String[2];
                try
                {
                    managementObject.InvokeMethod("GetOwner", owner);
                }
                catch
                {
                    owner[0] = "X";
                }
                String name = owner[0] != null ? owner[1] + "\\" + owner[0] : "X";
                owners[Convert.ToInt32(managementObject["Handle"])] = name;
                if(name.Length > biggestOwnerSize)
                {
                    biggestOwnerSize = name.Length;
                }
            }

            Process[] processes = Process.GetProcesses();
            ArrayList pidList = new ArrayList();
            object[] pids;
            foreach (Process process in processes)
            {
                pidList.Add(process.Id);
            }
            pids = pidList.ToArray();
            Array.Sort(pids);

            if(IsHighIntegrity())
            {
                Console.WriteLine("\n[*] Running \"ps\" in high integrity process. Results should be more complete.\n");
            }
            else
            {
                Console.WriteLine("\n[*] Not running \"ps\" in a high integrity process. Results will be limited.\n");
            }

            Console.WriteLine("PID     PPID    Arch   Session   Owner" + new string(' ', biggestOwnerSize - 5) + "   Process Name");
            Console.WriteLine("=====   =====   ====   =======   =====" + new string('=', biggestOwnerSize - 5) + "   ============");
            foreach (int pid in pids)
            {
                Process process = Process.GetProcessById(0); // fall back option so things don't break
                try
                {
                    process = Process.GetProcessById(pid);
                }
                catch { }
                String strSessID;
                try
                {
                    uint sessID;
                    ProcessIdToSessionId((uint)pid, out sessID);
                    strSessID = sessID.ToString();
                }
                catch(Exception)
                {
                    strSessID = "X";
                }
                String architecture;
                try
                {
                    architecture = IsWin64Emulator(process) ? "x86" : "x64";
                }
                catch(Exception)
                {
                    architecture = "X";
                }
                String ppidString;
                String userName;
                try
                {
                    if (!owners.TryGetValue(process.Id, out userName))
                    {
                        userName = "X";
                    }
                }
                catch (ArgumentNullException)
                {
                    userName = "X";
                }
                try
                {
                    Process parent = ParentProcessUtilities.GetParentProcess(process.Id);
                    ppidString = parent.Id.ToString();
                }
                catch
                {
                    ppidString = "X";
                }

                Console.WriteLine(pid.ToString() + new string(' ', 8 - pid.ToString().Length) + ppidString + new string(' ', 8 - ppidString.Length) + architecture + new string(' ', 7 - architecture.Length) + strSessID + new string(' ', 10 - strSessID.Length) + userName + new string(' ', biggestOwnerSize - userName.Length + 3) + process.ProcessName);
            }
        }
    }
}
