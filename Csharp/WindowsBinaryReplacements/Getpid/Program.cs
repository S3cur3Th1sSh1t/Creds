using System;
using System.Runtime.InteropServices;
using System.ComponentModel;
using System.Diagnostics;

namespace Getpid
{
    public class Program
    {
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
        public static void Main(string[] args)
        {
            string pid = "X";
            string proc = "X";
            string ppid = "X";
            string pproc = "X";
            try
            {
                pid = Process.GetCurrentProcess().Id.ToString();
            }
            catch { }
            try
            {
                proc = Process.GetCurrentProcess().ProcessName;
            }
            catch { }
            try
            {
                ppid = ParentProcessUtilities.GetParentProcess(Process.GetCurrentProcess().Id).Id.ToString();
            }
            catch { }
            try
            {
                pproc = ParentProcessUtilities.GetParentProcess(Process.GetCurrentProcess().Id).ProcessName;
            }
            catch { }

            Console.WriteLine("PID:  " + pid + new string(' ', 5 - pid.Length) + " (" + proc + ")");
            Console.WriteLine("PPID: " + ppid + new string(' ', 5 - ppid.Length) + " (" + pproc + ")");
        }
    }
}
