using System;

namespace MonkeyWorks.Unmanaged.Headers
{
    class ProcessThreadsApi
    {
       [Flags]
       public enum ThreadSecurityRights : long
        {
            THREAD_TERMINATE = 0x0001,
            THREAD_SUSPEND_RESUME = 0x0002,
            THREAD_GET_CONTEXT = 0x0008,
            THREAD_SET_CONTEXT = 0x0010,
            THREAD_SET_INFORMATION = 0x0020,
            THREAD_QUERY_INFORMATION = 0x0040,
            THREAD_SET_THREAD_TOKEN = 0x0080,
            THREAD_IMPERSONATE = 0x0100,
            THREAD_DIRECT_IMPERSONATION = 0x0200,                       
            THREAD_SET_LIMITED_INFORMATION = 0x0400,
            THREAD_QUERY_LIMITED_INFORMATION = 0x0800,
            THREAD_ALL_ACCESS = 0x1FFFFF,

            DELETE = 0x00010000L,
            READ_CONTROL = 0x00020000L,           
            WRITE_DAC = 0x00040000L,
            WRITE_OWNER = 0x00080000L,
            SYNCHRONIZE = 0x00100000L
        }

        [Flags]
        public enum ProcessSecurityRights : long
        {
            PROCESS_TERMINATE = 0x0001,
            PROCESS_CREATE_THREAD = 0x0002,
            PROCESS_VM_OPERATION = 0x0008,
            PROCESS_VM_READ = 0x0010,
            PROCESS_VM_WRITE = 0x0020,
            PROCESS_DUP_HANDLE = 0x0040,
            PROCESS_CREATE_PROCESS = 0x0080,
            PROCESS_SET_QUOTA = 0x0100,
            PROCESS_SET_INFORMATION = 0x0200,
            PROCESS_QUERY_INFORMATION = 0x0400,
            PROCESS_SUSPEND_RESUME = 0x0800,
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000,
            PROCESS_ALL_ACCESS = 0x1FFFFF,

            DELETE = 0x00010000L,
            READ_CONTROL = 0x00020000L,
            WRITE_DAC = 0x00040000L,
            WRITE_OWNER = 0x00080000L,
            SYNCHRONIZE = 0x00100000L
        }
    }
}