using System;

namespace Tokenvator
{
    class Constants
    {
        //Process Security and Access Rights
        //https://docs.microsoft.com/en-us/windows/desktop/procthread/process-security-and-access-rights
        internal const UInt32 DELETE                              = 0x00010000;
        internal const UInt32 READ_CONTROL                        = 0x00020000;
        internal const UInt32 SYNCHRONIZE                         = 0x00100000;
        internal const UInt32 WRITE_DAC                           = 0x00040000;
        internal const UInt32 WRITE_OWNER                         = 0x00080000;
        //https://msdn.microsoft.com/en-us/library/windows/desktop/ms684880%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        internal const UInt32 PROCESS_ALL_ACCESS                  = 0;
        internal const UInt32 PROCESS_CREATE_PROCESS              = 0x0080;
        internal const UInt32 PROCESS_CREATE_THREAD               = 0x0002;
        internal const UInt32 PROCESS_DUP_HANDLE                  = 0x0040;
        internal const UInt32 PROCESS_QUERY_INFORMATION           = 0x0400;
        internal const UInt32 PROCESS_QUERY_LIMITED_INFORMATION   = 0x1000;
        internal const UInt32 PROCESS_SET_INFORMATION             = 0x0200;
        internal const UInt32 PROCESS_SET_QUOTA                   = 0x0100;
        internal const UInt32 PROCESS_SUSPEND_RESUME              = 0x0800;
        internal const UInt32 PROCESS_TERMINATE                   = 0x0001;
        internal const UInt32 PROCESS_VM_OPERATION                = 0x0008;
        internal const UInt32 PROCESS_VM_READ                     = 0x0010;
        internal const UInt32 PROCESS_VM_WRITE                    = 0x0020;

        //Token 
        
        //https://docs.microsoft.com/en-us/windows/desktop/secauthz/standard-access-rights
        internal const UInt32 STANDARD_RIGHTS_ALL         = (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER | SYNCHRONIZE);
        internal const UInt32 STANDARD_RIGHTS_EXECUTE     = READ_CONTROL;
        internal const UInt32 STANDARD_RIGHTS_READ        = READ_CONTROL;
        internal const UInt32 STANDARD_RIGHTS_REQUIRED    = (DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER);//0x000F0000;
        internal const UInt32 STANDARD_RIGHTS_WRITE       = READ_CONTROL;

        //http://www.pinvoke.net/default.aspx/advapi32.openprocesstoken
        internal const UInt32 TOKEN_ASSIGN_PRIMARY        = 0x0001;
        internal const UInt32 TOKEN_DUPLICATE             = 0x0002;
        internal const UInt32 TOKEN_IMPERSONATE           = 0x0004;
        internal const UInt32 TOKEN_QUERY                 = 0x0008;
        internal const UInt32 TOKEN_QUERY_SOURCE          = 0x0010;
        internal const UInt32 TOKEN_ADJUST_PRIVILEGES     = 0x0020;
        internal const UInt32 TOKEN_ADJUST_GROUPS         = 0x0040;
        internal const UInt32 TOKEN_ADJUST_DEFAULT        = 0x0080;
        internal const UInt32 TOKEN_ADJUST_SESSIONID      = 0x0100;
        internal const UInt32 TOKEN_EXECUTE               = (STANDARD_RIGHTS_EXECUTE | TOKEN_IMPERSONATE);
        internal const UInt32 TOKEN_READ                  = (STANDARD_RIGHTS_READ | TOKEN_QUERY);
        internal const UInt32 TOKEN_WRITE                 = (STANDARD_RIGHTS_READ | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT);
        internal const UInt32 TOKEN_ALL_ACCESS            = (STANDARD_RIGHTS_REQUIRED | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_QUERY_SOURCE | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);
        internal const UInt32 TOKEN_ALT                   = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY);
        internal const UInt32 TOKEN_ALT2                  = (TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID);

        internal const Int32 ANYSIZE_ARRAY = 1;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446619(v=vs.85).aspx
        //https://docs.microsoft.com/en-us/windows/desktop/secauthz/privilege-constants
        internal const String SE_ASSIGNPRIMARYTOKEN_NAME  = "SeAssignPrimaryTokenPrivilege";
        internal const String SE_BACKUP_NAME              = "SeBackupPrivilege";
        internal const String SE_DEBUG_NAME               = "SeDebugPrivilege";
        internal const String SE_INCREASE_QUOTA_NAME      = "SeIncreaseQuotaPrivilege";
        internal const String SE_TCB_NAME                 = "SeTcbPrivilege";

        internal const UInt64 SE_GROUP_ENABLED            = 0x00000004L;
        internal const UInt64 SE_GROUP_ENABLED_BY_DEFAULT = 0x00000002L;
        internal const UInt64 SE_GROUP_INTEGRITY          = 0x00000020L;
        internal const UInt32 SE_GROUP_INTEGRITY_32       = 0x00000020;
        internal const UInt64 SE_GROUP_INTEGRITY_ENABLED  = 0x00000040L;
        internal const UInt64 SE_GROUP_LOGON_ID           = 0xC0000000L;
        internal const UInt64 SE_GROUP_MANDATORY          = 0x00000001L;
        internal const UInt64 SE_GROUP_OWNER              = 0x00000008L;
        internal const UInt64 SE_GROUP_RESOURCE           = 0x20000000L;
        internal const UInt64 SE_GROUP_USE_FOR_DENY_ONLY  = 0x00000010L;

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446583%28v=vs.85%29.aspx?f=255&MSPPError=-2147217396
        internal const UInt32 DISABLE_MAX_PRIVILEGE       = 0x1;
        internal const UInt32 SANDBOX_INERT               = 0x2;
        internal const UInt32 LUA_TOKEN                   = 0x4;
        internal const UInt32 WRITE_RESTRICTED            = 0x8;
    }
}
