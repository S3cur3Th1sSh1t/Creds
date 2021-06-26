using System;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Collections;
using System.DirectoryServices.AccountManagement;

using DWORD = System.UInt32;
using LARGE_INTEGER = System.UInt64;

namespace Whoami
{
    public class Program
    {
        public const Int32 ANYSIZE_ARRAY = 1;
        public const Int32 PRIVILEGE_SET_ALL_NECESSARY = 1;

        [DllImport("api-ms-win-security-base-l1-1-0.dll", CharSet = CharSet.Unicode, SetLastError = true, BestFitMapping = false)]
        [SuppressMessage("Microsoft.Security", "CA2118:ReviewSuppressUnmanagedCodeSecurityUsage")]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, ref LUID lpLuid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        [return: MarshalAs(UnmanagedType.Bool)]
        unsafe public static extern bool LookupPrivilegeName(
            string lpSystemName,
            IntPtr lpLuid,
            System.Text.StringBuilder lpName,
            ref Int32 cchName
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_USER
        {
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
            public SID_AND_ATTRIBUTES[] User;
        }

        // https://www.codeproject.com/articles/14828/how-to-get-process-owner-id-and-current-user-sid
        public const int TOKEN_QUERY = 0X00000008;

        [Flags]
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
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            MaxTokenInfoClass
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public int Attributes;
        }
        [DllImport("advapi32", CharSet = CharSet.Auto)]
        static extern bool ConvertSidToStringSid(
            IntPtr pSID,
            [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid
        );
        [DllImport("kernel32")]
        static extern IntPtr GetCurrentProcess(); //IntPtr instead of HANDLE
        [DllImport("advapi32")]
        static extern bool OpenProcessToken(
            IntPtr ProcessHandle, // handle to process //IntPtr instead of HANDLE
            int DesiredAccess, // desired access to process
            ref IntPtr TokenHandle // handle to open access token
        );

        [StructLayout(LayoutKind.Sequential)]
        public struct PRIVILEGE_SET
        {
            public DWORD PrivilegeCount;
            public DWORD Control;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = (Int32)ANYSIZE_ARRAY)]
            public LUID_AND_ATTRIBUTES[] Privilege;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES_ARRAY
        {
            public UInt32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public DWORD Attributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID
        {
            public DWORD LowPart;
            public DWORD HighPart;
        }
        [Flags]
        public enum SECURITY_IMPERSONATION_LEVEL : int
        {
            SecurityAnonymous = 0,
            SecurityIdentification = 1,
            SecurityImpersonation = 2,
            SecurityDelegation = 3
        };
        [Flags]
        public enum TOKEN_TYPE
        {
            TokenPrimary = 1,
            TokenImpersonation
        }
        [StructLayout(LayoutKind.Sequential)]
        internal struct TOKEN_STATISTICS
        {
            public LUID TokenId;
            public LUID AuthenticationId;
            public LARGE_INTEGER ExpirationTime;
            public TOKEN_TYPE TokenType;
            public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
            public DWORD DynamicCharged;
            public DWORD DynamicAvailable;
            public DWORD GroupCount;
            public DWORD PrivilegeCount;
            public LUID ModifiedId;
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, IntPtr TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern Boolean GetTokenInformation(IntPtr TokenHandle, TOKEN_INFORMATION_CLASS TokenInformationClass, ref TOKEN_STATISTICS TokenInformation, UInt32 TokenInformationLength, out UInt32 ReturnLength);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean PrivilegeCheck(IntPtr ClientToken, PRIVILEGE_SET RequiredPrivileges, IntPtr pfResult);
        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern Boolean PrivilegeCheck(IntPtr ClientToken, ref PRIVILEGE_SET RequiredPrivileges, out Int32 pfResult);
        
        static string GetSid()
        {
            IntPtr procToken = IntPtr.Zero;
            const int bufLength = 512;
            IntPtr tu = Marshal.AllocHGlobal(bufLength);
            UInt32 cb = bufLength;
            bool ret = false;
            TOKEN_USER tokUser;
            IntPtr SID = IntPtr.Zero;
            string SIDString = null;

            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ref procToken);
            ret = GetTokenInformation(procToken, TOKEN_INFORMATION_CLASS.TokenUser, tu, cb, out cb);
            if (ret)
            {
                tokUser = (TOKEN_USER)Marshal.PtrToStructure(tu, typeof(TOKEN_USER));
                SID = tokUser.User[0].Sid;
            }
            ConvertSidToStringSid(SID, ref SIDString);
            return SIDString;
        }
        
        ////////////////////////////////////////////////////////////////////////////////
        // Prints the tokens privileges // Taken from NetSPI's TokenVader project
        ////////////////////////////////////////////////////////////////////////////////
        public static void EnumerateTokenPrivileges()
        {
            IntPtr hToken = IntPtr.Zero;
            OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, ref hToken);

            UInt32 TokenInfLength;
            GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);

            if (TokenInfLength < 0 || TokenInfLength > Int32.MaxValue)
            {
                GetWin32Error("GetTokenInformation - 1 " + TokenInfLength);
                return;
            }
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)TokenInfLength);

            ////////////////////////////////////////////////////////////////////////////////
            if (!GetTokenInformation(hToken, TOKEN_INFORMATION_CLASS.TokenPrivileges, lpTokenInformation, TokenInfLength, out TokenInfLength))
            {
                GetWin32Error("GetTokenInformation - 2 " + TokenInfLength);
                return;
            }
            TOKEN_PRIVILEGES_ARRAY tokenPrivileges = (TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(lpTokenInformation, typeof(TOKEN_PRIVILEGES_ARRAY));
            Marshal.FreeHGlobal(lpTokenInformation);
            Console.WriteLine("[*] Enumerated {0} Privileges", tokenPrivileges.PrivilegeCount);
            Console.WriteLine();
            Console.WriteLine("{0,-45}{1,-30}", "Privilege Name", "Enabled");
            Console.WriteLine("{0,-45}{1,-30}", "==============", "=======");
            ////////////////////////////////////////////////////////////////////////////////
            for (Int32 i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                StringBuilder lpName = new StringBuilder();
                Int32 cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);

                LookupPrivilegeName(null, lpLuid, null, ref cchName);
                if (cchName <= 0 || cchName > Int32.MaxValue)
                {
                    GetWin32Error("LookupPrivilegeName Pass 1");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                lpName.EnsureCapacity(cchName + 1);
                if (!LookupPrivilegeName(null, lpLuid, lpName, ref cchName))
                {
                    GetWin32Error("LookupPrivilegeName Pass 2");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }

                PRIVILEGE_SET privilegeSet = new PRIVILEGE_SET
                {
                    PrivilegeCount = 1,
                    Control = PRIVILEGE_SET_ALL_NECESSARY,
                    Privilege = new LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                };

                Int32 pfResult = 0;
                if (!PrivilegeCheck(hToken, ref privilegeSet, out pfResult))
                {
                    GetWin32Error("PrivilegeCheck");
                    Marshal.FreeHGlobal(lpLuid);
                    continue;
                }
                Console.WriteLine("{0,-45}{1,-30}", lpName.ToString(), Convert.ToBoolean(pfResult));
                Marshal.FreeHGlobal(lpLuid);
            }
            Console.WriteLine();
        }
        public static void GetWin32Error(String location)
        {
            Console.WriteLine(" [-] Function {0} failed: ", location);
            Console.WriteLine(" [-] {0}", new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error()).Message);
        }
        public static ArrayList GetUserGroups(string sUserName)
        {
            ArrayList myItems = new ArrayList();
            PrincipalContext oPrincipalContext = new PrincipalContext(ContextType.Machine);
            UserPrincipal oUserPrincipal = UserPrincipal.FindByIdentity(oPrincipalContext, sUserName);

            PrincipalSearchResult<Principal> oPrincipalSearchResult = oUserPrincipal.GetGroups();

            foreach (Principal oResult in oPrincipalSearchResult)
            {
                myItems.Add(oResult.Name);
            }
            return myItems;
        }

        public static void Main(string[] args)
        {
            // Get current username
            // Get current SID
            // Get user's current privileges (eg: seDebugPrivilege)
            // Get user's current local groups

            string uname = WindowsIdentity.GetCurrent().Name;
            Console.WriteLine("Current User: " + uname);
            Console.WriteLine("Current Sid:  " + GetSid() + "\n");
            EnumerateTokenPrivileges();
            Console.WriteLine("\n[*] Local group membership:");
            Console.WriteLine("===========================");
            foreach (string group in GetUserGroups(uname))
            {
                Console.WriteLine(group);
            }
        }
    }
}
