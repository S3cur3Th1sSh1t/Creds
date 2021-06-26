using System;
using System.Runtime.InteropServices;
using System.Security.Principal;

using MonkeyWorks.Unmanaged.Headers;
using MonkeyWorks.Unmanaged.Libraries;

namespace Tokenvator
{
    class CheckPrivileges
    {            
        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        public Boolean GetSystem()
        {
            WindowsIdentity currentIdentity = WindowsIdentity.GetCurrent();
            if (!currentIdentity.IsSystem)
            {
                WindowsPrincipal currentPrincipal = new WindowsPrincipal(WindowsIdentity.GetCurrent());

                Console.WriteLine("Not running as SYSTEM, checking for Administrator access.");
                Console.WriteLine(String.Format("Operating as {0}", WindowsIdentity.GetCurrent().Name));

                if (CheckElevation(currentIdentity.Token))
                {
                    Console.WriteLine("Attempting to elevate to SYSTEM");
                    new Tokens().GetSystem();
                    if (!WindowsIdentity.GetCurrent().IsSystem)
                    {
                        Console.WriteLine("GetSystem Failed");
                        return false;
                    }
                    Console.WriteLine("Running as SYSTEM");
                    Console.WriteLine(" ");
                    return true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                Console.WriteLine("Running as SYSTEM");
                return true;
            }
            
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean PrintElevation(IntPtr hToken)
        {

            Int32 output = -1;
            if (!_QueryTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenElevationType, ref output))
            {
                Tokens.GetWin32Error("TokenElevationType");
                return false;
            }

            switch ((Winnt.TOKEN_ELEVATION_TYPE)output)
            {
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:
                    Console.WriteLine("[+] TokenElevationTypeDefault");
                    Console.WriteLine("[*] Token: Not Split");
                    //Console.WriteLine("ProcessIntegrity: Medium/Low");
                    return false;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    Console.WriteLine("[+] TokenElevationTypeFull");
                    Console.WriteLine("[*] Token: Split");
                    Console.WriteLine("[+] ProcessIntegrity: High");
                    return true;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    Console.WriteLine("[-] TokenElevationTypeLimited");
                    Console.WriteLine("[*] Token: Split");
                    Console.WriteLine("[-] ProcessIntegrity: Medium/Low");
                    Console.WriteLine("[!] Hint: Try to Bypass UAC");
                    return false;
                default:
                    Console.WriteLine("[-] Unknown integrity {0}", output);
                    Console.WriteLine("[!] Trying anyway");
                    return true;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean CheckElevation(IntPtr hToken)
        {
            Int32 output = -1;
            if (!_QueryTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenElevationType, ref output))
            {
                Tokens.GetWin32Error("TokenElevationType");
                return false;
            }

            switch ((Winnt.TOKEN_ELEVATION_TYPE)output)
            {
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeDefault:;
                    return false;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeFull:
                    return true;
                case Winnt.TOKEN_ELEVATION_TYPE.TokenElevationTypeLimited:
                    return false;
                default:
                    return true;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        //https://blogs.msdn.microsoft.com/cjacks/2006/10/08/how-to-determine-if-a-user-is-a-member-of-the-administrators-group-with-uac-enabled-on-windows-vista/
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean GetElevationType(IntPtr hToken, out Winnt._TOKEN_TYPE tokenType)
        {
            Int32 output = -1;
            if (!_QueryTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenType, ref output))
            {
                Tokens.GetWin32Error("TokenType");
                tokenType = 0;
                return false;
            }

            switch ((Winnt._TOKEN_TYPE)output)
            {
                case Winnt._TOKEN_TYPE.TokenPrimary:
                    Console.WriteLine("[+] Primary Token");
                    tokenType = Winnt._TOKEN_TYPE.TokenPrimary;
                    return true;
                case Winnt._TOKEN_TYPE.TokenImpersonation:
                    tokenType = Winnt._TOKEN_TYPE.TokenImpersonation;
                    if (!_QueryTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, ref output))
                    {
                        return false;
                    }
                    switch ((Winnt._SECURITY_IMPERSONATION_LEVEL)output)
                    {
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:
                            Console.WriteLine("[+] Anonymous Token");
                            return true;
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:
                            Console.WriteLine("[+] Identification Token");
                            return true;
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:
                            Console.WriteLine("[+] Impersonation Token");
                            return true;
                        case Winnt._SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:
                            Console.WriteLine("[+] Delegation Token");
                            return true;
                        default:
                            Console.WriteLine("[-] Unknown Impersionation Type");
                            return false;
                    }
                default:
                    Console.WriteLine("[-] Unknown Type {0}", output);
                    tokenType = 0;
                    return false;
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Displays the users associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetTokenOwner(IntPtr hToken)
        {
            UInt32 returnLength = 0;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenOwner, IntPtr.Zero, 0, out returnLength);
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)returnLength);
            Ntifs._TOKEN_OWNER tokenOwner;
            try
            {
                if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenOwner, lpTokenInformation, returnLength, out returnLength))
                {
                    Tokens.GetWin32Error("GetTokenInformation - Pass 2");
                    return;
                }
                tokenOwner = (Ntifs._TOKEN_OWNER)Marshal.PtrToStructure(lpTokenInformation, typeof(Ntifs._TOKEN_OWNER));
                if (IntPtr.Zero == tokenOwner.Owner)
                {
                    Tokens.GetWin32Error("PtrToStructure");
                }
            }
            catch (Exception ex)
            {
                Tokens.GetWin32Error("GetTokenInformation - Pass 2");
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
            }

            Console.WriteLine("[+] Owner: ");
            String sid, account;
            sid = account = String.Empty;
            _ReadSidAndName(tokenOwner.Owner, out sid, out account);
            Console.WriteLine("{0,-50} {1}", sid, account);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Displays the users associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public static void GetTokenUser(IntPtr hToken)
        {
            UInt32 returnLength = 0;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenUser, IntPtr.Zero, 0, out returnLength);
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)returnLength);
            Ntifs._TOKEN_USER tokenUser;
            try
            {
                if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenUser, lpTokenInformation, returnLength, out returnLength))
                {
                    Tokens.GetWin32Error("GetTokenInformation - Pass 2");
                    return;
                }
                tokenUser = (Ntifs._TOKEN_USER)Marshal.PtrToStructure(lpTokenInformation, typeof(Ntifs._TOKEN_USER));
                if (IntPtr.Zero == tokenUser.User[0].Sid)
                {
                    Tokens.GetWin32Error("PtrToStructure");
                }
            }
            catch (Exception ex)
            {
                Tokens.GetWin32Error("GetTokenInformation - Pass 2");
                Console.WriteLine(ex.Message);
                return;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
            }
            
            Console.WriteLine("[+] User: ");
            String sid, account;
            sid = account = String.Empty;
            _ReadSidAndName(tokenUser.User[0].Sid, out sid, out account);
            Console.WriteLine("{0,-50} {1}", sid, account);
            return;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Lists the groups associated with a token
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean GetTokenGroups(IntPtr hToken)
        {
            UInt32 returnLength = 0;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenGroups, IntPtr.Zero, 0, out returnLength);
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)returnLength);
            Ntifs._TOKEN_GROUPS tokenGroups;
            try
            {
                if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenGroups, lpTokenInformation, returnLength, out returnLength))
                {
                    Tokens.GetWin32Error("GetTokenInformation - Pass 2");
                    return false;
                }
                tokenGroups = (Ntifs._TOKEN_GROUPS)Marshal.PtrToStructure(lpTokenInformation, typeof(Ntifs._TOKEN_GROUPS));
            }
            catch (Exception ex)
            {
                Tokens.GetWin32Error("GetTokenInformation - Pass 2");
                Console.WriteLine(ex.Message);
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
            }

            Console.WriteLine("[+] Enumerated {0} Groups: ", tokenGroups.GroupCount);
            for (Int32 i = 0; i < tokenGroups.GroupCount; i++)
            {
                String sid, account;
                sid = account = String.Empty;
                _ReadSidAndName(tokenGroups.Groups[i].Sid, out sid, out account);
                Console.WriteLine("{0,-50} {1}", sid, account);
            }
            return true;
        }

        ////////////////////////////////////////////////////////////////////////////////
        //
        ////////////////////////////////////////////////////////////////////////////////
        private static void _ReadSidAndName(IntPtr pointer, out String sid, out String account)
        {
            sid = String.Empty;
            account = String.Empty;
            IntPtr lpSid = IntPtr.Zero;
            try
            {
                advapi32.ConvertSidToStringSid(pointer, ref lpSid);
                if (IntPtr.Zero == lpSid)
                {
                    return;
                }
                sid = Marshal.PtrToStringAuto(lpSid);

                if (!Enumeration.ConvertSidToName(pointer, out account))
                {
                    return;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
            finally
            {
                kernel32.LocalFree(lpSid);
            }
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Checks if a Privilege Exists and is Enabled
        ////////////////////////////////////////////////////////////////////////////////
        public static Boolean CheckTokenPrivilege(IntPtr hToken, String privilegeName, out Boolean exists, out Boolean enabled)
        {
            exists = false;
            enabled = false;
            ////////////////////////////////////////////////////////////////////////////////
            UInt32 TokenInfLength = 0;
            advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, IntPtr.Zero, 0, out TokenInfLength);
            if (TokenInfLength <= 0 || TokenInfLength > Int32.MaxValue)
            {
                Tokens.GetWin32Error("GetTokenInformation - 1 " + TokenInfLength);
                return false;
            }
            IntPtr lpTokenInformation = Marshal.AllocHGlobal((Int32)TokenInfLength);

            ////////////////////////////////////////////////////////////////////////////////
            if (!advapi32.GetTokenInformation(hToken, Winnt._TOKEN_INFORMATION_CLASS.TokenPrivileges, lpTokenInformation, TokenInfLength, out TokenInfLength))
            {
                Tokens.GetWin32Error("GetTokenInformation - 2 " + TokenInfLength);
                return false;
            }
            Winnt._TOKEN_PRIVILEGES_ARRAY tokenPrivileges = (Winnt._TOKEN_PRIVILEGES_ARRAY)Marshal.PtrToStructure(lpTokenInformation, typeof(Winnt._TOKEN_PRIVILEGES_ARRAY));
            Marshal.FreeHGlobal(lpTokenInformation);

            ////////////////////////////////////////////////////////////////////////////////
            for (Int32 i = 0; i < tokenPrivileges.PrivilegeCount; i++)
            {
                System.Text.StringBuilder lpName = new System.Text.StringBuilder();
                Int32 cchName = 0;
                IntPtr lpLuid = Marshal.AllocHGlobal(Marshal.SizeOf(tokenPrivileges.Privileges[i]));
                Marshal.StructureToPtr(tokenPrivileges.Privileges[i].Luid, lpLuid, true);
                try
                {
                    advapi32.LookupPrivilegeName(null, lpLuid, null, ref cchName);
                    if (cchName <= 0 || cchName > Int32.MaxValue)
                    {
                        Tokens.GetWin32Error("LookupPrivilegeName Pass 1");
                        continue;
                    }

                    lpName.EnsureCapacity(cchName + 1);
                    if (!advapi32.LookupPrivilegeName(null, lpLuid, lpName, ref cchName))
                    {
                        Tokens.GetWin32Error("LookupPrivilegeName Pass 2");
                        continue;
                    }

                    if (lpName.ToString() != privilegeName)
                    {
                        continue;
                    }
                    exists = true;

                    Winnt._PRIVILEGE_SET privilegeSet = new Winnt._PRIVILEGE_SET
                    {
                        PrivilegeCount = 1,
                        Control = Winnt.PRIVILEGE_SET_ALL_NECESSARY,
                        Privilege = new Winnt._LUID_AND_ATTRIBUTES[] { tokenPrivileges.Privileges[i] }
                    };

                    Int32 pfResult = 0;
                    if (!advapi32.PrivilegeCheck(hToken, ref privilegeSet, out pfResult))
                    {
                        Tokens.GetWin32Error("PrivilegeCheck");
                        continue;
                    }
                    enabled = Convert.ToBoolean(pfResult);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    return false;
                }
                finally
                {
                    Marshal.FreeHGlobal(lpLuid);
                }
            }
            Console.WriteLine();
            return false;
        }

        ////////////////////////////////////////////////////////////////////////////////
        // Private function to query a token with an enumeration result
        ////////////////////////////////////////////////////////////////////////////////
        private static Boolean _QueryTokenInformation(IntPtr hToken, Winnt._TOKEN_INFORMATION_CLASS informationClass, ref Int32 dwTokenInformation)
        {
            UInt32 tokenInformationLength = (UInt32)Marshal.SizeOf(typeof(UInt32));
            IntPtr lpTokenInformation = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UInt32)));
            try
            {
                UInt32 returnLength = 0;
                if (!advapi32.GetTokenInformation(hToken, informationClass, lpTokenInformation, tokenInformationLength, out returnLength))
                {
                    Tokens.GetWin32Error("GetTokenInformation");
                    return false;
                }
                dwTokenInformation = Marshal.ReadInt32(lpTokenInformation);
            }
            catch(Exception ex)
            {
                Tokens.GetWin32Error("GetTokenInformation");
                Console.WriteLine("[-] {0}", ex.Message);
                return false;
            }
            finally
            {
                Marshal.FreeHGlobal(lpTokenInformation);
            }
            return true;
        }
    }
}