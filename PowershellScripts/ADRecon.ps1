<#

.SYNOPSIS

    ADRecon is a tool which gathers information about the Active Directory and generates a report which can provide a holistic picture of the current state of the target AD environment.

.DESCRIPTION

    ADRecon is a tool which extracts and combines various artefacts (as highlighted below) out of an AD environment. The information can be presented in a specially formatted Microsoft Excel report that includes summary views with metrics to facilitate analysis and provide a holistic picture of the current state of the target AD environment.
    The tool is useful to various classes of security professionals like auditors, DFIR, students, administrators, etc. It can also be an invaluable post-exploitation tool for a penetration tester.
    It can be run from any workstation that is connected to the environment, even hosts that are not domain members. Furthermore, the tool can be executed in the context of a non-privileged (i.e. standard domain user) account.
    Fine Grained Password Policy, LAPS and BitLocker may require Privileged user accounts.
    The tool will use Microsoft Remote Server Administration Tools (RSAT) if available, otherwise it will communicate with the Domain Controller using LDAP.
    The following information is gathered by the tool:
    * Forest;
    * Domain;
    * Trusts;
    * Sites;
    * Subnets;
    * Schema History;
    * Default and Fine Grained Password Policy (if implemented);
    * Domain Controllers, SMB versions, whether SMB Signing is supported and FSMO roles;
    * Users and their attributes;
    * Service Principal Names (SPNs);
    * Groups, memberships and changes;
    * Organizational Units (OUs);
    * GroupPolicy objects and gPLink details;
    * DNS Zones and Records;
    * Printers;
    * Computers and their attributes;
    * PasswordAttributes (Experimental);
    * LAPS passwords (if implemented);
    * BitLocker Recovery Keys (if implemented);
    * ACLs (DACLs and SACLs) for the Domain, OUs, Root Containers, GPO, Users, Computers and Groups objects (not included in the default collection method);
    * GPOReport (requires RSAT);
    * Kerberoast (not included in the default collection method); and
    * Domain accounts used for service accounts (requires privileged account and not included in the default collection method).

    Author     : Prashant Mahajan

.NOTES

    The following commands can be used to turn off ExecutionPolicy: (Requires Admin Privs)

    PS > $ExecPolicy = Get-ExecutionPolicy
    PS > Set-ExecutionPolicy bypass
    PS > .\ADRecon.ps1
    PS > Set-ExecutionPolicy $ExecPolicy

    OR

    Start the PowerShell as follows:
    powershell.exe -ep bypass

    OR

    Already have a PowerShell open ?
    PS > $Env:PSExecutionPolicyPreference = 'Bypass'

    OR

    powershell.exe -nologo -executionpolicy bypass -noprofile -file ADRecon.ps1

.PARAMETER Method
	Which method to use; ADWS (default), LDAP

.PARAMETER DomainController
	Domain Controller IP Address or Domain FQDN.

.PARAMETER Credential
	Domain Credentials.

.PARAMETER GenExcel
	Path for ADRecon output folder containing the CSV files to generate the ADRecon-Report.xlsx. Use it to generate the ADRecon-Report.xlsx when Microsoft Excel is not installed on the host used to run ADRecon.

.PARAMETER OutputDir
	Path for ADRecon output folder to save the files and the ADRecon-Report.xlsx. (The folder specified will be created if it doesn't exist)

.PARAMETER Collect
    Which modules to run; Comma separated; e.g Forest,Domain (Default all except Kerberoast, DomainAccountsusedforServiceLogon)
    Valid values include: Forest, Domain, Trusts, Sites, Subnets, SchemaHistory, PasswordPolicy, FineGrainedPasswordPolicy, DomainControllers, Users, UserSPNs, PasswordAttributes, Groups, GroupChanges, GroupMembers, OUs, GPOs, gPLinks, DNSZones, DNSRecords, Printers, Computers, ComputerSPNs, LAPS, BitLocker, ACLs, GPOReport, Kerberoast, DomainAccountsusedforServiceLogon.

.PARAMETER OutputType
    Output Type; Comma seperated; e.g STDOUT,CSV,XML,JSON,HTML,Excel (Default STDOUT with -Collect parameter, else CSV and Excel).
    Valid values include: STDOUT, CSV, XML, JSON, HTML, Excel, All (excludes STDOUT).

.PARAMETER DormantTimeSpan
    Timespan for Dormant accounts. (Default 90 days)

.PARAMETER PassMaxAge
    Maximum machine account password age. (Default 30 days)

.PARAMETER PageSize
    The PageSize to set for the LDAP searcher object.

.PARAMETER Threads
    The number of threads to use during processing objects. (Default 10)

.PARAMETER OnlyEnabled
    Only collect details for enabled objects. (Default $false)

.PARAMETER Log
    Create ADRecon Log using Start-Transcript

.PARAMETER Logo
    Which Logo to use in the excel file? (Default ADRecon)
    Values include ADRecon, CyberCX, Payatu.

.EXAMPLE

	.\ADRecon.ps1 -GenExcel C:\ADRecon-Report-<timestamp>
    [*] ADRecon <version> by Prashant Mahajan (@prashant3535)
    [*] Generating ADRecon-Report.xlsx
    [+] Excelsheet Saved to: C:\ADRecon-Report-<timestamp>\<domain>-ADRecon-Report.xlsx

.EXAMPLE

	.\ADRecon.ps1 -DomainController <IP or FQDN> -Credential <domain\username>
    [*] ADRecon <version> by Prashant Mahajan (@prashant3535)
	[*] Running on <domain>\<hostname> - Member Workstation as <user>
    <snip>

    Example output from Domain Member with Alternate Credentials.

.EXAMPLE

	.\ADRecon.ps1 -DomainController <IP or FQDN> -Credential <domain\username> -Collect DomainControllers -OutputType Excel
    [*] ADRecon <version> by Prashant Mahajan (@prashant3535)
    [*] Running on WORKGROUP\<hostname> - Standalone Workstation as <user>
    [*] Commencing - <timestamp>
    [-] Domain Controllers
    [*] Total Execution Time (mins): <minutes>
    [*] Generating ADRecon-Report.xlsx
    [+] Excelsheet Saved to: C:\ADRecon-Report-<timestamp>\<domain>-ADRecon-Report.xlsx
    [*] Completed.
    [*] Output Directory: C:\ADRecon-Report-<timestamp>

    Example output from from a Non-Member using RSAT to only enumerate Domain Controllers.

.EXAMPLE

    .\ADRecon.ps1 -Method ADWS -DomainController <IP or FQDN> -Credential <domain\username>
    [*] ADRecon <version> by Prashant Mahajan (@prashant3535)
    [*] Running on WORKGROUP\<hostname> - Standalone Workstation as <user>
    [*] Commencing - <timestamp>
    [-] Domain
    [-] Forest
    [-] Trusts
    [-] Sites
    [-] Subnets
    [-] SchemaHistory - May take some time
    [-] Default Password Policy
    [-] Fine Grained Password Policy - May need a Privileged Account
    [-] Domain Controllers
    [-] Users and SPNs - May take some time
    [-] PasswordAttributes - Experimental
    [-] Groups and Membership Changes - May take some time
    [-] Group Memberships - May take some time
    [-] OrganizationalUnits (OUs)
    [-] GPOs
    [-] gPLinks - Scope of Management (SOM)
    [-] DNS Zones and Records
    [-] Printers
    [-] Computers and SPNs - May take some time
    [-] LAPS - Needs Privileged Account
    WARNING: [*] LAPS is not implemented.
    [-] BitLocker Recovery Keys - Needs Privileged Account
    [-] GPOReport - May take some time
    WARNING: [*] Run the tool using RUNAS.
    WARNING: [*] runas /user:<Domain FQDN>\<Username> /netonly powershell.exe
    [*] Total Execution Time (mins): <minutes>
    [*] Output Directory: C:\ADRecon-Report-<timestamp>
    [*] Generating ADRecon-Report.xlsx
    [+] Excelsheet Saved to: C:\ADRecon-Report-<timestamp>\<domain>-ADRecon-Report.xlsx

    Example output from a Non-Member using RSAT.

.EXAMPLE

    .\ADRecon.ps1 -Method LDAP -DomainController <IP or FQDN> -Credential <domain\username>
    [*] ADRecon <version> by Prashant Mahajan (@prashant3535)
    [*] Running on WORKGROUP\<hostname> - Standalone Workstation as <user>
    [*] LDAP bind Successful
    [*] Commencing - <timestamp>
    [-] Domain
    [-] Forest
    [-] Trusts
    [-] Sites
    [-] Subnets
    [-] SchemaHistory - May take some time
    [-] Default Password Policy
    [-] Fine Grained Password Policy - May need a Privileged Account
    [-] Domain Controllers
    [-] Users and SPNs - May take some time
    [-] PasswordAttributes - Experimental
    [-] Groups and Membership Changes - May take some time
    [-] Group Memberships - May take some time
    [-] OrganizationalUnits (OUs)
    [-] GPOs
    [-] gPLinks - Scope of Management (SOM)
    [-] DNS Zones and Records
    [-] Printers
    [-] Computers and SPNs - May take some time
    [-] LAPS - Needs Privileged Account
    WARNING: [*] LAPS is not implemented.
    [-] BitLocker Recovery Keys - Needs Privileged Account
    [-] GPOReport - May take some time
    WARNING: [*] Currently, the module is only supported with ADWS.
    [*] Total Execution Time (mins): <minutes>
    [*] Output Directory: C:\ADRecon-Report-<timestamp>
    [*] Generating ADRecon-Report.xlsx
    [+] Excelsheet Saved to: C:\ADRecon-Report-<timestamp>\<domain>-ADRecon-Report.xlsx

    Example output from a Non-Member using LDAP.

.LINK

    https://github.com/adrecon/ADRecon
#>

[CmdletBinding()]
param
(
    [Parameter(Mandatory = $false, HelpMessage = "Which method to use; ADWS (default), LDAP")]
    [ValidateSet('ADWS', 'LDAP')]
    [string] $Method = 'ADWS',

    [Parameter(Mandatory = $false, HelpMessage = "Domain Controller IP Address or Domain FQDN.")]
    [string] $DomainController = '',

    [Parameter(Mandatory = $false, HelpMessage = "Domain Credentials.")]
    [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

    [Parameter(Mandatory = $false, HelpMessage = "Path for ADRecon output folder containing the CSV files to generate the ADRecon-Report.xlsx. Use it to generate the ADRecon-Report.xlsx when Microsoft Excel is not installed on the host used to run ADRecon.")]
    [string] $GenExcel,

    [Parameter(Mandatory = $false, HelpMessage = "Path for ADRecon output folder to save the CSV/XML/JSON/HTML files and the ADRecon-Report.xlsx. (The folder specified will be created if it doesn't exist)")]
    [string] $OutputDir,

    [Parameter(Mandatory = $false, HelpMessage = "Which modules to run; Comma separated; e.g Forest,Domain (Default all except ACLs, Kerberoast and DomainAccountsusedforServiceLogon) Valid values include: Forest, Domain, Trusts, Sites, Subnets, SchemaHistory, PasswordPolicy, FineGrainedPasswordPolicy, DomainControllers, Users, UserSPNs, PasswordAttributes, Groups, GroupChanges, GroupMembers, OUs, GPOs, gPLinks, DNSZones, DNSRecords, Printers, Computers, ComputerSPNs, LAPS, BitLocker, ACLs, GPOReport, Kerberoast, DomainAccountsusedforServiceLogon")]
    [ValidateSet('Forest', 'Domain', 'Trusts', 'Sites', 'Subnets', 'SchemaHistory', 'PasswordPolicy', 'FineGrainedPasswordPolicy', 'DomainControllers', 'Users', 'UserSPNs', 'PasswordAttributes', 'Groups', 'GroupChanges', 'GroupMembers', 'OUs', 'GPOs', 'gPLinks', 'DNSZones', 'DNSRecords', 'Printers', 'Computers', 'ComputerSPNs', 'LAPS', 'BitLocker', 'ACLs', 'GPOReport', 'Kerberoast', 'DomainAccountsusedforServiceLogon', 'Default')]
    [array] $Collect = 'Default',

    [Parameter(Mandatory = $false, HelpMessage = "Output type; Comma seperated; e.g STDOUT,CSV,XML,JSON,HTML,Excel (Default STDOUT with -Collect parameter, else CSV and Excel)")]
    [ValidateSet('STDOUT', 'CSV', 'XML', 'JSON', 'EXCEL', 'HTML', 'All', 'Default')]
    [array] $OutputType = 'Default',

    [Parameter(Mandatory = $false, HelpMessage = "Timespan for Dormant accounts. Default 90 days")]
    [ValidateRange(1,1000)]
    [int] $DormantTimeSpan = 90,

    [Parameter(Mandatory = $false, HelpMessage = "Maximum machine account password age. Default 30 days")]
    [ValidateRange(1,1000)]
    [int] $PassMaxAge = 30,

    [Parameter(Mandatory = $false, HelpMessage = "The PageSize to set for the LDAP searcher object. Default 200")]
    [ValidateRange(1,10000)]
    [int] $PageSize = 200,

    [Parameter(Mandatory = $false, HelpMessage = "The number of threads to use during processing of objects. Default 10")]
    [ValidateRange(1,100)]
    [int] $Threads = 10,

    [Parameter(Mandatory = $false, HelpMessage = "Only collect details for enabled objects. Default `$false")]
    [bool] $OnlyEnabled = $false,

    [Parameter(Mandatory = $false, HelpMessage = "Create ADRecon Log using Start-Transcript.")]
    [switch] $Log,

    [Parameter(Mandatory = $false, HelpMessage = "Which Logo to use in the excel file? Default ADRecon")]
    [ValidateSet('ADRecon', 'CyberCX', 'Payatu')]
    [string] $Logo = "ADRecon"
)

$ADWSSource = @"
// Thanks Dennis Albuquerque for the C# multithreading code
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Threading;
using System.DirectoryServices;
//using System.Security.Principal;
using System.Security.AccessControl;
using System.Management.Automation;

using System.Diagnostics;
//using System.IO;
//using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Runtime.InteropServices;

namespace ADRecon
{
    public static class ADWSClass
    {
        private static DateTime Date1;
        private static int PassMaxAge;
        private static int DormantTimeSpan;
        private static Dictionary<string, string> AdGroupDictionary = new Dictionary<string, string>();
        private static string DomainSID;
        private static Dictionary<string, string> AdGPODictionary = new Dictionary<string, string>();
        private static Hashtable GUIDs = new Hashtable();
        private static Dictionary<string, string> AdSIDDictionary = new Dictionary<string, string>();
        private static readonly HashSet<string> Groups = new HashSet<string> ( new string[] {"268435456", "268435457", "536870912", "536870913"} );
        private static readonly HashSet<string> Users = new HashSet<string> ( new string[] { "805306368" } );
        private static readonly HashSet<string> Computers = new HashSet<string> ( new string[] { "805306369" }) ;
        private static readonly HashSet<string> TrustAccounts = new HashSet<string> ( new string[] { "805306370" } );

        [Flags]
        //Values taken from https://support.microsoft.com/en-au/kb/305144
        public enum UACFlags
        {
            SCRIPT = 1,        // 0x1
            ACCOUNTDISABLE = 2,        // 0x2
            HOMEDIR_REQUIRED = 8,        // 0x8
            LOCKOUT = 16,       // 0x10
            PASSWD_NOTREQD = 32,       // 0x20
            PASSWD_CANT_CHANGE = 64,       // 0x40
            ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128,      // 0x80
            TEMP_DUPLICATE_ACCOUNT = 256,      // 0x100
            NORMAL_ACCOUNT = 512,      // 0x200
            INTERDOMAIN_TRUST_ACCOUNT = 2048,     // 0x800
            WORKSTATION_TRUST_ACCOUNT = 4096,     // 0x1000
            SERVER_TRUST_ACCOUNT = 8192,     // 0x2000
            DONT_EXPIRE_PASSWD = 65536,    // 0x10000
            MNS_LOGON_ACCOUNT = 131072,   // 0x20000
            SMARTCARD_REQUIRED = 262144,   // 0x40000
            TRUSTED_FOR_DELEGATION = 524288,   // 0x80000
            NOT_DELEGATED = 1048576,  // 0x100000
            USE_DES_KEY_ONLY = 2097152,  // 0x200000
            DONT_REQUIRE_PREAUTH = 4194304,  // 0x400000
            PASSWORD_EXPIRED = 8388608,  // 0x800000
            TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216, // 0x1000000
            PARTIAL_SECRETS_ACCOUNT = 67108864 // 0x04000000
        }

        [Flags]
        //Values taken from https://blogs.msdn.microsoft.com/openspecification/2011/05/30/windows-configurations-for-kerberos-supported-encryption-type/
        public enum KerbEncFlags
        {
            ZERO = 0,
            DES_CBC_CRC = 1,        // 0x1
            DES_CBC_MD5 = 2,        // 0x2
            RC4_HMAC = 4,        // 0x4
            AES128_CTS_HMAC_SHA1_96 = 8,       // 0x18
            AES256_CTS_HMAC_SHA1_96 = 16       // 0x10
        }

		private static readonly Dictionary<string, string> Replacements = new Dictionary<string, string>()
        {
            //{System.Environment.NewLine, ""},
            //{",", ";"},
            {"\"", "'"}
        };

        public static string CleanString(Object StringtoClean)
        {
            // Remove extra spaces and new lines
            string CleanedString = string.Join(" ", ((Convert.ToString(StringtoClean)).Split((string[]) null, StringSplitOptions.RemoveEmptyEntries)));
            foreach (string Replacement in Replacements.Keys)
            {
                CleanedString = CleanedString.Replace(Replacement, Replacements[Replacement]);
            }
            return CleanedString;
        }

        public static int ObjectCount(Object[] ADRObject)
        {
            return ADRObject.Length;
        }

        public static Object[] DomainControllerParser(Object[] AdDomainControllers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdDomainControllers, numOfThreads, "DomainControllers");
            return ADRObj;
        }

        public static Object[] SchemaParser(Object[] AdSchemas, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdSchemas, numOfThreads, "SchemaHistory");
            return ADRObj;
        }

        public static Object[] UserParser(Object[] AdUsers, DateTime Date1, int DormantTimeSpan, int PassMaxAge, int numOfThreads)
        {
            ADWSClass.Date1 = Date1;
            ADWSClass.DormantTimeSpan = DormantTimeSpan;
            ADWSClass.PassMaxAge = PassMaxAge;

            Object[] ADRObj = runProcessor(AdUsers, numOfThreads, "Users");
            return ADRObj;
        }

        public static Object[] UserSPNParser(Object[] AdUsers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdUsers, numOfThreads, "UserSPNs");
            return ADRObj;
        }

        public static Object[] GroupParser(Object[] AdGroups, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdGroups, numOfThreads, "Groups");
            return ADRObj;
        }

        public static Object[] GroupChangeParser(Object[] AdGroups, DateTime Date1, int numOfThreads)
        {
            ADWSClass.Date1 = Date1;
            Object[] ADRObj = runProcessor(AdGroups, numOfThreads, "GroupChanges");
            return ADRObj;
        }

        public static Object[] GroupMemberParser(Object[] AdGroups, Object[] AdGroupMembers, string DomainSID, int numOfThreads)
        {
            ADWSClass.AdGroupDictionary = new Dictionary<string, string>();
            runProcessor(AdGroups, numOfThreads, "GroupsDictionary");
            ADWSClass.DomainSID = DomainSID;
            Object[] ADRObj = runProcessor(AdGroupMembers, numOfThreads, "GroupMembers");
            return ADRObj;
        }

        public static Object[] OUParser(Object[] AdOUs, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdOUs, numOfThreads, "OUs");
            return ADRObj;
        }

        public static Object[] GPOParser(Object[] AdGPOs, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdGPOs, numOfThreads, "GPOs");
            return ADRObj;
        }

        public static Object[] SOMParser(Object[] AdGPOs, Object[] AdSOMs, int numOfThreads)
        {
            ADWSClass.AdGPODictionary = new Dictionary<string, string>();
            runProcessor(AdGPOs, numOfThreads, "GPOsDictionary");
            Object[] ADRObj = runProcessor(AdSOMs, numOfThreads, "SOMs");
            return ADRObj;
        }

        public static Object[] PrinterParser(Object[] ADPrinters, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(ADPrinters, numOfThreads, "Printers");
            return ADRObj;
        }

        public static Object[] ComputerParser(Object[] AdComputers, DateTime Date1, int DormantTimeSpan, int PassMaxAge, int numOfThreads)
        {
            ADWSClass.Date1 = Date1;
            ADWSClass.DormantTimeSpan = DormantTimeSpan;
            ADWSClass.PassMaxAge = PassMaxAge;

            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "Computers");
            return ADRObj;
        }

        public static Object[] ComputerSPNParser(Object[] AdComputers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "ComputerSPNs");
            return ADRObj;
        }

        public static Object[] LAPSParser(Object[] AdComputers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "LAPS");
            return ADRObj;
        }

        public static Object[] DACLParser(Object[] ADObjects, Object PSGUIDs, int numOfThreads)
        {
            ADWSClass.AdSIDDictionary = new Dictionary<string, string>();
            runProcessor(ADObjects, numOfThreads, "SIDDictionary");
            ADWSClass.GUIDs = (Hashtable) PSGUIDs;
            Object[] ADRObj = runProcessor(ADObjects, numOfThreads, "DACLs");
            return ADRObj;
        }

        public static Object[] SACLParser(Object[] ADObjects, Object PSGUIDs, int numOfThreads)
        {
            ADWSClass.GUIDs = (Hashtable) PSGUIDs;
            Object[] ADRObj = runProcessor(ADObjects, numOfThreads, "SACLs");
            return ADRObj;
        }

        static Object[] runProcessor(Object[] arrayToProcess, int numOfThreads, string processorType)
        {
            int totalRecords = arrayToProcess.Length;
            IRecordProcessor recordProcessor = recordProcessorFactory(processorType);
            IResultsHandler resultsHandler = new SimpleResultsHandler ();
            int numberOfRecordsPerThread = totalRecords / numOfThreads;
            int remainders = totalRecords % numOfThreads;

            Thread[] threads = new Thread[numOfThreads];
            for (int i = 0; i < numOfThreads; i++)
            {
                int numberOfRecordsToProcess = numberOfRecordsPerThread;
                if (i == (numOfThreads - 1))
                {
                    //last thread, do the remaining records
                    numberOfRecordsToProcess += remainders;
                }

                //split the full array into chunks to be given to different threads
                Object[] sliceToProcess = new Object[numberOfRecordsToProcess];
                Array.Copy(arrayToProcess, i * numberOfRecordsPerThread, sliceToProcess, 0, numberOfRecordsToProcess);
                ProcessorThread processorThread = new ProcessorThread(i, recordProcessor, resultsHandler, sliceToProcess);
                threads[i] = new Thread(processorThread.processThreadRecords);
                threads[i].Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }

            return resultsHandler.finalise();
        }

        static IRecordProcessor recordProcessorFactory(string name)
        {
            switch (name)
            {
                case "DomainControllers":
                    return new DomainControllerRecordProcessor();
                case "SchemaHistory":
                    return new SchemaRecordProcessor();
                case "Users":
                    return new UserRecordProcessor();
                case "UserSPNs":
                    return new UserSPNRecordProcessor();
                case "Groups":
                    return new GroupRecordProcessor();
                case "GroupChanges":
                    return new GroupChangeRecordProcessor();
                case "GroupsDictionary":
                    return new GroupRecordDictionaryProcessor();
                case "GroupMembers":
                    return new GroupMemberRecordProcessor();
                case "OUs":
                    return new OURecordProcessor();
                case "GPOs":
                    return new GPORecordProcessor();
                case "GPOsDictionary":
                    return new GPORecordDictionaryProcessor();
                case "SOMs":
                    return new SOMRecordProcessor();
                case "Printers":
                    return new PrinterRecordProcessor();
                case "Computers":
                    return new ComputerRecordProcessor();
                case "ComputerSPNs":
                    return new ComputerSPNRecordProcessor();
                case "LAPS":
                    return new LAPSRecordProcessor();
                case "SIDDictionary":
                    return new SIDRecordDictionaryProcessor();
                case "DACLs":
                    return new DACLRecordProcessor();
                case "SACLs":
                    return new SACLRecordProcessor();
            }
            throw new ArgumentException("Invalid processor type " + name);
        }

        class ProcessorThread
        {
            readonly int id;
            readonly IRecordProcessor recordProcessor;
            readonly IResultsHandler resultsHandler;
            readonly Object[] objectsToBeProcessed;

            public ProcessorThread(int id, IRecordProcessor recordProcessor, IResultsHandler resultsHandler, Object[] objectsToBeProcessed)
            {
                this.recordProcessor = recordProcessor;
                this.id = id;
                this.resultsHandler = resultsHandler;
                this.objectsToBeProcessed = objectsToBeProcessed;
            }

            public void processThreadRecords()
            {
                for (int i = 0; i < objectsToBeProcessed.Length; i++)
                {
                    Object[] result = recordProcessor.processRecord(objectsToBeProcessed[i]);
                    resultsHandler.processResults(result); //this is a thread safe operation
                }
            }
        }

        //The interface and implmentation class used to process a record (this implemmentation just returns a log type string)

        interface IRecordProcessor
        {
            PSObject[] processRecord(Object record);
        }

        class DomainControllerRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdDC = (PSObject) record;
                    bool Infra = false;
                    bool Naming = false;
                    bool Schema = false;
                    bool RID = false;
                    bool PDC = false;
                    PSObject DCSMBObj = new PSObject();

                    string OperatingSystem = CleanString((AdDC.Members["OperatingSystem"].Value != null ? AdDC.Members["OperatingSystem"].Value : "-") + " " + AdDC.Members["OperatingSystemHotfix"].Value + " " + AdDC.Members["OperatingSystemServicePack"].Value + " " + AdDC.Members["OperatingSystemVersion"].Value);

                    foreach (var OperationMasterRole in (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdDC.Members["OperationMasterRoles"].Value)
                    {
                        switch (OperationMasterRole.ToString())
                        {
                            case "InfrastructureMaster":
                            Infra = true;
                            break;
                            case "DomainNamingMaster":
                            Naming = true;
                            break;
                            case "SchemaMaster":
                            Schema = true;
                            break;
                            case "RIDMaster":
                            RID = true;
                            break;
                            case "PDCEmulator":
                            PDC = true;
                            break;
                        }
                    }
                    PSObject DCObj = new PSObject();
                    DCObj.Members.Add(new PSNoteProperty("Domain", AdDC.Members["Domain"].Value));
                    DCObj.Members.Add(new PSNoteProperty("Site", AdDC.Members["Site"].Value));
                    DCObj.Members.Add(new PSNoteProperty("Name", AdDC.Members["Name"].Value));
                    DCObj.Members.Add(new PSNoteProperty("IPv4Address", AdDC.Members["IPv4Address"].Value));
                    DCObj.Members.Add(new PSNoteProperty("Operating System", OperatingSystem));
                    DCObj.Members.Add(new PSNoteProperty("Hostname", AdDC.Members["HostName"].Value));
                    DCObj.Members.Add(new PSNoteProperty("Infra", Infra));
                    DCObj.Members.Add(new PSNoteProperty("Naming", Naming));
                    DCObj.Members.Add(new PSNoteProperty("Schema", Schema));
                    DCObj.Members.Add(new PSNoteProperty("RID", RID));
                    DCObj.Members.Add(new PSNoteProperty("PDC", PDC));
                    if (AdDC.Members["IPv4Address"].Value != null)
                    {
                        DCSMBObj = GetPSObject(AdDC.Members["IPv4Address"].Value);
                    }
                    else
                    {
                        DCSMBObj = new PSObject();
                        DCSMBObj.Members.Add(new PSNoteProperty("SMB Port Open", false));
                    }
                    foreach (PSPropertyInfo psPropertyInfo in DCSMBObj.Properties)
                    {
                        if (Convert.ToString(psPropertyInfo.Name) == "SMB Port Open" && (bool) psPropertyInfo.Value == false)
                        {
                            DCObj.Members.Add(new PSNoteProperty(psPropertyInfo.Name, psPropertyInfo.Value));
                            DCObj.Members.Add(new PSNoteProperty("SMB1(NT LM 0.12)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB2(0x0202)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB2(0x0210)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB3(0x0300)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB3(0x0302)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB3(0x0311)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB Signing", null));
                            break;
                        }
                        else
                        {
                            DCObj.Members.Add(new PSNoteProperty(psPropertyInfo.Name, psPropertyInfo.Value));
                        }
                    }
                    return new PSObject[] { DCObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("{0} Exception caught.", e);
                    return new PSObject[] { };
                }
            }
        }

        class SchemaRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdSchema = (PSObject) record;

                    PSObject SchemaObj = new PSObject();
                    SchemaObj.Members.Add(new PSNoteProperty("ObjectClass", AdSchema.Members["ObjectClass"].Value));
                    SchemaObj.Members.Add(new PSNoteProperty("Name", AdSchema.Members["Name"].Value));
                    SchemaObj.Members.Add(new PSNoteProperty("whenCreated", AdSchema.Members["whenCreated"].Value));
                    SchemaObj.Members.Add(new PSNoteProperty("whenChanged", AdSchema.Members["whenChanged"].Value));
                    SchemaObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSchema.Members["DistinguishedName"].Value));
                    return new PSObject[] { SchemaObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class UserRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdUser = (PSObject) record;
                    bool? Enabled = null;
                    bool MustChangePasswordatLogon = false;
                    bool PasswordNotChangedafterMaxAge = false;
                    bool NeverLoggedIn = false;
                    int? DaysSinceLastLogon = null;
                    int? DaysSinceLastPasswordChange = null;
                    int? AccountExpirationNumofDays = null;
                    bool Dormant = false;
                    string SIDHistory = "";
                    bool? KerberosRC4 = null;
                    bool? KerberosAES128 = null;
                    bool? KerberosAES256 = null;
                    string DelegationType = null;
                    string DelegationProtocol = null;
                    string DelegationServices = null;
                    DateTime? LastLogonDate = null;
                    DateTime? PasswordLastSet = null;
                    DateTime? AccountExpires = null;
                    bool? AccountNotDelegated = null;
                    bool? HasSPN = null;

                    try
                    {
                        // The Enabled field can be blank which raises an exception. This may occur when the user is not allowed to query the UserAccountControl attribute.
                        Enabled = (bool) AdUser.Members["Enabled"].Value;
                    }
                    catch //(Exception e)
                    {
                        //Console.WriteLine("Exception caught: {0}", e);
                    }
                    if (AdUser.Members["lastLogonTimeStamp"].Value != null)
                    {
                        //LastLogonDate = DateTime.FromFileTime((long)(AdUser.Members["lastLogonTimeStamp"].Value));
                        // LastLogonDate is lastLogonTimeStamp converted to local time
                        LastLogonDate = Convert.ToDateTime(AdUser.Members["LastLogonDate"].Value);
                        DaysSinceLastLogon = Math.Abs((Date1 - (DateTime)LastLogonDate).Days);
                        if (DaysSinceLastLogon > DormantTimeSpan)
                        {
                            Dormant = true;
                        }
                    }
                    else
                    {
                        NeverLoggedIn = true;
                    }
                    if (Convert.ToString(AdUser.Members["pwdLastSet"].Value) == "0")
                    {
                        if ((bool) AdUser.Members["PasswordNeverExpires"].Value == false)
                        {
                            MustChangePasswordatLogon = true;
                        }
                    }
                    if (AdUser.Members["PasswordLastSet"].Value != null)
                    {
                        //PasswordLastSet = DateTime.FromFileTime((long)(AdUser.Members["pwdLastSet"].Value));
                        // PasswordLastSet is pwdLastSet converted to local time
                        PasswordLastSet = Convert.ToDateTime(AdUser.Members["PasswordLastSet"].Value);
                        DaysSinceLastPasswordChange = Math.Abs((Date1 - (DateTime)PasswordLastSet).Days);
                        if (DaysSinceLastPasswordChange > PassMaxAge)
                        {
                            PasswordNotChangedafterMaxAge = true;
                        }
                    }
                    //https://msdn.microsoft.com/en-us/library/ms675098(v=vs.85).aspx
                    //if ((Int64) AdUser.Members["accountExpires"].Value != (Int64) 9223372036854775807)
                    //{
                        //if ((Int64) AdUser.Members["accountExpires"].Value != (Int64) 0)
                        if (AdUser.Members["AccountExpirationDate"].Value != null)
                        {
                            try
                            {
                                //AccountExpires = DateTime.FromFileTime((long)(AdUser.Members["accountExpires"].Value));
                                // AccountExpirationDate is accountExpires converted to local time
                                AccountExpires = Convert.ToDateTime(AdUser.Members["AccountExpirationDate"].Value);
                                AccountExpirationNumofDays = ((int)((DateTime)AccountExpires - Date1).Days);

                            }
                            catch //(Exception e)
                            {
                                //Console.WriteLine("Exception caught: {0}", e);
                            }
                        }
                    //}
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection history = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdUser.Members["SIDHistory"].Value;
                    string sids = "";
                    foreach (var value in history)
                    {
                        sids = sids + "," + Convert.ToString(value);
                    }
                    SIDHistory = sids.TrimStart(',');
                    if (AdUser.Members["msDS-SupportedEncryptionTypes"].Value != null)
                    {
                        var userKerbEncFlags = (KerbEncFlags) AdUser.Members["msDS-SupportedEncryptionTypes"].Value;
                        if (userKerbEncFlags != KerbEncFlags.ZERO)
                        {
                            KerberosRC4 = (userKerbEncFlags & KerbEncFlags.RC4_HMAC) == KerbEncFlags.RC4_HMAC;
                            KerberosAES128 = (userKerbEncFlags & KerbEncFlags.AES128_CTS_HMAC_SHA1_96) == KerbEncFlags.AES128_CTS_HMAC_SHA1_96;
                            KerberosAES256 = (userKerbEncFlags & KerbEncFlags.AES256_CTS_HMAC_SHA1_96) == KerbEncFlags.AES256_CTS_HMAC_SHA1_96;
                        }
                    }
                    if (AdUser.Members["UserAccountControl"].Value != null)
                    {
                        AccountNotDelegated = !((bool) AdUser.Members["AccountNotDelegated"].Value);
                        if ((bool) AdUser.Members["TrustedForDelegation"].Value)
                        {
                            DelegationType = "Unconstrained";
                            DelegationServices = "Any";
                        }
                        if (AdUser.Members["msDS-AllowedToDelegateTo"] != null)
                        {
                            Microsoft.ActiveDirectory.Management.ADPropertyValueCollection delegateto = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdUser.Members["msDS-AllowedToDelegateTo"].Value;
                            if (delegateto.Value != null)
                            {
                                DelegationType = "Constrained";
                                foreach (var value in delegateto)
                                {
                                    DelegationServices = DelegationServices + "," + Convert.ToString(value);
                                }
                                DelegationServices = DelegationServices.TrimStart(',');
                            }
                        }
                        if ((bool) AdUser.Members["TrustedToAuthForDelegation"].Value == true)
                        {
                            DelegationProtocol = "Any";
                        }
                        else if (DelegationType != null)
                        {
                            DelegationProtocol = "Kerberos";
                        }
                    }

                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection SPNs = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdUser.Members["servicePrincipalName"].Value;
                    if (SPNs.Value == null)
                    {
                        HasSPN = false;
                    }
                    else
                    {
                        HasSPN = true;
                    }

                    PSObject UserObj = new PSObject();
                    UserObj.Members.Add(new PSNoteProperty("UserName", CleanString(AdUser.Members["SamAccountName"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Name", CleanString(AdUser.Members["Name"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                    UserObj.Members.Add(new PSNoteProperty("Must Change Password at Logon", MustChangePasswordatLogon));
                    UserObj.Members.Add(new PSNoteProperty("Cannot Change Password", AdUser.Members["CannotChangePassword"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Password Never Expires", AdUser.Members["PasswordNeverExpires"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Reversible Password Encryption", AdUser.Members["AllowReversiblePasswordEncryption"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Smartcard Logon Required", AdUser.Members["SmartcardLogonRequired"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Permitted", AccountNotDelegated));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos DES Only", AdUser.Members["UseDESKeyOnly"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos RC4", KerberosRC4));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos AES-128bit", KerberosAES128));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos AES-256bit", KerberosAES256));
                    UserObj.Members.Add(new PSNoteProperty("Does Not Require Pre Auth", AdUser.Members["DoesNotRequirePreAuth"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Never Logged in", NeverLoggedIn));
                    UserObj.Members.Add(new PSNoteProperty("Logon Age (days)", DaysSinceLastLogon));
                    UserObj.Members.Add(new PSNoteProperty("Password Age (days)", DaysSinceLastPasswordChange));
                    UserObj.Members.Add(new PSNoteProperty("Dormant (> " + DormantTimeSpan + " days)", Dormant));
                    UserObj.Members.Add(new PSNoteProperty("Password Age (> " + PassMaxAge + " days)", PasswordNotChangedafterMaxAge));
                    UserObj.Members.Add(new PSNoteProperty("Account Locked Out", AdUser.Members["LockedOut"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Password Expired", AdUser.Members["PasswordExpired"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Password Not Required", AdUser.Members["PasswordNotRequired"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Type", DelegationType));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Protocol", DelegationProtocol));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Services", DelegationServices));
                    UserObj.Members.Add(new PSNoteProperty("Logon Workstations", AdUser.Members["LogonWorkstations"].Value));
                    UserObj.Members.Add(new PSNoteProperty("AdminCount", AdUser.Members["AdminCount"].Value));
                    UserObj.Members.Add(new PSNoteProperty("Primary GroupID", AdUser.Members["primaryGroupID"].Value));
                    UserObj.Members.Add(new PSNoteProperty("SID", AdUser.Members["SID"].Value));
                    UserObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    UserObj.Members.Add(new PSNoteProperty("HasSPN", HasSPN));
                    UserObj.Members.Add(new PSNoteProperty("Description", CleanString(AdUser.Members["Description"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Title", CleanString(AdUser.Members["Title"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Department", CleanString(AdUser.Members["Department"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Company", CleanString(AdUser.Members["Company"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Manager", CleanString(AdUser.Members["Manager"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Info", CleanString(AdUser.Members["Info"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Last Logon Date", LastLogonDate));
                    UserObj.Members.Add(new PSNoteProperty("Password LastSet", PasswordLastSet));
                    UserObj.Members.Add(new PSNoteProperty("Account Expiration Date", AccountExpires));
                    UserObj.Members.Add(new PSNoteProperty("Account Expiration (days)", AccountExpirationNumofDays));
                    UserObj.Members.Add(new PSNoteProperty("Mobile", CleanString(AdUser.Members["Mobile"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Email", CleanString(AdUser.Members["mail"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("HomeDirectory", AdUser.Members["homeDirectory"].Value));
                    UserObj.Members.Add(new PSNoteProperty("ProfilePath", AdUser.Members["profilePath"].Value));
                    UserObj.Members.Add(new PSNoteProperty("ScriptPath", AdUser.Members["ScriptPath"].Value));
                    UserObj.Members.Add(new PSNoteProperty("UserAccountControl", AdUser.Members["UserAccountControl"].Value));
                    UserObj.Members.Add(new PSNoteProperty("First Name", CleanString(AdUser.Members["givenName"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Middle Name", CleanString(AdUser.Members["middleName"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Last Name", CleanString(AdUser.Members["sn"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("Country", CleanString(AdUser.Members["c"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("whenCreated", AdUser.Members["whenCreated"].Value));
                    UserObj.Members.Add(new PSNoteProperty("whenChanged", AdUser.Members["whenChanged"].Value));
                    UserObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdUser.Members["DistinguishedName"].Value)));
                    UserObj.Members.Add(new PSNoteProperty("CanonicalName", CleanString(AdUser.Members["CanonicalName"].Value)));
                    return new PSObject[] { UserObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class UserSPNRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdUser = (PSObject) record;
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection SPNs = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdUser.Members["servicePrincipalName"].Value;
                    if (SPNs.Value == null)
                    {
                        return new PSObject[] { };
                    }
                    List<PSObject> SPNList = new List<PSObject>();
                    bool? Enabled = null;
                    string Memberof = null;
                    DateTime? PasswordLastSet = null;

                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdUser.Members["userAccountControl"].Value != null)
                    {
                        var userFlags = (UACFlags) AdUser.Members["userAccountControl"].Value;
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                    }
                    if (Convert.ToString(AdUser.Members["pwdLastSet"].Value) != "0")
                    {
                        PasswordLastSet = DateTime.FromFileTime((long)AdUser.Members["pwdLastSet"].Value);
                    }
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection MemberOfAttribute = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdUser.Members["memberof"].Value;
                    if (MemberOfAttribute.Value != null)
                    {
                        foreach (string Member in MemberOfAttribute)
                        {
                            Memberof = Memberof + "," + ((Convert.ToString(Member)).Split(',')[0]).Split('=')[1];
                        }
                        Memberof = Memberof.TrimStart(',');
                    }
                    string Description = CleanString(AdUser.Members["Description"].Value);
                    string PrimaryGroupID = Convert.ToString(AdUser.Members["primaryGroupID"].Value);
                    foreach (string SPN in SPNs)
                    {
                        string[] SPNArray = SPN.Split('/');
                        PSObject UserSPNObj = new PSObject();
                        UserSPNObj.Members.Add(new PSNoteProperty("Username", CleanString(AdUser.Members["SamAccountName"].Value)));
                        UserSPNObj.Members.Add(new PSNoteProperty("Name", CleanString(AdUser.Members["Name"].Value)));
                        UserSPNObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                        UserSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Password Last Set", PasswordLastSet));
                        UserSPNObj.Members.Add(new PSNoteProperty("Description", Description));
                        UserSPNObj.Members.Add(new PSNoteProperty("Primary GroupID", PrimaryGroupID));
                        UserSPNObj.Members.Add(new PSNoteProperty("Memberof", Memberof));
                        SPNList.Add( UserSPNObj );
                    }
                    return SPNList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdGroup = (PSObject) record;
                    string ManagedByValue = Convert.ToString(AdGroup.Members["managedBy"].Value);
                    string ManagedBy = "";
                    string SIDHistory = "";

                    if (AdGroup.Members["managedBy"].Value != null)
                    {
                        ManagedBy = (ManagedByValue.Split(new string[] { "CN=" },StringSplitOptions.RemoveEmptyEntries))[0].Split(new string[] { "OU=" },StringSplitOptions.RemoveEmptyEntries)[0].TrimEnd(',');
                    }
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection history = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdGroup.Members["SIDHistory"].Value;
                    string sids = "";
                    foreach (var value in history)
                    {
                        sids = sids + "," + Convert.ToString(value);
                    }
                    SIDHistory = sids.TrimStart(',');

                    PSObject GroupObj = new PSObject();
                    GroupObj.Members.Add(new PSNoteProperty("Name", AdGroup.Members["SamAccountName"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("AdminCount", AdGroup.Members["AdminCount"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("GroupCategory", AdGroup.Members["GroupCategory"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("GroupScope", AdGroup.Members["GroupScope"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("ManagedBy", ManagedBy));
                    GroupObj.Members.Add(new PSNoteProperty("SID", AdGroup.Members["sid"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    GroupObj.Members.Add(new PSNoteProperty("Description", CleanString(AdGroup.Members["Description"].Value)));
                    GroupObj.Members.Add(new PSNoteProperty("whenCreated", AdGroup.Members["whenCreated"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("whenChanged", AdGroup.Members["whenChanged"].Value));
                    GroupObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdGroup.Members["DistinguishedName"].Value)));
                    GroupObj.Members.Add(new PSNoteProperty("CanonicalName", AdGroup.Members["CanonicalName"].Value));
                    return new PSObject[] { GroupObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupChangeRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdGroup = (PSObject) record;
                    string Action = null;
                    int? DaysSinceAdded = null;
                    int? DaysSinceRemoved = null;
                    DateTime? AddedDate = null;
                    DateTime? RemovedDate = null;
                    List<PSObject> GroupChangesList = new List<PSObject>();

                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection ReplValueMetaData = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdGroup.Members["msDS-ReplValueMetaData"].Value;

                    if (ReplValueMetaData.Value != null)
                    {
                        foreach (string ReplData in ReplValueMetaData)
                        {
                            XmlDocument ReplXML = new XmlDocument();
                            ReplXML.LoadXml(ReplData.Replace("\x00", "").Replace("&","&amp;"));

                            if (ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeDeleted"].InnerText != "1601-01-01T00:00:00Z")
                            {
                                Action = "Removed";
                                AddedDate = DateTime.Parse(ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeCreated"].InnerText);
                                DaysSinceAdded = Math.Abs((Date1 - (DateTime) AddedDate).Days);
                                RemovedDate = DateTime.Parse(ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeDeleted"].InnerText);
                                DaysSinceRemoved = Math.Abs((Date1 - (DateTime) RemovedDate).Days);
                            }
                            else
                            {
                                Action = "Added";
                                AddedDate = DateTime.Parse(ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeCreated"].InnerText);
                                DaysSinceAdded = Math.Abs((Date1 - (DateTime) AddedDate).Days);
                                RemovedDate = null;
                                DaysSinceRemoved = null;
                            }

                            PSObject GroupChangeObj = new PSObject();
                            GroupChangeObj.Members.Add(new PSNoteProperty("Group Name", AdGroup.Members["SamAccountName"].Value));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Group DistinguishedName", CleanString(AdGroup.Members["DistinguishedName"].Value)));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Member DistinguishedName", CleanString(ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["pszObjectDn"].InnerText)));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Action", Action));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Added Age (Days)", DaysSinceAdded));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Removed Age (Days)", DaysSinceRemoved));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Added Date", AddedDate));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Removed Date", RemovedDate));
                            GroupChangeObj.Members.Add(new PSNoteProperty("ftimeCreated", ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeCreated"].InnerText));
                            GroupChangeObj.Members.Add(new PSNoteProperty("ftimeDeleted", ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeDeleted"].InnerText));
                            GroupChangesList.Add( GroupChangeObj );
                        }
                    }
                    return GroupChangesList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupRecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdGroup = (PSObject) record;
                    ADWSClass.AdGroupDictionary.Add((Convert.ToString(AdGroup.Properties["SID"].Value)), (Convert.ToString(AdGroup.Members["SamAccountName"].Value)));
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupMemberRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    // based on https://github.com/BloodHoundAD/BloodHound/blob/master/PowerShell/BloodHound.ps1
                    PSObject AdGroup = (PSObject) record;
                    List<PSObject> GroupsList = new List<PSObject>();
                    string SamAccountType = Convert.ToString(AdGroup.Members["samaccounttype"].Value);
                    string ObjectClass = Convert.ToString(AdGroup.Members["ObjectClass"].Value);
                    string AccountType = "";
                    string GroupName = "";
                    string MemberUserName = "-";
                    string MemberName = "";
                    string PrimaryGroupID = "";
                    PSObject GroupMemberObj = new PSObject();

                    if (ObjectClass == "foreignSecurityPrincipal")
                    {
                        AccountType = "foreignSecurityPrincipal";
                        MemberUserName = ((Convert.ToString(AdGroup.Members["DistinguishedName"].Value)).Split(',')[0]).Split('=')[1];
                        MemberName = null;
                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection MemberGroups = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdGroup.Members["memberof"].Value;
                        if (MemberGroups.Value != null)
                        {
                            foreach (string GroupMember in MemberGroups)
                            {
                                GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                                GroupMemberObj = new PSObject();
                                GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", AdGroup.Members["objectSid"].Value));
                                GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                GroupsList.Add( GroupMemberObj );
                            }
                        }
                    }
                    if (Groups.Contains(SamAccountType))
                    {
                        AccountType = "group";
                        MemberName = ((Convert.ToString(AdGroup.Members["DistinguishedName"].Value)).Split(',')[0]).Split('=')[1];
                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection MemberGroups = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdGroup.Members["memberof"].Value;
                        if (MemberGroups.Value != null)
                        {
                            foreach (string GroupMember in MemberGroups)
                            {
                                GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                                GroupMemberObj = new PSObject();
                                GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", AdGroup.Members["objectSid"].Value));
                                GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                GroupsList.Add( GroupMemberObj );
                            }
                        }
                    }
                    if (Users.Contains(SamAccountType))
                    {
                        AccountType = "user";
                        MemberName = ((Convert.ToString(AdGroup.Members["DistinguishedName"].Value)).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Members["sAMAccountName"].Value);
                        PrimaryGroupID = Convert.ToString(AdGroup.Members["primaryGroupID"].Value);
                        try
                        {
                            GroupName = ADWSClass.AdGroupDictionary[ADWSClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("Exception caught: {0}", e);
                            GroupName = PrimaryGroupID;
                        }

                        GroupMemberObj = new PSObject();
                        GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", AdGroup.Members["objectSid"].Value));
                        GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                        GroupsList.Add( GroupMemberObj );

                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection MemberGroups = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdGroup.Members["memberof"].Value;
                        if (MemberGroups.Value != null)
                        {
                            foreach (string GroupMember in MemberGroups)
                            {
                                GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                                GroupMemberObj = new PSObject();
                                GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", AdGroup.Members["objectSid"].Value));
                                GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                GroupsList.Add( GroupMemberObj );
                            }
                        }
                    }
                    if (Computers.Contains(SamAccountType))
                    {
                        AccountType = "computer";
                        MemberName = ((Convert.ToString(AdGroup.Members["DistinguishedName"].Value)).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Members["sAMAccountName"].Value);
                        PrimaryGroupID = Convert.ToString(AdGroup.Members["primaryGroupID"].Value);
                        try
                        {
                            GroupName = ADWSClass.AdGroupDictionary[ADWSClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("Exception caught: {0}", e);
                            GroupName = PrimaryGroupID;
                        }

                        GroupMemberObj = new PSObject();
                        GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", AdGroup.Members["objectSid"].Value));
                        GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                        GroupsList.Add( GroupMemberObj );

                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection MemberGroups = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection)AdGroup.Members["memberof"].Value;
                        if (MemberGroups.Value != null)
                        {
                            foreach (string GroupMember in MemberGroups)
                            {
                                GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                                GroupMemberObj = new PSObject();
                                GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                                GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", AdGroup.Members["objectSid"].Value));
                                GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                                GroupsList.Add( GroupMemberObj );
                            }
                        }
                    }
                    if (TrustAccounts.Contains(SamAccountType))
                    {
                        AccountType = "trust";
                        MemberName = ((Convert.ToString(AdGroup.Members["DistinguishedName"].Value)).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Members["sAMAccountName"].Value);
                        PrimaryGroupID = Convert.ToString(AdGroup.Members["primaryGroupID"].Value);
                        try
                        {
                            GroupName = ADWSClass.AdGroupDictionary[ADWSClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("Exception caught: {0}", e);
                            GroupName = PrimaryGroupID;
                        }

                        GroupMemberObj = new PSObject();
                        GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", AdGroup.Members["objectSid"].Value));
                        GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                        GroupsList.Add( GroupMemberObj );
                    }
                    return GroupsList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class OURecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdOU = (PSObject) record;
                    PSObject OUObj = new PSObject();
                    OUObj.Members.Add(new PSNoteProperty("Name", AdOU.Members["Name"].Value));
                    OUObj.Members.Add(new PSNoteProperty("Depth", ((Convert.ToString(AdOU.Members["DistinguishedName"].Value).Split(new string[] { "OU=" }, StringSplitOptions.None)).Length -1)));
                    OUObj.Members.Add(new PSNoteProperty("Description", AdOU.Members["Description"].Value));
                    OUObj.Members.Add(new PSNoteProperty("whenCreated", AdOU.Members["whenCreated"].Value));
                    OUObj.Members.Add(new PSNoteProperty("whenChanged", AdOU.Members["whenChanged"].Value));
                    OUObj.Members.Add(new PSNoteProperty("DistinguishedName", AdOU.Members["DistinguishedName"].Value));
                    return new PSObject[] { OUObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GPORecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdGPO = (PSObject) record;

                    PSObject GPOObj = new PSObject();
                    GPOObj.Members.Add(new PSNoteProperty("DisplayName", CleanString(AdGPO.Members["DisplayName"].Value)));
                    GPOObj.Members.Add(new PSNoteProperty("GUID", CleanString(AdGPO.Members["Name"].Value)));
                    GPOObj.Members.Add(new PSNoteProperty("whenCreated", AdGPO.Members["whenCreated"].Value));
                    GPOObj.Members.Add(new PSNoteProperty("whenChanged", AdGPO.Members["whenChanged"].Value));
                    GPOObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdGPO.Members["DistinguishedName"].Value)));
                    GPOObj.Members.Add(new PSNoteProperty("FilePath", AdGPO.Members["gPCFileSysPath"].Value));
                    return new PSObject[] { GPOObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GPORecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdGPO = (PSObject) record;
                    ADWSClass.AdGPODictionary.Add((Convert.ToString(AdGPO.Members["DistinguishedName"].Value).ToUpper()), (Convert.ToString(AdGPO.Members["DisplayName"].Value)));
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class SOMRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdSOM = (PSObject) record;
                    List<PSObject> SOMsList = new List<PSObject>();
                    int Depth = 0;
                    bool BlockInheritance = false;
                    bool? LinkEnabled = null;
                    bool? Enforced = null;
                    string gPLink = Convert.ToString(AdSOM.Members["gPLink"].Value);
                    string GPOName = null;

                    Depth = (Convert.ToString(AdSOM.Members["DistinguishedName"].Value).Split(new string[] { "OU=" }, StringSplitOptions.None)).Length -1;
                    if (AdSOM.Members["gPOptions"].Value != null && (int) AdSOM.Members["gPOptions"].Value == 1)
                    {
                        BlockInheritance = true;
                    }
                    var GPLinks = gPLink.Split(']', '[').Where(x => x.StartsWith("LDAP"));
                    int Order = (GPLinks.ToArray()).Length;
                    if (Order == 0)
                    {
                        PSObject SOMObj = new PSObject();
                        SOMObj.Members.Add(new PSNoteProperty("Name", AdSOM.Members["Name"].Value));
                        SOMObj.Members.Add(new PSNoteProperty("Depth", Depth));
                        SOMObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSOM.Members["DistinguishedName"].Value));
                        SOMObj.Members.Add(new PSNoteProperty("Link Order", null));
                        SOMObj.Members.Add(new PSNoteProperty("GPO", GPOName));
                        SOMObj.Members.Add(new PSNoteProperty("Enforced", Enforced));
                        SOMObj.Members.Add(new PSNoteProperty("Link Enabled", LinkEnabled));
                        SOMObj.Members.Add(new PSNoteProperty("BlockInheritance", BlockInheritance));
                        SOMObj.Members.Add(new PSNoteProperty("gPLink", gPLink));
                        SOMObj.Members.Add(new PSNoteProperty("gPOptions", AdSOM.Members["gPOptions"].Value));
                        SOMsList.Add( SOMObj );
                    }
                    foreach (string link in GPLinks)
                    {
                        string[] linksplit = link.Split('/', ';');
                        if (!Convert.ToBoolean((Convert.ToInt32(linksplit[3]) & 1)))
                        {
                            LinkEnabled = true;
                        }
                        else
                        {
                            LinkEnabled = false;
                        }
                        if (Convert.ToBoolean((Convert.ToInt32(linksplit[3]) & 2)))
                        {
                            Enforced = true;
                        }
                        else
                        {
                            Enforced = false;
                        }
                        GPOName = ADWSClass.AdGPODictionary.ContainsKey(linksplit[2].ToUpper()) ? ADWSClass.AdGPODictionary[linksplit[2].ToUpper()] : linksplit[2].Split('=',',')[1];
                        PSObject SOMObj = new PSObject();
                        SOMObj.Members.Add(new PSNoteProperty("Name", AdSOM.Members["Name"].Value));
                        SOMObj.Members.Add(new PSNoteProperty("Depth", Depth));
                        SOMObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSOM.Members["DistinguishedName"].Value));
                        SOMObj.Members.Add(new PSNoteProperty("Link Order", Order));
                        SOMObj.Members.Add(new PSNoteProperty("GPO", GPOName));
                        SOMObj.Members.Add(new PSNoteProperty("Enforced", Enforced));
                        SOMObj.Members.Add(new PSNoteProperty("Link Enabled", LinkEnabled));
                        SOMObj.Members.Add(new PSNoteProperty("BlockInheritance", BlockInheritance));
                        SOMObj.Members.Add(new PSNoteProperty("gPLink", gPLink));
                        SOMObj.Members.Add(new PSNoteProperty("gPOptions", AdSOM.Members["gPOptions"].Value));
                        SOMsList.Add( SOMObj );
                        Order--;
                    }
                    return SOMsList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class PrinterRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdPrinter = (PSObject) record;

                    PSObject PrinterObj = new PSObject();
                    PrinterObj.Members.Add(new PSNoteProperty("Name", AdPrinter.Members["Name"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("ServerName", AdPrinter.Members["serverName"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("ShareName", ((Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) (AdPrinter.Members["printShareName"].Value)).Value));
                    PrinterObj.Members.Add(new PSNoteProperty("DriverName", AdPrinter.Members["driverName"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("DriverVersion", AdPrinter.Members["driverVersion"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("PortName", ((Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) (AdPrinter.Members["portName"].Value)).Value));
                    PrinterObj.Members.Add(new PSNoteProperty("URL", ((Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) (AdPrinter.Members["url"].Value)).Value));
                    PrinterObj.Members.Add(new PSNoteProperty("whenCreated", AdPrinter.Members["whenCreated"].Value));
                    PrinterObj.Members.Add(new PSNoteProperty("whenChanged", AdPrinter.Members["whenChanged"].Value));
                    return new PSObject[] { PrinterObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class ComputerRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdComputer = (PSObject) record;
                    int? DaysSinceLastLogon = null;
                    int? DaysSinceLastPasswordChange = null;
                    bool Dormant = false;
                    bool PasswordNotChangedafterMaxAge = false;
                    string SIDHistory = "";
                    string DelegationType = null;
                    string DelegationProtocol = null;
                    string DelegationServices = null;
                    DateTime? LastLogonDate = null;
                    DateTime? PasswordLastSet = null;

                    if (AdComputer.Members["LastLogonDate"].Value != null)
                    {
                        //LastLogonDate = DateTime.FromFileTime((long)(AdComputer.Members["lastLogonTimeStamp"].Value));
                        // LastLogonDate is lastLogonTimeStamp converted to local time
                        LastLogonDate = Convert.ToDateTime(AdComputer.Members["LastLogonDate"].Value);
                        DaysSinceLastLogon = Math.Abs((Date1 - (DateTime)LastLogonDate).Days);
                        if (DaysSinceLastLogon > DormantTimeSpan)
                        {
                            Dormant = true;
                        }
                    }
                    if (AdComputer.Members["PasswordLastSet"].Value != null)
                    {
                        //PasswordLastSet = DateTime.FromFileTime((long)(AdComputer.Members["pwdLastSet"].Value));
                        // PasswordLastSet is pwdLastSet converted to local time
                        PasswordLastSet = Convert.ToDateTime(AdComputer.Members["PasswordLastSet"].Value);
                        DaysSinceLastPasswordChange = Math.Abs((Date1 - (DateTime)PasswordLastSet).Days);
                        if (DaysSinceLastPasswordChange > PassMaxAge)
                        {
                            PasswordNotChangedafterMaxAge = true;
                        }
                    }
                    if ( ((bool) AdComputer.Members["TrustedForDelegation"].Value) && ((int) AdComputer.Members["primaryGroupID"].Value == 515) )
                    {
                        DelegationType = "Unconstrained";
                        DelegationServices = "Any";
                    }
                    if (AdComputer.Members["msDS-AllowedToDelegateTo"] != null)
                    {
                        Microsoft.ActiveDirectory.Management.ADPropertyValueCollection delegateto = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdComputer.Members["msDS-AllowedToDelegateTo"].Value;
                        if (delegateto.Value != null)
                        {
                            DelegationType = "Constrained";
                            foreach (var value in delegateto)
                            {
                                DelegationServices = DelegationServices + "," + Convert.ToString(value);
                            }
                            DelegationServices = DelegationServices.TrimStart(',');
                        }
                    }
                    if ((bool) AdComputer.Members["TrustedToAuthForDelegation"].Value)
                    {
                        DelegationProtocol = "Any";
                    }
                    else if (DelegationType != null)
                    {
                        DelegationProtocol = "Kerberos";
                    }
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection history = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdComputer.Members["SIDHistory"].Value;
                    string sids = "";
                    foreach (var value in history)
                    {
                        sids = sids + "," + Convert.ToString(value);
                    }
                    SIDHistory = sids.TrimStart(',');
                    string OperatingSystem = CleanString((AdComputer.Members["OperatingSystem"].Value != null ? AdComputer.Members["OperatingSystem"].Value : "-") + " " + AdComputer.Members["OperatingSystemHotfix"].Value + " " + AdComputer.Members["OperatingSystemServicePack"].Value + " " + AdComputer.Members["OperatingSystemVersion"].Value);

                    PSObject ComputerObj = new PSObject();
                    ComputerObj.Members.Add(new PSNoteProperty("UserName", CleanString(AdComputer.Members["SamAccountName"].Value)));
                    ComputerObj.Members.Add(new PSNoteProperty("Name", CleanString(AdComputer.Members["Name"].Value)));
                    ComputerObj.Members.Add(new PSNoteProperty("DNSHostName", AdComputer.Members["DNSHostName"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("Enabled", AdComputer.Members["Enabled"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("IPv4Address", AdComputer.Members["IPv4Address"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("Operating System", OperatingSystem));
                    ComputerObj.Members.Add(new PSNoteProperty("Logon Age (days)", DaysSinceLastLogon));
                    ComputerObj.Members.Add(new PSNoteProperty("Password Age (days)", DaysSinceLastPasswordChange));
                    ComputerObj.Members.Add(new PSNoteProperty("Dormant (> " + DormantTimeSpan + " days)", Dormant));
                    ComputerObj.Members.Add(new PSNoteProperty("Password Age (> " + PassMaxAge + " days)", PasswordNotChangedafterMaxAge));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Type", DelegationType));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Protocol", DelegationProtocol));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Services", DelegationServices));
                    ComputerObj.Members.Add(new PSNoteProperty("Primary Group ID", AdComputer.Members["primaryGroupID"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("SID", AdComputer.Members["SID"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    ComputerObj.Members.Add(new PSNoteProperty("Description", CleanString(AdComputer.Members["Description"].Value)));
                    ComputerObj.Members.Add(new PSNoteProperty("ms-ds-CreatorSid", AdComputer.Members["ms-ds-CreatorSid"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("Last Logon Date", LastLogonDate));
                    ComputerObj.Members.Add(new PSNoteProperty("Password LastSet", PasswordLastSet));
                    ComputerObj.Members.Add(new PSNoteProperty("UserAccountControl", AdComputer.Members["UserAccountControl"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("whenCreated", AdComputer.Members["whenCreated"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("whenChanged", AdComputer.Members["whenChanged"].Value));
                    ComputerObj.Members.Add(new PSNoteProperty("Distinguished Name", AdComputer.Members["DistinguishedName"].Value));
                    return new PSObject[] { ComputerObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class ComputerSPNRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdComputer = (PSObject) record;
                    Microsoft.ActiveDirectory.Management.ADPropertyValueCollection SPNs = (Microsoft.ActiveDirectory.Management.ADPropertyValueCollection) AdComputer.Members["servicePrincipalName"].Value;
                    if (SPNs.Value == null)
                    {
                        return new PSObject[] { };
                    }
                    List<PSObject> SPNList = new List<PSObject>();

                    foreach (string SPN in SPNs)
                    {
                        bool flag = true;
                        string[] SPNArray = SPN.Split('/');
                        foreach (PSObject Obj in SPNList)
                        {
                            if ( (string) Obj.Members["Service"].Value == SPNArray[0] )
                            {
                                Obj.Members["Host"].Value = string.Join(",", (Obj.Members["Host"].Value + "," + SPNArray[1]).Split(',').Distinct().ToArray());
                                flag = false;
                            }
                        }
                        if (flag)
                        {
                            PSObject ComputerSPNObj = new PSObject();
                            ComputerSPNObj.Members.Add(new PSNoteProperty("UserName", CleanString(AdComputer.Members["SamAccountName"].Value)));
                            ComputerSPNObj.Members.Add(new PSNoteProperty("Name", CleanString(AdComputer.Members["Name"].Value)));
                            ComputerSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                            ComputerSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                            SPNList.Add( ComputerSPNObj );
                        }
                    }
                    return SPNList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class LAPSRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdComputer = (PSObject) record;
                    bool? Enabled = null;
                    bool PasswordStored = false;
                    DateTime? CurrentExpiration = null;
                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdComputer.Members["userAccountControl"].Value != null)
                    {
                        var userFlags = (UACFlags) AdComputer.Members["userAccountControl"].Value;
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                    }
                    try
                    {
                        CurrentExpiration = DateTime.FromFileTime((long)(AdComputer.Members["ms-Mcs-AdmPwdExpirationTime"].Value));
                        PasswordStored = true;
                    }
                    catch //(Exception e)
                    {
                        //Console.WriteLine("Exception caught: {0}", e);
                    }
                    PSObject LAPSObj = new PSObject();
                    LAPSObj.Members.Add(new PSNoteProperty("Hostname", (AdComputer.Members["DNSHostName"].Value != null ? AdComputer.Members["DNSHostName"].Value : AdComputer.Members["CN"].Value )));
                    LAPSObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                    LAPSObj.Members.Add(new PSNoteProperty("Stored", PasswordStored));
                    LAPSObj.Members.Add(new PSNoteProperty("Readable", (AdComputer.Members["ms-Mcs-AdmPwd"].Value != null ? true : false)));
                    LAPSObj.Members.Add(new PSNoteProperty("Password", AdComputer.Members["ms-Mcs-AdmPwd"].Value));
                    LAPSObj.Members.Add(new PSNoteProperty("Expiration", CurrentExpiration));
                    return new PSObject[] { LAPSObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class SIDRecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdObject = (PSObject) record;
                    switch (Convert.ToString(AdObject.Members["ObjectClass"].Value))
                    {
                        case "user":
                        case "computer":
                        case "group":
                            ADWSClass.AdSIDDictionary.Add(Convert.ToString(AdObject.Members["objectsid"].Value), Convert.ToString(AdObject.Members["Name"].Value));
                            break;
                    }
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class DACLRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdObject = (PSObject) record;
                    string Name = null;
                    string Type = null;
                    List<PSObject> DACLList = new List<PSObject>();

                    Name = Convert.ToString(AdObject.Members["Name"].Value);

                    switch (Convert.ToString(AdObject.Members["objectClass"].Value))
                    {
                        case "user":
                            Type = "User";
                            break;
                        case "computer":
                            Type = "Computer";
                            break;
                        case "group":
                            Type = "Group";
                            break;
                        case "container":
                            Type = "Container";
                            break;
                        case "groupPolicyContainer":
                            Type = "GPO";
                            Name = Convert.ToString(AdObject.Members["DisplayName"].Value);
                            break;
                        case "organizationalUnit":
                            Type = "OU";
                            break;
                        case "domainDNS":
                            Type = "Domain";
                            break;
                        default:
                            Type = Convert.ToString(AdObject.Members["objectClass"].Value);
                            break;
                    }

                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdObject.Members["ntsecuritydescriptor"] != null)
                    {
                        DirectoryObjectSecurity DirObjSec = (DirectoryObjectSecurity) AdObject.Members["ntsecuritydescriptor"].Value;
                        AuthorizationRuleCollection AccessRules = (AuthorizationRuleCollection) DirObjSec.GetAccessRules(true,true,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAccessRule Rule in AccessRules)
                        {
                            string IdentityReference = Convert.ToString(Rule.IdentityReference);
                            string Owner = Convert.ToString(DirObjSec.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)));
                            PSObject ObjectObj = new PSObject();
                            ObjectObj.Members.Add(new PSNoteProperty("Name", CleanString(Name)));
                            ObjectObj.Members.Add(new PSNoteProperty("Type", Type));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectTypeName", ADWSClass.GUIDs[Convert.ToString(Rule.ObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectTypeName", ADWSClass.GUIDs[Convert.ToString(Rule.InheritedObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("ActiveDirectoryRights", Rule.ActiveDirectoryRights));
                            ObjectObj.Members.Add(new PSNoteProperty("AccessControlType", Rule.AccessControlType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReferenceName", ADWSClass.AdSIDDictionary.ContainsKey(IdentityReference) ? ADWSClass.AdSIDDictionary[IdentityReference] : IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("OwnerName", ADWSClass.AdSIDDictionary.ContainsKey(Owner) ? ADWSClass.AdSIDDictionary[Owner] : Owner));
                            ObjectObj.Members.Add(new PSNoteProperty("Inherited", Rule.IsInherited));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectFlags", Rule.ObjectFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceFlags", Rule.InheritanceFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceType", Rule.InheritanceType));
                            ObjectObj.Members.Add(new PSNoteProperty("PropagationFlags", Rule.PropagationFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectType", Rule.ObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectType", Rule.InheritedObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReference", Rule.IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("Owner", Owner));
                            ObjectObj.Members.Add(new PSNoteProperty("DistinguishedName", AdObject.Members["DistinguishedName"].Value));
                            DACLList.Add( ObjectObj );
                        }
                    }

                    return DACLList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

    class SACLRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    PSObject AdObject = (PSObject) record;
                    string Name = null;
                    string Type = null;
                    List<PSObject> SACLList = new List<PSObject>();

                    Name = Convert.ToString(AdObject.Members["Name"].Value);

                    switch (Convert.ToString(AdObject.Members["objectClass"].Value))
                    {
                        case "user":
                            Type = "User";
                            break;
                        case "computer":
                            Type = "Computer";
                            break;
                        case "group":
                            Type = "Group";
                            break;
                        case "container":
                            Type = "Container";
                            break;
                        case "groupPolicyContainer":
                            Type = "GPO";
                            Name = Convert.ToString(AdObject.Members["DisplayName"].Value);
                            break;
                        case "organizationalUnit":
                            Type = "OU";
                            break;
                        case "domainDNS":
                            Type = "Domain";
                            break;
                        default:
                            Type = Convert.ToString(AdObject.Members["objectClass"].Value);
                            break;
                    }

                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdObject.Members["ntsecuritydescriptor"] != null)
                    {
                        DirectoryObjectSecurity DirObjSec = (DirectoryObjectSecurity) AdObject.Members["ntsecuritydescriptor"].Value;
                        AuthorizationRuleCollection AuditRules = (AuthorizationRuleCollection) DirObjSec.GetAuditRules(true,true,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAuditRule Rule in AuditRules)
                        {
                            PSObject ObjectObj = new PSObject();
                            ObjectObj.Members.Add(new PSNoteProperty("Name", CleanString(Name)));
                            ObjectObj.Members.Add(new PSNoteProperty("Type", Type));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectTypeName", ADWSClass.GUIDs[Convert.ToString(Rule.ObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectTypeName", ADWSClass.GUIDs[Convert.ToString(Rule.InheritedObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("ActiveDirectoryRights", Rule.ActiveDirectoryRights));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReference", Rule.IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("AuditFlags", Rule.AuditFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectFlags", Rule.ObjectFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceFlags", Rule.InheritanceFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceType", Rule.InheritanceType));
                            ObjectObj.Members.Add(new PSNoteProperty("Inherited", Rule.IsInherited));
                            ObjectObj.Members.Add(new PSNoteProperty("PropagationFlags", Rule.PropagationFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectType", Rule.ObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectType", Rule.InheritedObjectType));
                            SACLList.Add( ObjectObj );
                        }
                    }

                    return SACLList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        //The interface and implmentation class used to handle the results (this implementation just writes the strings to a file)

        interface IResultsHandler
        {
            void processResults(Object[] t);

            Object[] finalise();
        }

        class SimpleResultsHandler : IResultsHandler
        {
            private Object lockObj = new Object();
            private List<Object> processed = new List<Object>();

            public SimpleResultsHandler()
            {
            }

            public void processResults(Object[] results)
            {
                lock (lockObj)
                {
                    if (results.Length != 0)
                    {
                        for (var i = 0; i < results.Length; i++)
                        {
                            processed.Add((PSObject)results[i]);
                        }
                    }
                }
            }

            public Object[] finalise()
            {
                return processed.ToArray();
            }
        }
"@

$LDAPSource = @"
// Thanks Dennis Albuquerque for the C# multithreading code
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Xml;
using System.Net;
using System.Threading;
using System.DirectoryServices;
using System.Security.Principal;
using System.Security.AccessControl;
using System.Management.Automation;

using System.Diagnostics;
//using System.IO;
using System.Net.Sockets;
using System.Text;
using System.Runtime.InteropServices;

namespace ADRecon
{
    public static class LDAPClass
    {
        private static DateTime Date1;
        private static int PassMaxAge;
        private static int DormantTimeSpan;
        private static Dictionary<string, string> AdGroupDictionary = new Dictionary<string, string>();
        private static string DomainSID;
        private static Dictionary<string, string> AdGPODictionary = new Dictionary<string, string>();
        private static Hashtable GUIDs = new Hashtable();
        private static Dictionary<string, string> AdSIDDictionary = new Dictionary<string, string>();
        private static readonly HashSet<string> Groups = new HashSet<string> ( new string[] {"268435456", "268435457", "536870912", "536870913"} );
        private static readonly HashSet<string> Users = new HashSet<string> ( new string[] { "805306368" } );
        private static readonly HashSet<string> Computers = new HashSet<string> ( new string[] { "805306369" }) ;
        private static readonly HashSet<string> TrustAccounts = new HashSet<string> ( new string[] { "805306370" } );

        [Flags]
        //Values taken from https://support.microsoft.com/en-au/kb/305144
        public enum UACFlags
        {
            SCRIPT = 1,        // 0x1
            ACCOUNTDISABLE = 2,        // 0x2
            HOMEDIR_REQUIRED = 8,        // 0x8
            LOCKOUT = 16,       // 0x10
            PASSWD_NOTREQD = 32,       // 0x20
            PASSWD_CANT_CHANGE = 64,       // 0x40
            ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128,      // 0x80
            TEMP_DUPLICATE_ACCOUNT = 256,      // 0x100
            NORMAL_ACCOUNT = 512,      // 0x200
            INTERDOMAIN_TRUST_ACCOUNT = 2048,     // 0x800
            WORKSTATION_TRUST_ACCOUNT = 4096,     // 0x1000
            SERVER_TRUST_ACCOUNT = 8192,     // 0x2000
            DONT_EXPIRE_PASSWD = 65536,    // 0x10000
            MNS_LOGON_ACCOUNT = 131072,   // 0x20000
            SMARTCARD_REQUIRED = 262144,   // 0x40000
            TRUSTED_FOR_DELEGATION = 524288,   // 0x80000
            NOT_DELEGATED = 1048576,  // 0x100000
            USE_DES_KEY_ONLY = 2097152,  // 0x200000
            DONT_REQUIRE_PREAUTH = 4194304,  // 0x400000
            PASSWORD_EXPIRED = 8388608,  // 0x800000
            TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216, // 0x1000000
            PARTIAL_SECRETS_ACCOUNT = 67108864 // 0x04000000
        }

        [Flags]
        //Values taken from https://blogs.msdn.microsoft.com/openspecification/2011/05/30/windows-configurations-for-kerberos-supported-encryption-type/
        public enum KerbEncFlags
        {
            ZERO = 0,
            DES_CBC_CRC = 1,        // 0x1
            DES_CBC_MD5 = 2,        // 0x2
            RC4_HMAC = 4,        // 0x4
            AES128_CTS_HMAC_SHA1_96 = 8,       // 0x18
            AES256_CTS_HMAC_SHA1_96 = 16       // 0x10
        }

        [Flags]
        //Values taken from https://support.microsoft.com/en-au/kb/305144
        public enum GroupTypeFlags
        {
            GLOBAL_GROUP       = 2,            // 0x00000002
            DOMAIN_LOCAL_GROUP = 4,            // 0x00000004
            LOCAL_GROUP        = 4,            // 0x00000004
            UNIVERSAL_GROUP    = 8,            // 0x00000008
            SECURITY_ENABLED   = -2147483648   // 0x80000000
        }

		private static readonly Dictionary<string, string> Replacements = new Dictionary<string, string>()
        {
            //{System.Environment.NewLine, ""},
            //{",", ";"},
            {"\"", "'"}
        };

        public static string CleanString(Object StringtoClean)
        {
            // Remove extra spaces and new lines
            string CleanedString = string.Join(" ", ((Convert.ToString(StringtoClean)).Split((string[]) null, StringSplitOptions.RemoveEmptyEntries)));
            foreach (string Replacement in Replacements.Keys)
            {
                CleanedString = CleanedString.Replace(Replacement, Replacements[Replacement]);
            }
            return CleanedString;
        }

        public static int ObjectCount(Object[] ADRObject)
        {
            return ADRObject.Length;
        }

        public static Object[] DomainControllerParser(Object[] AdDomainControllers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdDomainControllers, numOfThreads, "DomainControllers");
            return ADRObj;
        }

        public static Object[] SchemaParser(Object[] AdSchemas, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdSchemas, numOfThreads, "SchemaHistory");
            return ADRObj;
        }

        public static Object[] UserParser(Object[] AdUsers, DateTime Date1, int DormantTimeSpan, int PassMaxAge, int numOfThreads)
        {
            LDAPClass.Date1 = Date1;
            LDAPClass.DormantTimeSpan = DormantTimeSpan;
            LDAPClass.PassMaxAge = PassMaxAge;

            Object[] ADRObj = runProcessor(AdUsers, numOfThreads, "Users");
            return ADRObj;
        }

        public static Object[] UserSPNParser(Object[] AdUsers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdUsers, numOfThreads, "UserSPNs");
            return ADRObj;
        }

        public static Object[] GroupParser(Object[] AdGroups, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdGroups, numOfThreads, "Groups");
            return ADRObj;
        }

        public static Object[] GroupChangeParser(Object[] AdGroups, DateTime Date1, int numOfThreads)
        {
            LDAPClass.Date1 = Date1;
            Object[] ADRObj = runProcessor(AdGroups, numOfThreads, "GroupChanges");
            return ADRObj;
        }

        public static Object[] GroupMemberParser(Object[] AdGroups, Object[] AdGroupMembers, string DomainSID, int numOfThreads)
        {
            LDAPClass.AdGroupDictionary = new Dictionary<string, string>();
            runProcessor(AdGroups, numOfThreads, "GroupsDictionary");
            LDAPClass.DomainSID = DomainSID;
            Object[] ADRObj = runProcessor(AdGroupMembers, numOfThreads, "GroupMembers");
            return ADRObj;
        }

        public static Object[] OUParser(Object[] AdOUs, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdOUs, numOfThreads, "OUs");
            return ADRObj;
        }

        public static Object[] GPOParser(Object[] AdGPOs, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdGPOs, numOfThreads, "GPOs");
            return ADRObj;
        }

        public static Object[] SOMParser(Object[] AdGPOs, Object[] AdSOMs, int numOfThreads)
        {
            LDAPClass.AdGPODictionary = new Dictionary<string, string>();
            runProcessor(AdGPOs, numOfThreads, "GPOsDictionary");
            Object[] ADRObj = runProcessor(AdSOMs, numOfThreads, "SOMs");
            return ADRObj;
        }

        public static Object[] PrinterParser(Object[] ADPrinters, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(ADPrinters, numOfThreads, "Printers");
            return ADRObj;
        }

        public static Object[] ComputerParser(Object[] AdComputers, DateTime Date1, int DormantTimeSpan, int PassMaxAge, int numOfThreads)
        {
            LDAPClass.Date1 = Date1;
            LDAPClass.DormantTimeSpan = DormantTimeSpan;
            LDAPClass.PassMaxAge = PassMaxAge;

            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "Computers");
            return ADRObj;
        }

        public static Object[] ComputerSPNParser(Object[] AdComputers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "ComputerSPNs");
            return ADRObj;
        }

        public static Object[] LAPSParser(Object[] AdComputers, int numOfThreads)
        {
            Object[] ADRObj = runProcessor(AdComputers, numOfThreads, "LAPS");
            return ADRObj;
        }

        public static Object[] DACLParser(Object[] ADObjects, Object PSGUIDs, int numOfThreads)
        {
            LDAPClass.AdSIDDictionary = new Dictionary<string, string>();
            runProcessor(ADObjects, numOfThreads, "SIDDictionary");
            LDAPClass.GUIDs = (Hashtable) PSGUIDs;
            Object[] ADRObj = runProcessor(ADObjects, numOfThreads, "DACLs");
            return ADRObj;
        }

        public static Object[] SACLParser(Object[] ADObjects, Object PSGUIDs, int numOfThreads)
        {
            LDAPClass.GUIDs = (Hashtable) PSGUIDs;
            Object[] ADRObj = runProcessor(ADObjects, numOfThreads, "SACLs");
            return ADRObj;
        }

        static Object[] runProcessor(Object[] arrayToProcess, int numOfThreads, string processorType)
        {
            int totalRecords = arrayToProcess.Length;
            IRecordProcessor recordProcessor = recordProcessorFactory(processorType);
            IResultsHandler resultsHandler = new SimpleResultsHandler ();
            int numberOfRecordsPerThread = totalRecords / numOfThreads;
            int remainders = totalRecords % numOfThreads;

            Thread[] threads = new Thread[numOfThreads];
            for (int i = 0; i < numOfThreads; i++)
            {
                int numberOfRecordsToProcess = numberOfRecordsPerThread;
                if (i == (numOfThreads - 1))
                {
                    //last thread, do the remaining records
                    numberOfRecordsToProcess += remainders;
                }

                //split the full array into chunks to be given to different threads
                Object[] sliceToProcess = new Object[numberOfRecordsToProcess];
                Array.Copy(arrayToProcess, i * numberOfRecordsPerThread, sliceToProcess, 0, numberOfRecordsToProcess);
                ProcessorThread processorThread = new ProcessorThread(i, recordProcessor, resultsHandler, sliceToProcess);
                threads[i] = new Thread(processorThread.processThreadRecords);
                threads[i].Start();
            }
            foreach (Thread t in threads)
            {
                t.Join();
            }

            return resultsHandler.finalise();
        }

        static IRecordProcessor recordProcessorFactory(string name)
        {
            switch (name)
            {
                case "DomainControllers":
                    return new DomainControllerRecordProcessor();
                case "SchemaHistory":
                    return new SchemaRecordProcessor();
                case "Users":
                    return new UserRecordProcessor();
                case "UserSPNs":
                    return new UserSPNRecordProcessor();
                case "Groups":
                    return new GroupRecordProcessor();
                case "GroupChanges":
                    return new GroupChangeRecordProcessor();
                case "GroupsDictionary":
                    return new GroupRecordDictionaryProcessor();
                case "GroupMembers":
                    return new GroupMemberRecordProcessor();
                case "OUs":
                    return new OURecordProcessor();
                case "GPOs":
                    return new GPORecordProcessor();
                case "GPOsDictionary":
                    return new GPORecordDictionaryProcessor();
                case "SOMs":
                    return new SOMRecordProcessor();
                case "Printers":
                    return new PrinterRecordProcessor();
                case "Computers":
                    return new ComputerRecordProcessor();
                case "ComputerSPNs":
                    return new ComputerSPNRecordProcessor();
                case "LAPS":
                    return new LAPSRecordProcessor();
                case "SIDDictionary":
                    return new SIDRecordDictionaryProcessor();
                case "DACLs":
                    return new DACLRecordProcessor();
                case "SACLs":
                    return new SACLRecordProcessor();
            }
            throw new ArgumentException("Invalid processor type " + name);
        }

        class ProcessorThread
        {
            readonly int id;
            readonly IRecordProcessor recordProcessor;
            readonly IResultsHandler resultsHandler;
            readonly Object[] objectsToBeProcessed;

            public ProcessorThread(int id, IRecordProcessor recordProcessor, IResultsHandler resultsHandler, Object[] objectsToBeProcessed)
            {
                this.recordProcessor = recordProcessor;
                this.id = id;
                this.resultsHandler = resultsHandler;
                this.objectsToBeProcessed = objectsToBeProcessed;
            }

            public void processThreadRecords()
            {
                for (int i = 0; i < objectsToBeProcessed.Length; i++)
                {
                    Object[] result = recordProcessor.processRecord(objectsToBeProcessed[i]);
                    resultsHandler.processResults(result); //this is a thread safe operation
                }
            }
        }

        //The interface and implmentation class used to process a record (this implemmentation just returns a log type string)

        interface IRecordProcessor
        {
            PSObject[] processRecord(Object record);
        }

        class DomainControllerRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    System.DirectoryServices.ActiveDirectory.DomainController AdDC = (System.DirectoryServices.ActiveDirectory.DomainController) record;
                    bool? Infra = false;
                    bool? Naming = false;
                    bool? Schema = false;
                    bool? RID = false;
                    bool? PDC = false;
                    string Domain = null;
                    string Site = null;
                    string OperatingSystem = null;
                    PSObject DCSMBObj = new PSObject();

                    try
                    {
                        Domain = AdDC.Domain.ToString();
                        foreach (var OperationMasterRole in (System.DirectoryServices.ActiveDirectory.ActiveDirectoryRoleCollection) AdDC.Roles)
                        {
                            switch (OperationMasterRole.ToString())
                            {
                                case "InfrastructureRole":
                                Infra = true;
                                break;
                                case "NamingRole":
                                Naming = true;
                                break;
                                case "SchemaRole":
                                Schema = true;
                                break;
                                case "RidRole":
                                RID = true;
                                break;
                                case "PdcRole":
                                PDC = true;
                                break;
                            }
                        }
                        Site = AdDC.SiteName;
                        OperatingSystem = AdDC.OSVersion.ToString();
                    }
                    catch (System.DirectoryServices.ActiveDirectory.ActiveDirectoryServerDownException)// e)
                    {
                        //Console.WriteLine("Exception caught: {0}", e);
                        Infra = null;
                        Naming = null;
                        Schema = null;
                        RID = null;
                        PDC = null;
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine("Exception caught: {0}", e);
                    }
                    PSObject DCObj = new PSObject();
                    DCObj.Members.Add(new PSNoteProperty("Domain", Domain));
                    DCObj.Members.Add(new PSNoteProperty("Site", Site));
                    DCObj.Members.Add(new PSNoteProperty("Name", Convert.ToString(AdDC.Name).Split('.')[0]));
                    DCObj.Members.Add(new PSNoteProperty("IPv4Address", AdDC.IPAddress));
                    DCObj.Members.Add(new PSNoteProperty("Operating System", OperatingSystem));
                    DCObj.Members.Add(new PSNoteProperty("Hostname", AdDC.Name));
                    DCObj.Members.Add(new PSNoteProperty("Infra", Infra));
                    DCObj.Members.Add(new PSNoteProperty("Naming", Naming));
                    DCObj.Members.Add(new PSNoteProperty("Schema", Schema));
                    DCObj.Members.Add(new PSNoteProperty("RID", RID));
                    DCObj.Members.Add(new PSNoteProperty("PDC", PDC));
                    if (AdDC.IPAddress != null)
                    {
                        DCSMBObj = GetPSObject(AdDC.IPAddress);
                    }
                    else
                    {
                        DCSMBObj = new PSObject();
                        DCSMBObj.Members.Add(new PSNoteProperty("SMB Port Open", false));
                    }
                    foreach (PSPropertyInfo psPropertyInfo in DCSMBObj.Properties)
                    {
                        if (Convert.ToString(psPropertyInfo.Name) == "SMB Port Open" && (bool) psPropertyInfo.Value == false)
                        {
                            DCObj.Members.Add(new PSNoteProperty(psPropertyInfo.Name, psPropertyInfo.Value));
                            DCObj.Members.Add(new PSNoteProperty("SMB1(NT LM 0.12)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB2(0x0202)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB2(0x0210)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB3(0x0300)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB3(0x0302)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB3(0x0311)", null));
                            DCObj.Members.Add(new PSNoteProperty("SMB Signing", null));
                            break;
                        }
                        else
                        {
                            DCObj.Members.Add(new PSNoteProperty(psPropertyInfo.Name, psPropertyInfo.Value));
                        }
                    }
                    return new PSObject[] { DCObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class SchemaRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdSchema = (SearchResult) record;

                    PSObject SchemaObj = new PSObject();
                    SchemaObj.Members.Add(new PSNoteProperty("ObjectClass", AdSchema.Properties["objectclass"][0]));
                    SchemaObj.Members.Add(new PSNoteProperty("Name", AdSchema.Properties["name"][0]));
                    SchemaObj.Members.Add(new PSNoteProperty("whenCreated", AdSchema.Properties["whencreated"][0]));
                    SchemaObj.Members.Add(new PSNoteProperty("whenChanged", AdSchema.Properties["whenchanged"][0]));
                    SchemaObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSchema.Properties["distinguishedname"][0]));
                    return new PSObject[] { SchemaObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class UserRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdUser = (SearchResult) record;
                    bool? Enabled = null;
                    bool? CannotChangePassword = null;
                    bool? PasswordNeverExpires = null;
                    bool? AccountLockedOut = null;
                    bool? PasswordExpired = null;
                    bool? ReversiblePasswordEncryption = null;
                    bool? DelegationPermitted = null;
                    bool? SmartcardRequired = null;
                    bool? UseDESKeyOnly = null;
                    bool? PasswordNotRequired = null;
                    bool? TrustedforDelegation = null;
                    bool? TrustedtoAuthforDelegation = null;
                    bool? DoesNotRequirePreAuth = null;
                    bool? KerberosRC4 = null;
                    bool? KerberosAES128 = null;
                    bool? KerberosAES256 = null;
                    string DelegationType = null;
                    string DelegationProtocol = null;
                    string DelegationServices = null;
                    bool MustChangePasswordatLogon = false;
                    int? DaysSinceLastLogon = null;
                    int? DaysSinceLastPasswordChange = null;
                    int? AccountExpirationNumofDays = null;
                    bool PasswordNotChangedafterMaxAge = false;
                    bool NeverLoggedIn = false;
                    bool Dormant = false;
                    DateTime? LastLogonDate = null;
                    DateTime? PasswordLastSet = null;
                    DateTime? AccountExpires = null;
                    byte[] ntSecurityDescriptor = null;
                    bool DenyEveryone = false;
                    bool DenySelf = false;
                    string SIDHistory = "";
                    bool? HasSPN = null;

                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdUser.Properties["useraccountcontrol"].Count != 0)
                    {
                        var userFlags = (UACFlags) AdUser.Properties["useraccountcontrol"][0];
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                        PasswordNeverExpires = (userFlags & UACFlags.DONT_EXPIRE_PASSWD) == UACFlags.DONT_EXPIRE_PASSWD;
                        AccountLockedOut = (userFlags & UACFlags.LOCKOUT) == UACFlags.LOCKOUT;
                        DelegationPermitted = !((userFlags & UACFlags.NOT_DELEGATED) == UACFlags.NOT_DELEGATED);
                        SmartcardRequired = (userFlags & UACFlags.SMARTCARD_REQUIRED) == UACFlags.SMARTCARD_REQUIRED;
                        ReversiblePasswordEncryption = (userFlags & UACFlags.ENCRYPTED_TEXT_PASSWORD_ALLOWED) == UACFlags.ENCRYPTED_TEXT_PASSWORD_ALLOWED;
                        UseDESKeyOnly = (userFlags & UACFlags.USE_DES_KEY_ONLY) == UACFlags.USE_DES_KEY_ONLY;
                        PasswordNotRequired = (userFlags & UACFlags.PASSWD_NOTREQD) == UACFlags.PASSWD_NOTREQD;
                        PasswordExpired = (userFlags & UACFlags.PASSWORD_EXPIRED) == UACFlags.PASSWORD_EXPIRED;
                        TrustedforDelegation = (userFlags & UACFlags.TRUSTED_FOR_DELEGATION) == UACFlags.TRUSTED_FOR_DELEGATION;
                        TrustedtoAuthforDelegation = (userFlags & UACFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) == UACFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION;
                        DoesNotRequirePreAuth = (userFlags & UACFlags.DONT_REQUIRE_PREAUTH) == UACFlags.DONT_REQUIRE_PREAUTH;
                    }
                    if (AdUser.Properties["msds-supportedencryptiontypes"].Count != 0)
                    {
                        var userKerbEncFlags = (KerbEncFlags) AdUser.Properties["msds-supportedencryptiontypes"][0];
                        if (userKerbEncFlags != KerbEncFlags.ZERO)
                        {
                            KerberosRC4 = (userKerbEncFlags & KerbEncFlags.RC4_HMAC) == KerbEncFlags.RC4_HMAC;
                            KerberosAES128 = (userKerbEncFlags & KerbEncFlags.AES128_CTS_HMAC_SHA1_96) == KerbEncFlags.AES128_CTS_HMAC_SHA1_96;
                            KerberosAES256 = (userKerbEncFlags & KerbEncFlags.AES256_CTS_HMAC_SHA1_96) == KerbEncFlags.AES256_CTS_HMAC_SHA1_96;
                        }
                    }
                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdUser.Properties["ntsecuritydescriptor"].Count != 0)
                    {
                        ntSecurityDescriptor = (byte[]) AdUser.Properties["ntsecuritydescriptor"][0];
                    }
                    else
                    {
                        DirectoryEntry AdUserEntry = ((SearchResult)record).GetDirectoryEntry();
                        ntSecurityDescriptor = (byte[]) AdUserEntry.ObjectSecurity.GetSecurityDescriptorBinaryForm();
                    }
                    if (ntSecurityDescriptor != null)
                    {
                        DirectoryObjectSecurity DirObjSec = new ActiveDirectorySecurity();
                        DirObjSec.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
                        AuthorizationRuleCollection AccessRules = (AuthorizationRuleCollection) DirObjSec.GetAccessRules(true,false,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAccessRule Rule in AccessRules)
                        {
                            if ((Convert.ToString(Rule.ObjectType)).Equals("ab721a53-1e2f-11d0-9819-00aa0040529b"))
                            {
                                if (Rule.AccessControlType.ToString() == "Deny")
                                {
                                    string ObjectName = Convert.ToString(Rule.IdentityReference);
                                    if (ObjectName == "Everyone")
                                    {
                                        DenyEveryone = true;
                                    }
                                    if (ObjectName == "NT AUTHORITY\\SELF")
                                    {
                                        DenySelf = true;
                                    }
                                }
                            }
                        }
                        if (DenyEveryone && DenySelf)
                        {
                            CannotChangePassword = true;
                        }
                        else
                        {
                            CannotChangePassword = false;
                        }
                    }
                    if (AdUser.Properties["lastlogontimestamp"].Count != 0)
                    {
                        LastLogonDate = DateTime.FromFileTime((long)(AdUser.Properties["lastlogontimestamp"][0]));
                        DaysSinceLastLogon = Math.Abs((Date1 - (DateTime)LastLogonDate).Days);
                        if (DaysSinceLastLogon > DormantTimeSpan)
                        {
                            Dormant = true;
                        }
                    }
                    else
                    {
                        NeverLoggedIn = true;
                    }
                    if (AdUser.Properties["pwdLastSet"].Count != 0)
                    {
                        if (Convert.ToString(AdUser.Properties["pwdlastset"][0]) == "0")
                        {
                            if ((bool) PasswordNeverExpires == false)
                            {
                                MustChangePasswordatLogon = true;
                            }
                        }
                        else
                        {
                            PasswordLastSet = DateTime.FromFileTime((long)(AdUser.Properties["pwdlastset"][0]));
                            DaysSinceLastPasswordChange = Math.Abs((Date1 - (DateTime)PasswordLastSet).Days);
                            if (DaysSinceLastPasswordChange > PassMaxAge)
                            {
                                PasswordNotChangedafterMaxAge = true;
                            }
                        }
                    }
                    if (AdUser.Properties["accountExpires"].Count != 0)
                    {
                        if ((Int64) AdUser.Properties["accountExpires"][0] != (Int64) 9223372036854775807)
                        {
                            if ((Int64) AdUser.Properties["accountExpires"][0] != (Int64) 0)
                            {
                                try
                                {
                                    //https://msdn.microsoft.com/en-us/library/ms675098(v=vs.85).aspx
                                    AccountExpires = DateTime.FromFileTime((long)(AdUser.Properties["accountExpires"][0]));
                                    AccountExpirationNumofDays = ((int)((DateTime)AccountExpires - Date1).Days);

                                }
                                catch //(Exception e)
                                {
                                    //    Console.WriteLine("Exception caught: {0}", e);
                                }
                            }
                        }
                    }
                    if (AdUser.Properties["useraccountcontrol"].Count != 0)
                    {
                        if ((bool) TrustedforDelegation)
                        {
                            DelegationType = "Unconstrained";
                            DelegationServices = "Any";
                        }
                        if (AdUser.Properties["msDS-AllowedToDelegateTo"].Count >= 1)
                        {
                            DelegationType = "Constrained";
                            for (int i = 0; i < AdUser.Properties["msDS-AllowedToDelegateTo"].Count; i++)
                            {
                                var delegateto = AdUser.Properties["msDS-AllowedToDelegateTo"][i];
                                DelegationServices = DelegationServices + "," + Convert.ToString(delegateto);
                            }
                            DelegationServices = DelegationServices.TrimStart(',');
                        }
                        if ((bool) TrustedtoAuthforDelegation)
                        {
                            DelegationProtocol = "Any";
                        }
                        else if (DelegationType != null)
                        {
                            DelegationProtocol = "Kerberos";
                        }
                    }
                    if (AdUser.Properties["sidhistory"].Count >= 1)
                    {
                        string sids = "";
                        for (int i = 0; i < AdUser.Properties["sidhistory"].Count; i++)
                        {
                            var history = AdUser.Properties["sidhistory"][i];
                            sids = sids + "," + Convert.ToString(new SecurityIdentifier((byte[])history, 0));
                        }
                        SIDHistory = sids.TrimStart(',');
                    }
                    if (AdUser.Properties["serviceprincipalname"].Count == 0)
                    {
                        HasSPN = false;
                    }
                    else if (AdUser.Properties["serviceprincipalname"].Count > 0)
                    {
                        HasSPN = true;
                    }

                    PSObject UserObj = new PSObject();
                    UserObj.Members.Add(new PSNoteProperty("UserName", (AdUser.Properties["samaccountname"].Count != 0 ? CleanString(AdUser.Properties["samaccountname"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Name", (AdUser.Properties["name"].Count != 0 ? CleanString(AdUser.Properties["name"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                    UserObj.Members.Add(new PSNoteProperty("Must Change Password at Logon", MustChangePasswordatLogon));
                    UserObj.Members.Add(new PSNoteProperty("Cannot Change Password", CannotChangePassword));
                    UserObj.Members.Add(new PSNoteProperty("Password Never Expires", PasswordNeverExpires));
                    UserObj.Members.Add(new PSNoteProperty("Reversible Password Encryption", ReversiblePasswordEncryption));
                    UserObj.Members.Add(new PSNoteProperty("Smartcard Logon Required", SmartcardRequired));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Permitted", DelegationPermitted));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos DES Only", UseDESKeyOnly));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos RC4", KerberosRC4));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos AES-128bit", KerberosAES128));
                    UserObj.Members.Add(new PSNoteProperty("Kerberos AES-256bit", KerberosAES256));
                    UserObj.Members.Add(new PSNoteProperty("Does Not Require Pre Auth", DoesNotRequirePreAuth));
                    UserObj.Members.Add(new PSNoteProperty("Never Logged in", NeverLoggedIn));
                    UserObj.Members.Add(new PSNoteProperty("Logon Age (days)", DaysSinceLastLogon));
                    UserObj.Members.Add(new PSNoteProperty("Password Age (days)", DaysSinceLastPasswordChange));
                    UserObj.Members.Add(new PSNoteProperty("Dormant (> " + DormantTimeSpan + " days)", Dormant));
                    UserObj.Members.Add(new PSNoteProperty("Password Age (> " + PassMaxAge + " days)", PasswordNotChangedafterMaxAge));
                    UserObj.Members.Add(new PSNoteProperty("Account Locked Out", AccountLockedOut));
                    UserObj.Members.Add(new PSNoteProperty("Password Expired", PasswordExpired));
                    UserObj.Members.Add(new PSNoteProperty("Password Not Required", PasswordNotRequired));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Type", DelegationType));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Protocol", DelegationProtocol));
                    UserObj.Members.Add(new PSNoteProperty("Delegation Services", DelegationServices));
                    UserObj.Members.Add(new PSNoteProperty("Logon Workstations", (AdUser.Properties["userworkstations"].Count != 0 ? AdUser.Properties["userworkstations"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("AdminCount", (AdUser.Properties["admincount"].Count != 0 ? AdUser.Properties["admincount"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("Primary GroupID", (AdUser.Properties["primarygroupid"].Count != 0 ? AdUser.Properties["primarygroupid"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("SID", Convert.ToString(new SecurityIdentifier((byte[])AdUser.Properties["objectSID"][0], 0))));
                    UserObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    UserObj.Members.Add(new PSNoteProperty("HasSPN", HasSPN));
                    UserObj.Members.Add(new PSNoteProperty("Description", (AdUser.Properties["Description"].Count != 0 ? CleanString(AdUser.Properties["Description"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Title", (AdUser.Properties["Title"].Count != 0 ? CleanString(AdUser.Properties["Title"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Department", (AdUser.Properties["Department"].Count != 0 ? CleanString(AdUser.Properties["Department"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Company", (AdUser.Properties["Company"].Count != 0 ? CleanString(AdUser.Properties["Company"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Manager", (AdUser.Properties["Manager"].Count != 0 ? CleanString(AdUser.Properties["Manager"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Info", (AdUser.Properties["info"].Count != 0 ? CleanString(AdUser.Properties["info"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Last Logon Date", LastLogonDate));
                    UserObj.Members.Add(new PSNoteProperty("Password LastSet", PasswordLastSet));
                    UserObj.Members.Add(new PSNoteProperty("Account Expiration Date", AccountExpires));
                    UserObj.Members.Add(new PSNoteProperty("Account Expiration (days)", AccountExpirationNumofDays));
                    UserObj.Members.Add(new PSNoteProperty("Mobile", (AdUser.Properties["mobile"].Count != 0 ? CleanString(AdUser.Properties["mobile"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Email", (AdUser.Properties["mail"].Count != 0 ? CleanString(AdUser.Properties["mail"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("HomeDirectory", (AdUser.Properties["homedirectory"].Count != 0 ? AdUser.Properties["homedirectory"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("ProfilePath", (AdUser.Properties["profilepath"].Count != 0 ? AdUser.Properties["profilepath"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("ScriptPath", (AdUser.Properties["scriptpath"].Count != 0 ? AdUser.Properties["scriptpath"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("UserAccountControl", (AdUser.Properties["useraccountcontrol"].Count != 0 ? AdUser.Properties["useraccountcontrol"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("First Name", (AdUser.Properties["givenName"].Count != 0 ? CleanString(AdUser.Properties["givenName"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Middle Name", (AdUser.Properties["middleName"].Count != 0 ? CleanString(AdUser.Properties["middleName"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Last Name", (AdUser.Properties["sn"].Count != 0 ? CleanString(AdUser.Properties["sn"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("Country", (AdUser.Properties["c"].Count != 0 ? CleanString(AdUser.Properties["c"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("whenCreated", (AdUser.Properties["whencreated"].Count != 0 ? AdUser.Properties["whencreated"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("whenChanged", (AdUser.Properties["whenchanged"].Count != 0 ? AdUser.Properties["whenchanged"][0] : "")));
                    UserObj.Members.Add(new PSNoteProperty("DistinguishedName", (AdUser.Properties["distinguishedname"].Count != 0 ? CleanString(AdUser.Properties["distinguishedname"][0]) : "")));
                    UserObj.Members.Add(new PSNoteProperty("CanonicalName", (AdUser.Properties["canonicalname"].Count != 0 ? CleanString(AdUser.Properties["canonicalname"][0]) : "")));
                    return new PSObject[] { UserObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class UserSPNRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdUser = (SearchResult) record;
                    if (AdUser.Properties["serviceprincipalname"].Count == 0)
                    {
                        return new PSObject[] { };
                    }
                    List<PSObject> SPNList = new List<PSObject>();
                    bool? Enabled = null;
                    string Memberof = null;
                    DateTime? PasswordLastSet = null;

                    if (AdUser.Properties["pwdlastset"].Count != 0)
                    {
                        if (Convert.ToString(AdUser.Properties["pwdlastset"][0]) != "0")
                        {
                            PasswordLastSet = DateTime.FromFileTime((long)(AdUser.Properties["pwdLastSet"][0]));
                        }
                    }
                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdUser.Properties["useraccountcontrol"].Count != 0)
                    {
                        var userFlags = (UACFlags) AdUser.Properties["useraccountcontrol"][0];
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                    }
                    string Description = (AdUser.Properties["Description"].Count != 0 ? CleanString(AdUser.Properties["Description"][0]) : "");
                    string PrimaryGroupID = (AdUser.Properties["primarygroupid"].Count != 0 ? Convert.ToString(AdUser.Properties["primarygroupid"][0]) : "");
                    if (AdUser.Properties["memberof"].Count != 0)
                    {
                        foreach (string Member in AdUser.Properties["memberof"])
                        {
                            Memberof = Memberof + "," + ((Convert.ToString(Member)).Split(',')[0]).Split('=')[1];
                        }
                        Memberof = Memberof.TrimStart(',');
                    }
                    foreach (string SPN in AdUser.Properties["serviceprincipalname"])
                    {
                        string[] SPNArray = SPN.Split('/');
                        PSObject UserSPNObj = new PSObject();
                        UserSPNObj.Members.Add(new PSNoteProperty("UserName", (AdUser.Properties["samaccountname"].Count != 0 ? CleanString(AdUser.Properties["samaccountname"][0]) : "")));
                        UserSPNObj.Members.Add(new PSNoteProperty("Name", (AdUser.Properties["name"].Count != 0 ? CleanString(AdUser.Properties["name"][0]) : "")));
                        UserSPNObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                        UserSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                        UserSPNObj.Members.Add(new PSNoteProperty("Password Last Set", PasswordLastSet));
                        UserSPNObj.Members.Add(new PSNoteProperty("Description", Description));
                        UserSPNObj.Members.Add(new PSNoteProperty("Primary GroupID", PrimaryGroupID));
                        UserSPNObj.Members.Add(new PSNoteProperty("Memberof", Memberof));
                        SPNList.Add( UserSPNObj );
                    }
                    return SPNList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdGroup = (SearchResult) record;
                    string ManagedByValue = AdGroup.Properties["managedby"].Count != 0 ? Convert.ToString(AdGroup.Properties["managedby"][0]) : "";
                    string ManagedBy = "";
                    string GroupCategory = null;
                    string GroupScope = null;
                    string SIDHistory = "";

                    if (AdGroup.Properties["managedBy"].Count != 0)
                    {
                        ManagedBy = (ManagedByValue.Split(new string[] { "CN=" },StringSplitOptions.RemoveEmptyEntries))[0].Split(new string[] { "OU=" },StringSplitOptions.RemoveEmptyEntries)[0].TrimEnd(',');
                    }

                    if (AdGroup.Properties["grouptype"].Count != 0)
                    {
                        var groupTypeFlags = (GroupTypeFlags) AdGroup.Properties["grouptype"][0];
                        GroupCategory = (groupTypeFlags & GroupTypeFlags.SECURITY_ENABLED) == GroupTypeFlags.SECURITY_ENABLED ? "Security" : "Distribution";

                        if ((groupTypeFlags & GroupTypeFlags.UNIVERSAL_GROUP) == GroupTypeFlags.UNIVERSAL_GROUP)
                        {
                            GroupScope = "Universal";
                        }
                        else if ((groupTypeFlags & GroupTypeFlags.GLOBAL_GROUP) == GroupTypeFlags.GLOBAL_GROUP)
                        {
                            GroupScope = "Global";
                        }
                        else if ((groupTypeFlags & GroupTypeFlags.DOMAIN_LOCAL_GROUP) == GroupTypeFlags.DOMAIN_LOCAL_GROUP)
                        {
                            GroupScope = "DomainLocal";
                        }
                    }
                    if (AdGroup.Properties["sidhistory"].Count >= 1)
                    {
                        string sids = "";
                        for (int i = 0; i < AdGroup.Properties["sidhistory"].Count; i++)
                        {
                            var history = AdGroup.Properties["sidhistory"][i];
                            sids = sids + "," + Convert.ToString(new SecurityIdentifier((byte[])history, 0));
                        }
                        SIDHistory = sids.TrimStart(',');
                    }

                    PSObject GroupObj = new PSObject();
                    GroupObj.Members.Add(new PSNoteProperty("Name", AdGroup.Properties["samaccountname"][0]));
                    GroupObj.Members.Add(new PSNoteProperty("AdminCount", (AdGroup.Properties["admincount"].Count != 0 ? AdGroup.Properties["admincount"][0] : "")));
                    GroupObj.Members.Add(new PSNoteProperty("GroupCategory", GroupCategory));
                    GroupObj.Members.Add(new PSNoteProperty("GroupScope", GroupScope));
                    GroupObj.Members.Add(new PSNoteProperty("ManagedBy", ManagedBy));
                    GroupObj.Members.Add(new PSNoteProperty("SID", Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSID"][0], 0))));
                    GroupObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    GroupObj.Members.Add(new PSNoteProperty("Description", (AdGroup.Properties["Description"].Count != 0 ? CleanString(AdGroup.Properties["Description"][0]) : "")));
                    GroupObj.Members.Add(new PSNoteProperty("whenCreated", AdGroup.Properties["whencreated"][0]));
                    GroupObj.Members.Add(new PSNoteProperty("whenChanged", AdGroup.Properties["whenchanged"][0]));
                    GroupObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdGroup.Properties["distinguishedname"][0])));
                    GroupObj.Members.Add(new PSNoteProperty("CanonicalName", AdGroup.Properties["canonicalname"][0]));
                    return new PSObject[] { GroupObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupChangeRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdGroup = (SearchResult) record;
                    string Action = null;
                    int? DaysSinceAdded = null;
                    int? DaysSinceRemoved = null;
                    DateTime? AddedDate = null;
                    DateTime? RemovedDate = null;
                    List<PSObject> GroupChangesList = new List<PSObject>();

                    System.DirectoryServices.ResultPropertyValueCollection ReplValueMetaData = (System.DirectoryServices.ResultPropertyValueCollection) AdGroup.Properties["msDS-ReplValueMetaData"];

                    if (ReplValueMetaData.Count != 0)
                    {
                        foreach (string ReplData in ReplValueMetaData)
                        {
                            XmlDocument ReplXML = new XmlDocument();
                            ReplXML.LoadXml(ReplData.Replace("\x00", "").Replace("&","&amp;"));

                            if (ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeDeleted"].InnerText != "1601-01-01T00:00:00Z")
                            {
                                Action = "Removed";
                                AddedDate = DateTime.Parse(ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeCreated"].InnerText);
                                DaysSinceAdded = Math.Abs((Date1 - (DateTime) AddedDate).Days);
                                RemovedDate = DateTime.Parse(ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeDeleted"].InnerText);
                                DaysSinceRemoved = Math.Abs((Date1 - (DateTime) RemovedDate).Days);
                            }
                            else
                            {
                                Action = "Added";
                                AddedDate = DateTime.Parse(ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeCreated"].InnerText);
                                DaysSinceAdded = Math.Abs((Date1 - (DateTime) AddedDate).Days);
                                RemovedDate = null;
                                DaysSinceRemoved = null;
                            }

                            PSObject GroupChangeObj = new PSObject();
                            GroupChangeObj.Members.Add(new PSNoteProperty("Group Name", AdGroup.Properties["samaccountname"][0]));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Group DistinguishedName", CleanString(AdGroup.Properties["distinguishedname"][0])));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Member DistinguishedName", CleanString(ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["pszObjectDn"].InnerText)));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Action", Action));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Added Age (Days)", DaysSinceAdded));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Removed Age (Days)", DaysSinceRemoved));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Added Date", AddedDate));
                            GroupChangeObj.Members.Add(new PSNoteProperty("Removed Date", RemovedDate));
                            GroupChangeObj.Members.Add(new PSNoteProperty("ftimeCreated", ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeCreated"].InnerText));
                            GroupChangeObj.Members.Add(new PSNoteProperty("ftimeDeleted", ReplXML.SelectSingleNode("DS_REPL_VALUE_META_DATA")["ftimeDeleted"].InnerText));
                            GroupChangesList.Add( GroupChangeObj );
                        }
                    }
                    return GroupChangesList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupRecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdGroup = (SearchResult) record;
                    LDAPClass.AdGroupDictionary.Add((Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSID"][0], 0))),(Convert.ToString(AdGroup.Properties["samaccountname"][0])));
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GroupMemberRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    // https://github.com/BloodHoundAD/BloodHound/blob/master/PowerShell/BloodHound.ps1
                    SearchResult AdGroup = (SearchResult) record;
                    List<PSObject> GroupsList = new List<PSObject>();
                    string SamAccountType = AdGroup.Properties["samaccounttype"].Count != 0 ? Convert.ToString(AdGroup.Properties["samaccounttype"][0]) : "";
                    string ObjectClass = Convert.ToString(AdGroup.Properties["objectclass"][AdGroup.Properties["objectclass"].Count-1]);
                    string AccountType = "";
                    string GroupName = "";
                    string MemberUserName = "-";
                    string MemberName = "";
                    string PrimaryGroupID = "";
                    PSObject GroupMemberObj = new PSObject();

                    if (ObjectClass == "foreignSecurityPrincipal")
                    {
                        AccountType = "foreignSecurityPrincipal";
                        MemberName = null;
                        MemberUserName = ((Convert.ToString(AdGroup.Properties["DistinguishedName"][0])).Split(',')[0]).Split('=')[1];
                        foreach (string GroupMember in AdGroup.Properties["memberof"])
                        {
                            GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                            GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSid"][0], 0))));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }
                    }

                    if (Groups.Contains(SamAccountType))
                    {
                        AccountType = "group";
                        MemberName = ((Convert.ToString(AdGroup.Properties["DistinguishedName"][0])).Split(',')[0]).Split('=')[1];
                        foreach (string GroupMember in AdGroup.Properties["memberof"])
                        {
                            GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                            GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSid"][0], 0))));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }
                    }
                    if (Users.Contains(SamAccountType))
                    {
                        AccountType = "user";
                        MemberName = ((Convert.ToString(AdGroup.Properties["DistinguishedName"][0])).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Properties["sAMAccountName"][0]);
                        PrimaryGroupID = Convert.ToString(AdGroup.Properties["primaryGroupID"][0]);
                        try
                        {
                            GroupName = LDAPClass.AdGroupDictionary[LDAPClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("Exception caught: {0}", e);
                            GroupName = PrimaryGroupID;
                        }

                        GroupMemberObj = new PSObject();
                        GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSid"][0], 0))));
                        GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                        GroupsList.Add( GroupMemberObj );

                        foreach (string GroupMember in AdGroup.Properties["memberof"])
                        {
                            GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                            GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSid"][0], 0))));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }
                    }
                    if (Computers.Contains(SamAccountType))
                    {
                        AccountType = "computer";
                        MemberName = ((Convert.ToString(AdGroup.Properties["DistinguishedName"][0])).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Properties["sAMAccountName"][0]);
                        PrimaryGroupID = Convert.ToString(AdGroup.Properties["primaryGroupID"][0]);
                        try
                        {
                            GroupName = LDAPClass.AdGroupDictionary[LDAPClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("Exception caught: {0}", e);
                            GroupName = PrimaryGroupID;
                        }

                        GroupMemberObj = new PSObject();
                        GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSid"][0], 0))));
                        GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                        GroupsList.Add( GroupMemberObj );

                        foreach (string GroupMember in AdGroup.Properties["memberof"])
                        {
                            GroupName = ((Convert.ToString(GroupMember)).Split(',')[0]).Split('=')[1];
                            GroupMemberObj = new PSObject();
                            GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                            GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSid"][0], 0))));
                            GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                            GroupsList.Add( GroupMemberObj );
                        }
                    }
                    if (TrustAccounts.Contains(SamAccountType))
                    {
                        AccountType = "trust";
                        MemberName = ((Convert.ToString(AdGroup.Properties["DistinguishedName"][0])).Split(',')[0]).Split('=')[1];
                        MemberUserName = Convert.ToString(AdGroup.Properties["sAMAccountName"][0]);
                        PrimaryGroupID = Convert.ToString(AdGroup.Properties["primaryGroupID"][0]);
                        try
                        {
                            GroupName = LDAPClass.AdGroupDictionary[LDAPClass.DomainSID + "-" + PrimaryGroupID];
                        }
                        catch //(Exception e)
                        {
                            //Console.WriteLine("Exception caught: {0}", e);
                            GroupName = PrimaryGroupID;
                        }

                        GroupMemberObj = new PSObject();
                        GroupMemberObj.Members.Add(new PSNoteProperty("Group Name", GroupName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member UserName", MemberUserName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member Name", MemberName));
                        GroupMemberObj.Members.Add(new PSNoteProperty("Member SID", Convert.ToString(new SecurityIdentifier((byte[])AdGroup.Properties["objectSid"][0], 0))));
                        GroupMemberObj.Members.Add(new PSNoteProperty("AccountType", AccountType));
                        GroupsList.Add( GroupMemberObj );
                    }
                    return GroupsList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class OURecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdOU = (SearchResult) record;

                    PSObject OUObj = new PSObject();
                    OUObj.Members.Add(new PSNoteProperty("Name", AdOU.Properties["name"][0]));
                    OUObj.Members.Add(new PSNoteProperty("Depth", ((Convert.ToString(AdOU.Properties["distinguishedname"][0]).Split(new string[] { "OU=" }, StringSplitOptions.None)).Length -1)));
                    OUObj.Members.Add(new PSNoteProperty("Description", (AdOU.Properties["description"].Count != 0 ? AdOU.Properties["description"][0] : "")));
                    OUObj.Members.Add(new PSNoteProperty("whenCreated", AdOU.Properties["whencreated"][0]));
                    OUObj.Members.Add(new PSNoteProperty("whenChanged", AdOU.Properties["whenchanged"][0]));
                    OUObj.Members.Add(new PSNoteProperty("DistinguishedName", AdOU.Properties["distinguishedname"][0]));
                    return new PSObject[] { OUObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GPORecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdGPO = (SearchResult) record;

                    PSObject GPOObj = new PSObject();
                    GPOObj.Members.Add(new PSNoteProperty("DisplayName", CleanString(AdGPO.Properties["displayname"][0])));
                    GPOObj.Members.Add(new PSNoteProperty("GUID", CleanString(AdGPO.Properties["name"][0])));
                    GPOObj.Members.Add(new PSNoteProperty("whenCreated", AdGPO.Properties["whenCreated"][0]));
                    GPOObj.Members.Add(new PSNoteProperty("whenChanged", AdGPO.Properties["whenChanged"][0]));
                    GPOObj.Members.Add(new PSNoteProperty("DistinguishedName", CleanString(AdGPO.Properties["distinguishedname"][0])));
                    GPOObj.Members.Add(new PSNoteProperty("FilePath", AdGPO.Properties["gpcfilesyspath"][0]));
                    return new PSObject[] { GPOObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class GPORecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdGPO = (SearchResult) record;
                    LDAPClass.AdGPODictionary.Add((Convert.ToString(AdGPO.Properties["distinguishedname"][0]).ToUpper()), (Convert.ToString(AdGPO.Properties["displayname"][0])));
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class SOMRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdSOM = (SearchResult) record;

                    List<PSObject> SOMsList = new List<PSObject>();
                    int Depth = 0;
                    bool BlockInheritance = false;
                    bool? LinkEnabled = null;
                    bool? Enforced = null;
                    string gPLink = (AdSOM.Properties["gPLink"].Count != 0 ? Convert.ToString(AdSOM.Properties["gPLink"][0]) : "");
                    string GPOName = null;

                    Depth = ((Convert.ToString(AdSOM.Properties["distinguishedname"][0]).Split(new string[] { "OU=" }, StringSplitOptions.None)).Length -1);
                    if (AdSOM.Properties["gPOptions"].Count != 0)
                    {
                        if ((int) AdSOM.Properties["gPOptions"][0] == 1)
                        {
                            BlockInheritance = true;
                        }
                    }
                    var GPLinks = gPLink.Split(']', '[').Where(x => x.StartsWith("LDAP"));
                    int Order = (GPLinks.ToArray()).Length;
                    if (Order == 0)
                    {
                        PSObject SOMObj = new PSObject();
                        SOMObj.Members.Add(new PSNoteProperty("Name", AdSOM.Properties["name"][0]));
                        SOMObj.Members.Add(new PSNoteProperty("Depth", Depth));
                        SOMObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSOM.Properties["distinguishedname"][0]));
                        SOMObj.Members.Add(new PSNoteProperty("Link Order", null));
                        SOMObj.Members.Add(new PSNoteProperty("GPO", GPOName));
                        SOMObj.Members.Add(new PSNoteProperty("Enforced", Enforced));
                        SOMObj.Members.Add(new PSNoteProperty("Link Enabled", LinkEnabled));
                        SOMObj.Members.Add(new PSNoteProperty("BlockInheritance", BlockInheritance));
                        SOMObj.Members.Add(new PSNoteProperty("gPLink", gPLink));
                        SOMObj.Members.Add(new PSNoteProperty("gPOptions", (AdSOM.Properties["gpoptions"].Count != 0 ? AdSOM.Properties["gpoptions"][0] : "")));
                        SOMsList.Add( SOMObj );
                    }
                    foreach (string link in GPLinks)
                    {
                        string[] linksplit = link.Split('/', ';');
                        if (!Convert.ToBoolean((Convert.ToInt32(linksplit[3]) & 1)))
                        {
                            LinkEnabled = true;
                        }
                        else
                        {
                            LinkEnabled = false;
                        }
                        if (Convert.ToBoolean((Convert.ToInt32(linksplit[3]) & 2)))
                        {
                            Enforced = true;
                        }
                        else
                        {
                            Enforced = false;
                        }
                        GPOName = LDAPClass.AdGPODictionary.ContainsKey(linksplit[2].ToUpper()) ? LDAPClass.AdGPODictionary[linksplit[2].ToUpper()] : linksplit[2].Split('=',',')[1];
                        PSObject SOMObj = new PSObject();
                        SOMObj.Members.Add(new PSNoteProperty("Name", AdSOM.Properties["name"][0]));
                        SOMObj.Members.Add(new PSNoteProperty("Depth", Depth));
                        SOMObj.Members.Add(new PSNoteProperty("DistinguishedName", AdSOM.Properties["distinguishedname"][0]));
                        SOMObj.Members.Add(new PSNoteProperty("Link Order", Order));
                        SOMObj.Members.Add(new PSNoteProperty("GPO", GPOName));
                        SOMObj.Members.Add(new PSNoteProperty("Enforced", Enforced));
                        SOMObj.Members.Add(new PSNoteProperty("Link Enabled", LinkEnabled));
                        SOMObj.Members.Add(new PSNoteProperty("BlockInheritance", BlockInheritance));
                        SOMObj.Members.Add(new PSNoteProperty("gPLink", gPLink));
                        SOMObj.Members.Add(new PSNoteProperty("gPOptions", (AdSOM.Properties["gpoptions"].Count != 0 ? AdSOM.Properties["gpoptions"][0] : "")));
                        SOMsList.Add( SOMObj );
                        Order--;
                    }
                    return SOMsList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class PrinterRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdPrinter = (SearchResult) record;

                    PSObject PrinterObj = new PSObject();
                    PrinterObj.Members.Add(new PSNoteProperty("Name", AdPrinter.Properties["Name"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("ServerName", AdPrinter.Properties["serverName"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("ShareName", AdPrinter.Properties["printShareName"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("DriverName", AdPrinter.Properties["driverName"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("DriverVersion", AdPrinter.Properties["driverVersion"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("PortName", AdPrinter.Properties["portName"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("URL", AdPrinter.Properties["url"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("whenCreated", AdPrinter.Properties["whenCreated"][0]));
                    PrinterObj.Members.Add(new PSNoteProperty("whenChanged", AdPrinter.Properties["whenChanged"][0]));
                    return new PSObject[] { PrinterObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class ComputerRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdComputer = (SearchResult) record;
                    bool Dormant = false;
                    bool? Enabled = null;
                    bool PasswordNotChangedafterMaxAge = false;
                    bool? TrustedforDelegation = null;
                    bool? TrustedtoAuthforDelegation = null;
                    string DelegationType = null;
                    string DelegationProtocol = null;
                    string DelegationServices = null;
                    string StrIPAddress = null;
                    int? DaysSinceLastLogon = null;
                    int? DaysSinceLastPasswordChange = null;
                    DateTime? LastLogonDate = null;
                    DateTime? PasswordLastSet = null;

                    if (AdComputer.Properties["dnshostname"].Count != 0)
                    {
                        try
                        {
                            StrIPAddress = Convert.ToString(Dns.GetHostEntry(Convert.ToString(AdComputer.Properties["dnshostname"][0])).AddressList[0]);
                        }
                        catch
                        {
                            StrIPAddress = null;
                        }
                    }
                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdComputer.Properties["useraccountcontrol"].Count != 0)
                    {
                        var userFlags = (UACFlags) AdComputer.Properties["useraccountcontrol"][0];
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                        TrustedforDelegation = (userFlags & UACFlags.TRUSTED_FOR_DELEGATION) == UACFlags.TRUSTED_FOR_DELEGATION;
                        TrustedtoAuthforDelegation = (userFlags & UACFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION) == UACFlags.TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION;
                    }
                    if (AdComputer.Properties["lastlogontimestamp"].Count != 0)
                    {
                        LastLogonDate = DateTime.FromFileTime((long)(AdComputer.Properties["lastlogontimestamp"][0]));
                        DaysSinceLastLogon = Math.Abs((Date1 - (DateTime)LastLogonDate).Days);
                        if (DaysSinceLastLogon > DormantTimeSpan)
                        {
                            Dormant = true;
                        }
                    }
                    if (AdComputer.Properties["pwdlastset"].Count != 0)
                    {
                        PasswordLastSet = DateTime.FromFileTime((long)(AdComputer.Properties["pwdlastset"][0]));
                        DaysSinceLastPasswordChange = Math.Abs((Date1 - (DateTime)PasswordLastSet).Days);
                        if (DaysSinceLastPasswordChange > PassMaxAge)
                        {
                            PasswordNotChangedafterMaxAge = true;
                        }
                    }
                    if ( ((bool) TrustedforDelegation) && ((int) AdComputer.Properties["primarygroupid"][0] == 515) )
                    {
                        DelegationType = "Unconstrained";
                        DelegationServices = "Any";
                    }
                    if (AdComputer.Properties["msDS-AllowedToDelegateTo"].Count >= 1)
                    {
                        DelegationType = "Constrained";
                        for (int i = 0; i < AdComputer.Properties["msDS-AllowedToDelegateTo"].Count; i++)
                        {
                            var delegateto = AdComputer.Properties["msDS-AllowedToDelegateTo"][i];
                            DelegationServices = DelegationServices + "," + Convert.ToString(delegateto);
                        }
                        DelegationServices = DelegationServices.TrimStart(',');
                    }
                    if ((bool) TrustedtoAuthforDelegation)
                    {
                        DelegationProtocol = "Any";
                    }
                    else if (DelegationType != null)
                    {
                        DelegationProtocol = "Kerberos";
                    }
                    string SIDHistory = "";
                    if (AdComputer.Properties["sidhistory"].Count >= 1)
                    {
                        string sids = "";
                        for (int i = 0; i < AdComputer.Properties["sidhistory"].Count; i++)
                        {
                            var history = AdComputer.Properties["sidhistory"][i];
                            sids = sids + "," + Convert.ToString(new SecurityIdentifier((byte[])history, 0));
                        }
                        SIDHistory = sids.TrimStart(',');
                    }
                    string OperatingSystem = CleanString((AdComputer.Properties["operatingsystem"].Count != 0 ? AdComputer.Properties["operatingsystem"][0] : "-") + " " + (AdComputer.Properties["operatingsystemhotfix"].Count != 0 ? AdComputer.Properties["operatingsystemhotfix"][0] : " ") + " " + (AdComputer.Properties["operatingsystemservicepack"].Count != 0 ? AdComputer.Properties["operatingsystemservicepack"][0] : " ") + " " + (AdComputer.Properties["operatingsystemversion"].Count != 0 ? AdComputer.Properties["operatingsystemversion"][0] : " "));

                    PSObject ComputerObj = new PSObject();
                    ComputerObj.Members.Add(new PSNoteProperty("UserName", (AdComputer.Properties["samaccountname"].Count != 0 ? CleanString(AdComputer.Properties["samaccountname"][0]) : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("Name", (AdComputer.Properties["name"].Count != 0 ? CleanString(AdComputer.Properties["name"][0]) : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("DNSHostName", (AdComputer.Properties["dnshostname"].Count != 0 ? AdComputer.Properties["dnshostname"][0] : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                    ComputerObj.Members.Add(new PSNoteProperty("IPv4Address", StrIPAddress));
                    ComputerObj.Members.Add(new PSNoteProperty("Operating System", OperatingSystem));
                    ComputerObj.Members.Add(new PSNoteProperty("Logon Age (days)", DaysSinceLastLogon));
                    ComputerObj.Members.Add(new PSNoteProperty("Password Age (days)", DaysSinceLastPasswordChange));
                    ComputerObj.Members.Add(new PSNoteProperty("Dormant (> " + DormantTimeSpan + " days)", Dormant));
                    ComputerObj.Members.Add(new PSNoteProperty("Password Age (> " + PassMaxAge + " days)", PasswordNotChangedafterMaxAge));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Type", DelegationType));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Protocol", DelegationProtocol));
                    ComputerObj.Members.Add(new PSNoteProperty("Delegation Services", DelegationServices));
                    ComputerObj.Members.Add(new PSNoteProperty("Primary Group ID", (AdComputer.Properties["primarygroupid"].Count != 0 ? AdComputer.Properties["primarygroupid"][0] : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("SID", Convert.ToString(new SecurityIdentifier((byte[])AdComputer.Properties["objectSID"][0], 0))));
                    ComputerObj.Members.Add(new PSNoteProperty("SIDHistory", SIDHistory));
                    ComputerObj.Members.Add(new PSNoteProperty("Description", (AdComputer.Properties["Description"].Count != 0 ? CleanString(AdComputer.Properties["Description"][0]) : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("ms-ds-CreatorSid", (AdComputer.Properties["ms-ds-CreatorSid"].Count != 0 ? Convert.ToString(new SecurityIdentifier((byte[])AdComputer.Properties["ms-ds-CreatorSid"][0], 0)) : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("Last Logon Date", LastLogonDate));
                    ComputerObj.Members.Add(new PSNoteProperty("Password LastSet", PasswordLastSet));
                    ComputerObj.Members.Add(new PSNoteProperty("UserAccountControl", (AdComputer.Properties["useraccountcontrol"].Count != 0 ? AdComputer.Properties["useraccountcontrol"][0] : "")));
                    ComputerObj.Members.Add(new PSNoteProperty("whenCreated", AdComputer.Properties["whencreated"][0]));
                    ComputerObj.Members.Add(new PSNoteProperty("whenChanged", AdComputer.Properties["whenchanged"][0]));
                    ComputerObj.Members.Add(new PSNoteProperty("Distinguished Name", AdComputer.Properties["distinguishedname"][0]));
                    return new PSObject[] { ComputerObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class ComputerSPNRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdComputer = (SearchResult) record;
                    if (AdComputer.Properties["serviceprincipalname"].Count == 0)
                    {
                        return new PSObject[] { };
                    }
                    List<PSObject> SPNList = new List<PSObject>();

                    foreach (string SPN in AdComputer.Properties["serviceprincipalname"])
                    {
                        string[] SPNArray = SPN.Split('/');
                        bool flag = true;
                        foreach (PSObject Obj in SPNList)
                        {
                            if ( (string) Obj.Members["Service"].Value == SPNArray[0] )
                            {
                                Obj.Members["Host"].Value = string.Join(",", (Obj.Members["Host"].Value + "," + SPNArray[1]).Split(',').Distinct().ToArray());
                                flag = false;
                            }
                        }
                        if (flag)
                        {
                            PSObject ComputerSPNObj = new PSObject();
                            ComputerSPNObj.Members.Add(new PSNoteProperty("UserName", (AdComputer.Properties["samaccountname"].Count != 0 ? CleanString(AdComputer.Properties["samaccountname"][0]) : "")));
                            ComputerSPNObj.Members.Add(new PSNoteProperty("Name", (AdComputer.Properties["name"].Count != 0 ? CleanString(AdComputer.Properties["name"][0]) : "")));
                            ComputerSPNObj.Members.Add(new PSNoteProperty("Service", SPNArray[0]));
                            ComputerSPNObj.Members.Add(new PSNoteProperty("Host", SPNArray[1]));
                            SPNList.Add( ComputerSPNObj );
                        }
                    }
                    return SPNList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class LAPSRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdComputer = (SearchResult) record;
                    bool? Enabled = null;
                    bool PasswordStored = false;
                    DateTime? CurrentExpiration = null;
                    // When the user is not allowed to query the UserAccountControl attribute.
                    if (AdComputer.Properties["useraccountcontrol"].Count != 0)
                    {
                        var userFlags = (UACFlags) AdComputer.Properties["useraccountcontrol"][0];
                        Enabled = !((userFlags & UACFlags.ACCOUNTDISABLE) == UACFlags.ACCOUNTDISABLE);
                    }
                    if (AdComputer.Properties["ms-mcs-admpwdexpirationtime"].Count != 0)
                    {
                        CurrentExpiration = DateTime.FromFileTime((long)(AdComputer.Properties["ms-mcs-admpwdexpirationtime"][0]));
                        PasswordStored = true;
                    }
                    PSObject LAPSObj = new PSObject();
                    LAPSObj.Members.Add(new PSNoteProperty("Hostname", (AdComputer.Properties["dnshostname"].Count != 0 ? AdComputer.Properties["dnshostname"][0] : AdComputer.Properties["cn"][0] )));
                    LAPSObj.Members.Add(new PSNoteProperty("Enabled", Enabled));
                    LAPSObj.Members.Add(new PSNoteProperty("Stored", PasswordStored));
                    LAPSObj.Members.Add(new PSNoteProperty("Readable", (AdComputer.Properties["ms-mcs-admpwd"].Count != 0 ? true : false)));
                    LAPSObj.Members.Add(new PSNoteProperty("Password", (AdComputer.Properties["ms-mcs-admpwd"].Count != 0 ? AdComputer.Properties["ms-mcs-admpwd"][0] : null)));
                    LAPSObj.Members.Add(new PSNoteProperty("Expiration", CurrentExpiration));
                    return new PSObject[] { LAPSObj };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class SIDRecordDictionaryProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdObject = (SearchResult) record;
                    switch (Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]))
                    {
                        case "user":
                        case "computer":
                        case "group":
                            LDAPClass.AdSIDDictionary.Add(Convert.ToString(new SecurityIdentifier((byte[])AdObject.Properties["objectSID"][0], 0)), (Convert.ToString(AdObject.Properties["name"][0])));
                            break;
                    }
                    return new PSObject[] { };
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        class DACLRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdObject = (SearchResult) record;
                    byte[] ntSecurityDescriptor = null;
                    string Name = null;
                    string Type = null;
                    List<PSObject> DACLList = new List<PSObject>();

                    Name = Convert.ToString(AdObject.Properties["name"][0]);

                    switch (Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]))
                    {
                        case "user":
                            Type = "User";
                            break;
                        case "computer":
                            Type = "Computer";
                            break;
                        case "group":
                            Type = "Group";
                            break;
                        case "container":
                            Type = "Container";
                            break;
                        case "groupPolicyContainer":
                            Type = "GPO";
                            Name = Convert.ToString(AdObject.Properties["displayname"][0]);
                            break;
                        case "organizationalUnit":
                            Type = "OU";
                            break;
                        case "domainDNS":
                            Type = "Domain";
                            break;
                        default:
                            Type = Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]);
                            break;
                    }

                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdObject.Properties["ntsecuritydescriptor"].Count != 0)
                    {
                        ntSecurityDescriptor = (byte[]) AdObject.Properties["ntsecuritydescriptor"][0];
                    }
                    else
                    {
                        DirectoryEntry AdObjectEntry = ((SearchResult)record).GetDirectoryEntry();
                        ntSecurityDescriptor = (byte[]) AdObjectEntry.ObjectSecurity.GetSecurityDescriptorBinaryForm();
                    }
                    if (ntSecurityDescriptor != null)
                    {
                        DirectoryObjectSecurity DirObjSec = new ActiveDirectorySecurity();
                        DirObjSec.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
                        AuthorizationRuleCollection AccessRules = (AuthorizationRuleCollection) DirObjSec.GetAccessRules(true,true,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAccessRule Rule in AccessRules)
                        {
                            string IdentityReference = Convert.ToString(Rule.IdentityReference);
                            string Owner = Convert.ToString(DirObjSec.GetOwner(typeof(System.Security.Principal.SecurityIdentifier)));
                            PSObject ObjectObj = new PSObject();
                            ObjectObj.Members.Add(new PSNoteProperty("Name", CleanString(Name)));
                            ObjectObj.Members.Add(new PSNoteProperty("Type", Type));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectTypeName", LDAPClass.GUIDs[Convert.ToString(Rule.ObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectTypeName", LDAPClass.GUIDs[Convert.ToString(Rule.InheritedObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("ActiveDirectoryRights", Rule.ActiveDirectoryRights));
                            ObjectObj.Members.Add(new PSNoteProperty("AccessControlType", Rule.AccessControlType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReferenceName", LDAPClass.AdSIDDictionary.ContainsKey(IdentityReference) ? LDAPClass.AdSIDDictionary[IdentityReference] : IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("OwnerName", LDAPClass.AdSIDDictionary.ContainsKey(Owner) ? LDAPClass.AdSIDDictionary[Owner] : Owner));
                            ObjectObj.Members.Add(new PSNoteProperty("Inherited", Rule.IsInherited));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectFlags", Rule.ObjectFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceFlags", Rule.InheritanceFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceType", Rule.InheritanceType));
                            ObjectObj.Members.Add(new PSNoteProperty("PropagationFlags", Rule.PropagationFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectType", Rule.ObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectType", Rule.InheritedObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReference", Rule.IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("Owner", Owner));
                            ObjectObj.Members.Add(new PSNoteProperty("DistinguishedName", AdObject.Properties["distinguishedname"][0]));
                            DACLList.Add( ObjectObj );
                        }
                    }

                    return DACLList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

    class SACLRecordProcessor : IRecordProcessor
        {
            public PSObject[] processRecord(Object record)
            {
                try
                {
                    SearchResult AdObject = (SearchResult) record;
                    byte[] ntSecurityDescriptor = null;
                    string Name = null;
                    string Type = null;
                    List<PSObject> SACLList = new List<PSObject>();

                    Name = Convert.ToString(AdObject.Properties["name"][0]);

                    switch (Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]))
                    {
                        case "user":
                            Type = "User";
                            break;
                        case "computer":
                            Type = "Computer";
                            break;
                        case "group":
                            Type = "Group";
                            break;
                        case "container":
                            Type = "Container";
                            break;
                        case "groupPolicyContainer":
                            Type = "GPO";
                            Name = Convert.ToString(AdObject.Properties["displayname"][0]);
                            break;
                        case "organizationalUnit":
                            Type = "OU";
                            break;
                        case "domainDNS":
                            Type = "Domain";
                            break;
                        default:
                            Type = Convert.ToString(AdObject.Properties["objectclass"][AdObject.Properties["objectclass"].Count-1]);
                            break;
                    }

                    // When the user is not allowed to query the ntsecuritydescriptor attribute.
                    if (AdObject.Properties["ntsecuritydescriptor"].Count != 0)
                    {
                        ntSecurityDescriptor = (byte[]) AdObject.Properties["ntsecuritydescriptor"][0];
                    }
                    else
                    {
                        DirectoryEntry AdObjectEntry = ((SearchResult)record).GetDirectoryEntry();
                        ntSecurityDescriptor = (byte[]) AdObjectEntry.ObjectSecurity.GetSecurityDescriptorBinaryForm();
                    }
                    if (ntSecurityDescriptor != null)
                    {
                        DirectoryObjectSecurity DirObjSec = new ActiveDirectorySecurity();
                        DirObjSec.SetSecurityDescriptorBinaryForm(ntSecurityDescriptor);
                        AuthorizationRuleCollection AuditRules = (AuthorizationRuleCollection) DirObjSec.GetAuditRules(true,true,typeof(System.Security.Principal.NTAccount));
                        foreach (ActiveDirectoryAuditRule Rule in AuditRules)
                        {
                            string IdentityReference = Convert.ToString(Rule.IdentityReference);
                            PSObject ObjectObj = new PSObject();
                            ObjectObj.Members.Add(new PSNoteProperty("Name", CleanString(Name)));
                            ObjectObj.Members.Add(new PSNoteProperty("Type", Type));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectTypeName", LDAPClass.GUIDs[Convert.ToString(Rule.ObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectTypeName", LDAPClass.GUIDs[Convert.ToString(Rule.InheritedObjectType)]));
                            ObjectObj.Members.Add(new PSNoteProperty("ActiveDirectoryRights", Rule.ActiveDirectoryRights));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReferenceName", LDAPClass.AdSIDDictionary.ContainsKey(IdentityReference) ? LDAPClass.AdSIDDictionary[IdentityReference] : IdentityReference));
                            ObjectObj.Members.Add(new PSNoteProperty("AuditFlags", Rule.AuditFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectFlags", Rule.ObjectFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceFlags", Rule.InheritanceFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritanceType", Rule.InheritanceType));
                            ObjectObj.Members.Add(new PSNoteProperty("Inherited", Rule.IsInherited));
                            ObjectObj.Members.Add(new PSNoteProperty("PropagationFlags", Rule.PropagationFlags));
                            ObjectObj.Members.Add(new PSNoteProperty("ObjectType", Rule.ObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("InheritedObjectType", Rule.InheritedObjectType));
                            ObjectObj.Members.Add(new PSNoteProperty("IdentityReference", Rule.IdentityReference));
                            SACLList.Add( ObjectObj );
                        }
                    }

                    return SACLList.ToArray();
                }
                catch (Exception e)
                {
                    Console.WriteLine("Exception caught: {0}", e);
                    return new PSObject[] { };
                }
            }
        }

        //The interface and implmentation class used to handle the results (this implementation just writes the strings to a file)

        interface IResultsHandler
        {
            void processResults(Object[] t);

            Object[] finalise();
        }

        class SimpleResultsHandler : IResultsHandler
        {
            private Object lockObj = new Object();
            private List<Object> processed = new List<Object>();

            public SimpleResultsHandler()
            {
            }

            public void processResults(Object[] results)
            {
                lock (lockObj)
                {
                    if (results.Length != 0)
                    {
                        for (var i = 0; i < results.Length; i++)
                        {
                            processed.Add((PSObject)results[i]);
                        }
                    }
                }
            }

            public Object[] finalise()
            {
                return processed.ToArray();
            }
        }
"@

# modified version from https://github.com/vletoux/SmbScanner/blob/master/smbscanner.ps1
$PingCastleSMBScannerSource = @"

        [StructLayout(LayoutKind.Explicit)]
		struct SMB_Header {
			[FieldOffset(0)]
			public UInt32 Protocol;
			[FieldOffset(4)]
			public byte Command;
			[FieldOffset(5)]
			public int Status;
			[FieldOffset(9)]
			public byte  Flags;
			[FieldOffset(10)]
			public UInt16 Flags2;
			[FieldOffset(12)]
			public UInt16 PIDHigh;
			[FieldOffset(14)]
			public UInt64 SecurityFeatures;
			[FieldOffset(22)]
			public UInt16 Reserved;
			[FieldOffset(24)]
			public UInt16 TID;
			[FieldOffset(26)]
			public UInt16 PIDLow;
			[FieldOffset(28)]
			public UInt16 UID;
			[FieldOffset(30)]
			public UInt16 MID;
		};
		// https://msdn.microsoft.com/en-us/library/cc246529.aspx
		[StructLayout(LayoutKind.Explicit)]
		struct SMB2_Header {
			[FieldOffset(0)]
			public UInt32 ProtocolId;
			[FieldOffset(4)]
			public UInt16 StructureSize;
			[FieldOffset(6)]
			public UInt16 CreditCharge;
			[FieldOffset(8)]
			public UInt32 Status; // to do SMB3
			[FieldOffset(12)]
			public UInt16 Command;
			[FieldOffset(14)]
			public UInt16 CreditRequest_Response;
			[FieldOffset(16)]
			public UInt32 Flags;
			[FieldOffset(20)]
			public UInt32 NextCommand;
			[FieldOffset(24)]
			public UInt64 MessageId;
			[FieldOffset(32)]
			public UInt32 Reserved;
			[FieldOffset(36)]
			public UInt32 TreeId;
			[FieldOffset(40)]
			public UInt64 SessionId;
			[FieldOffset(48)]
			public UInt64 Signature1;
			[FieldOffset(56)]
			public UInt64 Signature2;
		}
        [StructLayout(LayoutKind.Explicit)]
		struct SMB2_NegotiateRequest
		{
			[FieldOffset(0)]
			public UInt16 StructureSize;
			[FieldOffset(2)]
			public UInt16 DialectCount;
			[FieldOffset(4)]
			public UInt16 SecurityMode;
			[FieldOffset(6)]
			public UInt16 Reserved;
			[FieldOffset(8)]
			public UInt32 Capabilities;
			[FieldOffset(12)]
			public Guid ClientGuid;
			[FieldOffset(28)]
			public UInt64 ClientStartTime;
			[FieldOffset(36)]
			public UInt16 DialectToTest;
		}
		const int SMB_COM_NEGOTIATE	= 0x72;
		const int SMB2_NEGOTIATE = 0;
		const int SMB_FLAGS_CASE_INSENSITIVE = 0x08;
		const int SMB_FLAGS_CANONICALIZED_PATHS = 0x10;
		const int SMB_FLAGS2_LONG_NAMES					= 0x0001;
		const int SMB_FLAGS2_EAS							= 0x0002;
		const int SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED	= 0x0010	;
		const int SMB_FLAGS2_IS_LONG_NAME					= 0x0040;
		const int SMB_FLAGS2_ESS							= 0x0800;
		const int SMB_FLAGS2_NT_STATUS					= 0x4000;
		const int SMB_FLAGS2_UNICODE						= 0x8000;
		const int SMB_DB_FORMAT_DIALECT = 0x02;
		static byte[] GenerateSmbHeaderFromCommand(byte command)
		{
			SMB_Header header = new SMB_Header();
			header.Protocol = 0x424D53FF;
			header.Command = command;
			header.Status = 0;
			header.Flags = SMB_FLAGS_CASE_INSENSITIVE | SMB_FLAGS_CANONICALIZED_PATHS;
			header.Flags2 = SMB_FLAGS2_LONG_NAMES | SMB_FLAGS2_EAS | SMB_FLAGS2_SECURITY_SIGNATURE_REQUIRED | SMB_FLAGS2_IS_LONG_NAME | SMB_FLAGS2_ESS | SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_UNICODE;
			header.PIDHigh = 0;
			header.SecurityFeatures = 0;
			header.Reserved = 0;
			header.TID = 0xffff;
			header.PIDLow = 0xFEFF;
			header.UID = 0;
			header.MID = 0;
			return getBytes(header);
		}
		static byte[] GenerateSmb2HeaderFromCommand(byte command)
		{
			SMB2_Header header = new SMB2_Header();
			header.ProtocolId = 0x424D53FE;
			header.Command = command;
			header.StructureSize = 64;
			header.Command = command;
			header.MessageId = 0;
			header.Reserved = 0xFEFF;
			return getBytes(header);
		}
		static byte[] getBytes(object structure)
		{
			int size = Marshal.SizeOf(structure);
			byte[] arr = new byte[size];
			IntPtr ptr = Marshal.AllocHGlobal(size);
			Marshal.StructureToPtr(structure, ptr, true);
			Marshal.Copy(ptr, arr, 0, size);
			Marshal.FreeHGlobal(ptr);
			return arr;
		}
		static byte[] getDialect(string dialect)
		{
			byte[] dialectBytes = Encoding.ASCII.GetBytes(dialect);
			byte[] output = new byte[dialectBytes.Length + 2];
			output[0] = 2;
			output[output.Length - 1] = 0;
			Array.Copy(dialectBytes, 0, output, 1, dialectBytes.Length);
			return output;
		}
		static byte[] GetNegotiateMessage(byte[] dialect)
		{
			byte[] output = new byte[dialect.Length + 3];
			output[0] = 0;
			output[1] = (byte) dialect.Length;
			output[2] = 0;
			Array.Copy(dialect, 0, output, 3, dialect.Length);
			return output;
		}
		// MS-SMB2  2.2.3 SMB2 NEGOTIATE Request
		static byte[] GetNegotiateMessageSmbv2(int DialectToTest)
		{
			SMB2_NegotiateRequest request = new SMB2_NegotiateRequest();
			request.StructureSize = 36;
			request.DialectCount = 1;
			request.SecurityMode = 1; // signing enabled
			request.ClientGuid = Guid.NewGuid();
			request.DialectToTest = (UInt16) DialectToTest;
			return getBytes(request);
		}
		static byte[] GetNegotiatePacket(byte[] header, byte[] smbPacket)
		{
			byte[] output = new byte[smbPacket.Length + header.Length + 4];
			output[0] = 0;
			output[1] = 0;
			output[2] = 0;
			output[3] = (byte)(smbPacket.Length + header.Length);
			Array.Copy(header, 0, output, 4, header.Length);
			Array.Copy(smbPacket, 0, output, 4 + header.Length, smbPacket.Length);
			return output;
		}
		public static bool DoesServerSupportDialect(string server, string dialect)
		{
			Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect);
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445);
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmbHeaderFromCommand(SMB_COM_NEGOTIATE);
				byte[] dialectEncoding = getDialect(dialect);
				byte[] negotiatemessage = GetNegotiateMessage(dialectEncoding);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();
				byte[] netbios = new byte[4];
				if (stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                {
                    return false;
                }
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                {
                    return false;
                }
				byte[] negotiateresponse = new byte[3];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                {
                    return false;
                }
				if (negotiateresponse[1] == 0 && negotiateresponse[2] == 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV1 dialect " + dialect + " = Not supported");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb1 is not supported on " + server);
			}
		}
		public static bool DoesServerSupportDialectWithSmbV2(string server, int dialect, bool checkSMBSigning)
		{
			Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2"));
			TcpClient client = new TcpClient();
			try
			{
				client.Connect(server, 445);
			}
			catch (Exception)
			{
				throw new Exception("port 445 is closed on " + server);
			}
			try
			{
				NetworkStream stream = client.GetStream();
				byte[] header = GenerateSmb2HeaderFromCommand(SMB2_NEGOTIATE);
				byte[] negotiatemessage = GetNegotiateMessageSmbv2(dialect);
				byte[] packet = GetNegotiatePacket(header, negotiatemessage);
				stream.Write(packet, 0, packet.Length);
				stream.Flush();
				byte[] netbios = new byte[4];
				if( stream.Read(netbios, 0, netbios.Length) != netbios.Length)
                {
                    return false;
                }
				byte[] smbHeader = new byte[Marshal.SizeOf(typeof(SMB2_Header))];
				if (stream.Read(smbHeader, 0, smbHeader.Length) != smbHeader.Length)
                {
                    return false;
                }
				if (smbHeader[8] != 0 || smbHeader[9] != 0 || smbHeader[10] != 0 || smbHeader[11] != 0)
				{
					Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Not supported via error code");
					return false;
				}
				byte[] negotiateresponse = new byte[6];
				if (stream.Read(negotiateresponse, 0, negotiateresponse.Length) != negotiateresponse.Length)
                {
                    return false;
                }
                if (checkSMBSigning)
                {
                    // https://support.microsoft.com/en-in/help/887429/overview-of-server-message-block-signing
                    // https://msdn.microsoft.com/en-us/library/cc246561.aspx
				    if (negotiateresponse[2] == 3)
				    {
					    Trace.WriteLine("Checking " + server + " for SMBV2 SMB Signing dialect 0x" + dialect.ToString("X2") + " = Supported");
					    return true;
				    }
                    else
                    {
                        return false;
                    }
                }
				int selectedDialect = negotiateresponse[5] * 0x100 + negotiateresponse[4];
				if (selectedDialect == dialect)
				{
					Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Supported");
					return true;
				}
				Trace.WriteLine("Checking " + server + " for SMBV2 dialect 0x" + dialect.ToString("X2") + " = Not supported via not returned dialect");
				return false;
			}
			catch (Exception)
			{
				throw new ApplicationException("Smb2 is not supported on " + server);
			}
		}
		public static bool SupportSMB1(string server)
		{
			try
			{
				return DoesServerSupportDialect(server, "NT LM 0.12");
			}
			catch (Exception)
			{
				return false;
			}
		}
		public static bool SupportSMB2(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0202, false) || DoesServerSupportDialectWithSmbV2(server, 0x0210, false));
			}
			catch (Exception)
			{
				return false;
			}
		}
		public static bool SupportSMB3(string server)
		{
			try
			{
				return (DoesServerSupportDialectWithSmbV2(server, 0x0300, false) || DoesServerSupportDialectWithSmbV2(server, 0x0302, false) || DoesServerSupportDialectWithSmbV2(server, 0x0311, false));
			}
			catch (Exception)
			{
				return false;
			}
		}
		public static string Name { get { return "smb"; } }
		public static PSObject GetPSObject(Object IPv4Address)
		{
            string computer = Convert.ToString(IPv4Address);
            PSObject DCSMBObj = new PSObject();
            if (computer == "")
            {
                DCSMBObj.Members.Add(new PSNoteProperty("SMB Port Open", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB1(NT LM 0.12)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB2(0x0202)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB2(0x0210)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0300)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0302)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0311)", null));
                DCSMBObj.Members.Add(new PSNoteProperty("SMB Signing", null));
                return DCSMBObj;
            }
            bool isPortOpened = true;
			bool SMBv1 = false;
			bool SMBv2_0x0202 = false;
			bool SMBv2_0x0210 = false;
			bool SMBv3_0x0300 = false;
			bool SMBv3_0x0302 = false;
			bool SMBv3_0x0311 = false;
            bool SMBSigning = false;
			try
			{
				try
				{
					SMBv1 = DoesServerSupportDialect(computer, "NT LM 0.12");
				}
				catch (ApplicationException)
				{
				}
				try
				{
					SMBv2_0x0202 = DoesServerSupportDialectWithSmbV2(computer, 0x0202, false);
					SMBv2_0x0210 = DoesServerSupportDialectWithSmbV2(computer, 0x0210, false);
					SMBv3_0x0300 = DoesServerSupportDialectWithSmbV2(computer, 0x0300, false);
					SMBv3_0x0302 = DoesServerSupportDialectWithSmbV2(computer, 0x0302, false);
					SMBv3_0x0311 = DoesServerSupportDialectWithSmbV2(computer, 0x0311, false);
				}
				catch (ApplicationException)
				{
				}
			}
			catch (Exception)
			{
				isPortOpened = false;
			}
			if (SMBv3_0x0311)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0311, true);
			}
			else if (SMBv3_0x0302)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0302, true);
			}
			else if (SMBv3_0x0300)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0300, true);
			}
			else if (SMBv2_0x0210)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0210, true);
			}
			else if (SMBv2_0x0202)
			{
				SMBSigning = DoesServerSupportDialectWithSmbV2(computer, 0x0202, true);
			}
            DCSMBObj.Members.Add(new PSNoteProperty("SMB Port Open", isPortOpened));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB1(NT LM 0.12)", SMBv1));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB2(0x0202)", SMBv2_0x0202));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB2(0x0210)", SMBv2_0x0210));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0300)", SMBv3_0x0300));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0302)", SMBv3_0x0302));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB3(0x0311)", SMBv3_0x0311));
            DCSMBObj.Members.Add(new PSNoteProperty("SMB Signing", SMBSigning));
            return DCSMBObj;
		}
	}
}
"@

# Import the LogonUser, ImpersonateLoggedOnUser and RevertToSelf Functions from advapi32.dll and the CloseHandle Function from kernel32.dll
# https://docs.microsoft.com/en-gb/powershell/module/Microsoft.PowerShell.Utility/Add-Type?view=powershell-5.1
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378184(v=vs.85).aspx
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa378612(v=vs.85).aspx
# https://msdn.microsoft.com/en-us/library/windows/desktop/aa379317(v=vs.85).aspx

$Advapi32Def = @'
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool RevertToSelf();
'@

# https://msdn.microsoft.com/en-us/library/windows/desktop/ms724211(v=vs.85).aspx

$Kernel32Def = @'
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
'@

Function Get-DateDiff
{
<#
.SYNOPSIS
    Get difference between two dates.

.DESCRIPTION
    Returns the difference between two dates.

.PARAMETER Date1
    [DateTime]
    Date

.PARAMETER Date2
    [DateTime]
    Date

.OUTPUTS
    [System.ValueType.TimeSpan]
    Returns the difference between the two dates.
#>
    param (
        [Parameter(Mandatory = $true)]
        [DateTime] $Date1,

        [Parameter(Mandatory = $true)]
        [DateTime] $Date2
    )

    If ($Date2 -gt $Date1)
    {
        $DDiff = $Date2 - $Date1
    }
    Else
    {
        $DDiff = $Date1 - $Date2
    }
    Return $DDiff
}

Function Get-DNtoFQDN
{
<#
.SYNOPSIS
    Gets Domain Distinguished Name (DN) from the Fully Qualified Domain Name (FQDN).

.DESCRIPTION
    Converts Domain Distinguished Name (DN) to Fully Qualified Domain Name (FQDN).

.PARAMETER ADObjectDN
    [string]
    Domain Distinguished Name (DN)

.OUTPUTS
    [String]
    Returns the Fully Qualified Domain Name (FQDN).

.LINK
    https://adsecurity.org/?p=440
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $ADObjectDN
    )

    $Index = $ADObjectDN.IndexOf('DC=')
    If ($Index)
    {
        $ADObjectDNDomainName = $($ADObjectDN.SubString($Index)) -replace 'DC=','' -replace ',','.'
    }
    Else
    {
        # Modified version from https://adsecurity.org/?p=440
        [array] $ADObjectDNArray = $ADObjectDN -Split ("DC=")
        $ADObjectDNArray | ForEach-Object {
            [array] $temp = $_ -Split (",")
            [string] $ADObjectDNArrayItemDomainName += $temp[0] + "."
        }
        $ADObjectDNDomainName = $ADObjectDNArrayItemDomainName.Substring(1, $ADObjectDNArrayItemDomainName.Length - 2)
    }
    Return $ADObjectDNDomainName
}

Function Export-ADRCSV
{
<#
.SYNOPSIS
    Exports Object to a CSV file.

.DESCRIPTION
    Exports Object to a CSV file using Export-CSV.

.PARAMETER ADRObj
    [PSObject]
    ADRObj

.PARAMETER ADFileName
    [String]
    Path to save the CSV File.

.OUTPUTS
    CSV file.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $ADFileName
    )

    Try
    {
        $ADRObj | Export-Csv -Path $ADFileName -NoTypeInformation -Encoding Default
    }
    Catch
    {
        Write-Warning "[Export-ADRCSV] Failed to export $($ADFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-ADRXML
{
<#
.SYNOPSIS
    Exports Object to a XML file.

.DESCRIPTION
    Exports Object to a XML file using Export-Clixml.

.PARAMETER ADRObj
    [PSObject]
    ADRObj

.PARAMETER ADFileName
    [String]
    Path to save the XML File.

.OUTPUTS
    XML file.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $ADFileName
    )

    Try
    {
        (ConvertTo-Xml -NoTypeInformation -InputObject $ADRObj).Save($ADFileName)
    }
    Catch
    {
        Write-Warning "[Export-ADRXML] Failed to export $($ADFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-ADRJSON
{
<#
.SYNOPSIS
    Exports Object to a JSON file.

.DESCRIPTION
    Exports Object to a JSON file using ConvertTo-Json.

.PARAMETER ADRObj
    [PSObject]
    ADRObj

.PARAMETER ADFileName
    [String]
    Path to save the JSON File.

.OUTPUTS
    JSON file.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $ADFileName
    )

    Try
    {
        ConvertTo-JSON -InputObject $ADRObj | Out-File -FilePath $ADFileName
    }
    Catch
    {
        Write-Warning "[Export-ADRJSON] Failed to export $($ADFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-ADRHTML
{
<#
.SYNOPSIS
    Exports Object to a HTML file.

.DESCRIPTION
    Exports Object to a HTML file using ConvertTo-Html.

.PARAMETER ADRObj
    [PSObject]
    ADRObj

.PARAMETER ADFileName
    [String]
    Path to save the HTML File.

.OUTPUTS
    HTML file.
#>
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String] $ADFileName,

        [Parameter(Mandatory = $false)]
        [String] $ADROutputDir = $null
    )

$Header = @"
<style type="text/css">
th {
	color:white;
	background-color:blue;
}
td, th {
	border:0px solid black;
	border-collapse:collapse;
	white-space:pre;
}
tr:nth-child(2n+1) {
    background-color: #dddddd;
}
tr:hover td {
    background-color: #c1d5f8;
}
table, tr, td, th {
	padding: 0px;
	margin: 0px;
	white-space:pre;
}
table {
	margin-left:1px;
}
</style>
"@
    Try
    {
        If ($ADFileName.Contains("Index"))
        {
            $HTMLPath  = -join($ADROutputDir,'\','HTML-Files')
            $HTMLPath = $((Convert-Path $HTMLPath).TrimEnd("\"))
            $HTMLFiles = Get-ChildItem -Path $HTMLPath -name
            $HTML = $HTMLFiles | ConvertTo-HTML -Title "ADRecon" -Property @{Label="Table of Contents";Expression={"<a href='$($_)'>$($_)</a>"}} -Head $Header

            Add-Type -AssemblyName System.Web
            [System.Web.HttpUtility]::HtmlDecode($HTML) | Out-File -FilePath $ADFileName
        }
        Else
        {
            If ($ADRObj -is [array])
            {
                $ADRObj | Select-Object * | ConvertTo-HTML -As Table -Head $Header | Out-File -FilePath $ADFileName
            }
            Else
            {
                ConvertTo-HTML -InputObject $ADRObj -As Table -Head $Header | Out-File -FilePath $ADFileName
            }
        }
    }
    Catch
    {
        Write-Warning "[Export-ADRHTML] Failed to export $($ADFileName)."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
}

Function Export-ADR
{
<#
.SYNOPSIS
    Helper function for all output types supported.

.DESCRIPTION
    Helper function for all output types supported.

.PARAMETER ADObjectDN
    [PSObject]
    ADRObj

.PARAMETER ADROutputDir
    [String]
    Path for ADRecon output folder.

.PARAMETER OutputType
    [array]
    Output Type.

.PARAMETER ADRModuleName
    [String]
    Module Name.

.OUTPUTS
    STDOUT, CSV, XML, JSON and/or HTML file, etc.
#>
    param(
        [Parameter(Mandatory = $true)]
        [PSObject] $ADRObj,

        [Parameter(Mandatory = $true)]
        [String] $ADROutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType,

        [Parameter(Mandatory = $true)]
        [String] $ADRModuleName
    )

    Switch ($OutputType)
    {
        'STDOUT'
        {
            If ($ADRModuleName -ne "AboutADRecon")
            {
                If ($ADRObj -is [array])
                {
                    # Fix for InvalidOperationException: The object of type "Microsoft.PowerShell.Commands.Internal.Format.FormatStartData" is not valid or not in the correct sequence.
                    $ADRObj | Out-String -Stream
                }
                Else
                {
                    # Fix for InvalidOperationException: The object of type "Microsoft.PowerShell.Commands.Internal.Format.FormatStartData" is not valid or not in the correct sequence.
                    $ADRObj | Format-List | Out-String -Stream
                }
            }
        }
        'CSV'
        {
            $ADFileName  = -join($ADROutputDir,'\','CSV-Files','\',$ADRModuleName,'.csv')
            Export-ADRCSV -ADRObj $ADRObj -ADFileName $ADFileName
        }
        'XML'
        {
            $ADFileName  = -join($ADROutputDir,'\','XML-Files','\',$ADRModuleName,'.xml')
            Export-ADRXML -ADRObj $ADRObj -ADFileName $ADFileName
        }
        'JSON'
        {
            $ADFileName  = -join($ADROutputDir,'\','JSON-Files','\',$ADRModuleName,'.json')
            Export-ADRJSON -ADRObj $ADRObj -ADFileName $ADFileName
        }
        'HTML'
        {
            $ADFileName  = -join($ADROutputDir,'\','HTML-Files','\',$ADRModuleName,'.html')
            Export-ADRHTML -ADRObj $ADRObj -ADFileName $ADFileName -ADROutputDir $ADROutputDir
        }
    }
}

Function Get-ADRExcelComObj
{
<#
.SYNOPSIS
    Creates a ComObject to interact with Microsoft Excel.

.DESCRIPTION
    Creates a ComObject to interact with Microsoft Excel if installed, else warning is raised.

.OUTPUTS
    [System.__ComObject] and [System.MarshalByRefObject]
    Creates global variables $excel and $workbook.
#>

    #Check if Excel is installed.
    Try
    {
        # Suppress verbose output
        $SaveVerbosePreference = $script:VerbosePreference
        $script:VerbosePreference = 'SilentlyContinue'
        $global:excel = New-Object -ComObject excel.application
        If ($SaveVerbosePreference)
        {
            $script:VerbosePreference = $SaveVerbosePreference
            Remove-Variable SaveVerbosePreference
        }
    }
    Catch
    {
        If ($SaveVerbosePreference)
        {
            $script:VerbosePreference = $SaveVerbosePreference
            Remove-Variable SaveVerbosePreference
        }
        Write-Warning "[Get-ADRExcelComObj] Excel does not appear to be installed. Skipping generation of ADRecon-Report.xlsx. Use the -GenExcel parameter to generate the ADRecon-Report.xslx on a host with Microsoft Excel installed."
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        Return $null
    }
    $excel.Visible = $true
    $excel.Interactive = $false
    $global:workbook = $excel.Workbooks.Add()
    If ($workbook.Worksheets.Count -eq 3)
    {
        $workbook.WorkSheets.Item(3).Delete()
        $workbook.WorkSheets.Item(2).Delete()
    }
}

Function Get-ADRExcelComObjRelease
{
<#
.SYNOPSIS
    Releases the ComObject created to interact with Microsoft Excel.

.DESCRIPTION
    Releases the ComObject created to interact with Microsoft Excel.

.PARAMETER ComObjtoRelease
    ComObjtoRelease

.PARAMETER Final
    Final
#>
    param(
        [Parameter(Mandatory = $true)]
        $ComObjtoRelease,

        [Parameter(Mandatory = $false)]
        [bool] $Final = $false
    )
    # https://msdn.microsoft.com/en-us/library/system.runtime.interopservices.marshal.releasecomobject(v=vs.110).aspx
    # https://msdn.microsoft.com/en-us/library/system.runtime.interopservices.marshal.finalreleasecomobject(v=vs.110).aspx
    If ($Final)
    {
        [System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($ComObjtoRelease) | Out-Null
    }
    Else
    {
        [System.Runtime.InteropServices.Marshal]::ReleaseComObject($ComObjtoRelease) | Out-Null
    }
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
}

Function Get-ADRExcelWorkbook
{
<#
.SYNOPSIS
    Adds a WorkSheet to the Workbook.

.DESCRIPTION
    Adds a WorkSheet to the Workbook using the $workboook global variable and assigns it a name.

.PARAMETER name
    [string]
    Name of the WorkSheet.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $name
    )

    $workbook.Worksheets.Add() | Out-Null
    $worksheet = $workbook.Worksheets.Item(1)
    $worksheet.Name = $name

    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Get-ADRExcelImport
{
<#
.SYNOPSIS
    Helper to import CSV to the current WorkSheet.

.DESCRIPTION
    Helper to import CSV to the current WorkSheet. Supports two methods.

.PARAMETER ADFileName
    [string]
    Filename of the CSV file to import.

.PARAMETER method
    [int]
    Method to use for the import.
    3 - Prints data horizontally. Headers column 1, then first data row in column 2, etc.

.PARAMETER row
    [int]
    Row.

.PARAMETER column
    [int]
    Column.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $ADFileName,

        [Parameter(Mandatory = $false)]
        [int] $Method = 1,

        [Parameter(Mandatory = $false)]
        [int] $row = 1,

        [Parameter(Mandatory = $false)]
        [int] $column = 1
    )

    $excel.ScreenUpdating = $false
    If ($Method -eq 1)
    {
        If (Test-Path $ADFileName)
        {
            $worksheet = $workbook.Worksheets.Item(1)
            $TxtConnector = ("TEXT;" + $ADFileName)
            $CellRef = $worksheet.Range("A1")
            #Build, use and remove the text file connector
            $Connector = $worksheet.QueryTables.add($TxtConnector, $CellRef)

            #65001: Unicode (UTF-8)
            $worksheet.QueryTables.item($Connector.name).TextFilePlatform = 65001
            $worksheet.QueryTables.item($Connector.name).TextFileCommaDelimiter = $True
            $worksheet.QueryTables.item($Connector.name).TextFileParseType = 1
            $worksheet.QueryTables.item($Connector.name).Refresh() | Out-Null
            $worksheet.QueryTables.item($Connector.name).delete()

            Get-ADRExcelComObjRelease -ComObjtoRelease $CellRef
            Remove-Variable CellRef
            Get-ADRExcelComObjRelease -ComObjtoRelease $Connector
            Remove-Variable Connector

            $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $worksheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes, $null)
            $listObject.TableStyle = "TableStyleLight2" # Style Cheat Sheet: https://msdn.microsoft.com/en-au/library/documentformat.openxml.spreadsheet.tablestyle.aspx
            $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null
        }
        Remove-Variable ADFileName
    }
    Elseif ($Method -eq 2)
    {
        $worksheet = $workbook.Worksheets.Item(1)
        If (Test-Path $ADFileName)
        {
            $ADTemp = Import-Csv -Path $ADFileName
            $ADTemp | ForEach-Object {
                Foreach ($prop in $_.PSObject.Properties)
                {
                    $worksheet.Cells.Item($row, $column) = $prop.Name
                    $worksheet.Cells.Item($row, $column + 1) = $prop.Value
                    $row++
                }
            }
            Remove-Variable ADTemp
            $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $worksheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes, $null)
            $listObject.TableStyle = "TableStyleLight2" # Style Cheat Sheet: https://msdn.microsoft.com/en-au/library/documentformat.openxml.spreadsheet.tablestyle.aspx
            $usedRange = $worksheet.UsedRange
            $usedRange.EntireColumn.AutoFit() | Out-Null
        }
        Else
        {
            $worksheet.Cells.Item($row, $column) = "Error!"
        }
        Remove-Variable ADFileName
    }
    Elseif ($Method -eq 3)
    {
        $worksheet = $workbook.Worksheets.Item(1)
        If (Test-Path $ADFileName)
        {
            $CsvData = Import-Csv -Path $ADFileName

            $row_output = $row
            $CsvData[0].PsObject.Properties.Name | ForEach {
                $worksheet.Cells.Item($row_output, $column) = $_
                $row_output++
            }
            Remove-Variable row_output

            $column_output = $column + 1
            $CsvData | ForEach-Object {
                $row_output = $row
                ForEach ($prop_value in $_.PSObject.Properties.Value)
                {
                    $worksheet.Cells.Item($row_output, $column_output) = $prop_value
                    $row_output++
                }
                $column_output++
            }
            Remove-Variable column_output
            Remove-Variable row_output

            Remove-Variable CsvData

            $listObject = $worksheet.ListObjects.Add([Microsoft.Office.Interop.Excel.XlListObjectSourceType]::xlSrcRange, $worksheet.UsedRange, $null, [Microsoft.Office.Interop.Excel.XlYesNoGuess]::xlYes, $null)
            $listObject.TableStyle = "TableStyleLight2" # Style Cheat Sheet: https://msdn.microsoft.com/en-au/library/documentformat.openxml.spreadsheet.tablestyle.aspx
            $usedRange = $worksheet.UsedRange
            $usedRange.EntireColumn.AutoFit() | Out-Null
        }
        Else
        {
            $worksheet.Cells.Item($row, $column) = "Error!"
        }
        Remove-Variable ADFileName

    }
    $excel.ScreenUpdating = $true

    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

# Thanks Anant Shrivastava for the suggestion of using Pivot Tables for generation of the Stats sheets.
Function Get-ADRExcelPivotTable
{
<#
.SYNOPSIS
    Helper to add Pivot Table to the current WorkSheet.

.DESCRIPTION
    Helper to add Pivot Table to the current WorkSheet.

.PARAMETER SrcSheetName
    [string]
    Source Sheet Name.

.PARAMETER PivotTableName
    [string]
    Pivot Table Name.

.PARAMETER PivotRows
    [array]
    Row names from Source Sheet.

.PARAMETER PivotColumns
    [array]
    Column names from Source Sheet.

.PARAMETER PivotFilters
    [array]
    Row/Column names from Source Sheet to use as filters.

.PARAMETER PivotValues
    [array]
    Row/Column names from Source Sheet to use for Values.

.PARAMETER PivotPercentage
    [array]
    Row/Column names from Source Sheet to use for Percentage.

.PARAMETER PivotLocation
    [array]
    Location of the Pivot Table in Row/Column.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $SrcSheetName,

        [Parameter(Mandatory = $true)]
        [string] $PivotTableName,

        [Parameter(Mandatory = $false)]
        [array] $PivotRows,

        [Parameter(Mandatory = $false)]
        [array] $PivotColumns,

        [Parameter(Mandatory = $false)]
        [array] $PivotFilters,

        [Parameter(Mandatory = $false)]
        [array] $PivotValues,

        [Parameter(Mandatory = $false)]
        [array] $PivotPercentage,

        [Parameter(Mandatory = $false)]
        [string] $PivotLocation = "R1C1"
    )

    $excel.ScreenUpdating = $false
    $SrcWorksheet = $workbook.Sheets.Item($SrcSheetName)
    $workbook.ShowPivotTableFieldList = $false

    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlpivottablesourcetype-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlpivottableversionlist-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlpivotfieldorientation-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/constants-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlsortorder-enumeration-excel
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlpivotfiltertype-enumeration-excel

    # xlDatabase = 1 # this just means local sheet data
    # xlPivotTableVersion12 = 3 # Excel 2007
    $PivotFailed = $false
    Try
    {
        $PivotCaches = $workbook.PivotCaches().Create([Microsoft.Office.Interop.Excel.XlPivotTableSourceType]::xlDatabase, $SrcWorksheet.UsedRange, [Microsoft.Office.Interop.Excel.XlPivotTableVersionList]::xlPivotTableVersion12)
    }
    Catch
    {
        $PivotFailed = $true
        Write-Verbose "[PivotCaches().Create] Failed"
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
    }
    If ( $PivotFailed -eq $true )
    {
        $rows = $SrcWorksheet.UsedRange.Rows.Count
        If ($SrcSheetName -eq "Computer SPNs")
        {
            $PivotCols = "A1:C"
        }
        ElseIf ($SrcSheetName -eq "Computers")
        {
            $PivotCols = "A1:F"
        }
        ElseIf ($SrcSheetName -eq "Users")
        {
            $PivotCols = "A1:C"
        }
        $UsedRange = $SrcWorksheet.Range($PivotCols+$rows)
        $PivotCaches = $workbook.PivotCaches().Create([Microsoft.Office.Interop.Excel.XlPivotTableSourceType]::xlDatabase, $UsedRange, [Microsoft.Office.Interop.Excel.XlPivotTableVersionList]::xlPivotTableVersion12)
        Remove-Variable rows
	    Remove-Variable PivotCols
        Remove-Variable UsedRange
    }
    Remove-Variable PivotFailed
    $PivotTable = $PivotCaches.CreatePivotTable($PivotLocation,$PivotTableName)
    # $workbook.ShowPivotTableFieldList = $true

    If ($PivotRows)
    {
        ForEach ($Row in $PivotRows)
        {
            $PivotField = $PivotTable.PivotFields($Row)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlRowField
        }
    }

    If ($PivotColumns)
    {
        ForEach ($Col in $PivotColumns)
        {
            $PivotField = $PivotTable.PivotFields($Col)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlColumnField
        }
    }

    If ($PivotFilters)
    {
        ForEach ($Fil in $PivotFilters)
        {
            $PivotField = $PivotTable.PivotFields($Fil)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlPageField
        }
    }

    If ($PivotValues)
    {
        ForEach ($Val in $PivotValues)
        {
            $PivotField = $PivotTable.PivotFields($Val)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlDataField
        }
    }

    If ($PivotPercentage)
    {
        ForEach ($Val in $PivotPercentage)
        {
            $PivotField = $PivotTable.PivotFields($Val)
            $PivotField.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlDataField
            $PivotField.Calculation = [Microsoft.Office.Interop.Excel.XlPivotFieldCalculation]::xlPercentOfTotal
            $PivotTable.ShowValuesRow = $false
        }
    }

    # $PivotFields.Caption = ""
    $excel.ScreenUpdating = $true

    Get-ADRExcelComObjRelease -ComObjtoRelease $PivotField
    Remove-Variable PivotField
    Get-ADRExcelComObjRelease -ComObjtoRelease $PivotTable
    Remove-Variable PivotTable
    Get-ADRExcelComObjRelease -ComObjtoRelease $PivotCaches
    Remove-Variable PivotCaches
    Get-ADRExcelComObjRelease -ComObjtoRelease $SrcWorksheet
    Remove-Variable SrcWorksheet
}

Function Get-ADRExcelAttributeStats
{
<#
.SYNOPSIS
    Helper to add Attribute Stats to the current WorkSheet.

.DESCRIPTION
    Helper to add Attribute Stats to the current WorkSheet.

.PARAMETER SrcSheetName
    [string]
    Source Sheet Name.

.PARAMETER Title1
    [string]
    Title1.

.PARAMETER PivotTableName
    [string]
    PivotTableName.

.PARAMETER PivotRows
    [string]
    PivotRows.

.PARAMETER PivotValues
    [string]
    PivotValues.

.PARAMETER PivotPercentage
    [string]
    PivotPercentage.

.PARAMETER Title2
    [string]
    Title2.

.PARAMETER ObjAttributes
    [OrderedDictionary]
    Attributes.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $SrcSheetName,

        [Parameter(Mandatory = $true)]
        [string] $Title1,

        [Parameter(Mandatory = $true)]
        [string] $PivotTableName,

        [Parameter(Mandatory = $true)]
        [string] $PivotRows,

        [Parameter(Mandatory = $true)]
        [string] $PivotValues,

        [Parameter(Mandatory = $true)]
        [string] $PivotPercentage,

        [Parameter(Mandatory = $true)]
        [string] $Title2,

        [Parameter(Mandatory = $true)]
        [System.Object] $ObjAttributes
    )

    $excel.ScreenUpdating = $false
    $worksheet = $workbook.Worksheets.Item(1)
    $SrcWorksheet = $workbook.Sheets.Item($SrcSheetName)

    $row = 1
    $column = 1
    $worksheet.Cells.Item($row, $column) = $Title1
    $worksheet.Cells.Item($row,$column).Style = "Heading 2"
    $worksheet.Cells.Item($row,$column).HorizontalAlignment = -4108
    $MergeCells = $worksheet.Range("A1:C1")
    $MergeCells.Select() | Out-Null
    $MergeCells.MergeCells = $true
    Remove-Variable MergeCells

    Get-ADRExcelPivotTable -SrcSheetName $SrcSheetName -PivotTableName $PivotTableName -PivotRows @($PivotRows) -PivotValues @($PivotValues) -PivotPercentage @($PivotPercentage) -PivotLocation "R2C1"
    $excel.ScreenUpdating = $false

    $row = 2
    "Type","Count","Percentage" | ForEach-Object {
        $worksheet.Cells.Item($row, $column) = $_
        $worksheet.Cells.Item($row, $column).Font.Bold = $True
        $column++
    }

    $row = 3
    $column = 1
    For($row = 3; $row -le 6; $row++)
    {
        $temptext = [string] $worksheet.Cells.Item($row, $column).Text
        switch ($temptext.ToUpper())
        {
            "TRUE" { $worksheet.Cells.Item($row, $column) = "Enabled" }
            "FALSE" { $worksheet.Cells.Item($row, $column) = "Disabled" }
            "GRAND TOTAL" { $worksheet.Cells.Item($row, $column) = "Total" }
        }
    }

    If ($ObjAttributes)
    {
        $row = 1
        $column = 6
        $worksheet.Cells.Item($row, $column) = $Title2
        $worksheet.Cells.Item($row,$column).Style = "Heading 2"
        $worksheet.Cells.Item($row,$column).HorizontalAlignment = -4108
        $MergeCells = $worksheet.Range("F1:L1")
        $MergeCells.Select() | Out-Null
        $MergeCells.MergeCells = $true
        Remove-Variable MergeCells

        $row++
        "Category","Enabled Count","Enabled Percentage","Disabled Count","Disabled Percentage","Total Count","Total Percentage" | ForEach-Object {
            $worksheet.Cells.Item($row, $column) = $_
            $worksheet.Cells.Item($row, $column).Font.Bold = $True
            $column++
        }
        $ExcelColumn = ($SrcWorksheet.Columns.Find("Enabled"))
        $EnabledColAddress = "$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1)):$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1))"
        $column = 6
        $i = 2

        $ObjAttributes.keys | ForEach-Object {
            $ExcelColumn = ($SrcWorksheet.Columns.Find($_))
            $ColAddress = "$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1)):$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1))"
            $row++
            $i++
            If ($_ -eq "Delegation Typ")
            {
                $worksheet.Cells.Item($row, $column) = "Unconstrained Delegation"
            }
            ElseIf ($_ -eq "Delegation Type")
            {
                $worksheet.Cells.Item($row, $column) = "Constrained Delegation"
            }
            Else
            {
                $worksheet.Cells.Item($row, $column).Formula = "='" + $SrcWorksheet.Name + "'!" + $ExcelColumn.Address($false,$false)
            }
            $worksheet.Cells.Item($row, $column+1).Formula = "=COUNTIFS('" + $SrcWorksheet.Name + "'!" + $EnabledColAddress + ',"TRUE",' + "'" + $SrcWorksheet.Name + "'!" + $ColAddress + ',' + $ObjAttributes[$_] + ')'
            $worksheet.Cells.Item($row, $column+2).Formula = '=IFERROR(G' + $i + '/VLOOKUP("Enabled",A3:B6,2,FALSE),0)'
            $worksheet.Cells.Item($row, $column+3).Formula = "=COUNTIFS('" + $SrcWorksheet.Name + "'!" + $EnabledColAddress + ',"FALSE",' + "'" + $SrcWorksheet.Name + "'!" + $ColAddress + ',' + $ObjAttributes[$_] + ')'
            $worksheet.Cells.Item($row, $column+4).Formula = '=IFERROR(I' + $i + '/VLOOKUP("Disabled",A3:B6,2,FALSE),0)'
            If ( ($_ -eq "SIDHistory") -or ($_ -eq "ms-ds-CreatorSid") )
            {
                # Remove count of FieldName
                $worksheet.Cells.Item($row, $column+5).Formula = "=COUNTIF('" + $SrcWorksheet.Name + "'!" + $ColAddress + ',' + $ObjAttributes[$_] + ')-1'
            }
            Else
            {
                $worksheet.Cells.Item($row, $column+5).Formula = "=COUNTIF('" + $SrcWorksheet.Name + "'!" + $ColAddress + ',' + $ObjAttributes[$_] + ')'
            }
            $worksheet.Cells.Item($row, $column+6).Formula = '=IFERROR(K' + $i + '/VLOOKUP("Total",A3:B6,2,FALSE),0)'
        }

        # http://www.excelhowto.com/macros/formatting-a-range-of-cells-in-excel-vba/
        "H", "J" , "L" | ForEach-Object {
            $rng = $_ + $($row - $ObjAttributes.Count + 1) + ":" + $_ + $($row)
            $worksheet.Range($rng).NumberFormat = "0.00%"
        }
    }
    $excel.ScreenUpdating = $true

    Get-ADRExcelComObjRelease -ComObjtoRelease $SrcWorksheet
    Remove-Variable SrcWorksheet
    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Get-ADRExcelChart
{
<#
.SYNOPSIS
    Helper to add charts to the current WorkSheet.

.DESCRIPTION
    Helper to add charts to the current WorkSheet.

.PARAMETER ChartType
    [int]
    Chart Type.

.PARAMETER ChartLayout
    [int]
    Chart Layout.

.PARAMETER ChartTitle
    [string]
    Title of the Chart.

.PARAMETER RangetoCover
    WorkSheet Range to be covered by the Chart.

.PARAMETER ChartData
    Data for the Chart.

.PARAMETER StartRow
    Start row to calculate data for the Chart.

.PARAMETER StartColumn
    Start column to calculate data for the Chart.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $ChartType,

        [Parameter(Mandatory = $true)]
        [int] $ChartLayout,

        [Parameter(Mandatory = $true)]
        [string] $ChartTitle,

        [Parameter(Mandatory = $true)]
        $RangetoCover,

        [Parameter(Mandatory = $false)]
        $ChartData = $null,

        [Parameter(Mandatory = $false)]
        $StartRow = $null,

        [Parameter(Mandatory = $false)]
        $StartColumn = $null
    )

    $excel.ScreenUpdating = $false
    $excel.DisplayAlerts = $false
    $worksheet = $workbook.Worksheets.Item(1)
    $chart = $worksheet.Shapes.AddChart().Chart
    # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlcharttype-enumeration-excel
    $chart.chartType = [int]([Microsoft.Office.Interop.Excel.XLChartType]::$ChartType)
    $chart.ApplyLayout($ChartLayout)
    If ($null -eq $ChartData)
    {
        If ($null -eq $StartRow)
        {
            $start = $worksheet.Range("A1")
        }
        Else
        {
            $start = $worksheet.Range($StartRow)
        }
        # get the last cell
        $X = $worksheet.Range($start,$start.End([Microsoft.Office.Interop.Excel.XLDirection]::xlDown))
        If ($null -eq $StartColumn)
        {
            $start = $worksheet.Range("B1")
        }
        Else
        {
            $start = $worksheet.Range($StartColumn)
        }
        # get the last cell
        $Y = $worksheet.Range($start,$start.End([Microsoft.Office.Interop.Excel.XLDirection]::xlDown))
        $ChartData = $worksheet.Range($X,$Y)

        Get-ADRExcelComObjRelease -ComObjtoRelease $X
        Remove-Variable X
        Get-ADRExcelComObjRelease -ComObjtoRelease $Y
        Remove-Variable Y
        Get-ADRExcelComObjRelease -ComObjtoRelease $start
        Remove-Variable start
    }
    $chart.SetSourceData($ChartData)
    # https://docs.microsoft.com/en-us/dotnet/api/microsoft.office.interop.excel.chartclass.plotby?redirectedfrom=MSDN&view=excel-pia#Microsoft_Office_Interop_Excel_ChartClass_PlotBy
    $chart.PlotBy = [Microsoft.Office.Interop.Excel.XlRowCol]::xlColumns
    $chart.seriesCollection(1).Select() | Out-Null
    $chart.SeriesCollection(1).ApplyDataLabels() | out-Null
    # modify the chart title
    $chart.HasTitle = $True
    $chart.ChartTitle.Text = $ChartTitle
    # Reposition the Chart
    $temp = $worksheet.Range($RangetoCover)
    # $chart.parent.placement = 3
    $chart.parent.top = $temp.Top
    $chart.parent.left = $temp.Left
    $chart.parent.width = $temp.Width
    If ($ChartTitle -ne "Privileged Groups in AD")
    {
        $chart.parent.height = $temp.Height
    }
    # $chart.Legend.Delete()
    $excel.ScreenUpdating = $true
    $excel.DisplayAlerts = $true

    Get-ADRExcelComObjRelease -ComObjtoRelease $chart
    Remove-Variable chart
    Get-ADRExcelComObjRelease -ComObjtoRelease $ChartData
    Remove-Variable ChartData
    Get-ADRExcelComObjRelease -ComObjtoRelease $temp
    Remove-Variable temp
    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Get-ADRExcelSort
{
<#
.SYNOPSIS
    Sorts a WorkSheet in the active Workbook.

.DESCRIPTION
    Sorts a WorkSheet in the active Workbook.

.PARAMETER ColumnName
    [string]
    Name of the Column.
#>
    param (
        [Parameter(Mandatory = $true)]
        [string] $ColumnName
    )

    $worksheet = $workbook.Worksheets.Item(1)
    $worksheet.Activate();

    $ExcelColumn = ($worksheet.Columns.Find($ColumnName))
    If ($ExcelColumn)
    {
        If ($ExcelColumn.Text -ne $ColumnName)
        {
            $BeginAddress = $ExcelColumn.Address(0,0,1,1)
            $End = $False
            Do {
                #Write-Verbose "[Get-ADRExcelSort] $($ExcelColumn.Text) selected instead of $($ColumnName) in the $($worksheet.Name) worksheet."
                $ExcelColumn = ($worksheet.Columns.FindNext($ExcelColumn))
                $Address = $ExcelColumn.Address(0,0,1,1)
                If ( ($Address -eq $BeginAddress) -or ($ExcelColumn.Text -eq $ColumnName) )
                {
                    $End = $True
                }
            } Until ($End -eq $True)
        }
        If ($ExcelColumn.Text -eq $ColumnName)
        {
            # Sort by Column
            $workSheet.ListObjects.Item(1).Sort.SortFields.Clear()
            $workSheet.ListObjects.Item(1).Sort.SortFields.Add($ExcelColumn) | Out-Null
            $worksheet.ListObjects.Item(1).Sort.Apply()
        }
        Else
        {
            Write-Verbose "[Get-ADRExcelSort] $($ColumnName) not found in the $($worksheet.Name) worksheet."
        }
    }
    Else
    {
        Write-Verbose "[Get-ADRExcelSort] $($ColumnName) not found in the $($worksheet.Name) worksheet."
    }
    Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
    Remove-Variable worksheet
}

Function Export-ADRExcel
{
<#
.SYNOPSIS
    Automates the generation of the ADRecon report.

.DESCRIPTION
    Automates the generation of the ADRecon report. If specific files exist, they are imported into the ADRecon report.

.PARAMETER ExcelPath
    [string]
    Path for ADRecon output folder containing the CSV files to generate the ADRecon-Report.xlsx

.PARAMETER Logo
    [string]
    Which Logo to use in the excel file? (Default ADRecon)

.OUTPUTS
    Creates the ADRecon-Report.xlsx report in the folder.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $ExcelPath,

        [Parameter(Mandatory = $false)]
        [string] $Logo = "ADRecon"
    )

    If ($PSVersionTable.PSEdition -eq "Core")
    {
        If ($PSVersionTable.Platform -eq "Win32NT")
        {
            $returndir = Get-Location
            Set-Location C:\Windows\assembly\
            $refFolder = (Get-ChildItem -Recurse  Microsoft.Office.Interop.Excel.dll).Directory
            Set-Location $refFolder
            Add-Type -AssemblyName "Microsoft.Office.Interop.Excel"
            Set-Location $returndir
            Remove-Variable returndir
            Remove-Variable refFolder
        }
    }

    $ExcelPath = $((Convert-Path $ExcelPath).TrimEnd("\"))
    $ReportPath = -join($ExcelPath,'\','CSV-Files')
    If (!(Test-Path $ReportPath))
    {
        Write-Warning "[Export-ADRExcel] Could not locate the CSV-Files directory ... Exiting"
        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        Return $null
    }
    Get-ADRExcelComObj
    If ($excel)
    {
        Write-Output "[*] Generating ADRecon-Report.xlsx"

        $ADFileName = -join($ReportPath,'\','AboutADRecon.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            $workbook.Worksheets.Item(1).Name = "About ADRecon"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(3,2) , "https://github.com/adrecon/ADRecon", "" , "", "github.com/adrecon/ADRecon") | Out-Null
            $workbook.Worksheets.Item(1).UsedRange.EntireColumn.AutoFit() | Out-Null
        }

        $ADFileName = -join($ReportPath,'\','Forest.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Forest"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Domain.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Domain"
            Get-ADRExcelImport -ADFileName $ADFileName
            $DomainObj = Import-CSV -Path $ADFileName
            Remove-Variable ADFileName
            $DomainName = -join($DomainObj[0].Value,"-")
            Remove-Variable DomainObj
        }

        $ADFileName = -join($ReportPath,'\','Trusts.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Trusts"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Subnets.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Subnets"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Sites.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Sites"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','SchemaHistory.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "SchemaHistory"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','FineGrainedPasswordPolicy.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Fine Grained Password Policy"
            Get-ADRExcelImport -ADFileName $ADFileName -Method 3
            Remove-Variable ADFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $usedRange = $worksheet.UsedRange

            $usedRange.Rows(2).WrapText = $True

            $usedRange.Columns | ForEach-Object {
                $_.ColumnWidth = 60
            }
            $usedRange.Rows(2).AutoFit() | Out-Null
            $usedRange.Columns["A"].AutoFit() | Out-Null
        }

        $ADFileName = -join($ReportPath,'\','DefaultPasswordPolicy.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Default Password Policy"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            $excel.ScreenUpdating = $false
            $worksheet = $workbook.Worksheets.Item(1)

            # https://docs.microsoft.com/en-us/office/vba/api/excel.xlhalign
            $worksheet.Range("C1:D1").HorizontalAlignment = -4108
            $workbook.Worksheets.Item(1).Cells.Item(1,7).HorizontalAlignment = -4108
            $worksheet.Range("B2:H10").HorizontalAlignment = -4108

            # https://docs.microsoft.com/en-us/office/vba/api/excel.range.borderaround

            "A2:B10", "C2:E10", "F2:G10", "H2:H10" | ForEach-Object {
                $worksheet.Range($_).BorderAround(1) | Out-Null
            }

            # https://docs.microsoft.com/en-us/dotnet/api/microsoft.office.interop.excel.formatconditions.add?view=excel-pia
            # $worksheet.Range().FormatConditions.Add
            # http://dmcritchie.mvps.org/excel/colors.htm
            # Values for Font.ColorIndex

            $ObjValues = @(
            # PCI v3.2.1 Enforce password history (passwords)
            "C2", '=IF(B2<4,TRUE, FALSE)'

            # PCI v3.2.1 Maximum password age (days)
            "C3", '=IF(OR(B3=0,B3>90),TRUE, FALSE)'

            # PCI v3.2.1 Minimum password age (days)

            # PCI v3.2.1 Minimum password length (characters)
            "C5", '=IF(B5<7,TRUE, FALSE)'

            # PCI v3.2.1 Password must meet complexity requirements
            "C6", '=IF(B6<>TRUE,TRUE, FALSE)'

            # PCI v3.2.1 Store password using reversible encryption for all users in the domain

            # PCI v3.2.1 Account lockout duration (mins)
            "C8", '=IF(AND(B8>=1,B8<30),TRUE, FALSE)'

            # PCI v3.2.1 Account lockout threshold (attempts)
            "C9", '=IF(OR(B9=0,B9>6),TRUE, FALSE)'

            # PCI v3.2.1 Reset account lockout counter after (mins)

            # PCI v4.0 Enforce password history (passwords)
            "D2", '=IF(B2<4,TRUE, FALSE)'

            # PCI v4.0 Maximum password age (days)
            "D3", '=IF(OR(B3=0,B3>90),TRUE, FALSE)'

            # PCI v4.0 Minimum password age (days)

            # PCI v4.0 Minimum password length (characters)
            "D5", '=IF(B5<12,TRUE, FALSE)'

            # PCI v4.0 Password must meet complexity requirements
            "D6", '=IF(B6<>TRUE,TRUE, FALSE)'

            # PCI v4.0 Store password using reversible encryption for all users in the domain

            # PCI v4.0 Account lockout duration (mins)
            "D8", '=IF(AND(B8>=1,B8<30),TRUE, FALSE)'

            # PCI v4.0 Account lockout threshold (attempts)
            "D9", '=IF(OR(B9=0,B9>10),TRUE, FALSE)'

            # PCI v4.0 Reset account lockout counter after (mins)

            # ACSC ISM Enforce password history (passwords)
            #"F2", '=IF(B2<8,TRUE, FALSE)'

            # ACSC ISM Maximum password age (days)
            "F3", '=IF(OR(B3=0,B3>365),TRUE, FALSE)'

            # ACSC ISM Minimum password age (days)
            #"F4", '=IF(B4=0,TRUE, FALSE)'

            # ACSC ISM Minimum password length (characters)
            "F5", '=IF(B5<14,TRUE, FALSE)'

            # ACSC ISM Password must meet complexity requirements
            #"F6", '=IF(B6<>TRUE,TRUE, FALSE)'

            # ACSC ISM Store password using reversible encryption for all users in the domain

            # ACSC ISM Account lockout duration (mins)

            # ACSC ISM Account lockout threshold (attempts)
            "F9", '=IF(OR(B9=0,B9>5),TRUE, FALSE)'

            # ACSC ISM Reset account lockout counter after (mins)

            # CIS Benchmark Enforce password history (passwords)
            "H2", '=IF(B2<24,TRUE, FALSE)'

            # CIS Benchmark Maximum password age (days)
            "H3", '=IF(OR(B3=0,B3>365),TRUE, FALSE)'

            # CIS Benchmark Minimum password age (days)
            "H4", '=IF(B4=0,TRUE, FALSE)'

            # CIS Benchmark Minimum password length (characters)
            "H5", '=IF(B5<14,TRUE, FALSE)'

            # CIS Benchmark Password must meet complexity requirements
            "H6", '=IF(B6<>TRUE,TRUE, FALSE)'

            # CIS Benchmark Store password using reversible encryption for all users in the domain
            "H7", '=IF(B7<>FALSE,TRUE, FALSE)'

            # CIS Benchmark Account lockout duration (mins)
            "H8", '=IF(AND(B8>=1,B8<15),TRUE, FALSE)'

            # CIS Benchmark Account lockout threshold (attempts)
            "H9", '=IF(OR(B9=0,B9>5),TRUE, FALSE)'

            # CIS Benchmark Reset account lockout counter after (mins)
            "H10", '=IF(B10<15,TRUE, FALSE)' )

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $worksheet.Range($ObjValues[$i]).FormatConditions.Add([Microsoft.Office.Interop.Excel.XlFormatConditionType]::xlExpression, 0, $ObjValues[$i+1]) | Out-Null
                $i++
            }

            "C2", "C3" , "C5", "C6", "C8", "C9", "D2", "D3" , "D5", "D6", "D8", "D9", "F5", "F9", "H2", "H3", "H4", "H5", "H6", "H7", "H8", "H9", "H10" | ForEach-Object {
                $worksheet.Range($_).FormatConditions.Item(1).StopIfTrue = $false
                $worksheet.Range($_).FormatConditions.Item(1).Font.ColorIndex = 3
            }

            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,5) , "https://www.pcisecuritystandards.org/document_library?category=pcidss&document=pci_dss", "" , "", "PCI DSS Requirement") | Out-Null
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1, 7) , "https://www.cyber.gov.au/acsc/view-all-content/ism", "" , "", "ISM Controls 16Jun2022") | Out-Null
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,8) , "https://www.cisecurity.org/benchmark/microsoft_windows_server/", "" , "", "CIS Benchmark 2022") | Out-Null

            $excel.ScreenUpdating = $true
            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        $ADFileName = -join($ReportPath,'\','DomainControllers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Domain Controllers"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','GroupChanges.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Group Changes"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "Group Name"
        }

        $ADFileName = -join($ReportPath,'\','DACLs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "DACLs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','SACLs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "SACLs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','GPOs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "GPOs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','gPLinks.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "gPLinks"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','DNSNodes','.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "DNS Records"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','DNSZones.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "DNS Zones"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Printers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Printers"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','BitLockerRecoveryKeys.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "BitLocker"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','LAPS.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "LAPS"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','ComputerSPNs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Computer SPNs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "UserName"
        }

        $ADFileName = -join($ReportPath,'\','Computers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Computers"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "UserName"

            $worksheet = $workbook.Worksheets.Item(1)
            # Freeze First Row and Column
            $worksheet.Select()
            $worksheet.Application.ActiveWindow.splitcolumn = 1
            $worksheet.Application.ActiveWindow.splitrow = 1
            $worksheet.Application.ActiveWindow.FreezePanes = $true

            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        $ADFileName = -join($ReportPath,'\','OUs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "OUs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Groups.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Groups"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "DistinguishedName"
        }

        $ADFileName = -join($ReportPath,'\','GroupMembers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Group Members"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "Group Name"
        }

        $ADFileName = -join($ReportPath,'\','UserSPNs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "User SPNs"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName
        }

        $ADFileName = -join($ReportPath,'\','Users.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Users"
            Get-ADRExcelImport -ADFileName $ADFileName
            Remove-Variable ADFileName

            Get-ADRExcelSort -ColumnName "UserName"

            $worksheet = $workbook.Worksheets.Item(1)

            # Freeze First Row and Column
            $worksheet.Select()
            $worksheet.Application.ActiveWindow.splitcolumn = 1
            $worksheet.Application.ActiveWindow.splitrow = 1
            $worksheet.Application.ActiveWindow.FreezePanes = $true

            $worksheet.Cells.Item(1,3).Interior.ColorIndex = 5
            $worksheet.Cells.Item(1,3).font.ColorIndex = 2
            # Set Filter to Enabled Accounts only
            $worksheet.UsedRange.Select() | Out-Null
            $excel.Selection.AutoFilter(3,$true) | Out-Null
            $worksheet.Cells.Item(1,1).Select() | Out-Null
            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        # Computer Role Stats
        $ADFileName = -join($ReportPath,'\','ComputerSPNs.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Computer Role Stats"
            Remove-Variable ADFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $PivotTableName = "Computer SPNs"
            Get-ADRExcelPivotTable -SrcSheetName "Computer SPNs" -PivotTableName $PivotTableName -PivotRows @("Service") -PivotValues @("Service")

            $worksheet.Cells.Item(1,1) = "Computer Role"
            $worksheet.Cells.Item(1,2) = "Count"

            # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlsortorder-enumeration-excel
            $worksheet.PivotTables($PivotTableName).PivotFields("Service").AutoSort([Microsoft.Office.Interop.Excel.XlSortOrder]::xlDescending,"Count")

            Get-ADRExcelChart -ChartType "xlColumnClustered" -ChartLayout 10 -ChartTitle "Computer Roles in AD" -RangetoCover "D2:U16"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "" , "'Computer SPNs'!A1", "", "Raw Data") | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
            Remove-Variable PivotTableName

            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        # Operating System Stats
        $ADFileName = -join($ReportPath,'\','Computers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Operating System Stats"
            Remove-Variable ADFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $PivotTableName = "Operating Systems"
            Get-ADRExcelPivotTable -SrcSheetName "Computers" -PivotTableName $PivotTableName -PivotRows @("Operating System") -PivotValues @("Operating System")

            $worksheet.Cells.Item(1,1) = "Operating System"
            $worksheet.Cells.Item(1,2) = "Count"

            # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlsortorder-enumeration-excel
            $worksheet.PivotTables($PivotTableName).PivotFields("Operating System").AutoSort([Microsoft.Office.Interop.Excel.XlSortOrder]::xlDescending,"Count")

            Get-ADRExcelChart -ChartType "xlColumnClustered" -ChartLayout 10 -ChartTitle "Operating Systems in AD" -RangetoCover "D2:S16"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "" , "Computers!A1", "", "Raw Data") | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
            Remove-Variable PivotTableName

            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        # Group Stats
        $ADFileName = -join($ReportPath,'\','GroupMembers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Privileged Group Stats"
            Remove-Variable ADFileName

            $worksheet = $workbook.Worksheets.Item(1)
            $PivotTableName = "Group Members"
            Get-ADRExcelPivotTable -SrcSheetName "Group Members" -PivotTableName $PivotTableName -PivotRows @("Group Name")-PivotFilters @("AccountType") -PivotValues @("AccountType")

            # Set the filter
            $worksheet.PivotTables($PivotTableName).PivotFields("AccountType").CurrentPage = "user"

            $worksheet.Cells.Item(1,2).Interior.ColorIndex = 5
            $worksheet.Cells.Item(1,2).font.ColorIndex = 2

            $worksheet.Cells.Item(3,1) = "Group Name"
            $worksheet.Cells.Item(3,2) = "Count (Not-Recursive)"

            $excel.ScreenUpdating = $false
            # Create a copy of the Pivot Table
            $PivotTableTemp = ($workbook.PivotCaches().Item($workbook.PivotCaches().Count)).CreatePivotTable("R1C5","PivotTableTemp")
            $PivotFieldTemp = $PivotTableTemp.PivotFields("Group Name")
            # Set a filter
            $PivotFieldTemp.Orientation = [Microsoft.Office.Interop.Excel.XlPivotFieldOrientation]::xlPageField
            Try
            {
                $PivotFieldTemp.CurrentPage = "Domain Admins"
            }
            Catch
            {
                # No Direct Domain Admins. Good Job!
                $NoDA = $true
            }
            If ($NoDA)
            {
                Try
                {
                    $PivotFieldTemp.CurrentPage = "Administrators"
                }
                Catch
                {
                    # No Direct Administrators
                }
            }
            # Create a Slicer
            $PivotSlicer = $workbook.SlicerCaches.Add($PivotTableTemp,$PivotFieldTemp)
            # Add Original Pivot Table to the Slicer
            $PivotSlicer.PivotTables.AddPivotTable($worksheet.PivotTables($PivotTableName))
            # Delete the Slicer
            $PivotSlicer.Delete()
            # Delete the Pivot Table Copy
            $PivotTableTemp.TableRange2.Delete() | Out-Null

            Get-ADRExcelComObjRelease -ComObjtoRelease $PivotFieldTemp
            Get-ADRExcelComObjRelease -ComObjtoRelease $PivotSlicer
            Get-ADRExcelComObjRelease -ComObjtoRelease $PivotTableTemp

            Remove-Variable PivotFieldTemp
            Remove-Variable PivotSlicer
            Remove-Variable PivotTableTemp

            "Account Operators","Administrators","Backup Operators","Cert Publishers","Crypto Operators","DnsAdmins","Domain Admins","Enterprise Admins","Enterprise Key Admins","Incoming Forest Trust Builders","Key Admins","Microsoft Advanced Threat Analytics Administrators","Network Operators","Print Operators","Protected Users","Remote Desktop Users","Schema Admins","Server Operators" | ForEach-Object {
                Try
                {
                    $worksheet.PivotTables($PivotTableName).PivotFields("Group Name").PivotItems($_).Visible = $true
                }
                Catch
                {
                    # when PivotItem is not found
                }
            }

            # https://msdn.microsoft.com/en-us/vba/excel-vba/articles/xlsortorder-enumeration-excel
            $worksheet.PivotTables($PivotTableName).PivotFields("Group Name").AutoSort([Microsoft.Office.Interop.Excel.XlSortOrder]::xlDescending,"Count (Not-Recursive)")

            $worksheet.Cells.Item(3,1).Interior.ColorIndex = 5
            $worksheet.Cells.Item(3,1).font.ColorIndex = 2

            $excel.ScreenUpdating = $true

            Get-ADRExcelChart -ChartType "xlColumnClustered" -ChartLayout 10 -ChartTitle "Privileged Groups in AD" -RangetoCover "D2:P16" -StartRow "A3" -StartColumn "B3"
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(1,4) , "" , "'Group Members'!A1", "", "Raw Data") | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false

            Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet
            Remove-Variable worksheet
        }

        # Computer Stats
        $ADFileName = -join($ReportPath,'\','Computers.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "Computer Stats"
            Remove-Variable ADFileName

            $ObjAttributes = New-Object System.Collections.Specialized.OrderedDictionary
            $ObjAttributes.Add("Delegation Typ",'"Unconstrained"')
            $ObjAttributes.Add("Delegation Type",'"Constrained"')
            $ObjAttributes.Add("SIDHistory",'"*"')
            $ObjAttributes.Add("Dormant",'"TRUE"')
            $ObjAttributes.Add("Password Age (> ",'"TRUE"')
            $ObjAttributes.Add("ms-ds-CreatorSid",'"*"')

            Get-ADRExcelAttributeStats -SrcSheetName "Computers" -Title1 "Computer Accounts in AD" -PivotTableName "Computer Accounts Status" -PivotRows "Enabled" -PivotValues "UserName" -PivotPercentage "UserName" -Title2 "Status of Computer Accounts" -ObjAttributes $ObjAttributes
            Remove-Variable ObjAttributes

            #Todo: Replace with a better way to include the LAPS Stats
            For($i = 1 ; $i -le $workbook.Sheets.count ; $i++)
            {
                $SrcSheetName = "LAPS"
                If ($workbook.Worksheets.item($i).name -eq $SrcSheetName)
                {
                    $ADRLAPSCheck = $true
                    break
                }
                Else
                {
                   $ADRLAPSCheck = $false
                }
            }
            If ($ADRLAPSCheck)
            {
                $worksheet = $workbook.Worksheets.Item(1)
                $ExcelColumn = $workbook.Sheets.Item("LAPS").Columns.Find("Stored")
                $ColAddress = "$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1)):$($ExcelColumn.Address($false,$false).Substring(0,$ExcelColumn.Address($false,$false).Length-1))"
                $i = 9
                $row = 9
                $column = 6
                $worksheet.Cells.Item($row, $column) = "LAPS"
                $worksheet.Cells.Item($row, $column+1).Formula = "=COUNTIFS('" + $SrcSheetName + "'!" + "B:B" + ',"TRUE",' + "'" + $SrcSheetName + "'!" + $ColAddress + ',' + "TRUE" + ')'
                $worksheet.Cells.Item($row, $column+2).Formula = '=IFERROR(G' + $i + '/VLOOKUP("Enabled",A3:B6,2,FALSE),0)'
                $worksheet.Cells.Item($row, $column+3).Formula = "=COUNTIFS('" + $SrcSheetName + "'!" + "B:B" + ',"FALSE",' + "'" + $SrcSheetName + "'!" + $ColAddress + ',' + "TRUE" + ')'
                $worksheet.Cells.Item($row, $column+4).Formula = '=IFERROR(I' + $i + '/VLOOKUP("Disabled",A3:B6,2,FALSE),0)'
                $worksheet.Cells.Item($row, $column+5).Formula = "=COUNTIF('" + $SrcSheetName + "'!" + $ColAddress + ',' + "TRUE" + ')'
                $worksheet.Cells.Item($row, $column+6).Formula = '=IFERROR(K' + $i + '/VLOOKUP("Total",A3:B6,2,FALSE),0)'

                # http://www.excelhowto.com/macros/formatting-a-range-of-cells-in-excel-vba/
                "H", "J" , "L" | ForEach-Object {
                    $rng = $_ + "9" + ":" + $_ + $($row)
                    $worksheet.Range($rng).NumberFormat = "0.00%"
                }

                Get-ADRExcelChart -ChartType "xlPie" -ChartLayout 3 -ChartTitle "Computer Accounts in AD" -RangetoCover "A12:D24" -ChartData $workbook.Worksheets.Item(1).Range("A3:A4,B3:B4")
                $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(11,1) , "" , "Computers!A1", "", "Raw Data") | Out-Null

                Get-ADRExcelChart -ChartType "xlBarClustered" -ChartLayout 1 -ChartTitle "Status of Computer Accounts" -RangetoCover "F12:L24" -ChartData $workbook.Worksheets.Item(1).Range("F2:F9,G2:G9")
                $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(11,6) , "" , "Computers!A1", "", "Raw Data") | Out-Null
            }
            Else
            {
                Get-ADRExcelChart -ChartType "xlPie" -ChartLayout 3 -ChartTitle "Computer Accounts in AD" -RangetoCover "A11:D23" -ChartData $workbook.Worksheets.Item(1).Range("A3:A4,B3:B4")
                $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(10,1) , "" , "Computers!A1", "", "Raw Data") | Out-Null

                Get-ADRExcelChart -ChartType "xlBarClustered" -ChartLayout 1 -ChartTitle "Status of Computer Accounts" -RangetoCover "F11:L23" -ChartData $workbook.Worksheets.Item(1).Range("F2:F8,G2:G8")
                $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(10,6) , "" , "Computers!A1", "", "Raw Data") | Out-Null
            }

            $workbook.Worksheets.Item(1).UsedRange.EntireColumn.AutoFit() | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
        }

        # User Stats
        $ADFileName = -join($ReportPath,'\','Users.csv')
        If (Test-Path $ADFileName)
        {
            Get-ADRExcelWorkbook -Name "User Stats"
            Remove-Variable ADFileName

            $ObjAttributes = New-Object System.Collections.Specialized.OrderedDictionary
            $ObjAttributes.Add("Must Change Password at Logon",'"TRUE"')
            $ObjAttributes.Add("Cannot Change Password",'"TRUE"')
            $ObjAttributes.Add("Password Never Expires",'"TRUE"')
            $ObjAttributes.Add("Reversible Password Encryption",'"TRUE"')
            $ObjAttributes.Add("Smartcard Logon Required",'"TRUE"')
            $ObjAttributes.Add("Delegation Permitted",'"TRUE"')
            $ObjAttributes.Add("Kerberos DES Only",'"TRUE"')
            $ObjAttributes.Add("Kerberos RC4",'"TRUE"')
            $ObjAttributes.Add("Does Not Require Pre Auth",'"TRUE"')
            $ObjAttributes.Add("Password Age (> ",'"TRUE"')
            $ObjAttributes.Add("Account Locked Out",'"TRUE"')
            $ObjAttributes.Add("Never Logged in",'"TRUE"')
            $ObjAttributes.Add("Dormant",'"TRUE"')
            $ObjAttributes.Add("Password Not Required",'"TRUE"')
            $ObjAttributes.Add("Delegation Typ",'"Unconstrained"')
            $ObjAttributes.Add("SIDHistory",'"*"')

            Get-ADRExcelAttributeStats -SrcSheetName "Users" -Title1 "User Accounts in AD" -PivotTableName "User Accounts Status" -PivotRows "Enabled" -PivotValues "UserName" -PivotPercentage "UserName" -Title2 "Status of User Accounts" -ObjAttributes $ObjAttributes
            Remove-Variable ObjAttributes

            Get-ADRExcelChart -ChartType "xlPie" -ChartLayout 3 -ChartTitle "User Accounts in AD" -RangetoCover "A21:D33" -ChartData $workbook.Worksheets.Item(1).Range("A3:A4,B3:B4")
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(20,1) , "" , "Users!A1", "", "Raw Data") | Out-Null

            Get-ADRExcelChart -ChartType "xlBarClustered" -ChartLayout 1 -ChartTitle "Status of User Accounts" -RangetoCover "F21:L43" -ChartData $workbook.Worksheets.Item(1).Range("F2:F18,G2:G18")
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item(20,6) , "" , "Users!A1", "", "Raw Data") | Out-Null

            $workbook.Worksheets.Item(1).UsedRange.EntireColumn.AutoFit() | Out-Null
            $excel.Windows.Item(1).Displaygridlines = $false
        }

        # Create Table of Contents
        Get-ADRExcelWorkbook -Name "Table of Contents"
        $worksheet = $workbook.Worksheets.Item(1)

        $excel.ScreenUpdating = $false
        # Image format and properties
        # $path = "C:\ADRecon_Logo.jpg"
        # $base64adrecon = [convert]::ToBase64String((Get-Content $path -Encoding byte))

        If ($Logo -eq "CyberCX")
        {
            $base64adrecon = "/9j/4AAQSkZJRgABAQAASABIAAD/4QCGRXhpZgAATU0AKgAAAAgAAwESAAMAAAABAAEAAAExAAIAAAAhAAAAModpAAQAAAABAAAAVAAAAABBZG9iZSBQaG90b3Nob3AgMjEuMiAoTWFjaW50b3NoKQAAAAOgAQADAAAAAQABAACgAgAEAAAAAQAAAligAwAEAAAAAQAAAKcAAAAA/+EK/2h0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8APD94cGFja2V0IGJlZ2luPSLvu78iIGlkPSJXNU0wTXBDZWhpSHpyZVN6TlRjemtjOWQiPz4gPHg6eG1wbWV0YSB4bWxuczp4PSJhZG9iZTpuczptZXRhLyIgeDp4bXB0az0iWE1QIENvcmUgNi4wLjAiPiA8cmRmOlJERiB4bWxuczpyZGY9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkvMDIvMjItcmRmLXN5bnRheC1ucyMiPiA8cmRmOkRlc2NyaXB0aW9uIHJkZjphYm91dD0iIiB4bWxuczp4bXA9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC8iIHhtbG5zOnhtcE1NPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvbW0vIiB4bWxuczpzdFJlZj0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL3NUeXBlL1Jlc291cmNlUmVmIyIgeG1wOkNyZWF0b3JUb29sPSJBZG9iZSBQaG90b3Nob3AgMjEuMiAoTWFjaW50b3NoKSIgeG1wTU06SW5zdGFuY2VJRD0ieG1wLmlpZDpCNTlFNjgwMDAxRTYxMUVCQUFDM0E1NzA4MDFFN0FENyIgeG1wTU06RG9jdW1lbnRJRD0ieG1wLmRpZDpCNTlFNjgwMTAxRTYxMUVCQUFDM0E1NzA4MDFFN0FENyI+IDx4bXBNTTpEZXJpdmVkRnJvbSBzdFJlZjppbnN0YW5jZUlEPSJ4bXAuaWlkOjlFMDI3ODg5MDFFNjExRUJBQUMzQTU3MDgwMUU3QUQ3IiBzdFJlZjpkb2N1bWVudElEPSJ4bXAuZGlkOjlFMDI3ODhBMDFFNjExRUJBQUMzQTU3MDgwMUU3QUQ3Ii8+IDwvcmRmOkRlc2NyaXB0aW9uPiA8L3JkZjpSREY+IDwveDp4bXBtZXRhPiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIDw/eHBhY2tldCBlbmQ9InciPz4A/+0AOFBob3Rvc2hvcCAzLjAAOEJJTQQEAAAAAAAAOEJJTQQlAAAAAAAQ1B2M2Y8AsgTpgAmY7PhCfv/AABEIAKcCWAMBIgACEQEDEQH/xAAfAAABBQEBAQEBAQAAAAAAAAAAAQIDBAUGBwgJCgv/xAC1EAACAQMDAgQDBQUEBAAAAX0BAgMABBEFEiExQQYTUWEHInEUMoGRoQgjQrHBFVLR8CQzYnKCCQoWFxgZGiUmJygpKjQ1Njc4OTpDREVGR0hJSlNUVVZXWFlaY2RlZmdoaWpzdHV2d3h5eoOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4eLj5OXm5+jp6vHy8/T19vf4+fr/xAAfAQADAQEBAQEBAQEBAAAAAAAAAQIDBAUGBwgJCgv/xAC1EQACAQIEBAMEBwUEBAABAncAAQIDEQQFITEGEkFRB2FxEyIygQgUQpGhscEJIzNS8BVictEKFiQ04SXxFxgZGiYnKCkqNTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqCg4SFhoeIiYqSk5SVlpeYmZqio6Slpqeoqaqys7S1tre4ubrCw8TFxsfIycrS09TV1tfY2dri4+Tl5ufo6ery8/T19vf4+fr/2wBDABwcHBwcHDAcHDBEMDAwRFxEREREXHRcXFxcXHSMdHR0dHR0jIyMjIyMjIyoqKioqKjExMTExNzc3Nzc3Nzc3Nz/2wBDASIkJDg0OGA0NGDmnICc5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm5ubm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UCRyK2aypQFkYD1rak+hnNdR0C7pB7c1p1VtVwpf1q1UVHdlQWgUUUVBRSu+q/jVQAnOO1aE8TSY244psEDxsS2MYxW8ZJRMnG7IIZzGNrcirYuIj/FUUlqCcxnHtVc28o7UrRlqO8kWXulA+Tk1RJLHJ5JqYW0p6jFW4rdY+Tyad4x2FZvcLeLy1yepqeiisW7u5olYKoXMRVvMXoetX6CAeDTjKzuDVzLimaI8cj0q4tzEevFMe1B5jOPaq5t5R2zWr5ZGfvIum4iHfNVZbguNq8CmCCU/w1Mlqern8BStFajvJleKMyNgdO5rVAAGB2pFVUG1RgUtROVyoxsNf7jfQ1kVsMMqR6iqH2WT2qqbS3Jmrl9fuj6UtIBgAUtZGgUUUUAFVby1S7hMTcHqD6GrVFNOwHAzwS28hilGCP1+lQ1309vDcpsmUMO3qPpWDPobA5t3BHo3+NdEaqe4rGNHc3EQxHIyj0Bpz3d1IMPKxHpmrLaVfL/yzz9CKaul3zH/AFePqR/jVXiIz6cqM7BEBJPQCtuHQ5mOZnCj25NblrY29oP3Q+bux61MqiWw7EGm2P2OPc/MjdfYelaVFFc7d3djM3U7v7Lb4Q/O/C+3qa42ujvdOvbu4aXK7ei89vyqp/Yt56p+f/1q3g4pbiZBptp9ruBuHyJy3+H412dVLK1FnAI+rHlj6mrdZTldjQUUUVAHK6xaeTL9oQfLJ19m/wDr1i131xAlxC0L9GH5e9cydEvM8FPz/wDrV0QmrWYmjR0a782P7M5+ZOnuP/rVt1zEGlX8EyyoUBU+v/1q2P8AiZf9Mv1qJJN3TA//0OkooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKYZIx1YUWAV2CKWPasnlj7mrE8/mfKvSi2j3PvPRf51vFcquzKTu7IvIuxQvpTqKKwNQooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//9HpKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKAGv9xvoayQCelaz/AHD9KzE61tT2ZnMkS2duTwKvqqou1elCfdFOqJSbKUUgoooqCgooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooA//9k="
        }
        ElseIf ($Logo -eq "Payatu")
        {
            $base64adrecon = "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"
        }
        Else
        {
		    $base64adrecon = "/9j/4AAQSkZJRgABAQAASABIAAD/4QBMRXhpZgAATU0AKgAAAAgAAgESAAMAAAABAAEAAIdpAAQAAAABAAAAJgAAAAAAAqACAAQAAAABAAAA6qADAAQAAAABAAAARgAAAAD/7QA4UGhvdG9zaG9wIDMuMAA4QklNBAQAAAAAAAA4QklNBCUAAAAAABDUHYzZjwCyBOmACZjs+EJ+/+ICoElDQ19QUk9GSUxFAAEBAAACkGxjbXMEMAAAbW50clJHQiBYWVogB+IAAwAbAAUANwAOYWNzcEFQUEwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPbWAAEAAAAA0y1sY21zAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALZGVzYwAAAQgAAAA4Y3BydAAAAUAAAABOd3RwdAAAAZAAAAAUY2hhZAAAAaQAAAAsclhZWgAAAdAAAAAUYlhZWgAAAeQAAAAUZ1hZWgAAAfgAAAAUclRSQwAAAgwAAAAgZ1RSQwAAAiwAAAAgYlRSQwAAAkwAAAAgY2hybQAAAmwAAAAkbWx1YwAAAAAAAAABAAAADGVuVVMAAAAcAAAAHABzAFIARwBCACAAYgB1AGkAbAB0AC0AaQBuAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAADIAAAAcAE4AbwAgAGMAbwBwAHkAcgBpAGcAaAB0ACwAIAB1AHMAZQAgAGYAcgBlAGUAbAB5AAAAAFhZWiAAAAAAAAD21gABAAAAANMtc2YzMgAAAAAAAQxKAAAF4///8yoAAAebAAD9h///+6L///2jAAAD2AAAwJRYWVogAAAAAAAAb5QAADjuAAADkFhZWiAAAAAAAAAknQAAD4MAALa+WFlaIAAAAAAAAGKlAAC3kAAAGN5wYXJhAAAAAAADAAAAAmZmAADypwAADVkAABPQAAAKW3BhcmEAAAAAAAMAAAACZmYAAPKnAAANWQAAE9AAAApbcGFyYQAAAAAAAwAAAAJmZgAA8qcAAA1ZAAAT0AAACltjaHJtAAAAAAADAAAAAKPXAABUewAATM0AAJmaAAAmZgAAD1z/wgARCABGAOoDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAwIEAQUABgcICQoL/8QAwxAAAQMDAgQDBAYEBwYECAZzAQIAAxEEEiEFMRMiEAZBUTIUYXEjB4EgkUIVoVIzsSRiMBbBctFDkjSCCOFTQCVjFzXwk3OiUESyg/EmVDZklHTCYNKEoxhw4idFN2WzVXWklcOF8tNGdoDjR1ZmtAkKGRooKSo4OTpISUpXWFlaZ2hpand4eXqGh4iJipCWl5iZmqClpqeoqaqwtba3uLm6wMTFxsfIycrQ1NXW19jZ2uDk5ebn6Onq8/T19vf4+fr/xAAfAQADAQEBAQEBAQEBAAAAAAABAgADBAUGBwgJCgv/xADDEQACAgEDAwMCAwUCBQIEBIcBAAIRAxASIQQgMUETBTAiMlEUQAYzI2FCFXFSNIFQJJGhQ7EWB2I1U/DRJWDBROFy8ReCYzZwJkVUkiei0ggJChgZGigpKjc4OTpGR0hJSlVWV1hZWmRlZmdoaWpzdHV2d3h5eoCDhIWGh4iJipCTlJWWl5iZmqCjpKWmp6ipqrCys7S1tre4ubrAwsPExcbHyMnK0NPU1dbX2Nna4OLj5OXm5+jp6vLz9PX29/j5+v/bAEMABQMEBAQDBQQEBAUFBQYHDAgHBwcHDwsLCQwRDxISEQ8RERMWHBcTFBoVEREYIRgaHR0fHx8TFyIkIh4kHB4fHv/bAEMBBQUFBwYHDggIDh4UERQeHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHv/aAAwDAQACEQMRAAAB8w2n2fNjTqjTqjTqjTqjTqjTqjTqjbVttW21bTqjbVtOqNtWnFj2dP3RuXfy/wBc8p7JltuB5/0A3n/ovL93R63zjqgeYbdbzW2TafWaxH84lRtc2+9ZJjp5Fry8deGn12oVvOJV2jpxMdh2CN5BF9Q6LPWcn63m3LWtzY4bedXiFuvm/W8l32ubDq+E7nJw1WZVx/rPk3rDqO08uCjX3UeW+pkeYAIHfO27PjOyy0856zketdVdXynU46c4HlundF8d2PHsHnZcDmEummZfVLzw/Ya+vcNzWZd6P5xnUvWcdqu0U+r1xXkGze8RT7RPXFeQbN+h6bznMPXmHmGUu+8842il6DmsR03MTqjbFdtq22rbattq22rbattq22rbattq22rbattq22r/2gAIAQEAAQUC/wB/o1O0bfFDJuVhLGvbY0y393t+w2quT4Ze5WEsa34U2+0vLYweGQdxtNomtbmCW3l/1FD+98Zf7Sty/wCMP2f/AGp+O/8AGntV5Juad9s0WO4eCv8AafP+/wDCqVI3bxYpKt5hiXIpHh7bCjd9ksreyUlSTDEuRSPD22FH9Hdre82kVruGxbTb3cX9Hdre77JZW9kpKknw9tMO4W2zbXFc3afDe2qO+2aLHcO2x7Sb+Pft2F9BZ3v6UsxZGw8QeO/8afhL/a14v/2teBxlZSeFFqXuu5BFk/BCQqyX4WlUvadgXZXvi7/a14LA9wnUrn5Ke0a7p456brJT8J6714v/ANrXgc0svEG8JvkeEyf014v/ANrXbwPQWS942ML2vctquLzd/wDjLvHf+NPZ7OXbTv8AdxXu4+Cf8Q2bePdL7eNunUH4J/xCa9u+d79eOSRcqvBX+0+f9+9n/wBqfjv/ABp+Ev8Aa34v/wBrXgr/AGnz/v8Awl/tb8X/AO1p2XKN3ut7DYqJqbS4ltZtqudsnjvp9hvVcnwy903CVXbwpe2ttZTGsu1bgZl72LRN/t9/c2jTH4bUnk+GXvYtE3+339zaNMfhtSeT4Ze6qt4N02y6sr9HJ8Mu/k2mzt7u4lupvCl7a21lMay+GporfdfE08Vxuv8Av9//2gAIAQMRAT8B/YDEeGPEbbEmA+6ndfFJHL7ZafaLt5fbKIkmkYyUhxi5IHPlIqJYeWJ+9NV9ri/E74sDc22P4Cw/Ex/Gg3Jn+JEq091M7YypEqdz7jufcROn3P6IlRtBpJv9g//aAAgBAhEBPwH9gEz+L83ICZgO04+XLL7LDs2i7Yy+2y+/HT34pmALRniykIi05ohBsW5pbY2Emo/hQblFyn7XJ/CRd1Nz/gfbmR5cgrGhl/EDk/CWf8IMogQcf4AmFm2k4ObtjjpnHcKZRsO3ii+z/V28UX2f6px2EYf6soCQpIsUxG0V+wf/2gAIAQEABj8C/wB/tGpe7x8uJQ6CpyXEUJ91r0K8qOGNYqlStWE3ATGTwqX7cf4uSeKE+616FeVO0y7mPLEuhXH+LKNsxXc+QHF8uZBQr0P+o0fN2v8At+Tj+Qdv/bcH9ntHtEwAipxHFqt4ySkDzd1/t+TX/aLjkWClFD1Hg1lKgRiODGKFEV1oGkm71p+0GqW2mMsnkkGropJB+LGKFEV1oGkm71p+0H/jn+9BmC3VzE0+bkVeLVCQdK6P/HP96DVLbTGWTySDV0UCD8XNJIpQKOFHLHdFUSE8CdHRN0Sfgpqt4ySkDz7rnEuHKPBothEU8o8fVx7OEcs09tw25XnRQNXB/Z7R/Itf9kO5T6lqV70NT6M7VyuqPpz7XI/lMq984lpnVcCQDya/7Id1p5/1NfUfaL9ou3r+24MdOl+0fxcdddGv+yHcn0P9TEKYeXgrj6uPXyLX/ZHe5J4ZMg2+oOvQ0xW0OMnkcXF/kuD+x2j3W4pyKeXFqnhriR5u6+f9TnVeSyKQdA5N0GPIkNRrr2uvn/U1/wAYk9o+b/xmT8XlIoqPqXdf7fk1/wBo9rf+27f+z2j+Ra/7Id18/wCpr/tFx/Itf9kdo+d+7y6mI9nlAjWOujJPmxLCrFY82i73CVPvYPEtKriaNRTw1ftx/i5LOKWtqD0D4drhE8yUFXCrWR+00Wd/L/FKcC1CyoYaaUZRDJihR6mFLXHkRrq/bj/FqFlQw0FKMohkxQo9TClrjyI11ftx/i89uUME6pIalbzKkrSaIq/bj/FmfbJEC5HCj50ysl+ruETypQVcKtZHq0STLCE04lqkhWFooNR/v+//xAAzEAEAAwACAgICAgMBAQAAAgsBEQAhMUFRYXGBkaGxwfDREOHxIDBAUGBwgJCgsMDQ4P/aAAgBAQABPyH/APXoQHLfFhkC0kH51UGYQeaOGZHJ/wAQTSvdf8TyMYzwVkAjDRDKZfoqYxJf/wBDP0v8390/hf8AP+7+mv7f+f8An4VPrihzizyv7Nf5TzeBygj8rzNkKfNBoEFJFi5IKcT+aDEIAJ/F9SyEUGgQUkWLkgpxP5v+L/dUHiER0/VjguHOfd/xf7qDEIAJ/F9SaEVf1wO+X2Dt/fd9X2Boc4s/9D4HIJnurZYZPTKL52bJlJYoh7v7f+f/AMHufCD+rAxmaP6lIXmKqus1UhsJfikYEjw004pmkDMoycNP2EPd/wDoXyDHO35E8Z3/AMEkjRPmgISKSSTrTLm8yppKfM//AIOPgBJ/F4dw9tlxp0b+9/a/tv5/58ljTr1c2lCENUOdUKYEHmNb9Hg4+v8AiRzqhxCj9n/g/dayb+zX+U8/8/SX9r/P/wCE3Sf5Tz/+C3CCwfJ4qyYPPLX50pb0xhXcHk8cUy6Qun/EL4Dj/wAKobHbKCiRSfmkbjB4qoMBQeFqHm7wA93/ABCg0APC1Dzd4Ae7/iMIEaEN6lrDn/EJbEGpyv5QQ0qls9soOJFp+aJwqaM+BH/6+P/aAAwDAQACEQMRAAAQ7zzzzzzz/wD/APP/AD/wKnmaoBooIKgvfeTw8W/lljjYE0YOWwgCijjT9T9yxgAg/wD/AP8A/wD/AP8A/wD/AP8A/wD/AP8A/8QAMxEBAQEAAwABAgUFAQEAAQEJAQARITEQQVFhIHHwkYGhsdHB4fEwQFBgcICQoLDA0OD/2gAIAQMRAT8Qsss/+gc3K+g2YqNujmNntBcY4JE21uQkNwSJtkl0UopDkyNYE+seLEtlyjlvqQLuXISvrdiTi4OcZYrBhDkYMyzYGSPSZbPLTi/KSt04vylo64+khMj01aW7f/wP/9oACAECEQE/EP8A7rwzk+pkCXCwYdPmR35LwpbQUI5KBt8GP7WoSHObUOp2Mh8yLHUIy2z8kAhghPyjinHx976E4yP2mI2Bl8r6QDitJflIwPi/oItnX0sIjA4It+rv5w7GHJgfOlfDgfOlfDiA3k+bB5TfGUf5OwB8f/gf/9oACAEBAAE/EP8A9P6uHOf3U76uX7rzzUI/5neXPN54/wCH/wChCDKAHlqdxZ8nuR6rm8UORxF9QjmPVVURhgv/ANb/AKs7xoQo4je71TziphgrUPGBeRPqi9cvQc40E7gNJ4rfuw+P+/i56/5H/IfH/Iv+b/8Ag/fxf8X4f8Mf4rz/AMDw8HXTEcFloORd/T7pZHfaZmifl/yvg/8A2XlD2XXGsrKPCQMa0rQehwF2fFaq0RSGn2pbjhg8sJfFVg5KxHjGtB6HAXZjitVaIpDT7f8AHNEibhMhqaRA7wmOQRP/ABwNxwweWEviqi81iPGNihoDyNN3jEgxETAeqIQ5R0x6mlAV8ssz/wAPa0gcVkonCuMUypAY/FHmQQOT192AsGoHUfx/w7q8Dr/RcwB8fzUGQdb7sQxlJsSzHFm/OECZlizBl7rrKRCYXNJaEnALJVOBE9euaWIJ4PO9VeYEik9qQAcjflf/AKupa5p//SyEks4/4Lp/Yq3RKOZ4oMQ6/ujHkYeQVRnWAiEnVNXKRJ4vgB6/n/hEfxRFkg85NSPikLWeSGF48lkBc8GHOx7v+xV/Jf8AgEz/AB58uqnveZDnKiJFEfDKtIjTK5o+GzFtwBcE8ji81AkZB9ySk2hBPIWfi/8A0P8AusW0BlGPd/f/AMqPT7uNWPd/x/u/7Xld82P+B1e8d380Cvt/K/4byv8AgPV/xfuwe6J4A1B50VbxhwHPqtRLE8rzYCoSCYHmsyslwhDgfdXi1yILMcX/AOt/1RwRw5Di9XZ0Xbx5ZPxQ7mpQN4IjjiiVjpSTs/1XCJophMP6sBvmXzJXjzf/AK3/AFRKxk5J2f6rhE0UwmH9WA3zL5krx5v/ANb/AKsblVUay79Ua2pCiMvHu/8A1v8Aqr0wehckJV1nQIw4uzs63js1Q4djQ/j1YTeP6sSkz/VVFL/fN/vn/vcwXuYokcFH/oxZs13/ALNd/wCrNn0ZxSPBZ2Xfn/8AAv1Zs+j/APT/AP/Z"
        }
        $bytes = [System.Convert]::FromBase64String($base64adrecon)
        Remove-Variable base64adrecon

        $CompanyLogo = -join($ReportPath,'\','ADRecon_Logo.jpg')
		$p = New-Object IO.MemoryStream($bytes, 0, $bytes.length)
		$p.Write($bytes, 0, $bytes.length)
        Add-Type -AssemblyName System.Drawing
		$picture = [System.Drawing.Image]::FromStream($p, $true)
		$picture.Save($CompanyLogo)

        Remove-Variable bytes
        Remove-Variable p
        Remove-Variable picture

        $LinkToFile = $false
        $SaveWithDocument = $true
        $Left = 0
        $Top = 0
        $Width = 150
        $Height = 50

        # Add image to the Sheet
        $worksheet.Shapes.AddPicture($CompanyLogo, $LinkToFile, $SaveWithDocument, $Left, $Top, $Width, $Height) | Out-Null

        Remove-Variable LinkToFile
        Remove-Variable SaveWithDocument
        Remove-Variable Left
        Remove-Variable Top
        Remove-Variable Width
        Remove-Variable Height

        If (Test-Path -Path $CompanyLogo)
        {
            Remove-Item $CompanyLogo
        }
        Remove-Variable CompanyLogo

        $row = 5
        $column = 1
        $worksheet.Cells.Item($row,$column)= "Table of Contents"
        $worksheet.Cells.Item($row,$column).Style = "Heading 2"
        $row++

        For($i=2; $i -le $workbook.Worksheets.Count; $i++)
        {
            $workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item($row,$column) , "" , "'$($workbook.Worksheets.Item($i).Name)'!A1", "", $workbook.Worksheets.Item($i).Name) | Out-Null
            $row++
        }

        $row++
		$workbook.Worksheets.Item(1).Hyperlinks.Add($workbook.Worksheets.Item(1).Cells.Item($row,1) , "https://github.com/adrecon/ADRecon", "" , "", "github.com/adrecon/ADRecon") | Out-Null

        $worksheet.UsedRange.EntireColumn.AutoFit() | Out-Null

        $excel.Windows.Item(1).Displaygridlines = $false
        $excel.ScreenUpdating = $true
        $ADStatFileName = -join($ExcelPath,'\',$DomainName,'ADRecon-Report.xlsx')
        Try
        {
            # Disable prompt if file exists
            $excel.DisplayAlerts = $False
            $workbook.SaveAs($ADStatFileName)
            Write-Output "[+] Excelsheet Saved to: $ADStatFileName"
        }
        Catch
        {
            Write-Error "[EXCEPTION] $($_.Exception.Message)"
        }
        $excel.Quit()
        Get-ADRExcelComObjRelease -ComObjtoRelease $worksheet -Final $true
        Remove-Variable worksheet
        Get-ADRExcelComObjRelease -ComObjtoRelease $workbook -Final $true
        Remove-Variable -Name workbook -Scope Global
        Get-ADRExcelComObjRelease -ComObjtoRelease $excel -Final $true
        Remove-Variable -Name excel -Scope Global
    }
}

Function Get-ADRDomain
{
<#
.SYNOPSIS
    Returns information of the current (or specified) domain.

.DESCRIPTION
    Returns information of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-ADRDomain] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        If ($ADDomain)
        {
            $DomainObj = @()

            # Values taken from https://technet.microsoft.com/en-us/library/hh852281(v=wps.630).aspx
            $FLAD = @{
	            0 = "Windows2000";
	            1 = "Windows2003/Interim";
	            2 = "Windows2003";
	            3 = "Windows2008";
	            4 = "Windows2008R2";
	            5 = "Windows2012";
	            6 = "Windows2012R2";
	            7 = "Windows2016"
            }
            $DomainMode = $FLAD[[convert]::ToInt32($ADDomain.DomainMode)] + "Domain"
            Remove-Variable FLAD
            If (-Not $DomainMode)
            {
                $DomainMode = $ADDomain.DomainMode
            }

            $ObjValues = @("Name", $ADDomain.DNSRoot, "NetBIOS", $ADDomain.NetBIOSName, "Functional Level", $DomainMode, "DomainSID", $ADDomain.DomainSID.Value)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $DomainObj += $Obj
            }
            Remove-Variable DomainMode

            For($i=0; $i -lt $ADDomain.ReplicaDirectoryServers.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain Controller"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADDomain.ReplicaDirectoryServers[$i]
                $DomainObj += $Obj
            }
            For($i=0; $i -lt $ADDomain.ReadOnlyReplicaDirectoryServers.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Read Only Domain Controller"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADDomain.ReadOnlyReplicaDirectoryServers[$i]
                $DomainObj += $Obj
            }

            Try
            {
                $ADForest = Get-ADForest $ADDomain.Forest
            }
            Catch
            {
                Write-Verbose "[Get-ADRDomain] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If (-Not $ADForest)
            {
                Try
                {
                    $ADForest = Get-ADForest -Server $DomainController
                }
                Catch
                {
                    Write-Warning "[Get-ADRDomain] Error getting Forest Context"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }
            If ($ADForest)
            {
                $DomainCreation = Get-ADObject -SearchBase "$($ADForest.PartitionsContainer)" -LDAPFilter "(&(objectClass=crossRef)(systemFlags=3)(Name=$($ADDomain.Name)))" -Properties whenCreated
                If (-Not $DomainCreation)
                {
                    $DomainCreation = Get-ADObject -SearchBase "$($ADForest.PartitionsContainer)" -LDAPFilter "(&(objectClass=crossRef)(systemFlags=3)(Name=$($ADDomain.NetBIOSName)))" -Properties whenCreated
                }
                Remove-Variable ADForest
            }
            # Get RIDAvailablePool
            Try
            {
                $RIDManager = Get-ADObject -Identity "CN=RID Manager$,CN=System,$($ADDomain.DistinguishedName)" -Properties rIDAvailablePool
                $RIDproperty = $RIDManager.rIDAvailablePool
                [int32] $totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                [int64] $temp64val = $totalSIDS * ([math]::Pow(2,32))
                $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                $RIDsRemaining = $totalSIDS - $RIDsIssued
                Remove-Variable RIDManager
                Remove-Variable RIDproperty
                Remove-Variable totalSIDS
                Remove-Variable temp64val
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error accessing CN=RID Manager$,CN=System,$($ADDomain.DistinguishedName)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            If ($DomainCreation)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Creation Date"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $DomainCreation.whenCreated
                $DomainObj += $Obj
                Remove-Variable DomainCreation
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "ms-DS-MachineAccountQuota"
            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $((Get-ADObject -Identity ($ADDomain.DistinguishedName) -Properties ms-DS-MachineAccountQuota).'ms-DS-MachineAccountQuota')
            $DomainObj += $Obj

            If ($RIDsIssued)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Issued"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsIssued
                $DomainObj += $Obj
                Remove-Variable RIDsIssued
            }
            If ($RIDsRemaining)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Remaining"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsRemaining
                $DomainObj += $Obj
                Remove-Variable RIDsRemaining
            }
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
            # Get RIDAvailablePool
            Try
            {
                $SearchPath = "CN=RID Manager$,CN=System"
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomain.distinguishedName)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                $objSearcherPath.PropertiesToLoad.AddRange(("ridavailablepool"))
                $objSearcherResult = $objSearcherPath.FindAll()
                $RIDproperty = $objSearcherResult.Properties.ridavailablepool
                [int32] $totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                [int64] $temp64val = $totalSIDS * ([math]::Pow(2,32))
                $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                $RIDsRemaining = $totalSIDS - $RIDsIssued
                Remove-Variable SearchPath
                $objSearchPath.Dispose()
                $objSearcherPath.Dispose()
                $objSearcherResult.Dispose()
                Remove-Variable RIDproperty
                Remove-Variable totalSIDS
                Remove-Variable temp64val
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error accessing CN=RID Manager$,CN=System,$($SearchPath),$($objDomain.distinguishedName)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            Try
            {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            If ($ForestContext)
            {
                Remove-Variable ForestContext
            }
            If ($ADForest)
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
            }
            If ($GlobalCatalog)
            {
                $DN = "GC://$($GlobalCatalog.IPAddress)/$($objDomain.distinguishedname)"
                Try
                {
                    $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($($DN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                    $ADObject.Dispose()
                }
                Catch
                {
                    Write-Warning "[Get-ADRDomain] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
                }
            }
            Else
            {
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            Try
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
                $DN = "GC://$($GlobalCatalog)/$($objDomain.distinguishedname)"
                $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($DN)
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                $ADObject.dispose()
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
            # Get RIDAvailablePool
            Try
            {
                $RIDManager = ([ADSI]"LDAP://CN=RID Manager$,CN=System,$($objDomain.distinguishedName)")
                $RIDproperty = $ObjDomain.ConvertLargeIntegerToInt64($RIDManager.Properties.rIDAvailablePool.value)
                [int32] $totalSIDS = $($RIDproperty) / ([math]::Pow(2,32))
                [int64] $temp64val = $totalSIDS * ([math]::Pow(2,32))
                $RIDsIssued = [int32]($($RIDproperty) - $temp64val)
                $RIDsRemaining = $totalSIDS - $RIDsIssued
                Remove-Variable RIDManager
                Remove-Variable RIDproperty
                Remove-Variable totalSIDS
                Remove-Variable temp64val
            }
            Catch
            {
                Write-Warning "[Get-ADRDomain] Error accessing CN=RID Manager$,CN=System,$($SearchPath),$($objDomain.distinguishedName)"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }

        If ($ADDomain)
        {
            $DomainObj = @()

            # Values taken from https://technet.microsoft.com/en-us/library/hh852281(v=wps.630).aspx
            $FLAD = @{
	            0 = "Windows2000";
	            1 = "Windows2003/Interim";
	            2 = "Windows2003";
	            3 = "Windows2008";
	            4 = "Windows2008R2";
	            5 = "Windows2012";
	            6 = "Windows2012R2";
	            7 = "Windows2016"
            }
            $DomainMode = $FLAD[[convert]::ToInt32($objDomainRootDSE.domainFunctionality,10)] + "Domain"
            Remove-Variable FLAD

            $ObjValues = @("Name", $ADDomain.Name, "NetBIOS", $objDomain.dc.value, "Functional Level", $DomainMode, "DomainSID", $ADDomainSID.Value)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $DomainObj += $Obj
            }
            Remove-Variable DomainMode

            For($i=0; $i -lt $ADDomain.DomainControllers.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain Controller"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADDomain.DomainControllers[$i]
                $DomainObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Creation Date"
            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $objDomain.whencreated.value
            $DomainObj += $Obj

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "ms-DS-MachineAccountQuota"
            $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $objDomain.'ms-DS-MachineAccountQuota'.value
            $DomainObj += $Obj

            If ($RIDsIssued)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Issued"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsIssued
                $DomainObj += $Obj
                Remove-Variable RIDsIssued
            }
            If ($RIDsRemaining)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "RIDs Remaining"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $RIDsRemaining
                $DomainObj += $Obj
                Remove-Variable RIDsRemaining
            }
        }
    }

    If ($DomainObj)
    {
        Return $DomainObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRForest
{
<#
.SYNOPSIS
    Returns information of the current (or specified) forest.

.DESCRIPTION
    Returns information of the current (or specified) forest.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-ADRForest] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADForest = Get-ADForest $ADDomain.Forest
        }
        Catch
        {
            Write-Verbose "[Get-ADRForest] Error getting Forest Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        Remove-Variable ADDomain

        If (-Not $ADForest)
        {
            Try
            {
                $ADForest = Get-ADForest -Server $DomainController
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error getting Forest Context using Server parameter"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }

        If ($ADForest)
        {
            # Get Tombstone Lifetime
            Try
            {
                $ADForestCNC = (Get-ADRootDSE).configurationNamingContext
                $ADForestDSCP = Get-ADObject -Identity "CN=Directory Service,CN=Windows NT,CN=Services,$($ADForestCNC)" -Partition $ADForestCNC -Properties *
                $ADForestTombstoneLifetime = $ADForestDSCP.tombstoneLifetime
                Remove-Variable ADForestCNC
                Remove-Variable ADForestDSCP
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error retrieving Tombstone Lifetime"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            # Check Recycle Bin Feature Status
            If ([convert]::ToInt32($ADForest.ForestMode) -ge 4)
            {
                Try
                {
                    $ADRecycleBin = Get-ADOptionalFeature -Identity "Recycle Bin Feature" -Properties whenCreated
                }
                Catch
                {
                    Write-Warning "[Get-ADRForest] Error retrieving Recycle Bin Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }

            # Check Privileged Access Management Feature status
            If ([convert]::ToInt32($ADForest.ForestMode) -ge 7)
            {
                Try
                {
                    $PrivilegedAccessManagement = Get-ADOptionalFeature -Identity "Privileged Access Management Feature"
                }
                Catch
                {
                    Write-Warning "[Get-ADRForest] Error retrieving Privileged Acceess Management Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }

            $ForestObj = @()

            # Values taken from https://technet.microsoft.com/en-us/library/hh852281(v=wps.630).aspx
            $FLAD = @{
                0 = "Windows2000";
                1 = "Windows2003/Interim";
                2 = "Windows2003";
                3 = "Windows2008";
                4 = "Windows2008R2";
                5 = "Windows2012";
                6 = "Windows2012R2";
                7 = "Windows2016"
            }
            $ForestMode = $FLAD[[convert]::ToInt32($ADForest.ForestMode)] + "Forest"
            Remove-Variable FLAD

            If (-Not $ForestMode)
            {
                $ForestMode = $ADForest.ForestMode
            }

            # LAPS Check
            $ADRLAPSCheck = Get-ADRLAPSCheck -Method ADWS

            $ObjValues = @("Name", $ADForest.Name, "Functional Level", $ForestMode, "Domain Naming Master", $ADForest.DomainNamingMaster, "Schema Master", $ADForest.SchemaMaster, "RootDomain", $ADForest.RootDomain, "Domain Count", $ADForest.Domains.Count, "Site Count", $ADForest.Sites.Count, "Global Catalog Count", $ADForest.GlobalCatalogs.Count)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $ForestObj += $Obj
            }
            Remove-Variable ForestMode

            For($i=0; $i -lt $ADForest.Domains.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Domains[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.Sites.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Site"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Sites[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.GlobalCatalogs.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "GlobalCatalog"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.GlobalCatalogs[$i]
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Tombstone Lifetime"
            If ($ADForestTombstoneLifetime)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForestTombstoneLifetime
                Remove-Variable ADForestTombstoneLifetime
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Not Retrieved"
            }
            $ForestObj += $Obj

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin (2008 R2 onwards)"
            If ($ADRecycleBin)
            {
                If ($ADRecycleBin.EnabledScopes.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj

                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin Enabled Date"
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADRecycleBin.whenCreated
                    $ForestObj += $Obj

                    For($i=0; $i -lt $($ADRecycleBin.EnabledScopes.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADRecycleBin.EnabledScopes[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                Remove-Variable ADRecycleBin
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Privileged Access Management (2016 onwards)"
            If ($PrivilegedAccessManagement)
            {
                If ($PrivilegedAccessManagement.EnabledScopes.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj
                    For($i=0; $i -lt $($PrivilegedAccessManagement.EnabledScopes.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $PrivilegedAccessManagement.EnabledScopes[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                Remove-Variable PrivilegedAccessManagement
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "LAPS"
            If ($ADRLAPSCheck)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                $ForestObj += $Obj

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "LAPS Installed Date"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $((Get-ADObject "CN=ms-Mcs-AdmPwd,$((Get-ADRootDSE).schemaNamingContext)" -Properties whenCreated).whenCreated)
                $ForestObj += $Obj
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            Remove-Variable ADForest
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext

            $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Remove-Variable ADDomain
            Try
            {
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable ForestContext

            # Get Tombstone Lifetime
            Try
            {
                $SearchPath = "CN=Directory Service,CN=Windows NT,CN=Services"
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.configurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                $objSearcherPath.Filter="(name=Directory Service)"
                $objSearcherResult = $objSearcherPath.FindAll()
                $ADForestTombstoneLifetime = $objSearcherResult.Properties.tombstoneLifetime
                Remove-Variable SearchPath
                $objSearchPath.Dispose()
                $objSearcherPath.Dispose()
                $objSearcherResult.Dispose()
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error retrieving Tombstone Lifetime"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            # Check Recycle Bin Feature Status
            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 4)
            {
                Try
                {
                    $SearchPath = "CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration"
                    $ADRecycleBin = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName, $Credential.GetNetworkCredential().Password
                    Remove-Variable SearchPath
                }
                Catch
                {
                    Write-Warning "[Get-ADRForest] Error retrieving Recycle Bin Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }
            # Check Privileged Access Management Feature status
            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 7)
            {
                Try
                {
                    $SearchPath = "CN=Privileged Access Management Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration"
                    $PrivilegedAccessManagement = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName, $Credential.GetNetworkCredential().Password
                    Remove-Variable SearchPath
                }
                Catch
                {
                    Write-Warning "[Get-ADRForest] Error retrieving Privileged Access Management Feature"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

            # Get Tombstone Lifetime
            $ADForestTombstoneLifetime = ([ADSI]"LDAP://CN=Directory Service,CN=Windows NT,CN=Services,$($objDomainRootDSE.configurationNamingContext)").tombstoneLifetime.value

            # Check Recycle Bin Feature Status
            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 4)
            {
                $ADRecycleBin = ([ADSI]"LDAP://CN=Recycle Bin Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($objDomain.distinguishedName)")
            }
            # Check Privileged Access Management Feature Status
            If ([convert]::ToInt32($objDomainRootDSE.forestFunctionality,10) -ge 7)
            {
                $PrivilegedAccessManagement = ([ADSI]"LDAP://CN=Privileged Access Management Feature,CN=Optional Features,CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$($objDomain.distinguishedName)")
            }
        }

        # LAPS Check
        $ADRLAPSCheck = Get-ADRLAPSCheck -Method LDAP -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential

        If ($ADForest)
        {
            $ForestObj = @()

            # Values taken from https://technet.microsoft.com/en-us/library/hh852281(v=wps.630).aspx
            $FLAD = @{
	            0 = "Windows2000";
	            1 = "Windows2003/Interim";
	            2 = "Windows2003";
	            3 = "Windows2008";
	            4 = "Windows2008R2";
	            5 = "Windows2012";
	            6 = "Windows2012R2";
                7 = "Windows2016"
            }
            $ForestMode = $FLAD[[convert]::ToInt32($objDomainRootDSE.forestFunctionality,10)] + "Forest"
            Remove-Variable FLAD

            $ObjValues = @("Name", $ADForest.Name, "Functional Level", $ForestMode, "Domain Naming Master", $ADForest.NamingRoleOwner, "Schema Master", $ADForest.SchemaRoleOwner, "RootDomain", $ADForest.RootDomain, "Domain Count", $ADForest.Domains.Count, "Site Count", $ADForest.Sites.Count, "Global Catalog Count", $ADForest.GlobalCatalogs.Count)

            For ($i = 0; $i -lt $($ObjValues.Count); $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
                $i++
                $ForestObj += $Obj
            }
            Remove-Variable ForestMode

            For($i=0; $i -lt $ADForest.Domains.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Domain"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Domains[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.Sites.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Site"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.Sites[$i]
                $ForestObj += $Obj
            }
            For($i=0; $i -lt $ADForest.GlobalCatalogs.Count; $i++)
            {
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "GlobalCatalog"
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForest.GlobalCatalogs[$i]
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Tombstone Lifetime"
            If ($ADForestTombstoneLifetime)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADForestTombstoneLifetime
                Remove-Variable ADForestTombstoneLifetime
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Not Retrieved"
            }
            $ForestObj += $Obj

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin (2008 R2 onwards)"
            If ($ADRecycleBin)
            {
                If ($ADRecycleBin.Properties.'msds-enabledfeaturebl'.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj

                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Recycle Bin Enabled Date"
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADRecycleBin.whencreated.value
                    $ForestObj += $Obj

                    For($i=0; $i -lt $($ADRecycleBin.Properties.'msds-enabledfeaturebl'.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADRecycleBin.Properties.'msds-enabledfeaturebl'[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                $ADRecycleBin.Dispose()
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Privileged Access Management (2016 onwards)"
            If ($PrivilegedAccessManagement)
            {
                If ($PrivilegedAccessManagement.Properties.'msDS-EnabledFeatureBL'.Count -gt 0)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                    $ForestObj += $Obj
                    For($i=0; $i -lt $($PrivilegedAccessManagement.Properties.'msDS-EnabledFeatureBL'.Count); $i++)
                    {
                        $Obj = New-Object PSObject
                        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "Enabled Scope"
                        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $PrivilegedAccessManagement.Properties.'msDS-EnabledFeatureBL'[$i]
                        $ForestObj += $Obj
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                    $ForestObj += $Obj
                }
                $PrivilegedAccessManagement.dispose()
            }
            Else
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Disabled"
                $ForestObj += $Obj
            }

            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "LAPS"
            If ($ADRLAPSCheck)
            {
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value "Enabled"
                $ForestObj += $Obj

                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value "LAPS Installed Date"
                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                {
                    $ADRLAPSInstalledDate = (New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/CN=ms-Mcs-AdmPwd,$($objDomainRootDSE.schemaNamingContext)", $Credential.UserName, $Credential.GetNetworkCredential().Password).whencreated.value
                }
                Else
                {
                    $ADRLAPSInstalledDate = ([ADSI]("LDAP://CN=ms-Mcs-AdmPwd,$($objDomainRootDSE.schemaNamingContext)")).whencreated.value
                }
                $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ADRLAPSInstalledDate
                $ForestObj += $Obj
                Remove-Variable ADRLAPSInstalledDate
            }

            Remove-Variable ADForest
        }
    }

    If ($ForestObj)
    {
        Return $ForestObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRTrust
{
<#
.SYNOPSIS
    Returns the Trusts of the current (or specified) domain.

.DESCRIPTION
    Returns the Trusts of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain
    )

    # Values taken from https://msdn.microsoft.com/en-us/library/cc223768.aspx
    $TDAD = @{
        0 = "Disabled";
        1 = "Inbound";
        2 = "Outbound";
        3 = "BiDirectional";
    }

    # Values taken from https://msdn.microsoft.com/en-us/library/cc223771.aspx
    $TTAD = @{
        1 = "Downlevel";
        2 = "Uplevel";
        3 = "MIT";
        4 = "DCE";
    }

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADTrusts = Get-ADObject -LDAPFilter "(objectClass=trustedDomain)" -Properties DistinguishedName,trustPartner,trustdirection,trusttype,TrustAttributes,whenCreated,whenChanged
        }
        Catch
        {
            Write-Warning "[Get-ADRTrust] Error while enumerating trustedDomain Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADTrusts)
        {
            Write-Verbose "[*] Total Trusts: $([ADRecon.ADWSClass]::ObjectCount($ADTrusts))"
            # Trust Info
            $ADTrustObj = @()
            $ADTrusts | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Source Domain" -Value (Get-DNtoFQDN $_.DistinguishedName)
                $Obj | Add-Member -MemberType NoteProperty -Name "Target Domain" -Value $_.trustPartner
                $TrustDirection = [string] $TDAD[$_.trustdirection]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Direction" -Value $TrustDirection
                $TrustType = [string] $TTAD[$_.trusttype]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Type" -Value $TrustType

                $TrustAttributes = $null
                If ([int32] $_.TrustAttributes -band 0x00000001) { $TrustAttributes += "Non Transitive," }
                If ([int32] $_.TrustAttributes -band 0x00000002) { $TrustAttributes += "UpLevel," }
                If ([int32] $_.TrustAttributes -band 0x00000004) { $TrustAttributes += "Quarantined," } #SID Filtering
                If ([int32] $_.TrustAttributes -band 0x00000008) { $TrustAttributes += "Forest Transitive," }
                If ([int32] $_.TrustAttributes -band 0x00000010) { $TrustAttributes += "Cross Organization," } #Selective Auth
                If ([int32] $_.TrustAttributes -band 0x00000020) { $TrustAttributes += "Within Forest," }
                If ([int32] $_.TrustAttributes -band 0x00000040) { $TrustAttributes += "Treat as External," }
                If ([int32] $_.TrustAttributes -band 0x00000080) { $TrustAttributes += "Uses RC4 Encryption," }
                If ([int32] $_.TrustAttributes -band 0x00000200) { $TrustAttributes += "No TGT Delegation," }
                If ([int32] $_.TrustAttributes -band 0x00000400) { $TrustAttributes += "PIM Trust," }
                If ($TrustAttributes)
                {
                    $TrustAttributes = $TrustAttributes.TrimEnd(",")
                }
                $Obj | Add-Member -MemberType NoteProperty -Name "Attributes" -Value $TrustAttributes
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.whenCreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.whenChanged))
                $ADTrustObj += $Obj
            }
            Remove-Variable ADTrusts
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=trustedDomain)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","trustpartner","trustdirection","trusttype","trustattributes","whencreated","whenchanged"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADTrusts = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRTrust] Error while enumerating trustedDomain Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADTrusts)
        {
            Write-Verbose "[*] Total Trusts: $([ADRecon.LDAPClass]::ObjectCount($ADTrusts))"
            # Trust Info
            $ADTrustObj = @()
            $ADTrusts | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Source Domain" -Value $(Get-DNtoFQDN ([string] $_.Properties.distinguishedname))
                $Obj | Add-Member -MemberType NoteProperty -Name "Target Domain" -Value $([string] $_.Properties.trustpartner)
                $TrustDirection = [string] $TDAD[$_.Properties.trustdirection]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Direction" -Value $TrustDirection
                $TrustType = [string] $TTAD[$_.Properties.trusttype]
                $Obj | Add-Member -MemberType NoteProperty -Name "Trust Type" -Value $TrustType

                $TrustAttributes = $null
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000001) { $TrustAttributes += "Non Transitive," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000002) { $TrustAttributes += "UpLevel," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000004) { $TrustAttributes += "Quarantined," } #SID Filtering
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000008) { $TrustAttributes += "Forest Transitive," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000010) { $TrustAttributes += "Cross Organization," } #Selective Auth
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000020) { $TrustAttributes += "Within Forest," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000040) { $TrustAttributes += "Treat as External," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000080) { $TrustAttributes += "Uses RC4 Encryption," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000200) { $TrustAttributes += "No TGT Delegation," }
                If ([int32] $_.Properties.trustattributes[0] -band 0x00000400) { $TrustAttributes += "PIM Trust," }
                If ($TrustAttributes)
                {
                    $TrustAttributes = $TrustAttributes.TrimEnd(",")
                }
                $Obj | Add-Member -MemberType NoteProperty -Name "Attributes" -Value $TrustAttributes
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.Properties.whenchanged))
                $ADTrustObj += $Obj
            }
            Remove-Variable ADTrusts
        }
    }

    If ($ADTrustObj)
    {
        Return $ADTrustObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRSite
{
<#
.SYNOPSIS
    Returns the Sites of the current (or specified) domain.

.DESCRIPTION
    Returns the Sites of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $SearchPath = "CN=Sites"
            $ADSites = Get-ADObject -SearchBase "$SearchPath,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectClass=site)" -Properties Name,Description,whenCreated,whenChanged
        }
        Catch
        {
            Write-Warning "[Get-ADRSite] Error while enumerating Site Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADSites)
        {
            Write-Verbose "[*] Total Sites: $([ADRecon.ADWSClass]::ObjectCount($ADSites))"
            # Sites Info
            $ADSiteObj = @()
            $ADSites | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $_.Description
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value $_.whenCreated
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value $_.whenChanged
                $ADSiteObj += $Obj
            }
            Remove-Variable ADSites
        }
    }

    If ($Method -eq 'LDAP')
    {
        $SearchPath = "CN=Sites"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectClass=site)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSites = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRSite] Error while enumerating Site Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADSites)
        {
            Write-Verbose "[*] Total Sites: $([ADRecon.LDAPClass]::ObjectCount($ADSites))"
            # Site Info
            $ADSiteObj = @()
            $ADSites | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $([string] $_.Properties.name)
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $([string] $_.Properties.description)
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.Properties.whenchanged))
                $ADSiteObj += $Obj
            }
            Remove-Variable ADSites
        }
    }

    If ($ADSiteObj)
    {
        Return $ADSiteObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRSubnet
{
<#
.SYNOPSIS
    Returns the Subnets of the current (or specified) domain.

.DESCRIPTION
    Returns the Subnets of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $SearchPath = "CN=Subnets,CN=Sites"
            $ADSubnets = Get-ADObject -SearchBase "$SearchPath,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectClass=subnet)" -Properties Name,Description,siteObject,whenCreated,whenChanged
        }
        Catch
        {
            Write-Warning "[Get-ADRSubnet] Error while enumerating Subnet Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADSubnets)
        {
            Write-Verbose "[*] Total Subnets: $([ADRecon.ADWSClass]::ObjectCount($ADSubnets))"
            # Subnets Info
            $ADSubnetObj = @()
            $ADSubnets | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Site" -Value $(($_.siteObject -Split ",")[0] -replace 'CN=','')
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $_.Description
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value $_.whenCreated
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value $_.whenChanged
                $ADSubnetObj += $Obj
            }
            Remove-Variable ADSubnets
        }
    }

    If ($Method -eq 'LDAP')
    {
        $SearchPath = "CN=Subnets,CN=Sites"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectClass=subnet)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSubnets = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRSubnet] Error while enumerating Subnet Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADSubnets)
        {
            Write-Verbose "[*] Total Subnets: $([ADRecon.LDAPClass]::ObjectCount($ADSubnets))"
            # Subnets Info
            $ADSubnetObj = @()
            $ADSubnets | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name "Site" -Value $((([string] $_.Properties.siteobject) -Split ",")[0] -replace 'CN=','')
                $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $([string] $_.Properties.name)
                $Obj | Add-Member -MemberType NoteProperty -Name "Description" -Value $([string] $_.Properties.description)
                $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name "whenChanged" -Value ([DateTime] $($_.Properties.whenchanged))
                $ADSubnetObj += $Obj
            }
            Remove-Variable ADSubnets
        }
    }

    If ($ADSubnetObj)
    {
        Return $ADSubnetObj
    }
    Else
    {
        Return $null
    }
}

# based on https://blogs.technet.microsoft.com/heyscriptingguy/2012/01/05/how-to-find-active-directory-schema-update-history-by-using-powershell/
Function Get-ADRSchemaHistory
{
<#
.SYNOPSIS
    Returns the Schema History of the current (or specified) domain.

.DESCRIPTION
    Returns the Schema History of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    RootDSE Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADSchemaHistory = @( Get-ADObject -SearchBase ((Get-ADRootDSE).schemaNamingContext) -SearchScope OneLevel -Filter * -Property DistinguishedName, Name, ObjectClass, whenChanged, whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-ADRSchemaHistory] Error while enumerating Schema Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADSchemaHistory)
        {
            Write-Verbose "[*] Total Schema Objects: $([ADRecon.ADWSClass]::ObjectCount($ADSchemaHistory))"
            $ADSchemaObj = [ADRecon.ADWSClass]::SchemaParser($ADSchemaHistory, $Threads)
            Remove-Variable ADSchemaHistory
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($objDomainRootDSE.schemaNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($objDomainRootDSE.schemaNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectClass=*)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","objectclass","whenchanged","whencreated"))
        $ObjSearcher.SearchScope = "OneLevel"

        Try
        {
            $ADSchemaHistory = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRSchemaHistory] Error while enumerating Schema Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADSchemaHistory)
        {
            Write-Verbose "[*] Total Schema Objects: $([ADRecon.LDAPClass]::ObjectCount($ADSchemaHistory))"
            $ADSchemaObj = [ADRecon.LDAPClass]::SchemaParser($ADSchemaHistory, $Threads)
            Remove-Variable ADSchemaHistory
        }
    }

    If ($ADSchemaObj)
    {
        Return $ADSchemaObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRDefaultPasswordPolicy
{
<#
.SYNOPSIS
    Returns the Default Password Policy of the current (or specified) domain.

.DESCRIPTION
    Returns the Default Password Policy of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADpasspolicy = Get-ADDefaultDomainPasswordPolicy
        }
        Catch
        {
            Write-Warning "[Get-ADRDefaultPasswordPolicy] Error while enumerating the Default Password Policy"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADpasspolicy)
        {
            $ObjValues = @( "Enforce password history (passwords)", $ADpasspolicy.PasswordHistoryCount, "4", "4", "Req. 8.2.5 / 8.3.7", "N/A", "-", "24 or more",
            "Maximum password age (days)", $ADpasspolicy.MaxPasswordAge.days, "90", "90", "Req. 8.2.4 / 8.3.9", "365", "ISM-1590 Rev:1 Mar22", "1 to 365",
            "Minimum password age (days)", $ADpasspolicy.MinPasswordAge.days, "N/A", "N/A", "-", "N/A", "-", "1 or more",
            "Minimum password length (characters)", $ADpasspolicy.MinPasswordLength, "7", "12", "Req. 8.2.3 / 8.3.6", "14", "Control: ISM-0421 Rev:8 Dec21", "14 or more",
            "Password must meet complexity requirements", $ADpasspolicy.ComplexityEnabled, $true, $true, "Req. 8.2.3 / 8.3.6", "N/A", "-", $true,
            "Store password using reversible encryption for all users in the domain", $ADpasspolicy.ReversibleEncryptionEnabled, "N/A", "N/A", "-", "N/A", "-", $false,
            "Account lockout duration (mins)", $ADpasspolicy.LockoutDuration.minutes, "0 (manual unlock) or 30", "0 (manual unlock) or 30", "Req. 8.1.7 / 8.3.4", "N/A", "-", "15 or more",
            "Account lockout threshold (attempts)", $ADpasspolicy.LockoutThreshold, "1 to 6", "1 to 10", "Req. 8.1.6 / 8.3.4", "1 to 5", "Control: ISM-1403 Rev:2 Oct19", "1 to 5",
            "Reset account lockout counter after (mins)", $ADpasspolicy.LockoutObservationWindow.minutes, "N/A", "N/A", "-", "N/A", "-", "15 or more" )

            Remove-Variable ADpasspolicy
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($ObjDomain)
        {
            #Value taken from https://msdn.microsoft.com/en-us/library/ms679431(v=vs.85).aspx
            $pwdProperties = @{
                "DOMAIN_PASSWORD_COMPLEX" = 1;
                "DOMAIN_PASSWORD_NO_ANON_CHANGE" = 2;
                "DOMAIN_PASSWORD_NO_CLEAR_CHANGE" = 4;
                "DOMAIN_LOCKOUT_ADMINS" = 8;
                "DOMAIN_PASSWORD_STORE_CLEARTEXT" = 16;
                "DOMAIN_REFUSE_PASSWORD_CHANGE" = 32
            }

            If (($ObjDomain.pwdproperties.value -band $pwdProperties["DOMAIN_PASSWORD_COMPLEX"]) -eq $pwdProperties["DOMAIN_PASSWORD_COMPLEX"])
            {
                $ComplexPasswords = $true
            }
            Else
            {
                $ComplexPasswords = $false
            }

            If (($ObjDomain.pwdproperties.value -band $pwdProperties["DOMAIN_PASSWORD_STORE_CLEARTEXT"]) -eq $pwdProperties["DOMAIN_PASSWORD_STORE_CLEARTEXT"])
            {
                $ReversibleEncryption = $true
            }
            Else
            {
                $ReversibleEncryption = $false
            }

            $LockoutDuration = $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.lockoutduration.value)/-600000000)

            If ($LockoutDuration -gt 99999)
            {
                $LockoutDuration = 0
            }

            $ObjValues = @( "Enforce password history (passwords)", $ObjDomain.PwdHistoryLength.value, "4", "4", "Req. 8.2.5 / 8.3.7", "N/A", "-", "24 or more",
                "Maximum password age (days)", $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.maxpwdage.value) / -864000000000), "90", "90", "Req. 8.2.4 / 8.3.9", "365", "ISM-1590 Rev:1 Mar22", "1 to 365",
            "Minimum password age (days)", $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.minpwdage.value) /-864000000000), "N/A", "N/A", "-", "N/A", "-", "1 or more",
            "Minimum password length (characters)", $ObjDomain.MinPwdLength.value, "7", "12", "Req. 8.2.3 / 8.3.6", "14", "Control: ISM-0421 Rev:8 Dec21", "14 or more",
            "Password must meet complexity requirements", $ComplexPasswords, $true, $true, "Req. 8.2.3 / 8.3.6", "N/A", "-", $true,
            "Store password using reversible encryption for all users in the domain", $ReversibleEncryption, "N/A", "N/A", "-", "N/A", "-", $false,
            "Account lockout duration (mins)", $LockoutDuration, "0 (manual unlock) or 30", "0 (manual unlock) or 30", "Req. 8.1.7 / 8.3.4", "N/A", "-", "15 or more",
            "Account lockout threshold (attempts)", $ObjDomain.LockoutThreshold.value, "1 to 6", "1 to 10", "Req. 8.1.6 / 8.3.4", "1 to 5", "Control: ISM-1403 Rev:2 Oct19", "1 to 5",
            "Reset account lockout counter after (mins)", $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.lockoutobservationWindow.value)/-600000000), "N/A", "N/A", "-", "N/A", "-", "15 or more" )

            Remove-Variable pwdProperties
            Remove-Variable ComplexPasswords
            Remove-Variable ReversibleEncryption
        }
    }

    If ($ObjValues)
    {
        $ADPassPolObj = @()
        For ($i = 0; $i -lt $($ObjValues.Count); $i++)
        {
            $Obj = New-Object PSObject
            $Obj | Add-Member -MemberType NoteProperty -Name "Policy" -Value $ObjValues[$i]
            $Obj | Add-Member -MemberType NoteProperty -Name "Current Value" -Value $ObjValues[$i+1]
            $Obj | Add-Member -MemberType NoteProperty -Name "PCI DSS v3.2.1" -Value $ObjValues[$i+2]
            $Obj | Add-Member -MemberType NoteProperty -Name "PCI DSS v4.0" -Value $ObjValues[$i+3]
            $Obj | Add-Member -MemberType NoteProperty -Name "PCI DSS Requirement" -Value $ObjValues[$i+4]
            $Obj | Add-Member -MemberType NoteProperty -Name "ACSC ISM" -Value $ObjValues[$i+5]
            $Obj | Add-Member -MemberType NoteProperty -Name "ISM Controls 16Jun2022" -Value $ObjValues[$i+6]
            $Obj | Add-Member -MemberType NoteProperty -Name "CIS Benchmark 2022" -Value $ObjValues[$i+7]
            $i += 7
            $ADPassPolObj += $Obj
        }
        Remove-Variable ObjValues
        Return $ADPassPolObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRFineGrainedPasswordPolicy
{
<#
.SYNOPSIS
    Returns the Fine Grained Password Policy of the current (or specified) domain.

.DESCRIPTION
    Returns the Fine Grained Password Policy of the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADFinepasspolicy = Get-ADFineGrainedPasswordPolicy -Filter *
        }
        Catch
        {
            Write-Warning "[Get-ADRFineGrainedPasswordPolicy] Error while enumerating the Fine Grained Password Policy"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADFinepasspolicy)
        {
            $FgppPassPolObj = @()

            $ADFinepasspolicy | ForEach-Object {
                $AppliesTo = ""
                $AppliesTo = $_.AppliesTo -join ", "

                $FgppValues = [ordered]@{
                    "Name"                                       = $($_.Name)
                    "Applies To"                                 = $AppliesTo
                    "Enforce password history"                   = $_.PasswordHistoryCount
                    "Maximum password age (days)"                = $_.MaxPasswordAge.days
                    "Minimum password age (days)"                = $_.MinPasswordAge.days
                    "Minimum password length"                    = $_.MinPasswordLength
                    "Password must meet complexity requirements" = $_.ComplexityEnabled
                    "Store password using reversible encryption" = $_.ReversibleEncryptionEnabled
                    "Account lockout duration (mins)"            = $_.LockoutDuration.minutes
                    "Account lockout threshold"                  = $_.LockoutThreshold
                    "Reset account lockout counter after (mins)" = $_.LockoutObservationWindow.minutes
                    "Precedence"                                 = $($_.Precedence)
                }

                $FgppObj = New-Object -TypeName PsObject -Property $FgppValues
                $FgppPassPolObj += $FgppObj
            }
            Remove-Variable ADFinepasspolicy
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($ObjDomain)
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            $ObjSearcher.Filter = "(objectClass=msDS-PasswordSettings)"
            $ObjSearcher.SearchScope = "Subtree"
            Try
            {
                $ADFinepasspolicy = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRFineGrainedPasswordPolicy] Error while enumerating the Fine Grained Password Policy"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }

            If ($ADFinepasspolicy)
            {
                If ([ADRecon.LDAPClass]::ObjectCount($ADFinepasspolicy) -ge 1)
                {
                    $FgppPassPolObj = @()
                    $ADFinepasspolicy | ForEach-Object {
                        $AppliesTo = ""
                        $AppliesTo = $_.Properties.'msds-psoappliesto' -join ", "

                        $FgppValues = [ordered]@{
                            "Name"                                       = $($_.Properties.name)
                            "Applies To"                                 = $AppliesTo
                            "Enforce password history"                   = $($_.Properties.'msds-passwordhistorylength')
                            "Maximum password age (days)"                = $($($_.Properties.'msds-maximumpasswordage') /-864000000000)
                            "Minimum password age (days)"                = $($($_.Properties.'msds-minimumpasswordage') /-864000000000)
                            "Minimum password length"                    = $($_.Properties.'msds-minimumpasswordlength')
                            "Password must meet complexity requirements" = $($_.Properties.'msds-passwordcomplexityenabled')
                            "Store password using reversible encryption" = $($_.Properties.'msds-passwordreversibleencryptionenabled')
                            "Account lockout duration (mins)"            = $($($_.Properties.'msds-lockoutduration')/-600000000)
                            "Account lockout threshold"                  = $($_.Properties.'msds-lockoutthreshold')
                            "Reset account lockout counter after (mins)" = $($($_.Properties.'msds-lockoutobservationwindow')/-600000000)
                            "Precedence"                                 = $($_.Properties.'msds-passwordsettingsprecedence')
                        }

                        $FgppObj = New-Object -TypeName PsObject -Property $FgppValues
                        $FgppPassPolObj += $FgppObj
                    }
                }
                Remove-Variable ADFinepasspolicy
            }
        }
    }

    If ($FgppPassPolObj)
    {
        Return $FgppPassPolObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRDomainController
{
<#
.SYNOPSIS
    Returns the domain controllers for the current (or specified) forest.

.DESCRIPTION
    Returns the domain controllers for the current (or specified) forest.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDomainControllers = @( Get-ADDomainController -Filter * )
        }
        Catch
        {
            Write-Warning "[Get-ADRDomainController] Error while enumerating DomainController Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        # DC Info
        If ($ADDomainControllers)
        {
            Write-Verbose "[*] Total Domain Controllers: $([ADRecon.ADWSClass]::ObjectCount($ADDomainControllers))"
            $DCObj = [ADRecon.ADWSClass]::DomainControllerParser($ADDomainControllers, $Threads)
            Remove-Variable ADDomainControllers
        }
    }

    If ($Method -eq 'LDAP')
    {
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRDomainController] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
        }

        If ($ADDomain.DomainControllers)
        {
            Write-Verbose "[*] Total Domain Controllers: $([ADRecon.LDAPClass]::ObjectCount($ADDomain.DomainControllers))"
            $DCObj = [ADRecon.LDAPClass]::DomainControllerParser($ADDomain.DomainControllers, $Threads)
            Remove-Variable ADDomain
        }
    }

    If ($DCObj)
    {
        Return $DCObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRUser
{
<#
.SYNOPSIS
    Returns all users and/or service principal name (SPN) in the current (or specified) domain.

.DESCRIPTION
    Returns all users and/or  service principal name (SPN) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER date
    [DateTime]
    Date when ADRecon was executed.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DormantTimeSpan
    [int]
    Timespan for Dormant accounts. Default 90 days.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.PARAMETER ADRUsers
    [bool]

.PARAMETER ADRUserSPNs
    [bool]

.PARAMETER OnlyEnabled
    [bool]

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $DormantTimeSpan = 90,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $false)]
        [int] $ADRUsers = $true,

        [Parameter(Mandatory = $false)]
        [int] $ADRUserSPNs = $false,

        [Parameter(Mandatory = $false)]
        [int] $OnlyEnabled = $false
    )

    If ($Method -eq 'ADWS')
    {
        If (!$ADRUsers)
        {
            Try
            {
                If ($OnlyEnabled)
                {
                    $ADUsers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306368)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -ResultPageSize $PageSize -Properties Name,Description,memberOf,sAMAccountName,servicePrincipalName,primaryGroupID,pwdLastSet,userAccountControl )
                }
                Else
                {
                    $ADUsers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306368)(servicePrincipalName=*))" -ResultPageSize $PageSize -Properties Name,Description,memberOf,sAMAccountName,servicePrincipalName,primaryGroupID,pwdLastSet,userAccountControl )
                }
            }
            Catch
            {
                Write-Warning "[Get-ADRUser] Error while enumerating UserSPN Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }
        Else
        {
            Try
            {
                If ($OnlyEnabled)
                {
                    $ADUsers = @( Get-ADUser -Filter 'enabled -eq $true' -ResultPageSize $PageSize -Properties AccountExpirationDate,accountExpires,AccountNotDelegated,AdminCount,AllowReversiblePasswordEncryption,c,CannotChangePassword,CanonicalName,Company,Department,Description,DistinguishedName,DoesNotRequirePreAuth,Enabled,givenName,homeDirectory,Info,LastLogonDate,lastLogonTimestamp,LockedOut,LogonWorkstations,mail,Manager,memberOf,middleName,mobile,'msDS-AllowedToDelegateTo','msDS-SupportedEncryptionTypes',Name,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,primaryGroupID,profilePath,pwdlastset,SamAccountName,ScriptPath,servicePrincipalName,SID,SIDHistory,SmartcardLogonRequired,sn,Title,TrustedForDelegation,TrustedToAuthForDelegation,UseDESKeyOnly,UserAccountControl,whenChanged,whenCreated )
                }
                Else
                {
                    $ADUsers = @( Get-ADUser -Filter * -ResultPageSize $PageSize -Properties AccountExpirationDate,accountExpires,AccountNotDelegated,AdminCount,AllowReversiblePasswordEncryption,c,CannotChangePassword,CanonicalName,Company,Department,Description,DistinguishedName,DoesNotRequirePreAuth,Enabled,givenName,homeDirectory,Info,LastLogonDate,lastLogonTimestamp,LockedOut,LogonWorkstations,mail,Manager,memberOf,middleName,mobile,'msDS-AllowedToDelegateTo','msDS-SupportedEncryptionTypes',Name,PasswordExpired,PasswordLastSet,PasswordNeverExpires,PasswordNotRequired,primaryGroupID,profilePath,pwdlastset,SamAccountName,ScriptPath,servicePrincipalName,SID,SIDHistory,SmartcardLogonRequired,sn,Title,TrustedForDelegation,TrustedToAuthForDelegation,UseDESKeyOnly,UserAccountControl,whenChanged,whenCreated )
                }
            }
            Catch
            {
                Write-Warning "[Get-ADRUser] Error while enumerating User Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }
        If ($ADUsers)
        {
            Write-Verbose "[*] Total Users: $([ADRecon.ADWSClass]::ObjectCount($ADUsers))"
            If ($ADRUsers)
            {
                Try
                {
                    $ADpasspolicy = Get-ADDefaultDomainPasswordPolicy
                    $PassMaxAge = $ADpasspolicy.MaxPasswordAge.days
                    Remove-Variable ADpasspolicy
                }
                Catch
                {
                    Write-Warning "[Get-ADRUser] Error retrieving Max Password Age from the Default Password Policy. Using value as 90 days"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $PassMaxAge = 90
                }
                $UserObj = [ADRecon.ADWSClass]::UserParser($ADUsers, $date, $DormantTimeSpan, $PassMaxAge, $Threads)
            }
            If ($ADRUserSPNs)
            {
                $UserSPNObj = [ADRecon.ADWSClass]::UserSPNParser($ADUsers, $Threads)
            }
            Remove-Variable ADUsers
        }
    }

    If ($Method -eq 'LDAP')
    {
        If (!$ADRUsers)
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            If ($OnlyEnabled)
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            }
            Else
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306368)(servicePrincipalName=*))"
            }
            $ObjSearcher.PropertiesToLoad.AddRange(("name","description","memberof","samaccountname","serviceprincipalname","primarygroupid","pwdlastset","useraccountcontrol"))
            $ObjSearcher.SearchScope = "Subtree"
            Try
            {
                $ADUsers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRUser] Error while enumerating UserSPN Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()
        }
        Else
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            If ($OnlyEnabled)
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306368)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            }
            Else
            {
                $ObjSearcher.Filter = "(samAccountType=805306368)"
            }
                # https://msdn.microsoft.com/en-us/library/system.directoryservices.securitymasks(v=vs.110).aspx
            $ObjSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]'Dacl'
            $ObjSearcher.PropertiesToLoad.AddRange(("accountExpires","admincount","c","canonicalname","company","department","description","distinguishedname","givenName","homedirectory","info","lastLogontimestamp","mail","manager","memberof","middleName","mobile","msDS-AllowedToDelegateTo","msDS-SupportedEncryptionTypes","name","ntsecuritydescriptor","objectsid","primarygroupid","profilepath","pwdLastSet","samaccountName","scriptpath","serviceprincipalname","sidhistory","sn","title","useraccountcontrol","userworkstations","whenchanged","whencreated"))
            $ObjSearcher.SearchScope = "Subtree"
            Try
            {
                $ADUsers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRUser] Error while enumerating User Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()
        }
        If ($ADUsers)
        {
            Write-Verbose "[*] Total Users: $([ADRecon.LDAPClass]::ObjectCount($ADUsers))"
            If ($ADRUsers)
            {
                $PassMaxAge = $($ObjDomain.ConvertLargeIntegerToInt64($ObjDomain.maxpwdage.value) /-864000000000)
                If (-Not $PassMaxAge)
                {
                    Write-Warning "[Get-ADRUser] Error retrieving Max Password Age from the Default Password Policy. Using value as 90 days"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $PassMaxAge = 90
                }
                $UserObj = [ADRecon.LDAPClass]::UserParser($ADUsers, $date, $DormantTimeSpan, $PassMaxAge, $Threads)
            }
            If ($ADRUserSPNs)
            {
                $UserSPNObj = [ADRecon.LDAPClass]::UserSPNParser($ADUsers, $Threads)
            }
            Remove-Variable ADUsers
        }
    }

    If ($UserObj)
    {
        Export-ADR -ADRObj $UserObj -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Users"
        Remove-Variable UserObj
    }
    If ($UserSPNObj)
    {
        Export-ADR -ADRObj $UserSPNObj -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "UserSPNs"
        Remove-Variable UserSPNObj
    }
}

#TODO
Function Get-ADRPasswordAttributes
{
<#
.SYNOPSIS
    Returns all objects with plaintext passwords in the current (or specified) domain.

.DESCRIPTION
    Returns all objects with plaintext passwords in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.OUTPUTS
    PSObject.

.LINK
    https://www.ibm.com/support/knowledgecenter/en/ssw_aix_71/com.ibm.aix.security/ad_password_attribute_selection.htm
    https://msdn.microsoft.com/en-us/library/cc223248.aspx
    https://msdn.microsoft.com/en-us/library/cc223249.aspx
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADUsers = Get-ADObject -LDAPFilter '(|(UserPassword=*)(UnixUserPassword=*)(unicodePwd=*)(msSFU30Password=*))' -ResultPageSize $PageSize -Properties *
        }
        Catch
        {
            Write-Warning "[Get-ADRPasswordAttributes] Error while enumerating Password Attributes"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADUsers)
        {
            Write-Warning "[*] Total PasswordAttribute Objects: $([ADRecon.ADWSClass]::ObjectCount($ADUsers))"
            $UserObj = $ADUsers
            Remove-Variable ADUsers
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(UserPassword=*)(UnixUserPassword=*)(unicodePwd=*)(msSFU30Password=*))"
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADUsers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRPasswordAttributes] Error while enumerating Password Attributes"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADUsers)
        {
            $cnt = [ADRecon.LDAPClass]::ObjectCount($ADUsers)
            If ($cnt -gt 0)
            {
                Write-Warning "[*] Total PasswordAttribute Objects: $cnt"
            }
            $UserObj = $ADUsers
            Remove-Variable ADUsers
        }
    }

    If ($UserObj)
    {
        Return $UserObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRGroup
{
<#
.SYNOPSIS
    Returns all groups and/or membership changes in the current (or specified) domain.

.DESCRIPTION
    Returns all groups and/or membership changes in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER date
    [DateTime]
    Date when ADRecon was executed.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.PARAMETER ADROutputDir
    [string]
    Path for ADRecon output folder.

.PARAMETER OutputType
    [array]
    Output Type.

.PARAMETER ADRGroups
    [bool]

.PARAMETER ADRGroupChanges
    [bool]

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $true)]
        [string] $ADROutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType,

        [Parameter(Mandatory = $false)]
        [bool] $ADRGroups = $true,

        [Parameter(Mandatory = $false)]
        [bool] $ADRGroupChanges = $false
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADGroups = @( Get-ADGroup -Filter * -ResultPageSize $PageSize -Properties AdminCount,CanonicalName,DistinguishedName,Description,GroupCategory,GroupScope,SamAccountName,SID,SIDHistory,managedBy,'msDS-ReplValueMetaData',whenChanged,whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-ADRGroup] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADGroups)
        {
            Write-Verbose "[*] Total Groups: $([ADRecon.ADWSClass]::ObjectCount($ADGroups))"
            If ($ADRGroups)
            {
                $GroupObj = [ADRecon.ADWSClass]::GroupParser($ADGroups, $Threads)
            }
            If ($ADRGroupChanges)
            {
                $GroupChangesObj = [ADRecon.ADWSClass]::GroupChangeParser($ADGroups, $date, $Threads)
            }
            Remove-Variable ADGroups
            Remove-Variable ADRGroups
            Remove-Variable ADRGroupChanges
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=group)"
        $ObjSearcher.PropertiesToLoad.AddRange(("admincount","canonicalname", "distinguishedname", "description", "grouptype","samaccountname", "sidhistory", "managedby", "msds-replvaluemetadata", "objectsid", "whencreated", "whenchanged"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGroups = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGroup] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADGroups)
        {
            Write-Verbose "[*] Total Groups: $([ADRecon.LDAPClass]::ObjectCount($ADGroups))"
            If ($ADRGroups)
            {
                $GroupObj = [ADRecon.LDAPClass]::GroupParser($ADGroups, $Threads)
            }
            If ($ADRGroupChanges)
            {
                $GroupChangesObj = [ADRecon.LDAPClass]::GroupChangeParser($ADGroups, $date, $Threads)
            }
            Remove-Variable ADGroups
            Remove-Variable ADRGroups
            Remove-Variable ADRGroupChanges
        }
    }

    If ($GroupObj)
    {
        Export-ADR -ADRObj $GroupObj -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Groups"
        Remove-Variable GroupObj
    }

    If ($GroupChangesObj)
    {
        Export-ADR -ADRObj $GroupChangesObj -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "GroupChanges"
        Remove-Variable GroupChangesObj
    }
}

Function Get-ADRGroupMember
{
<#
.SYNOPSIS
    Returns all groups and their members in the current (or specified) domain.

.DESCRIPTION
    Returns all groups and their members in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDomain = Get-ADDomain
            $ADDomainSID = $ADDomain.DomainSID.Value
            Remove-Variable ADDomain
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADGroups = $ADGroups = @( Get-ADGroup -Filter * -ResultPageSize $PageSize -Properties SamAccountName,SID )
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        Try
        {
            $ADGroupMembers = @( Get-ADObject -LDAPFilter '(|(memberof=*)(primarygroupid=*))' -Properties DistinguishedName,ObjectClass,memberof,primaryGroupID,sAMAccountName,samaccounttype, objectSid )
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error while enumerating GroupMember Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ( ($ADDomainSID) -and ($ADGroups) -and ($ADGroupMembers) )
        {
            Write-Verbose "[*] Total GroupMember Objects: $([ADRecon.ADWSClass]::ObjectCount($ADGroupMembers))"
            $GroupMemberObj = [ADRecon.ADWSClass]::GroupMemberParser($ADGroups, $ADGroupMembers, $ADDomainSID, $Threads)
            Remove-Variable ADGroups
            Remove-Variable ADGroupMembers
            Remove-Variable ADDomainSID
        }
    }

    If ($Method -eq 'LDAP')
    {

        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRGroupMember] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
            Try
            {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRGroupMember] Error getting Forest Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
            If ($ForestContext)
            {
                Remove-Variable ForestContext
            }
            If ($ADForest)
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
            }
            If ($GlobalCatalog)
            {
                $DN = "GC://$($GlobalCatalog.IPAddress)/$($objDomain.distinguishedname)"
                Try
                {
                    $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($($DN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                    $ADObject.Dispose()
                }
                Catch
                {
                    Write-Warning "[Get-ADRGroupMember] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
                }
            }
            Else
            {
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            Try
            {
                $GlobalCatalog = $ADForest.FindGlobalCatalog()
                $DN = "GC://$($GlobalCatalog)/$($objDomain.distinguishedname)"
                $ADObject = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList ($DN)
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($ADObject.objectSid[0], 0)
                $ADObject.dispose()
            }
            Catch
            {
                Write-Warning "[Get-ADRGroupMember] Error retrieving Domain SID using the GlobalCatalog $($GlobalCatalog.IPAddress). Using SID from the ObjDomain."
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                $ADDomainSID = New-Object System.Security.Principal.SecurityIdentifier($objDomain.objectSid[0], 0)
            }
        }

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=group)"
        $ObjSearcher.PropertiesToLoad.AddRange(("samaccountname", "objectsid"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGroups = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error while enumerating Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(memberof=*)(primarygroupid=*))"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname", "dnshostname", "objectclass", "primarygroupid", "memberof", "samaccountname", "samaccounttype", "objectsid"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGroupMembers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGroupMember] Error while enumerating GroupMember Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ( ($ADDomainSID) -and ($ADGroups) -and ($ADGroupMembers) )
        {
            Write-Verbose "[*] Total GroupMember Objects: $([ADRecon.LDAPClass]::ObjectCount($ADGroupMembers))"
            $GroupMemberObj = [ADRecon.LDAPClass]::GroupMemberParser($ADGroups, $ADGroupMembers, $ADDomainSID, $Threads)
            Remove-Variable ADGroups
            Remove-Variable ADGroupMembers
            Remove-Variable ADDomainSID
        }
    }

    If ($GroupMemberObj)
    {
        Return $GroupMemberObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADROU
{
<#
.SYNOPSIS
    Returns all Organizational Units (OU) in the current (or specified) domain.

.DESCRIPTION
    Returns all Organizational Units (OU) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADOUs = @( Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName,Description,Name,whenCreated,whenChanged )
        }
        Catch
        {
            Write-Warning "[Get-ADROU] Error while enumerating OU Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADOUs)
        {
            Write-Verbose "[*] Total OUs: $([ADRecon.ADWSClass]::ObjectCount($ADOUs))"
            $OUObj = [ADRecon.ADWSClass]::OUParser($ADOUs, $Threads)
            Remove-Variable ADOUs
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectclass=organizationalunit)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","description","name","whencreated","whenchanged"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADOUs = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADROU] Error while enumerating OU Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADOUs)
        {
            Write-Verbose "[*] Total OUs: $([ADRecon.LDAPClass]::ObjectCount($ADOUs))"
            $OUObj = [ADRecon.LDAPClass]::OUParser($ADOUs, $Threads)
            Remove-Variable ADOUs
        }
    }

    If ($OUObj)
    {
        Return $OUObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRGPO
{
<#
.SYNOPSIS
    Returns all Group Policy Objects (GPO) in the current (or specified) domain.

.DESCRIPTION
    Returns all Group Policy Objects (GPO) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADGPOs = @( Get-ADObject -LDAPFilter '(objectCategory=groupPolicyContainer)' -Properties DisplayName,DistinguishedName,Name,gPCFileSysPath,whenCreated,whenChanged )
        }
        Catch
        {
            Write-Warning "[Get-ADRGPO] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADGPOs)
        {
            Write-Verbose "[*] Total GPOs: $([ADRecon.ADWSClass]::ObjectCount($ADGPOs))"
            $GPOsObj = [ADRecon.ADWSClass]::GPOParser($ADGPOs, $Threads)
            Remove-Variable ADGPOs
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectCategory=groupPolicyContainer)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGPOs = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGPO] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADGPOs)
        {
            Write-Verbose "[*] Total GPOs: $([ADRecon.LDAPClass]::ObjectCount($ADGPOs))"
            $GPOsObj = [ADRecon.LDAPClass]::GPOParser($ADGPOs, $Threads)
            Remove-Variable ADGPOs
        }
    }

    If ($GPOsObj)
    {
        Return $GPOsObj
    }
    Else
    {
        Return $null
    }
}

# based on https://github.com/GoateePFE/GPLinkReport/blob/master/gPLinkReport.ps1
Function Get-ADRGPLink
{
<#
.SYNOPSIS
    Returns all group policy links (gPLink) applied to Scope of Management (SOM) in the current (or specified) domain.

.DESCRIPTION
    Returns all group policy links (gPLink) applied to Scope of Management (SOM) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADSOMs = @( Get-ADObject -LDAPFilter '(|(objectclass=domain)(objectclass=organizationalUnit))' -Properties DistinguishedName,Name,gPLink,gPOptions )
            $ADSOMs += @( Get-ADObject -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter "(objectclass=site)" -Properties DistinguishedName,Name,gPLink,gPOptions )
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating SOM Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADGPOs = @( Get-ADObject -LDAPFilter '(objectCategory=groupPolicyContainer)' -Properties DisplayName,DistinguishedName )
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ( ($ADSOMs) -and ($ADGPOs) )
        {
            Write-Verbose "[*] Total SOMs: $([ADRecon.ADWSClass]::ObjectCount($ADSOMs))"
            $SOMObj = [ADRecon.ADWSClass]::SOMParser($ADGPOs, $ADSOMs, $Threads)
            Remove-Variable ADSOMs
            Remove-Variable ADGPOs
        }
    }

    If ($Method -eq 'LDAP')
    {
        $ADSOMs = @()
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(|(objectclass=domain)(objectclass=organizationalUnit))"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","gplink","gpoptions"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSOMs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating SOM Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        $SearchPath = "CN=Sites"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$SearchPath,$($objDomainRootDSE.ConfigurationNamingContext)"
        }
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $ObjSearcher.Filter = "(objectclass=site)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","gplink","gpoptions"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADSOMs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating SOM Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectCategory=groupPolicyContainer)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADGPOs = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRGPLink] Error while enumerating groupPolicyContainer Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ( ($ADSOMs) -and ($ADGPOs) )
        {
            Write-Verbose "[*] Total SOMs: $([ADRecon.LDAPClass]::ObjectCount($ADSOMs))"
            $SOMObj = [ADRecon.LDAPClass]::SOMParser($ADGPOs, $ADSOMs, $Threads)
            Remove-Variable ADSOMs
            Remove-Variable ADGPOs
        }
    }

    If ($SOMObj)
    {
        Return $SOMObj
    }
    Else
    {
        Return $null
    }
}

# Modified Convert-DNSRecord function from https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
Function Convert-DNSRecord
{
<#
.SYNOPSIS

Helpers that decodes a binary DNS record blob.

Author: Michael B. Smith, Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: None

.DESCRIPTION

Decodes a binary blob representing an Active Directory DNS entry.
Used by Get-DomainDNSRecord.

Adapted/ported from Michael B. Smith's code at https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1

.PARAMETER DNSRecord

A byte array representing the DNS record.

.OUTPUTS

System.Management.Automation.PSCustomObject

Outputs custom PSObjects with detailed information about the DNS record entry.

.LINK

https://raw.githubusercontent.com/mmessano/PowerShell/master/dns-dump.ps1
#>

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Byte[]]
        $DNSRecord
    )

    BEGIN {
        Function Get-Name
        {
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseOutputTypeCorrectly', '')]
            [CmdletBinding()]
            Param(
                [Byte[]]
                $Raw
            )

            [Int]$Length = $Raw[0]
            [Int]$Segments = $Raw[1]
            [Int]$Index =  2
            [String]$Name  = ''

            while ($Segments-- -gt 0)
            {
                [Int]$SegmentLength = $Raw[$Index++]
                while ($SegmentLength-- -gt 0)
                {
                    $Name += [Char]$Raw[$Index++]
                }
                $Name += "."
            }
            $Name
        }
    }

    PROCESS
    {
        # $RDataLen = [BitConverter]::ToUInt16($DNSRecord, 0)
        $RDataType = [BitConverter]::ToUInt16($DNSRecord, 2)
        $UpdatedAtSerial = [BitConverter]::ToUInt32($DNSRecord, 8)

        $TTLRaw = $DNSRecord[12..15]

        # reverse for big endian
        $Null = [array]::Reverse($TTLRaw)
        $TTL = [BitConverter]::ToUInt32($TTLRaw, 0)

        $Age = [BitConverter]::ToUInt32($DNSRecord, 20)
        If ($Age -ne 0)
        {
            $TimeStamp = ((Get-Date -Year 1601 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0).AddHours($age)).ToString()
        }
        Else
        {
            $TimeStamp = '[static]'
        }

        $DNSRecordObject = New-Object PSObject

        switch ($RDataType)
        {
            1
            {
                $IP = "{0}.{1}.{2}.{3}" -f $DNSRecord[24], $DNSRecord[25], $DNSRecord[26], $DNSRecord[27]
                $Data = $IP
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'A'
            }

            2
            {
                $NSName = Get-Name $DNSRecord[24..$DNSRecord.length]
                $Data = $NSName
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'NS'
            }

            5
            {
                $Alias = Get-Name $DNSRecord[24..$DNSRecord.length]
                $Data = $Alias
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'CNAME'
            }

            6
            {
                $PrimaryNS = Get-Name $DNSRecord[44..$DNSRecord.length]
                $ResponsibleParty = Get-Name $DNSRecord[$(46+$DNSRecord[44])..$DNSRecord.length]
                $SerialRaw = $DNSRecord[24..27]
                # reverse for big endian
                $Null = [array]::Reverse($SerialRaw)
                $Serial = [BitConverter]::ToUInt32($SerialRaw, 0)

                $RefreshRaw = $DNSRecord[28..31]
                $Null = [array]::Reverse($RefreshRaw)
                $Refresh = [BitConverter]::ToUInt32($RefreshRaw, 0)

                $RetryRaw = $DNSRecord[32..35]
                $Null = [array]::Reverse($RetryRaw)
                $Retry = [BitConverter]::ToUInt32($RetryRaw, 0)

                $ExpiresRaw = $DNSRecord[36..39]
                $Null = [array]::Reverse($ExpiresRaw)
                $Expires = [BitConverter]::ToUInt32($ExpiresRaw, 0)

                $MinTTLRaw = $DNSRecord[40..43]
                $Null = [array]::Reverse($MinTTLRaw)
                $MinTTL = [BitConverter]::ToUInt32($MinTTLRaw, 0)

                $Data = "[" + $Serial + "][" + $PrimaryNS + "][" + $ResponsibleParty + "][" + $Refresh + "][" + $Retry + "][" + $Expires + "][" + $MinTTL + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SOA'
            }

            12
            {
                $Ptr = Get-Name $DNSRecord[24..$DNSRecord.length]
                $Data = $Ptr
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'PTR'
            }

            13
            {
                [string]$CPUType = ""
                [string]$OSType  = ""
                [int]$SegmentLength = $DNSRecord[24]
                $Index = 25
                while ($SegmentLength-- -gt 0)
                {
                    $CPUType += [char]$DNSRecord[$Index++]
                }
                $Index = 24 + $DNSRecord[24] + 1
                [int]$SegmentLength = $Index++
                while ($SegmentLength-- -gt 0)
                {
                    $OSType += [char]$DNSRecord[$Index++]
                }
                $Data = "[" + $CPUType + "][" + $OSType + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'HINFO'
            }

            15
            {
                $PriorityRaw = $DNSRecord[24..25]
                # reverse for big endian
                $Null = [array]::Reverse($PriorityRaw)
                $Priority = [BitConverter]::ToUInt16($PriorityRaw, 0)
                $MXHost   = Get-Name $DNSRecord[26..$DNSRecord.length]
                $Data = "[" + $Priority + "][" + $MXHost + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'MX'
            }

            16
            {
                [string]$TXT  = ''
                [int]$SegmentLength = $DNSRecord[24]
                $Index = 25
                while ($SegmentLength-- -gt 0)
                {
                    $TXT += [char]$DNSRecord[$Index++]
                }
                $Data = $TXT
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'TXT'
            }

            28
            {
        		### yeah, this doesn't do all the fancy formatting that can be done for IPv6
                $AAAA = ""
                for ($i = 24; $i -lt 40; $i+=2)
                {
                    $BlockRaw = $DNSRecord[$i..$($i+1)]
                    # reverse for big endian
                    $Null = [array]::Reverse($BlockRaw)
                    $Block = [BitConverter]::ToUInt16($BlockRaw, 0)
			        $AAAA += ($Block).ToString('x4')
			        If ($i -ne 38)
                    {
                        $AAAA += ':'
                    }
                }
                $Data = $AAAA
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'AAAA'
            }

            33
            {
                $PriorityRaw = $DNSRecord[24..25]
                # reverse for big endian
                $Null = [array]::Reverse($PriorityRaw)
                $Priority = [BitConverter]::ToUInt16($PriorityRaw, 0)

                $WeightRaw = $DNSRecord[26..27]
                $Null = [array]::Reverse($WeightRaw)
                $Weight = [BitConverter]::ToUInt16($WeightRaw, 0)

                $PortRaw = $DNSRecord[28..29]
                $Null = [array]::Reverse($PortRaw)
                $Port = [BitConverter]::ToUInt16($PortRaw, 0)

                $SRVHost = Get-Name $DNSRecord[30..$DNSRecord.length]
                $Data = "[" + $Priority + "][" + $Weight + "][" + $Port + "][" + $SRVHost + "]"
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'SRV'
            }

            default
            {
                $Data = $([System.Convert]::ToBase64String($DNSRecord[24..$DNSRecord.length]))
                $DNSRecordObject | Add-Member Noteproperty 'RecordType' 'UNKNOWN'
            }
        }
        $DNSRecordObject | Add-Member Noteproperty 'UpdatedAtSerial' $UpdatedAtSerial
        $DNSRecordObject | Add-Member Noteproperty 'TTL' $TTL
        $DNSRecordObject | Add-Member Noteproperty 'Age' $Age
        $DNSRecordObject | Add-Member Noteproperty 'TimeStamp' $TimeStamp
        $DNSRecordObject | Add-Member Noteproperty 'Data' $Data
        Return $DNSRecordObject
    }
}

Function Get-ADRDNSZone
{
<#
.SYNOPSIS
    Returns all DNS Zones and Records in the current (or specified) domain.

.DESCRIPTION
    Returns all DNS Zones and Records in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER ADROutputDir
    [string]
    Path for ADRecon output folder.

.PARAMETER OutputType
    [array]
    Output Type.

.PARAMETER ADRDNSZones
    [bool]

.PARAMETER ADRDNSRecords
    [bool]

.OUTPUTS
    CSV files are created in the folder specified with the information.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $true)]
        [string] $ADROutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType,

        [Parameter(Mandatory = $false)]
        [bool] $ADRDNSZones = $true,

        [Parameter(Mandatory = $false)]
        [bool] $ADRDNSRecords = $false
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADDNSZones = Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -Properties Name,whenCreated,whenChanged,usncreated,usnchanged,distinguishedname
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        $DNSZoneArray = @()
        If ($ADDNSZones)
        {
            $DNSZoneArray += $ADDNSZones
            Remove-Variable ADDNSZones
        }

        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        Try
        {
            $ADDNSZones1 = Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -SearchBase "DC=DomainDnsZones,$($ADDomain.DistinguishedName)" -Properties Name,whenCreated,whenChanged,usncreated,usnchanged,distinguishedname
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating DC=DomainDnsZones,$($ADDomain.DistinguishedName) dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        If ($ADDNSZones1)
        {
            $DNSZoneArray += $ADDNSZones1
            Remove-Variable ADDNSZones1
        }

        Try
        {
            $ADDNSZones2 = Get-ADObject -LDAPFilter '(objectClass=dnsZone)' -SearchBase "DC=ForestDnsZones,DC=$($ADDomain.Forest -replace '\.',',DC=')" -Properties Name,whenCreated,whenChanged,usncreated,usnchanged,distinguishedname
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating DC=ForestDnsZones,DC=$($ADDomain.Forest -replace '\.',',DC=') dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        If ($ADDNSZones2)
        {
            $DNSZoneArray += $ADDNSZones2
            Remove-Variable ADDNSZones2
        }

        If ($ADDomain)
        {
            Remove-Variable ADDomain
        }

        Write-Verbose "[*] Total DNS Zones: $([ADRecon.ADWSClass]::ObjectCount($DNSZoneArray))"

        If ($DNSZoneArray)
        {
            $ADDNSZonesObj = @()
            $ADDNSNodesObj = @()
            $DNSZoneArray | ForEach-Object {
                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $([ADRecon.ADWSClass]::CleanString($_.Name))
                Try
                {
                    $DNSNodes = Get-ADObject -SearchBase $($_.DistinguishedName) -LDAPFilter '(objectClass=dnsNode)' -Properties DistinguishedName,dnsrecord,dNSTombstoned,Name,ProtectedFromAccidentalDeletion,showInAdvancedViewOnly,whenChanged,whenCreated
                }
                Catch
                {
                    Write-Warning "[Get-ADRDNSZone] Error while enumerating $($_.DistinguishedName) dnsNode Objects"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
                If ($DNSNodes)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $($DNSNodes | Measure-Object | Select-Object -ExpandProperty Count)
                    $DNSNodes | ForEach-Object {
                        $ObjNode = New-Object PSObject
                        $ObjNode | Add-Member -MemberType NoteProperty -Name ZoneName -Value $Obj.Name
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Name -Value $_.Name
                        Try
                        {
                            $DNSRecord = Convert-DNSRecord $_.dnsrecord[0]
                        }
                        Catch
                        {
                            Write-Warning "[Get-ADRDNSZone] Error while converting the DNSRecord"
                            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                        }
                        $ObjNode | Add-Member -MemberType NoteProperty -Name RecordType -Value $DNSRecord.RecordType
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Data -Value $DNSRecord.Data
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TTL -Value $DNSRecord.TTL
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Age -Value $DNSRecord.Age
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TimeStamp -Value $DNSRecord.TimeStamp
                        $ObjNode | Add-Member -MemberType NoteProperty -Name UpdatedAtSerial -Value $DNSRecord.UpdatedAtSerial
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenCreated -Value $_.whenCreated
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenChanged -Value $_.whenChanged
                        # TO DO LDAP part
                        #$ObjNode | Add-Member -MemberType NoteProperty -Name dNSTombstoned -Value $_.dNSTombstoned
                        #$ObjNode | Add-Member -MemberType NoteProperty -Name ProtectedFromAccidentalDeletion -Value $_.ProtectedFromAccidentalDeletion
                        $ObjNode | Add-Member -MemberType NoteProperty -Name showInAdvancedViewOnly -Value $_.showInAdvancedViewOnly
                        $ObjNode | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName
                        $ADDNSNodesObj += $ObjNode
                        If ($DNSRecord)
                        {
                            Remove-Variable DNSRecord
                        }
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $null
                }
                $Obj | Add-Member -MemberType NoteProperty -Name USNCreated -Value $_.usncreated
                $Obj | Add-Member -MemberType NoteProperty -Name USNChanged -Value $_.usnchanged
                $Obj | Add-Member -MemberType NoteProperty -Name whenCreated -Value $_.whenCreated
                $Obj | Add-Member -MemberType NoteProperty -Name whenChanged -Value $_.whenChanged
                $Obj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $_.DistinguishedName
                $ADDNSZonesObj += $Obj
            }
            Write-Verbose "[*] Total DNS Records: $([ADRecon.ADWSClass]::ObjectCount($ADDNSNodesObj))"
            Remove-Variable DNSZoneArray
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.PropertiesToLoad.AddRange(("name","whencreated","whenchanged","usncreated","usnchanged","distinguishedname"))
        $ObjSearcher.Filter = "(objectClass=dnsZone)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADDNSZones = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating dnsZone Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $ObjSearcher.dispose()

        $DNSZoneArray = @()
        If ($ADDNSZones)
        {
            $DNSZoneArray += $ADDNSZones
            Remove-Variable ADDNSZones
        }

        $SearchPath = "DC=DomainDnsZones"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),$($objDomain.distinguishedName)", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($SearchPath),$($objDomain.distinguishedName)"
        }
        $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $objSearcherPath.Filter = "(objectClass=dnsZone)"
        $objSearcherPath.PageSize = $PageSize
        $objSearcherPath.PropertiesToLoad.AddRange(("name","whencreated","whenchanged","usncreated","usnchanged","distinguishedname"))
        $objSearcherPath.SearchScope = "Subtree"

        Try
        {
            $ADDNSZones1 = $objSearcherPath.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating $($SearchPath),$($objDomain.distinguishedName) dnsZone Objects."
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $objSearcherPath.dispose()

        If ($ADDNSZones1)
        {
            $DNSZoneArray += $ADDNSZones1
            Remove-Variable ADDNSZones1
        }

        $SearchPath = "DC=ForestDnsZones"
        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRForest] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            Remove-Variable DomainContext
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SearchPath),DC=$($ADDomain.Forest.Name -replace '\.',',DC=')", $Credential.UserName,$Credential.GetNetworkCredential().Password
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($SearchPath),DC=$($ADDomain.Forest.Name -replace '\.',',DC=')"
        }

        $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
        $objSearcherPath.Filter = "(objectClass=dnsZone)"
        $objSearcherPath.PageSize = $PageSize
        $objSearcherPath.PropertiesToLoad.AddRange(("name","whencreated","whenchanged","usncreated","usnchanged","distinguishedname"))
        $objSearcherPath.SearchScope = "Subtree"

        Try
        {
            $ADDNSZones2 = $objSearcherPath.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRDNSZone] Error while enumerating $($SearchPath),DC=$($ADDomain.Forest.Name -replace '\.',',DC=') dnsZone Objects."
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $objSearcherPath.dispose()

        If ($ADDNSZones2)
        {
            $DNSZoneArray += $ADDNSZones2
            Remove-Variable ADDNSZones2
        }

        If($ADDomain)
        {
            Remove-Variable ADDomain
        }

        Write-Verbose "[*] Total DNS Zones: $([ADRecon.LDAPClass]::ObjectCount($DNSZoneArray))"

        If ($DNSZoneArray)
        {
            $ADDNSZonesObj = @()
            $ADDNSNodesObj = @()
            $DNSZoneArray | ForEach-Object {
                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                {
                    $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($_.Properties.distinguishedname)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                }
                Else
                {
                    $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($_.Properties.distinguishedname)"
                }
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                $objSearcherPath.Filter = "(objectClass=dnsNode)"
                $objSearcherPath.PageSize = $PageSize
                $objSearcherPath.PropertiesToLoad.AddRange(("distinguishedname","dnsrecord","name","dc","showinadvancedviewonly","whenchanged","whencreated"))
                Try
                {
                    $DNSNodes = $objSearcherPath.FindAll()
                }
                Catch
                {
                    Write-Warning "[Get-ADRDNSZone] Error while enumerating $($_.Properties.distinguishedname) dnsNode Objects"
                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                }
                $objSearcherPath.dispose()
                Remove-Variable objSearchPath

                # Create the object for each instance.
                $Obj = New-Object PSObject
                $Obj | Add-Member -MemberType NoteProperty -Name Name -Value $([ADRecon.LDAPClass]::CleanString($_.Properties.name[0]))
                If ($DNSNodes)
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $($DNSNodes | Measure-Object | Select-Object -ExpandProperty Count)
                    $DNSNodes | ForEach-Object {
                        $ObjNode = New-Object PSObject
                        $ObjNode | Add-Member -MemberType NoteProperty -Name ZoneName -Value $Obj.Name
                        $name = ([string] $($_.Properties.name))
                        If (-Not $name)
                        {
                            $name = ([string] $($_.Properties.dc))
                        }
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Name -Value $name
                        Try
                        {
                            $DNSRecord = Convert-DNSRecord $_.Properties.dnsrecord[0]
                        }
                        Catch
                        {
                            Write-Warning "[Get-ADRDNSZone] Error while converting the DNSRecord"
                            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                        }
                        $ObjNode | Add-Member -MemberType NoteProperty -Name RecordType -Value $DNSRecord.RecordType
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Data -Value $DNSRecord.Data
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TTL -Value $DNSRecord.TTL
                        $ObjNode | Add-Member -MemberType NoteProperty -Name Age -Value $DNSRecord.Age
                        $ObjNode | Add-Member -MemberType NoteProperty -Name TimeStamp -Value $DNSRecord.TimeStamp
                        $ObjNode | Add-Member -MemberType NoteProperty -Name UpdatedAtSerial -Value $DNSRecord.UpdatedAtSerial
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenCreated -Value ([DateTime] $($_.Properties.whencreated))
                        $ObjNode | Add-Member -MemberType NoteProperty -Name whenChanged -Value ([DateTime] $($_.Properties.whenchanged))
                        # TO DO
                        #$ObjNode | Add-Member -MemberType NoteProperty -Name dNSTombstoned -Value $null
                        #$ObjNode | Add-Member -MemberType NoteProperty -Name ProtectedFromAccidentalDeletion -Value $null
                        $ObjNode | Add-Member -MemberType NoteProperty -Name showInAdvancedViewOnly -Value ([string] $($_.Properties.showinadvancedviewonly))
                        $ObjNode | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value ([string] $($_.Properties.distinguishedname))
                        $ADDNSNodesObj += $ObjNode
                        If ($DNSRecord)
                        {
                            Remove-Variable DNSRecord
                        }
                    }
                }
                Else
                {
                    $Obj | Add-Member -MemberType NoteProperty -Name RecordCount -Value $null
                }
                $Obj | Add-Member -MemberType NoteProperty -Name USNCreated -Value ([string] $($_.Properties.usncreated))
                $Obj | Add-Member -MemberType NoteProperty -Name USNChanged -Value ([string] $($_.Properties.usnchanged))
                $Obj | Add-Member -MemberType NoteProperty -Name whenCreated -Value ([DateTime] $($_.Properties.whencreated))
                $Obj | Add-Member -MemberType NoteProperty -Name whenChanged -Value ([DateTime] $($_.Properties.whenchanged))
                $Obj | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value ([string] $($_.Properties.distinguishedname))
                $ADDNSZonesObj += $Obj
            }
            Write-Verbose "[*] Total DNS Records: $([ADRecon.LDAPClass]::ObjectCount($ADDNSNodesObj))"
            Remove-Variable DNSZoneArray
        }
    }

    If ($ADDNSZonesObj -and $ADRDNSZones)
    {
        Export-ADR $ADDNSZonesObj $ADROutputDir $OutputType "DNSZones"
        Remove-Variable ADDNSZonesObj
    }

    If ($ADDNSNodesObj -and $ADRDNSRecords)
    {
        Export-ADR $ADDNSNodesObj $ADROutputDir $OutputType "DNSNodes"
        Remove-Variable ADDNSNodesObj
    }
}

Function Get-ADRPrinter
{
<#
.SYNOPSIS
    Returns all printers in the current (or specified) domain.

.DESCRIPTION
    Returns all printers in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>

    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADPrinters = @( Get-ADObject -LDAPFilter '(objectCategory=printQueue)' -Properties driverName,driverVersion,Name,portName,printShareName,serverName,url,whenChanged,whenCreated )
        }
        Catch
        {
            Write-Warning "[Get-ADRPrinter] Error while enumerating printQueue Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADPrinters)
        {
            Write-Verbose "[*] Total Printers: $([ADRecon.ADWSClass]::ObjectCount($ADPrinters))"
            $PrintersObj = [ADRecon.ADWSClass]::PrinterParser($ADPrinters, $Threads)
            Remove-Variable ADPrinters
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectCategory=printQueue)"
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADPrinters = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRPrinter] Error while enumerating printQueue Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADPrinters)
        {
            $cnt = $([ADRecon.LDAPClass]::ObjectCount($ADPrinters))
            If ($cnt -ge 1)
            {
                Write-Verbose "[*] Total Printers: $cnt"
                $PrintersObj = [ADRecon.LDAPClass]::PrinterParser($ADPrinters, $Threads)
            }
            Remove-Variable ADPrinters
        }
    }

    If ($PrintersObj)
    {
        Return $PrintersObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRComputer
{
<#
.SYNOPSIS
    Returns all computers and/or service principal name (SPN) in the current (or specified) domain.

.DESCRIPTION
    Returns all computers and/or service principal name (SPN) in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER date
    [DateTime]
    Date when ADRecon was executed.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DormantTimeSpan
    [int]
    Timespan for Dormant accounts. Default 90 days.

.PARAMTER PassMaxAge
    [int]
    Maximum machine account password age. Default 30 days
    https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/domain-member-maximum-machine-account-password-age

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.PARAMETER ADRComputers
    [bool]

.PARAMETER ADRComputerSPNs
    [bool]

.PARAMETER OnlyEnabled
    [bool]

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $true)]
        [int] $DormantTimeSpan = 90,

        [Parameter(Mandatory = $true)]
        [int] $PassMaxAge = 30,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $false)]
        [int] $ADRComputers = $true,

        [Parameter(Mandatory = $false)]
        [int] $ADRComputerSPNs = $false,

        [Parameter(Mandatory = $false)]
        [int] $OnlyEnabled = $false
    )

    If ($Method -eq 'ADWS')
    {
        If (!$ADRComputers)
        {
            Try
            {
                If ($OnlyEnabled)
                {
                    $ADComputers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306369)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -ResultPageSize $PageSize -Properties Name, servicePrincipalName )
                }
                Else
                {
                    $ADComputers = @( Get-ADObject -LDAPFilter "(&(samAccountType=805306369)(servicePrincipalName=*))" -ResultPageSize $PageSize -Properties Name,servicePrincipalName )
                }
            }
            Catch
            {
                Write-Warning "[Get-ADRComputer] Error while enumerating ComputerSPN Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }
        Else
        {
            Try
            {
                If ($OnlyEnabled)
                {
                    $ADComputers = @( Get-ADComputer -Filter 'enabled -eq $true' -ResultPageSize $PageSize -Properties Description,DistinguishedName,DNSHostName,Enabled,IPv4Address,LastLogonDate,'msDS-AllowedToDelegateTo','ms-ds-CreatorSid','msDS-SupportedEncryptionTypes',Name,OperatingSystem,OperatingSystemHotfix,OperatingSystemServicePack,OperatingSystemVersion,PasswordLastSet,primaryGroupID,SamAccountName,servicePrincipalName,SID,SIDHistory,TrustedForDelegation,TrustedToAuthForDelegation,UserAccountControl,whenChanged,whenCreated )
                }
                Else
                {
                    $ADComputers = @( Get-ADComputer -Filter * -ResultPageSize $PageSize -Properties Description,DistinguishedName,DNSHostName,Enabled,IPv4Address,LastLogonDate,'msDS-AllowedToDelegateTo','ms-ds-CreatorSid','msDS-SupportedEncryptionTypes',Name,OperatingSystem,OperatingSystemHotfix,OperatingSystemServicePack,OperatingSystemVersion,PasswordLastSet,primaryGroupID,SamAccountName,servicePrincipalName,SID,SIDHistory,TrustedForDelegation,TrustedToAuthForDelegation,UserAccountControl,whenChanged,whenCreated )
                }
            }
            Catch
            {
                Write-Warning "[Get-ADRComputer] Error while enumerating Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
        }
        If ($ADComputers)
        {
            Write-Verbose "[*] Total Computers: $([ADRecon.ADWSClass]::ObjectCount($ADComputers))"
            If ($ADRComputers)
            {
                $ComputerObj = [ADRecon.ADWSClass]::ComputerParser($ADComputers, $date, $DormantTimeSpan, $PassMaxAge, $Threads)
            }
            If ($ADRComputerSPNs)
            {
                $ComputerSPNObj = [ADRecon.ADWSClass]::ComputerSPNParser($ADComputers, $Threads)
            }
            Remove-Variable ADComputers
        }
    }

    If ($Method -eq 'LDAP')
    {
        If (!$ADRComputers)
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            If ($OnlyEnabled)
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306369)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            }
            Else
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306369)(servicePrincipalName=*))"
            }
            $ObjSearcher.PropertiesToLoad.AddRange(("name","serviceprincipalname"))
            $ObjSearcher.SearchScope = "Subtree"
            Try
            {
                $ADComputers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRComputer] Error while enumerating ComputerSPN Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()
        }
        Else
        {
            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            If ($OnlyEnabled)
            {
                $ObjSearcher.Filter = "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
            }
            Else
            {
                $ObjSearcher.Filter = "(samAccountType=805306369)"
            }
            $ObjSearcher.PropertiesToLoad.AddRange(("description","distinguishedname","dnshostname","lastlogontimestamp","msDS-AllowedToDelegateTo","ms-ds-CreatorSid","msDS-SupportedEncryptionTypes","name","objectsid","operatingsystem","operatingsystemhotfix","operatingsystemservicepack","operatingsystemversion","primarygroupid","pwdlastset","samaccountname","serviceprincipalname","sidhistory","useraccountcontrol","whenchanged","whencreated"))
            $ObjSearcher.SearchScope = "Subtree"

            Try
            {
                $ADComputers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRComputer] Error while enumerating Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()
        }

        If ($ADComputers)
        {
            Write-Verbose "[*] Total Computers: $([ADRecon.LDAPClass]::ObjectCount($ADComputers))"
            If ($ADRComputers)
            {
                $ComputerObj = [ADRecon.LDAPClass]::ComputerParser($ADComputers, $date, $DormantTimeSpan, $PassMaxAge, $Threads)
            }
            If ($ADRComputerSPNs)
            {
                $ComputerSPNObj = [ADRecon.LDAPClass]::ComputerSPNParser($ADComputers, $Threads)
            }
            Remove-Variable ADComputers
        }
    }

    If ($ComputerObj)
    {
        Export-ADR -ADRObj $ComputerObj -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Computers"
        Remove-Variable ComputerObj
    }
    If ($ComputerSPNObj)
    {
        Export-ADR -ADRObj $ComputerSPNObj -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "ComputerSPNs"
        Remove-Variable ComputerSPNObj
    }
}

Function Get-ADRLAPSCheck
{
<#
.SYNOPSIS
    Checks if LAPS (local administrator) is enabled in the current (or specified) domain.

.DESCRIPTION
    Checks if LAPS (local administrator) is enabled in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomainRootDSE
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    Bool.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomainRootDSE,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADRLAPSCheck = @( Get-ADObject "CN=ms-Mcs-AdmPwd,$((Get-ADRootDSE).schemaNamingContext)" )
        }
        Catch
        {
            Write-Verbose "[*] LAPS is not implemented."
            Return $false
        }

        If ($ADRLAPSCheck)
        {
            Remove-Variable ADRLAPSCheck
            Return $true
        }
        Else
        {
            Return $false
        }
    }

    If ($Method -eq 'LDAP')
    {
        Try
        {
            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
            {
                $ADRLAPSCheckDSE = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/CN=ms-Mcs-AdmPwd,$($objDomainRootDSE.schemaNamingContext)", $Credential.UserName, $Credential.GetNetworkCredential().Password
                If (-Not ($ADRLAPSCheckDSE.Path))
                {
                    $ADRLAPSCheck = $false
                }
                Else
                {
                    $ADRLAPSCheck = $true
                    $ADRLAPSCheckDSE.dispose()
                }
            }
            Else
            {
                $ADRLAPSCheck = [ADSI]::Exists("LDAP://CN=ms-Mcs-AdmPwd,$($objDomainRootDSE.schemaNamingContext)")
            }
        }
        Catch
        {
            Write-Verbose "[Get-ADRLAPSCheck] Error while checking for existance of LAPS Properties"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($ADRLAPSCheck)
        {
            Remove-Variable ADRLAPSCheck
            Return $true
        }
        Else
        {
            Return $false
        }
    }
}

# based on https://github.com/kfosaaen/Get-LAPSPasswords/blob/master/Get-LAPSPasswords.ps1
Function Get-ADRLAPS
{
<#
.SYNOPSIS
    Returns all LAPS (local administrator) stored passwords in the current (or specified) domain.

.DESCRIPTION
    Returns all LAPS (local administrator) stored passwords in the current (or specified) domain. Other details such as the Password Expiration, whether the password is readable by the current user are also returned.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADComputers = @( Get-ADObject -LDAPFilter "(samAccountType=805306369)" -Properties CN, DNSHostName, 'ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime',useraccountcontrol -ResultPageSize $PageSize )
        }
        Catch
        {
            Write-Warning "[Get-ADRLAPS] Error while enumerating LAPS Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADComputers)
        {
            Write-Verbose "[*] Total LAPS Objects: $([ADRecon.ADWSClass]::ObjectCount($ADComputers))"
            $LAPSObj = [ADRecon.ADWSClass]::LAPSParser($ADComputers, $Threads)
            Remove-Variable ADComputers
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(samAccountType=805306369)"
        $ObjSearcher.PropertiesToLoad.AddRange(("cn","dnshostname","ms-mcs-admpwd","ms-mcs-admpwdexpirationtime","useraccountcontrol"))
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADComputers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRLAPS] Error while enumerating LAPS Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADComputers)
        {
            Write-Verbose "[*] Total LAPS Objects: $([ADRecon.LDAPClass]::ObjectCount($ADComputers))"
            $LAPSObj = [ADRecon.LDAPClass]::LAPSParser($ADComputers, $Threads)
            Remove-Variable ADComputers
        }
    }

    If ($LAPSObj)
    {
        Return $LAPSObj
    }
    Else
    {
        Return $null
    }
}

Function Get-ADRBitLocker
{
<#
.SYNOPSIS
    Returns all BitLocker Recovery Keys stored in the current (or specified) domain.

.DESCRIPTION
    Returns all BitLocker Recovery Keys stored in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADBitLockerRecoveryKeys = Get-ADObject -LDAPFilter '(objectClass=msFVE-RecoveryInformation)' -Properties distinguishedName,msFVE-RecoveryPassword,msFVE-RecoveryGuid,msFVE-VolumeGuid,Name,whenCreated
        }
        Catch
        {
            Write-Warning "[Get-ADRBitLocker] Error while enumerating msFVE-RecoveryInformation Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADBitLockerRecoveryKeys)
        {
            $cnt = $([ADRecon.ADWSClass]::ObjectCount($ADBitLockerRecoveryKeys))
            If ($cnt -ge 1)
            {
                Write-Verbose "[*] Total BitLocker Recovery Keys: $cnt"
                $BitLockerObj = @()
                $ADBitLockerRecoveryKeys | ForEach-Object {
                    # Create the object for each instance.
                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Distinguished Name" -Value $((($_.distinguishedName -split '}')[1]).substring(1))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value $_.Name
                    $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value $_.whenCreated
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key ID" -Value $([GUID] $_.'msFVE-RecoveryGuid')
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key" -Value $_.'msFVE-RecoveryPassword'
                    $Obj | Add-Member -MemberType NoteProperty -Name "Volume GUID" -Value $([GUID] $_.'msFVE-VolumeGuid')
                    Try
                    {
                        $TempComp = Get-ADComputer -Identity $Obj.'Distinguished Name' -Properties msTPM-OwnerInformation,msTPM-TpmInformationForComputer
                    }
                    Catch
                    {
                        Write-Warning "[Get-ADRBitLocker] Error while enumerating $($Obj.'Distinguished Name') Computer Object"
                        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    }
                    If ($TempComp)
                    {
                        # msTPM-OwnerInformation (Vista/7 or Server 2008/R2)
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $TempComp.'msTPM-OwnerInformation'

                        # msTPM-TpmInformationForComputer (Windows 8/10 or Server 2012/R2)
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $TempComp.'msTPM-TpmInformationForComputer'
                        If ($null -ne $TempComp.'msTPM-TpmInformationForComputer')
                        {
                            # Grab the TPM Owner Info from the msTPM-InformationObject
                            $TPMObject = Get-ADObject -Identity $TempComp.'msTPM-TpmInformationForComputer' -Properties msTPM-OwnerInformation
                            $TPMRecoveryInfo = $TPMObject.'msTPM-OwnerInformation'
                        }
                        Else
                        {
                            $TPMRecoveryInfo = $null
                        }
                    }
                    Else
                    {
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $null
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $null
                        $TPMRecoveryInfo = $null

                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "TPM Owner Password" -Value $TPMRecoveryInfo
                    $BitLockerObj += $Obj
                }
            }
            Remove-Variable ADBitLockerRecoveryKeys
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=msFVE-RecoveryInformation)"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedName","msfve-recoverypassword","msfve-recoveryguid","msfve-volumeguid","mstpm-ownerinformation","mstpm-tpminformationforcomputer","name","whencreated"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $ADBitLockerRecoveryKeys = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRBitLocker] Error while enumerating msFVE-RecoveryInformation Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADBitLockerRecoveryKeys)
        {
            $cnt = $([ADRecon.LDAPClass]::ObjectCount($ADBitLockerRecoveryKeys))
            If ($cnt -ge 1)
            {
                Write-Verbose "[*] Total BitLocker Recovery Keys: $cnt"
                $BitLockerObj = @()
                $ADBitLockerRecoveryKeys | ForEach-Object {
                    # Create the object for each instance.
                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Distinguished Name" -Value $((($_.Properties.distinguishedname -split '}')[1]).substring(1))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Name" -Value ([string] ($_.Properties.name))
                    $Obj | Add-Member -MemberType NoteProperty -Name "whenCreated" -Value ([DateTime] $($_.Properties.whencreated))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key ID" -Value $([GUID] $_.Properties.'msfve-recoveryguid'[0])
                    $Obj | Add-Member -MemberType NoteProperty -Name "Recovery Key" -Value ([string] ($_.Properties.'msfve-recoverypassword'))
                    $Obj | Add-Member -MemberType NoteProperty -Name "Volume GUID" -Value $([GUID] $_.Properties.'msfve-volumeguid'[0])

                    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
                    $ObjSearcher.PageSize = $PageSize
                    $ObjSearcher.Filter = "(&(samAccountType=805306369)(distinguishedName=$($Obj.'Distinguished Name')))"
                    $ObjSearcher.PropertiesToLoad.AddRange(("mstpm-ownerinformation","mstpm-tpminformationforcomputer"))
                    $ObjSearcher.SearchScope = "Subtree"

                    Try
                    {
                        $TempComp = $ObjSearcher.FindAll()
                    }
                    Catch
                    {
                        Write-Warning "[Get-ADRBitLocker] Error while enumerating $($Obj.'Distinguished Name') Computer Object"
                        Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                    }
                    $ObjSearcher.dispose()

                    If ($TempComp)
                    {
                        # msTPM-OwnerInformation (Vista/7 or Server 2008/R2)
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $([string] $TempComp.Properties.'mstpm-ownerinformation')

                        # msTPM-TpmInformationForComputer (Windows 8/10 or Server 2012/R2)
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $([string] $TempComp.Properties.'mstpm-tpminformationforcomputer')
                        If ($null -ne $TempComp.Properties.'mstpm-tpminformationforcomputer')
                        {
                            # Grab the TPM Owner Info from the msTPM-InformationObject
                            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                            {
                                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($TempComp.Properties.'mstpm-tpminformationforcomputer')", $Credential.UserName,$Credential.GetNetworkCredential().Password
                                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
                                $objSearcherPath.PropertiesToLoad.AddRange(("mstpm-ownerinformation"))
                                Try
                                {
                                    $TPMObject = $objSearcherPath.FindAll()
                                }
                                Catch
                                {
                                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                }
                                $objSearcherPath.dispose()

                                If ($TPMObject)
                                {
                                    $TPMRecoveryInfo = $([string] $TPMObject.Properties.'mstpm-ownerinformation')
                                }
                                Else
                                {
                                    $TPMRecoveryInfo = $null
                                }
                            }
                            Else
                            {
                                Try
                                {
                                    $TPMObject = ([ADSI]"LDAP://$($TempComp.Properties.'mstpm-tpminformationforcomputer')")
                                }
                                Catch
                                {
                                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                }
                                If ($TPMObject)
                                {
                                    $TPMRecoveryInfo = $([string] $TPMObject.Properties.'mstpm-ownerinformation')
                                }
                                Else
                                {
                                    $TPMRecoveryInfo = $null
                                }
                            }
                        }
                    }
                    Else
                    {
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-OwnerInformation" -Value $null
                        $Obj | Add-Member -MemberType NoteProperty -Name "msTPM-TpmInformationForComputer" -Value $null
                        $TPMRecoveryInfo = $null
                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "TPM Owner Password" -Value $TPMRecoveryInfo
                    $BitLockerObj += $Obj
                }
            }
            Remove-Variable cnt
            Remove-Variable ADBitLockerRecoveryKeys
        }
    }

    If ($BitLockerObj)
    {
        Return $BitLockerObj
    }
    Else
    {
        Return $null
    }
}

# Modified ConvertFrom-SID function from https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
Function ConvertFrom-SID
{
<#
.SYNOPSIS
    Converts a security identifier (SID) to a group/user name.

    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause

.DESCRIPTION
    Converts a security identifier string (SID) to a group/user name using IADsNameTranslate interface.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER ObjectSid
    Specifies one or more SIDs to convert.

.PARAMETER DomainFQDN
    Specifies the FQDN of the Domain.

.PARAMETER Credential
    Specifies an alternate credential to use for the translation.

.PARAMETER ResolveSIDs
    [bool]
    Whether to resolve SIDs in the ACLs module. (Default False)

.EXAMPLE

    ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108

    TESTLAB\harmj0y

.EXAMPLE

    "S-1-5-21-890171859-3433809279-3366196753-1107", "S-1-5-21-890171859-3433809279-3366196753-1108", "S-1-5-32-562" | ConvertFrom-SID

    TESTLAB\WINDOWS2$
    TESTLAB\harmj0y
    BUILTIN\Distributed COM Users

.EXAMPLE

    $SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm', $SecPassword)
    ConvertFrom-SID S-1-5-21-890171859-3433809279-3366196753-1108 -Credential $Cred

    TESTLAB\harmj0y

.INPUTS
    [String]
    Accepts one or more SID strings on the pipeline.

.OUTPUTS
    [String]
    The converted DOMAIN\username.
#>
    Param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [Alias('SID')]
        #[ValidatePattern('^S-1-.*')]
        [String]
        $ObjectSid,

        [Parameter(Mandatory = $false)]
        [string] $DomainFQDN,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [bool] $ResolveSID = $false
    )

    BEGIN {
        # Name Translator Initialization Types
        # https://msdn.microsoft.com/en-us/library/aa772266%28v=vs.85%29.aspx
        $ADS_NAME_INITTYPE_DOMAIN   = 1 # Initializes a NameTranslate object by setting the domain that the object binds to.
        #$ADS_NAME_INITTYPE_SERVER   = 2 # Initializes a NameTranslate object by setting the server that the object binds to.
        $ADS_NAME_INITTYPE_GC       = 3 # Initializes a NameTranslate object by locating the global catalog that the object binds to.

        # Name Transator Name Types
        # https://msdn.microsoft.com/en-us/library/aa772267%28v=vs.85%29.aspx
        #$ADS_NAME_TYPE_1779                     = 1 # Name format as specified in RFC 1779. For example, "CN=Jeff Smith,CN=users,DC=Fabrikam,DC=com".
        #$ADS_NAME_TYPE_CANONICAL                = 2 # Canonical name format. For example, "Fabrikam.com/Users/Jeff Smith".
        $ADS_NAME_TYPE_NT4                      = 3 # Account name format used in Windows. For example, "Fabrikam\JeffSmith".
        #$ADS_NAME_TYPE_DISPLAY                  = 4 # Display name format. For example, "Jeff Smith".
        #$ADS_NAME_TYPE_DOMAIN_SIMPLE            = 5 # Simple domain name format. For example, "JeffSmith@Fabrikam.com".
        #$ADS_NAME_TYPE_ENTERPRISE_SIMPLE        = 6 # Simple enterprise name format. For example, "JeffSmith@Fabrikam.com".
        #$ADS_NAME_TYPE_GUID                     = 7 # Global Unique Identifier format. For example, "{95ee9fff-3436-11d1-b2b0-d15ae3ac8436}".
        $ADS_NAME_TYPE_UNKNOWN                  = 8 # Unknown name type. The system will estimate the format. This element is a meaningful option only with the IADsNameTranslate.Set or the IADsNameTranslate.SetEx method, but not with the IADsNameTranslate.Get or IADsNameTranslate.GetEx method.
        #$ADS_NAME_TYPE_USER_PRINCIPAL_NAME      = 9 # User principal name format. For example, "JeffSmith@Fabrikam.com".
        #$ADS_NAME_TYPE_CANONICAL_EX             = 10 # Extended canonical name format. For example, "Fabrikam.com/Users Jeff Smith".
        #$ADS_NAME_TYPE_SERVICE_PRINCIPAL_NAME   = 11 # Service principal name format. For example, "www/www.fabrikam.com@fabrikam.com".
        #$ADS_NAME_TYPE_SID_OR_SID_HISTORY_NAME  = 12 # A SID string, as defined in the Security Descriptor Definition Language (SDDL), for either the SID of the current object or one from the object SID history. For example, "O:AOG:DAD:(A;;RPWPCCDCLCSWRCWDWOGA;;;S-1-0-0)"

        # https://msdn.microsoft.com/en-us/library/aa772250.aspx
        #$ADS_CHASE_REFERRALS_NEVER       = (0x00) # The client should never chase the referred-to server. Setting this option prevents a client from contacting other servers in a referral process.
        #$ADS_CHASE_REFERRALS_SUBORDINATE = (0x20) # The client chases only subordinate referrals which are a subordinate naming context in a directory tree. For example, if the base search is requested for "DC=Fabrikam,DC=Com", and the server returns a result set and a referral of "DC=Sales,DC=Fabrikam,DC=Com" on the AdbSales server, the client can contact the AdbSales server to continue the search. The ADSI LDAP provider always turns off this flag for paged searches.
        #$ADS_CHASE_REFERRALS_EXTERNAL    = (0x40) # The client chases external referrals. For example, a client requests server A to perform a search for "DC=Fabrikam,DC=Com". However, server A does not contain the object, but knows that an independent server, B, owns it. It then refers the client to server B.
        $ADS_CHASE_REFERRALS_ALWAYS      = (0x60) # Referrals are chased for either the subordinate or external type.
    }

    PROCESS {
        $TargetSid = $($ObjectSid.TrimStart("O:"))
        $TargetSid = $($TargetSid.Trim('*'))
        If ($TargetSid -match '^S-1-.*')
        {
            Try
            {
                # try to resolve any built-in SIDs first - https://support.microsoft.com/en-us/kb/243330
                Switch ($TargetSid) {
                    'S-1-0'         { 'Null Authority' }
                    'S-1-0-0'       { 'Nobody' }
                    'S-1-1'         { 'World Authority' }
                    'S-1-1-0'       { 'Everyone' }
                    'S-1-2'         { 'Local Authority' }
                    'S-1-2-0'       { 'Local' }
                    'S-1-2-1'       { 'Console Logon ' }
                    'S-1-3'         { 'Creator Authority' }
                    'S-1-3-0'       { 'Creator Owner' }
                    'S-1-3-1'       { 'Creator Group' }
                    'S-1-3-2'       { 'Creator Owner Server' }
                    'S-1-3-3'       { 'Creator Group Server' }
                    'S-1-3-4'       { 'Owner Rights' }
                    'S-1-4'         { 'Non-unique Authority' }
                    'S-1-5'         { 'NT Authority' }
                    'S-1-5-1'       { 'Dialup' }
                    'S-1-5-2'       { 'Network' }
                    'S-1-5-3'       { 'Batch' }
                    'S-1-5-4'       { 'Interactive' }
                    'S-1-5-6'       { 'Service' }
                    'S-1-5-7'       { 'Anonymous' }
                    'S-1-5-8'       { 'Proxy' }
                    'S-1-5-9'       { 'Enterprise Domain Controllers' }
                    'S-1-5-10'      { 'Principal Self' }
                    'S-1-5-11'      { 'Authenticated Users' }
                    'S-1-5-12'      { 'Restricted Code' }
                    'S-1-5-13'      { 'Terminal Server Users' }
                    'S-1-5-14'      { 'Remote Interactive Logon' }
                    'S-1-5-15'      { 'This Organization ' }
                    'S-1-5-17'      { 'This Organization ' }
                    'S-1-5-18'      { 'Local System' }
                    'S-1-5-19'      { 'NT Authority' }
                    'S-1-5-20'      { 'NT Authority' }
                    'S-1-5-80-0'    { 'All Services ' }
                    'S-1-5-32-544'  { 'BUILTIN\Administrators' }
                    'S-1-5-32-545'  { 'BUILTIN\Users' }
                    'S-1-5-32-546'  { 'BUILTIN\Guests' }
                    'S-1-5-32-547'  { 'BUILTIN\Power Users' }
                    'S-1-5-32-548'  { 'BUILTIN\Account Operators' }
                    'S-1-5-32-549'  { 'BUILTIN\Server Operators' }
                    'S-1-5-32-550'  { 'BUILTIN\Print Operators' }
                    'S-1-5-32-551'  { 'BUILTIN\Backup Operators' }
                    'S-1-5-32-552'  { 'BUILTIN\Replicators' }
                    'S-1-5-32-554'  { 'BUILTIN\Pre-Windows 2000 Compatible Access' }
                    'S-1-5-32-555'  { 'BUILTIN\Remote Desktop Users' }
                    'S-1-5-32-556'  { 'BUILTIN\Network Configuration Operators' }
                    'S-1-5-32-557'  { 'BUILTIN\Incoming Forest Trust Builders' }
                    'S-1-5-32-558'  { 'BUILTIN\Performance Monitor Users' }
                    'S-1-5-32-559'  { 'BUILTIN\Performance Log Users' }
                    'S-1-5-32-560'  { 'BUILTIN\Windows Authorization Access Group' }
                    'S-1-5-32-561'  { 'BUILTIN\Terminal Server License Servers' }
                    'S-1-5-32-562'  { 'BUILTIN\Distributed COM Users' }
                    'S-1-5-32-569'  { 'BUILTIN\Cryptographic Operators' }
                    'S-1-5-32-573'  { 'BUILTIN\Event Log Readers' }
                    'S-1-5-32-574'  { 'BUILTIN\Certificate Service DCOM Access' }
                    'S-1-5-32-575'  { 'BUILTIN\RDS Remote Access Servers' }
                    'S-1-5-32-576'  { 'BUILTIN\RDS Endpoint Servers' }
                    'S-1-5-32-577'  { 'BUILTIN\RDS Management Servers' }
                    'S-1-5-32-578'  { 'BUILTIN\Hyper-V Administrators' }
                    'S-1-5-32-579'  { 'BUILTIN\Access Control Assistance Operators' }
                    'S-1-5-32-580'  { 'BUILTIN\Remote Management Users' }
                    Default {
                        # based on Convert-ADName function from https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
                        If ( ($TargetSid -match '^S-1-.*') -and ($ResolveSID) )
                        {
                            If ($Method -eq 'ADWS')
                            {
                                Try
                                {
                                    $ADObject = Get-ADObject -Filter "objectSid -eq '$TargetSid'" -Properties DistinguishedName,sAMAccountName
                                }
                                Catch
                                {
                                    Write-Warning "[ConvertFrom-SID] Error while enumerating Object using SID"
                                    Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                }
                                If ($ADObject)
                                {
                                    $UserDomain = Get-DNtoFQDN -ADObjectDN $ADObject.DistinguishedName
                                    $ADSOutput = $UserDomain + "\" + $ADObject.sAMAccountName
                                    Remove-Variable UserDomain
                                }
                            }

                            If ($Method -eq 'LDAP')
                            {
                                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                                {
                                    $ADObject = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainFQDN/<SID=$TargetSid>",($Credential.GetNetworkCredential()).UserName,($Credential.GetNetworkCredential()).Password)
                                }
                                Else
                                {
                                    $ADObject = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainFQDN/<SID=$TargetSid>")
                                }
                                If ($ADObject)
                                {
                                    If (-Not ([string]::IsNullOrEmpty($ADObject.Properties.samaccountname)) )
                                    {
                                        $UserDomain = Get-DNtoFQDN -ADObjectDN $([string] ($ADObject.Properties.distinguishedname))
                                        $ADSOutput = $UserDomain + "\" + $([string] ($ADObject.Properties.samaccountname))
                                        Remove-Variable UserDomain
                                    }
                                }
                            }

                            If ( (-Not $ADSOutput) -or ([string]::IsNullOrEmpty($ADSOutput)) )
                            {
                                $ADSOutputType = $ADS_NAME_TYPE_NT4
                                $Init = $true
                                $Translate = New-Object -ComObject NameTranslate
                                If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                                {
                                    $ADSInitType = $ADS_NAME_INITTYPE_DOMAIN
                                    Try
                                    {
                                        [System.__ComObject].InvokeMember("InitEx","InvokeMethod",$null,$Translate,$(@($ADSInitType,$DomainFQDN,($Credential.GetNetworkCredential()).UserName,$DomainFQDN,($Credential.GetNetworkCredential()).Password)))
                                    }
                                    Catch
                                    {
                                        $Init = $false
                                        #Write-Verbose "[ConvertFrom-SID] Error initializing translation for $($TargetSid) using alternate credentials"
                                        #Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                    }
                                }
                                Else
                                {
                                    $ADSInitType = $ADS_NAME_INITTYPE_GC
                                    Try
                                    {
                                        [System.__ComObject].InvokeMember("Init","InvokeMethod",$null,$Translate,($ADSInitType,$null))
                                    }
                                    Catch
                                    {
                                        $Init = $false
                                        #Write-Verbose "[ConvertFrom-SID] Error initializing translation for $($TargetSid)"
                                        #Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                    }
                                }
                                If ($Init)
                                {
                                    [System.__ComObject].InvokeMember("ChaseReferral","SetProperty",$null,$Translate,$ADS_CHASE_REFERRALS_ALWAYS)
                                    Try
                                    {
                                        [System.__ComObject].InvokeMember("Set","InvokeMethod",$null,$Translate,($ADS_NAME_TYPE_UNKNOWN, $TargetSID))
                                        $ADSOutput = [System.__ComObject].InvokeMember("Get","InvokeMethod",$null,$Translate,$ADSOutputType)
                                    }
                                    Catch
                                    {
                                        #Write-Verbose "[ConvertFrom-SID] Error translating $($TargetSid)"
                                        #Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                                    }
                                }
                            }
                        }
                        If (-Not ([string]::IsNullOrEmpty($ADSOutput)) )
                        {
                            Return $ADSOutput
                        }
                        Else
                        {
                            Return $TargetSid
                        }
                    }
                }
            }
            Catch
            {
                #Write-Output "[ConvertFrom-SID] Error converting SID $($TargetSid)"
                #Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }
        Else
        {
            Return $TargetSid
        }
    }
}

# based on https://gallery.technet.microsoft.com/Active-Directory-OU-1d09f989
Function Get-ADRACL
{
<#
.SYNOPSIS
    Returns all ACLs for the Domain, OUs, Root Containers, GPO, User, Computer and Group objects in the current (or specified) domain.

.DESCRIPTION
    Returns all ACLs for the Domain, OUs, Root Containers, GPO, User, Computer and Group objects in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER ResolveSIDs
    [bool]
    Whether to resolve SIDs in the ACLs module. (Default False)

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.

.LINK
    https://gallery.technet.microsoft.com/Active-Directory-OU-1d09f989
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [string] $DomainController,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [bool] $ResolveSID = $false,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $false)]
        [string] $DnBase = $($ADDomain.DistinguishedName)
    )

    If ($Method -eq 'ADWS')
    {
        If ($Credential -eq [Management.Automation.PSCredential]::Empty)
        {
            If (Test-Path AD:)
            {
                Set-Location AD:
            }
            Else
            {
                Write-Warning "Default AD drive not found ... Skipping ACL enumeration"
                Return $null
            }
        }
        $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}
        Try
        {
            Write-Verbose "[*] Enumerating schemaIDs"
            $schemaIDs = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -LDAPFilter '(schemaIDGUID=*)' -Properties name, schemaIDGUID
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating schemaIDs"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($schemaIDs)
        {
            $schemaIDs | Where-Object {$_} | ForEach-Object {
                # convert the GUID
                $GUIDs[(New-Object Guid (,$_.schemaIDGUID)).Guid] = $_.name
            }
            Remove-Variable schemaIDs
        }

        Try
        {
            Write-Verbose "[*] Enumerating Active Directory Rights"
            $schemaIDs = Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).configurationNamingContext)" -LDAPFilter '(objectClass=controlAccessRight)' -Properties name, rightsGUID
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating Active Directory Rights"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($schemaIDs)
        {
            $schemaIDs | Where-Object {$_} | ForEach-Object {
                # convert the GUID
                $GUIDs[(New-Object Guid (,$_.rightsGUID)).Guid] = $_.name
            }
            Remove-Variable schemaIDs
        }

        # Get the DistinguishedNames of Domain, OUs, Root Containers and GroupPolicy objects.
        $Objs = @()
        Try
        {
            $ADDomain = Get-ADDomain
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error getting Domain Context"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        Try
        {
            Write-Verbose "[*] Enumerating Domain, OU, GPO, User, Computer and Group Objects"
            $Objs += Get-ADObject -SearchBase $DnBase -LDAPFilter '(|(objectClass=domain)(objectCategory=organizationalunit)(objectCategory=groupPolicyContainer)(samAccountType=805306368)(samAccountType=805306369)(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))' -Properties DisplayName, DistinguishedName, Name, ntsecuritydescriptor, ObjectClass, objectsid
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating Domain, OU, GPO, User, Computer and Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }

        If ($ADDomain)
        {
            Try
            {
                Write-Verbose "[*] Enumerating Root Container Objects"
                $Objs += Get-ADObject -SearchBase $($ADDomain.DistinguishedName) -SearchScope OneLevel -LDAPFilter '(objectClass=container)' -Properties DistinguishedName, Name, ntsecuritydescriptor, ObjectClass
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error while enumerating Root Container Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }

        If ($Objs)
        {
            $ACLObj = @()
            Write-Verbose "[*] Total Objects: $([ADRecon.ADWSClass]::ObjectCount($Objs))"
            Write-Verbose "[-] DACLs"
            $DACLObj = [ADRecon.ADWSClass]::DACLParser($Objs, $GUIDs, $Threads)
            #Write-Verbose "[-] SACLs - May need a Privileged Account"
            Write-Warning "[*] SACLs - Currently, the module is only supported with LDAP."
            #$SACLObj = [ADRecon.ADWSClass]::SACLParser($Objs, $GUIDs, $Threads)
            Remove-Variable Objs
            Remove-Variable GUIDs
        }
    }

    If ($Method -eq 'LDAP')
    {
        $GUIDs = @{'00000000-0000-0000-0000-000000000000' = 'All'}

        If ($Credential -ne [Management.Automation.PSCredential]::Empty)
        {
            $DomainFQDN = Get-DNtoFQDN($objDomain.distinguishedName)
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain",$($DomainFQDN),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
            Try
            {
                $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            Try
            {
                $ForestContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Forest",$($ADDomain.Forest),$($Credential.UserName),$($Credential.GetNetworkCredential().password))
                $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ForestContext)
                $SchemaPath = $ADForest.Schema.Name
                Remove-Variable ADForest
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error enumerating SchemaPath"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }
        Else
        {
            $ADDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            $ADForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
            $SchemaPath = $ADForest.Schema.Name
            Remove-Variable ADForest
        }

        If ($SchemaPath)
        {
            Write-Verbose "[*] Enumerating schemaIDs"
            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
            {
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SchemaPath)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
            }
            Else
            {
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher ([ADSI] "LDAP://$($SchemaPath)")
            }
            $objSearcherPath.PageSize = $PageSize
            $objSearcherPath.filter = "(schemaIDGUID=*)"

            Try
            {
                $SchemaSearcher = $objSearcherPath.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error enumerating SchemaIDs"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If ($SchemaSearcher)
            {
                $SchemaSearcher | Where-Object {$_} | ForEach-Object {
                    # convert the GUID
                    $GUIDs[(New-Object Guid (,$_.properties.schemaidguid[0])).Guid] = $_.properties.name[0]
                }
                $SchemaSearcher.dispose()
            }
            $objSearcherPath.dispose()

            Write-Verbose "[*] Enumerating Active Directory Rights"
            If ($Credential -ne [Management.Automation.PSCredential]::Empty)
            {
                $objSearchPath = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/$($SchemaPath.replace("Schema","Extended-Rights"))", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher $objSearchPath
            }
            Else
            {
                $objSearcherPath = New-Object System.DirectoryServices.DirectorySearcher ([ADSI] "LDAP://$($SchemaPath.replace("Schema","Extended-Rights"))")
            }
            $objSearcherPath.PageSize = $PageSize
            $objSearcherPath.filter = "(objectClass=controlAccessRight)"

            Try
            {
                $RightsSearcher = $objSearcherPath.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRACL] Error enumerating Active Directory Rights"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }

            If ($RightsSearcher)
            {
                $RightsSearcher | Where-Object {$_} | ForEach-Object {
                    # convert the GUID
                    $GUIDs[$_.properties.rightsguid[0].toString()] = $_.properties.name[0]
                }
                $RightsSearcher.dispose()
            }
            $objSearcherPath.dispose()
        }

        # Get the Domain, OUs, Root Containers, GPO, User, Computer and Group objects.
        $Objs = @()
        Write-Verbose "[*] Enumerating Domain, OU, GPO, User, Computer and Group Objects"
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $objSearcherPath.SearchRoot = "LDAP://$DnBase"
        $ObjSearcher.Filter = "(|(objectClass=domain)(objectCategory=organizationalunit)(objectCategory=groupPolicyContainer)(samAccountType=805306368)(samAccountType=805306369)(samaccounttype=268435456)(samaccounttype=268435457)(samaccounttype=536870912)(samaccounttype=536870913))"
        # https://msdn.microsoft.com/en-us/library/system.directoryservices.securitymasks(v=vs.110).aspx
        $ObjSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Group -bor [System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Sacl
        $ObjSearcher.PropertiesToLoad.AddRange(("displayname","distinguishedname","name","ntsecuritydescriptor","objectclass","objectsid"))
        $ObjSearcher.SearchScope = "Subtree"

        Try
        {
            $Objs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating Domain, OU, GPO, User, Computer and Group Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $ObjSearcher.dispose()

        Write-Verbose "[*] Enumerating Root Container Objects"
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(objectClass=container)"
        # https://msdn.microsoft.com/en-us/library/system.directoryservices.securitymasks(v=vs.110).aspx
        $ObjSearcher.SecurityMasks = $ObjSearcher.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Dacl -bor [System.DirectoryServices.SecurityMasks]::Group -bor [System.DirectoryServices.SecurityMasks]::Owner -bor [System.DirectoryServices.SecurityMasks]::Sacl
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","name","ntsecuritydescriptor","objectclass"))
        $ObjSearcher.SearchScope = "OneLevel"

        Try
        {
            $Objs += $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRACL] Error while enumerating Root Container Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        $ObjSearcher.dispose()

        If ($Objs)
        {
            Write-Verbose "[*] Total Objects: $([ADRecon.LDAPClass]::ObjectCount($Objs))"
            Write-Verbose "[-] DACLs"
            $DACLObj = [ADRecon.LDAPClass]::DACLParser($Objs, $GUIDs, $Threads)
            Write-Verbose "[-] SACLs - May need a Privileged Account"
            $SACLObj = [ADRecon.LDAPClass]::SACLParser($Objs, $GUIDs, $Threads)
            Remove-Variable Objs
            Remove-Variable GUIDs
        }
    }

    If ($DACLObj)
    {
        Export-ADR $DACLObj $ADROutputDir $OutputType "DACLs"
        Remove-Variable DACLObj
    }

    If ($SACLObj)
    {
        Export-ADR $SACLObj $ADROutputDir $OutputType "SACLs"
        Remove-Variable SACLObj
    }
}

Function Get-ADRGPOReport
{
<#
.SYNOPSIS
    Runs the Get-GPOReport cmdlet if available.

.DESCRIPTION
    Runs the Get-GPOReport cmdlet if available and saves in HTML and XML formats.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER UseAltCreds
    [bool]
    Whether to use provided credentials or not.

.PARAMETER ADROutputDir
    [string]
    Path for ADRecon output folder.

.OUTPUTS
    HTML and XML GPOReports are created in the folder specified.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [bool] $UseAltCreds,

        [Parameter(Mandatory = $true)]
        [string] $ADROutputDir
    )

    If ($Method -eq 'ADWS')
    {
        Try
        {
            # Suppress verbose output on module import
            $SaveVerbosePreference = $script:VerbosePreference
            $script:VerbosePreference = 'SilentlyContinue'

            If ($PSVersionTable.PSEdition -eq "Core")
            {
                Import-Module GroupPolicy -SkipEditionCheck -WarningAction Stop -ErrorAction Stop | Out-Null
            }
            Else
            {
                Import-Module GroupPolicy -WarningAction Stop -ErrorAction Stop | Out-Null
            }
            If ($SaveVerbosePreference)
            {
                $script:VerbosePreference = $SaveVerbosePreference
                Remove-Variable SaveVerbosePreference
            }
        }
        Catch
        {
            Write-Warning "[Get-ADRGPOReport] Error importing the GroupPolicy Module. Skipping GPOReport"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            If ($SaveVerbosePreference)
            {
                $script:VerbosePreference = $SaveVerbosePreference
                Remove-Variable SaveVerbosePreference
            }
            Return $null
        }
        Try
        {
            Write-Verbose "[*] GPOReport XML"
            $ADFileName = -join($ADROutputDir,'\','GPO-Report','.xml')
            Get-GPOReport -All -ReportType XML -Path $ADFileName
        }
        Catch
        {
            If ($UseAltCreds)
            {
                Write-Warning "[*] Run the tool using RUNAS."
                Write-Warning "[*] runas /user:<Domain FQDN>\<Username> /netonly powershell.exe"
                Return $null
            }
            Write-Warning "[Get-ADRGPOReport] Error getting the GPOReport in XML"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
        Try
        {
            Write-Verbose "[*] GPOReport HTML"
            $ADFileName = -join($ADROutputDir,'\','GPO-Report','.html')
            Get-GPOReport -All -ReportType HTML -Path $ADFileName
        }
        Catch
        {
            If ($UseAltCreds)
            {
                Write-Warning "[*] Run the tool using RUNAS."
                Write-Warning "[*] runas /user:<Domain FQDN>\<Username> /netonly powershell.exe"
                Return $null
            }
            Write-Warning "[Get-ADRGPOReport] Error getting the GPOReport in XML"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
        }
    }
    If ($Method -eq 'LDAP')
    {
        Write-Warning "[*] Currently, the module is only supported with ADWS."
    }
}

# Modified Invoke-UserImpersonation function from https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
Function Get-ADRUserImpersonation
{
<#
.SYNOPSIS

Creates a new "runas /netonly" type logon and impersonates the token.

Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: PSReflect

.DESCRIPTION

This function uses LogonUser() with the LOGON32_LOGON_NEW_CREDENTIALS LogonType
to simulate "runas /netonly". The resulting token is then impersonated with
ImpersonateLoggedOnUser() and the token handle is returned for later usage
with Invoke-RevertToSelf.

.PARAMETER Credential

A [Management.Automation.PSCredential] object with alternate credentials
to impersonate in the current thread space.

.PARAMETER TokenHandle

An IntPtr TokenHandle returned by a previous Invoke-UserImpersonation.
If this is supplied, LogonUser() is skipped and only ImpersonateLoggedOnUser()
is executed.

.PARAMETER Quiet

Suppress any warnings about STA vs MTA.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Invoke-UserImpersonation -Credential $Cred

.OUTPUTS

IntPtr

The TokenHandle result from LogonUser.
#>

    [OutputType([IntPtr])]
    [CmdletBinding(DefaultParameterSetName = 'Credential')]
    Param(
        [Parameter(Mandatory = $True, ParameterSetName = 'Credential')]
        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential,

        [Parameter(Mandatory = $True, ParameterSetName = 'TokenHandle')]
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle,

        [Switch]
        $Quiet
    )

    If (([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') -and (-not $PSBoundParameters['Quiet']))
    {
        Write-Warning "[Get-ADRUserImpersonation] powershell.exe process is not currently in a single-threaded apartment state, token impersonation may not work."
    }

    If ($PSBoundParameters['TokenHandle'])
    {
        $LogonTokenHandle = $TokenHandle
    }
    Else
    {
        $LogonTokenHandle = [IntPtr]::Zero
        $NetworkCredential = $Credential.GetNetworkCredential()
        $UserDomain = $NetworkCredential.Domain
        If (-Not $UserDomain)
        {
            Write-Warning "[Get-ADRUserImpersonation] Use credential with Domain FQDN. (<Domain FQDN>\<Username>)"
        }
        $UserName = $NetworkCredential.UserName
        Write-Warning "[Get-ADRUserImpersonation] Executing LogonUser() with user: $($UserDomain)\$($UserName)"

        # LOGON32_LOGON_NEW_CREDENTIALS = 9, LOGON32_PROVIDER_WINNT50 = 3
        #   this is to simulate "runas.exe /netonly" functionality
        $Result = $Advapi32::LogonUser($UserName, $UserDomain, $NetworkCredential.Password, 9, 3, [ref]$LogonTokenHandle)
        $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

        If (-not $Result)
        {
            throw "[Get-ADRUserImpersonation] LogonUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
        }
    }

    # actually impersonate the token from LogonUser()
    $Result = $Advapi32::ImpersonateLoggedOnUser($LogonTokenHandle)

    If (-not $Result)
    {
        throw "[Get-ADRUserImpersonation] ImpersonateLoggedOnUser() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Verbose "[Get-ADR-UserImpersonation] Alternate credentials successfully impersonated"
    $LogonTokenHandle
}

# Modified Invoke-RevertToSelf function from https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
Function Get-ADRRevertToSelf
{
<#
.SYNOPSIS

Reverts any token impersonation.

Author: Will Schroeder (@harmj0y)
License: BSD 3-Clause
Required Dependencies: PSReflect

.DESCRIPTION

This function uses RevertToSelf() to revert any impersonated tokens.
If -TokenHandle is passed (the token handle returned by Invoke-UserImpersonation),
CloseHandle() is used to close the opened handle.

.PARAMETER TokenHandle

An optional IntPtr TokenHandle returned by Invoke-UserImpersonation.

.EXAMPLE

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
$Token = Invoke-UserImpersonation -Credential $Cred
Invoke-RevertToSelf -TokenHandle $Token
#>

    [CmdletBinding()]
    Param(
        [ValidateNotNull()]
        [IntPtr]
        $TokenHandle
    )

    If ($PSBoundParameters['TokenHandle'])
    {
        Write-Warning "[Get-ADRRevertToSelf] Reverting token impersonation and closing LogonUser() token handle"
        $Result = $Kernel32::CloseHandle($TokenHandle)
    }

    $Result = $Advapi32::RevertToSelf()
    $LastError = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error();

    If (-not $Result)
    {
        Write-Error "[Get-ADRRevertToSelf] RevertToSelf() Error: $(([ComponentModel.Win32Exception] $LastError).Message)"
    }

    Write-Verbose "[Get-ADRRevertToSelf] Token impersonation successfully reverted"
}

# Modified Get-DomainSPNTicket function from https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
Function Get-ADRSPNTicket
{
<#
<#
.SYNOPSIS
    Request the kerberos ticket for a specified service principal name (SPN).

    Author: machosec, Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: Invoke-UserImpersonation, Invoke-RevertToSelf

.DESCRIPTION
    This function will either take one SPN strings, and will request a kerberos ticket for the given SPN using System.IdentityModel.Tokens.KerberosRequestorSecurityToken. The encrypted portion of the ticket is then extracted and output in either crackable Hashcat format.

.PARAMETER UserSPN
    [string]
    Service Principal Name.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $UserSPN
    )

    Try
    {
        $Null = [Reflection.Assembly]::LoadWithPartialName('System.IdentityModel')
        $Ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $UserSPN
    }
    Catch
    {
        Write-Warning "[Get-ADRSPNTicket] Error requesting ticket for SPN $UserSPN"
        Write-Warning "[EXCEPTION] $($_.Exception.Message)"
        Return $null
    }

    If ($Ticket)
    {
        $TicketByteStream = $Ticket.GetRequest()
    }

    If ($TicketByteStream)
    {
        $TicketHexStream = [System.BitConverter]::ToString($TicketByteStream) -replace '-'

        # TicketHexStream == GSS-API Frame (see https://tools.ietf.org/html/rfc4121#section-4.1)
        # No easy way to parse ASN1, so we'll try some janky regex to parse the embedded KRB_AP_REQ.Ticket object
        If ($TicketHexStream -match 'a382....3082....A0030201(?<EtypeLen>..)A1.{1,4}.......A282(?<CipherTextLen>....)........(?<DataToEnd>.+)')
        {
            $Etype = [Convert]::ToByte( $Matches.EtypeLen, 16 )
            $CipherTextLen = [Convert]::ToUInt32($Matches.CipherTextLen, 16)-4
            $CipherText = $Matches.DataToEnd.Substring(0,$CipherTextLen*2)

            # Make sure the next field matches the beginning of the KRB_AP_REQ.Authenticator object
            If ($Matches.DataToEnd.Substring($CipherTextLen*2, 4) -ne 'A482')
            {
                Write-Warning '[Get-ADRSPNTicket] Error parsing ciphertext for the SPN  $($Ticket.ServicePrincipalName).' # Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq
                $Hash = $null
            }
            Else
            {
                $Hash = "$($CipherText.Substring(0,32))`$$($CipherText.Substring(32))"
            }
        }
        Else
        {
            Write-Warning "[Get-ADRSPNTicket] Unable to parse ticket structure for the SPN  $($Ticket.ServicePrincipalName)." # Use the TicketByteHexStream field and extract the hash offline with Get-KerberoastHashFromAPReq
            $Hash = $null
        }
    }
    $Obj = New-Object PSObject
    $Obj | Add-Member -MemberType NoteProperty -Name "ServicePrincipalName" -Value $Ticket.ServicePrincipalName
    $Obj | Add-Member -MemberType NoteProperty -Name "Etype" -Value $Etype
    $Obj | Add-Member -MemberType NoteProperty -Name "Hash" -Value $Hash
    Return $Obj
}

Function Get-ADRKerberoast
{
<#
.SYNOPSIS
    Returns all user service principal name (SPN) hashes in the current (or specified) domain.

.DESCRIPTION
    Returns all user service principal name (SPN) hashes in the current (or specified) domain.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [int] $PageSize
    )

    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
    {
        $LogonToken = Get-ADRUserImpersonation -Credential $Credential
    }

    If ($Method -eq 'ADWS')
    {
        Try
        {
            $ADUsers = Get-ADObject -LDAPFilter "(&(!objectClass=computer)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))" -Properties sAMAccountName,servicePrincipalName,DistinguishedName -ResultPageSize $PageSize
        }
        Catch
        {
            Write-Warning "[Get-ADRKerberoast] Error while enumerating UserSPN Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }

        If ($ADUsers)
        {
            $UserSPNObj = @()
            $ADUsers | ForEach-Object {
                ForEach ($UserSPN in $_.servicePrincipalName)
                {
                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Username" -Value $_.sAMAccountName
                    $Obj | Add-Member -MemberType NoteProperty -Name "ServicePrincipalName" -Value $UserSPN

                    $HashObj = Get-ADRSPNTicket $UserSPN
                    If ($HashObj)
                    {
                        $UserDomain = $_.DistinguishedName.SubString($_.DistinguishedName.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        # JohnTheRipper output format
                        $JTRHash = "`$krb5tgs`$$($HashObj.ServicePrincipalName):$($HashObj.Hash)"
                        # hashcat output format
                        $HashcatHash = "`$krb5tgs`$$($HashObj.Etype)`$*$($_.SamAccountName)`$$UserDomain`$$($HashObj.ServicePrincipalName)*`$$($HashObj.Hash)"
                    }
                    Else
                    {
                        $JTRHash = $null
                        $HashcatHash = $null
                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "John" -Value $JTRHash
                    $Obj | Add-Member -MemberType NoteProperty -Name "Hashcat" -Value $HashcatHash
                    $UserSPNObj += $Obj
                }
            }
            Remove-Variable ADUsers
        }
    }

    If ($Method -eq 'LDAP')
    {
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
        $ObjSearcher.PageSize = $PageSize
        $ObjSearcher.Filter = "(&(!objectClass=computer)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))"
        $ObjSearcher.PropertiesToLoad.AddRange(("distinguishedname","samaccountname","serviceprincipalname","useraccountcontrol"))
        $ObjSearcher.SearchScope = "Subtree"
        Try
        {
            $ADUsers = $ObjSearcher.FindAll()
        }
        Catch
        {
            Write-Warning "[Get-ADRKerberoast] Error while enumerating UserSPN Objects"
            Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            Return $null
        }
        $ObjSearcher.dispose()

        If ($ADUsers)
        {
            $UserSPNObj = @()
            $ADUsers | ForEach-Object {
                ForEach ($UserSPN in $_.Properties.serviceprincipalname)
                {
                    $Obj = New-Object PSObject
                    $Obj | Add-Member -MemberType NoteProperty -Name "Username" -Value $_.Properties.samaccountname[0]
                    $Obj | Add-Member -MemberType NoteProperty -Name "ServicePrincipalName" -Value $UserSPN

                    $HashObj = Get-ADRSPNTicket $UserSPN
                    If ($HashObj)
                    {
                        $UserDomain = $_.Properties.distinguishedname[0].SubString($_.Properties.distinguishedname[0].IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        # JohnTheRipper output format
                        $JTRHash = "`$krb5tgs`$$($HashObj.ServicePrincipalName):$($HashObj.Hash)"
                        # hashcat output format
                        $HashcatHash = "`$krb5tgs`$$($HashObj.Etype)`$*$($_.Properties.samaccountname)`$$UserDomain`$$($HashObj.ServicePrincipalName)*`$$($HashObj.Hash)"
                    }
                    Else
                    {
                        $JTRHash = $null
                        $HashcatHash = $null
                    }
                    $Obj | Add-Member -MemberType NoteProperty -Name "John" -Value $JTRHash
                    $Obj | Add-Member -MemberType NoteProperty -Name "Hashcat" -Value $HashcatHash
                    $UserSPNObj += $Obj
                }
            }
            Remove-Variable ADUsers
        }
    }

    If ($LogonToken)
    {
        Get-ADRRevertToSelf -TokenHandle $LogonToken
    }

    If ($UserSPNObj)
    {
        Return $UserSPNObj
    }
    Else
    {
        Return $null
    }
}

# based on https://gallery.technet.microsoft.com/scriptcenter/PowerShell-script-to-find-6fc15ecb
Function Get-ADRDomainAccountsusedforServiceLogon
{
<#
.SYNOPSIS
    Returns all accounts used by services on computers in an Active Directory domain.

.DESCRIPTION
    Retrieves a list of all computers in the current domain and reads service configuration using Get-WmiObject.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER objDomain
    [DirectoryServices.DirectoryEntry]
    Domain Directory Entry object.

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $false)]
        [DirectoryServices.DirectoryEntry] $objDomain,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10
    )

    BEGIN {
        $readServiceAccounts = [scriptblock] {
            # scriptblock to retrieve service list form a remove machine
            $hostname = [string] $args[0]
            $OperatingSystem = [string] $args[1]
            #$Credential = [Management.Automation.PSCredential] $args[2]
            $Credential = $args[2]
            $timeout = 250
            $port = 135
            Try
            {
                $tcpclient = New-Object System.Net.Sockets.TcpClient
                $result = $tcpclient.BeginConnect($hostname,$port,$null,$null)
                $success = $result.AsyncWaitHandle.WaitOne($timeout,$null)
            }
            Catch
            {
                $warning = "$hostname ($OperatingSystem) is unreachable $($_.Exception.Message)"
                $success = $false
                $tcpclient.Close()
            }
            If ($success)
            {
                # PowerShellv2 does not support New-CimSession
                If ($PSVersionTable.PSVersion.Major -ne 2)
                {
                    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                    {
                        $session = New-CimSession -ComputerName $hostname -SessionOption $(New-CimSessionOption -Protocol DCOM) -Credential $Credential
                        If ($session)
                        {
                            $serviceList = @( Get-CimInstance -ClassName Win32_Service -Property Name,StartName,SystemName -CimSession $session -ErrorAction Stop)
                        }
                    }
                    Else
                    {
                        $session = New-CimSession -ComputerName $hostname -SessionOption $(New-CimSessionOption -Protocol DCOM)
                        If ($session)
                        {
                            $serviceList = @( Get-CimInstance -ClassName Win32_Service -Property Name,StartName,SystemName -CimSession $session -ErrorAction Stop )
                        }
                    }
                }
                Else
                {
                    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
                    {
                        $serviceList = @( Get-WmiObject -Class Win32_Service -ComputerName $hostname -Credential $Credential -Impersonation 3 -Property Name,StartName,SystemName -ErrorAction Stop )
                    }
                    Else
                    {
                        $serviceList = @( Get-WmiObject -Class Win32_Service -ComputerName $hostname -Property Name,StartName,SystemName -ErrorAction Stop )
                    }
                }
                $serviceList
            }
            Try
            {
                If ($tcpclient) { $tcpclient.EndConnect($result) | Out-Null }
            }
            Catch
            {
                $warning = "$hostname ($OperatingSystem) : $($_.Exception.Message)"
            }
            $warning
        }

        Function processCompletedJobs()
        {
            # reads service list from completed jobs,
            # updates $serviceAccount table and removes completed job

            $jobs = Get-Job -State Completed
            ForEach( $job in $jobs )
            {
                If ($null -ne $job)
                {
                    $data = Receive-Job $job
                    Remove-Job $job
                }

                If ($data)
                {
                    If ( $data.GetType() -eq [Object[]] )
                    {
                        $serviceList = $data | Where-Object { if ($_.StartName) { $_ }}
                        $serviceList | ForEach-Object {
                            $Obj = New-Object PSObject
                            $Obj | Add-Member -MemberType NoteProperty -Name "Account" -Value $_.StartName
                            $Obj | Add-Member -MemberType NoteProperty -Name "Service Name" -Value $_.Name
                            $Obj | Add-Member -MemberType NoteProperty -Name "SystemName" -Value $_.SystemName
                            If ($_.StartName.toUpper().Contains($currentDomain))
                            {
                                $Obj | Add-Member -MemberType NoteProperty -Name "Running as Domain User" -Value $true
                            }
                            Else
                            {
                                $Obj | Add-Member -MemberType NoteProperty -Name "Running as Domain User" -Value $false
                            }
                            $script:serviceAccounts += $Obj
                        }
                    }
                    ElseIf ( $data.GetType() -eq [String] )
                    {
                        $script:warnings += $data
                        Write-Verbose $data
                    }
                }
            }
        }
    }

    PROCESS
    {
        $script:serviceAccounts = @()
        [string[]] $warnings = @()
        If ($Method -eq 'ADWS')
        {
            Try
            {
                $ADDomain = Get-ADDomain
            }
            Catch
            {
                Write-Warning "[Get-ADRDomainAccountsusedforServiceLogon] Error getting Domain Context"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            If ($ADDomain)
            {
                $currentDomain = $ADDomain.NetBIOSName.toUpper()
                Remove-Variable ADDomain
            }
            Else
            {
                $currentDomain = ""
                Write-Warning "Current Domain could not be retrieved."
            }

            Try
            {
                $ADComputers = Get-ADComputer -Filter { Enabled -eq $true -and OperatingSystem -Like "*Windows*" } -Properties Name,DNSHostName,OperatingSystem
            }
            Catch
            {
                Write-Warning "[Get-ADRDomainAccountsusedforServiceLogon] Error while enumerating Windows Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }

            If ($ADComputers)
            {
                # start data retrieval job for each server in the list
                # use up to $Threads threads
                $cnt = $([ADRecon.ADWSClass]::ObjectCount($ADComputers))
                Write-Verbose "[*] Total Windows Hosts: $cnt"
                $icnt = 0
                $ADComputers | ForEach-Object {
                    $StopWatch = [System.Diagnostics.StopWatch]::StartNew()
                    If( $_.dnshostname )
	                {
                        $args = @($_.DNSHostName, $_.OperatingSystem, $Credential)
		                Start-Job -ScriptBlock $readServiceAccounts -Name "read_$($_.name)" -ArgumentList $args | Out-Null
		                ++$icnt
		                If ($StopWatch.Elapsed.TotalMilliseconds -ge 1000)
                        {
                            Write-Progress -Activity "Retrieving data from servers" -Status "$("{0:N2}" -f (($icnt/$cnt*100),2)) % Complete:" -PercentComplete 100
                            $StopWatch.Reset()
                            $StopWatch.Start()
		                }
                        while ( ( Get-Job -State Running).count -ge $Threads ) { Start-Sleep -Seconds 3 }
		                processCompletedJobs
	                }
                }

                # process remaining jobs

                Write-Progress -Activity "Retrieving data from servers" -Status "Waiting for background jobs to complete..." -PercentComplete 100
                Wait-Job -State Running -Timeout 30  | Out-Null
                Get-Job -State Running | Stop-Job
                processCompletedJobs
                Write-Progress -Activity "Retrieving data from servers" -Completed -Status "All Done"
            }
        }

        If ($Method -eq 'LDAP')
        {
            $currentDomain = ([string]($objDomain.name)).toUpper()

            $objSearcher = New-Object System.DirectoryServices.DirectorySearcher $objDomain
            $ObjSearcher.PageSize = $PageSize
            $ObjSearcher.Filter = "(&(samAccountType=805306369)(!userAccountControl:1.2.840.113556.1.4.803:=2)(operatingSystem=*Windows*))"
            $ObjSearcher.PropertiesToLoad.AddRange(("name","dnshostname","operatingsystem"))
            $ObjSearcher.SearchScope = "Subtree"

            Try
            {
                $ADComputers = $ObjSearcher.FindAll()
            }
            Catch
            {
                Write-Warning "[Get-ADRDomainAccountsusedforServiceLogon] Error while enumerating Windows Computer Objects"
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
                Return $null
            }
            $ObjSearcher.dispose()

            If ($ADComputers)
            {
                # start data retrieval job for each server in the list
                # use up to $Threads threads
                $cnt = $([ADRecon.LDAPClass]::ObjectCount($ADComputers))
                Write-Verbose "[*] Total Windows Hosts: $cnt"
                $icnt = 0
                $ADComputers | ForEach-Object {
                    If( $_.Properties.dnshostname )
	                {
                        $args = @($_.Properties.dnshostname, $_.Properties.operatingsystem, $Credential)
		                Start-Job -ScriptBlock $readServiceAccounts -Name "read_$($_.Properties.name)" -ArgumentList $args | Out-Null
		                ++$icnt
		                If ($StopWatch.Elapsed.TotalMilliseconds -ge 1000)
                        {
		                    Write-Progress -Activity "Retrieving data from servers" -Status "$("{0:N2}" -f (($icnt/$cnt*100),2)) % Complete:" -PercentComplete 100
                            $StopWatch.Reset()
                            $StopWatch.Start()
		                }
		                while ( ( Get-Job -State Running).count -ge $Threads ) { Start-Sleep -Seconds 3 }
		                processCompletedJobs
	                }
                }

                # process remaining jobs
                Write-Progress -Activity "Retrieving data from servers" -Status "Waiting for background jobs to complete..." -PercentComplete 100
                Wait-Job -State Running -Timeout 30  | Out-Null
                Get-Job -State Running | Stop-Job
                processCompletedJobs
                Write-Progress -Activity "Retrieving data from servers" -Completed -Status "All Done"
            }
        }

        If ($script:serviceAccounts)
        {
            Return $script:serviceAccounts
        }
        Else
        {
            Return $null
        }
    }
}

Function Remove-EmptyADROutputDir
{
<#
.SYNOPSIS
    Removes ADRecon output folder if empty.

.DESCRIPTION
    Removes ADRecon output folder if empty.

.PARAMETER ADROutputDir
    [string]
	Path for ADRecon output folder.

.PARAMETER OutputType
    [array]
    Output Type.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $ADROutputDir,

        [Parameter(Mandatory = $true)]
        [array] $OutputType
    )

    Switch ($OutputType)
    {
        'CSV'
        {
            $CSVPath  = -join($ADROutputDir,'\','CSV-Files')
            If (!(Test-Path -Path $CSVPath\*))
            {
                Write-Verbose "Removed Empty Directory $CSVPath"
                Remove-Item $CSVPath
            }
        }
        'XML'
        {
            $XMLPath  = -join($ADROutputDir,'\','XML-Files')
            If (!(Test-Path -Path $XMLPath\*))
            {
                Write-Verbose "Removed Empty Directory $XMLPath"
                Remove-Item $XMLPath
            }
        }
        'JSON'
        {
            $JSONPath  = -join($ADROutputDir,'\','JSON-Files')
            If (!(Test-Path -Path $JSONPath\*))
            {
                Write-Verbose "Removed Empty Directory $JSONPath"
                Remove-Item $JSONPath
            }
        }
        'HTML'
        {
            $HTMLPath  = -join($ADROutputDir,'\','HTML-Files')
            If (!(Test-Path -Path $HTMLPath\*))
            {
                Write-Verbose "Removed Empty Directory $HTMLPath"
                Remove-Item $HTMLPath
            }
        }
    }
    If (!(Test-Path -Path $ADROutputDir\*))
    {
        Remove-Item $ADROutputDir
        Write-Verbose "Removed Empty Directory $ADROutputDir"
    }
}

Function Get-ADRAbout
{
<#
.SYNOPSIS
    Returns information about ADRecon.

.DESCRIPTION
    Returns information about ADRecon.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER date
    [DateTime]
    Date

.PARAMETER ADReconVersion
    [string]
    ADRecon Version.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER RanonComputer
    [string]
    Details of the Computer running ADRecon.

.PARAMETER TotalTime
    [string]
    TotalTime.

.OUTPUTS
    PSObject.
#>
    param(
        [Parameter(Mandatory = $true)]
        [string] $Method,

        [Parameter(Mandatory = $true)]
        [DateTime] $date,

        [Parameter(Mandatory = $true)]
        [string] $ADReconVersion,

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $true)]
        [string] $RanonComputer,

        [Parameter(Mandatory = $true)]
        [string] $TotalTime
    )

    $AboutADRecon = @()

    $Version = $Method + " Version"

    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
    {
        $Username = $($Credential.UserName)
    }
    Else
    {
        $Username = $([Environment]::UserName)
    }

    $ObjValues = @("Date", $($date), "ADRecon", "https://github.com/adrecon/ADRecon", $Version, $($ADReconVersion), "Ran as user", $Username, "Ran on computer", $RanonComputer, "Execution Time (mins)", $($TotalTime))

    For ($i = 0; $i -lt $($ObjValues.Count); $i++)
    {
        $Obj = New-Object PSObject
        $Obj | Add-Member -MemberType NoteProperty -Name "Category" -Value $ObjValues[$i]
        $Obj | Add-Member -MemberType NoteProperty -Name "Value" -Value $ObjValues[$i+1]
        $i++
        $AboutADRecon += $Obj
    }
    Return $AboutADRecon
}

Function Invoke-ADRecon
{
<#
.SYNOPSIS
    Wrapper function to run ADRecon modules.

.DESCRIPTION
    Wrapper function to set variables, check dependencies and run ADRecon modules.

.PARAMETER Method
    [string]
    Which method to use; ADWS (default), LDAP.

.PARAMETER Collect
    [array]
    Which modules to run; Tenant, Forest, Domain, Trusts, Sites, Subnets, PasswordPolicy, FineGrainedPasswordPolicy, DomainControllers, Users, UserSPNs, PasswordAttributes, Groups, GroupMembers, GroupChanges, OUs, GPOs, gPLinks, DNSZones, Printers, Computers, ComputerSPNs, LAPS, BitLocker, ACLs, GPOReport, Kerberoast, DomainAccountsusedforServiceLogon.

.PARAMETER DomainController
    [string]
    IP Address of the Domain Controller.

.PARAMETER Credential
    [Management.Automation.PSCredential]
    Credentials.

.PARAMETER OutputDir
    [string]
	Path for ADRecon output folder to save the CSV files and the ADRecon-Report.xlsx.

.PARAMETER DormantTimeSpan
    [int]
    Timespan for Dormant accounts. Default 90 days.

.PARAMETER PassMaxAge
    [int]
    Maximum machine account password age. Default 30 days

.PARAMETER PageSize
    [int]
    The PageSize to set for the LDAP searcher object. Default 200.

.PARAMETER Threads
    [int]
    The number of threads to use during processing of objects. Default 10.

.PARAMETER OnlyEnabled
    [bool]
    Only collect details for enabled objects.

.PARAMETER UseAltCreds
    [bool]
    Whether to use provided credentials or not.

.PARAMETER Logo
    [string]
    Which Logo to use in the excel file? ADRecon (default), CyberCX, Payatu.

.OUTPUTS
    STDOUT, CSV, XML, JSON, HTML and/or Excel file is created in the folder specified with the information.
#>
    param(
        [Parameter(Mandatory = $false)]
        [string] $GenExcel,

        [Parameter(Mandatory = $false)]
        [ValidateSet('ADWS', 'LDAP')]
        [string] $Method = 'ADWS',

        [Parameter(Mandatory = $false)]
        [array] $Collect = 'Default',

        [Parameter(Mandatory = $false)]
        [string] $DomainController = '',

        [Parameter(Mandatory = $false)]
        [Management.Automation.PSCredential] $Credential = [Management.Automation.PSCredential]::Empty,

        [Parameter(Mandatory = $false)]
        [array] $OutputType = 'Default',

        [Parameter(Mandatory = $false)]
        [string] $ADROutputDir,

        [Parameter(Mandatory = $false)]
        [int] $DormantTimeSpan = 90,

        [Parameter(Mandatory = $false)]
        [int] $PassMaxAge = 30,

        [Parameter(Mandatory = $false)]
        [int] $PageSize = 200,

        [Parameter(Mandatory = $false)]
        [int] $Threads = 10,

        [Parameter(Mandatory = $false)]
        [bool] $OnlyEnabled = $false,

        [Parameter(Mandatory = $false)]
        [bool] $UseAltCreds = $false,

        [Parameter(Mandatory = $false)]
        [ValidateSet('ADRecon', 'CyberCX', 'Payatu')]
        [string] $Logo = "ADRecon"
    )

    If ($PSVersionTable.PSEdition -eq "Core")
    {
        If ($PSVersionTable.Platform -ne "Win32NT")
        {
            Write-Warning "[Invoke-ADRecon] Currently not supported ... Exiting"
            Return $null
        }
    }

    [string] $ADReconVersion = "v1.27"
    Write-Output "[*] ADRecon $ADReconVersion by Prashant Mahajan (@prashant3535)"

    If ($GenExcel)
    {
        If (-Not (Test-Path $GenExcel))
        {
            Write-Output "[Invoke-ADRecon] Invalid Path ... Exiting"
            Return $null
        }
        Export-ADRExcel -ExcelPath $GenExcel -Logo $Logo
        Return $null
    }

    # Suppress verbose output
    $SaveVerbosePreference = $script:VerbosePreference
    $script:VerbosePreference = 'SilentlyContinue'
    Try
    {
        If ($PSVersionTable.PSVersion.Major -ne 2)
        {
            $computer = Get-CimInstance -ClassName Win32_ComputerSystem
            $computerdomainrole = ($computer).DomainRole
        }
        Else
        {
            $computer = Get-WMIObject win32_computersystem
            $computerdomainrole = ($computer).DomainRole
        }
    }
    Catch
    {
        Write-Output "[Invoke-ADRecon] $($_.Exception.Message)"
    }
    If ($SaveVerbosePreference)
    {
        $script:VerbosePreference = $SaveVerbosePreference
        Remove-Variable SaveVerbosePreference
    }

    switch ($computerdomainrole)
    {
        0
        {
            [string] $computerrole = "Standalone Workstation"
            $Env:ADPS_LoadDefaultDrive = 0
            $UseAltCreds = $true
        }
        1 { [string] $computerrole = "Member Workstation" }
        2
        {
            [string] $computerrole = "Standalone Server"
            $UseAltCreds = $true
            $Env:ADPS_LoadDefaultDrive = 0
        }
        3 { [string] $computerrole = "Member Server" }
        4 { [string] $computerrole = "Backup Domain Controller" }
        5 { [string] $computerrole = "Primary Domain Controller" }
        default { Write-Output "Computer Role could not be identified." }
    }

    $RanonComputer = "$($computer.domain)\$([Environment]::MachineName) - $($computerrole)"
    Remove-Variable computer
    Remove-Variable computerdomainrole
    Remove-Variable computerrole

    # If either DomainController or Credentials are provided, treat as non-member
    If (($DomainController -ne "") -or ($Credential -ne [Management.Automation.PSCredential]::Empty))
    {
        # Disable loading of default drive on member
        If (($Method -eq 'ADWS') -and (-Not $UseAltCreds))
        {
            $Env:ADPS_LoadDefaultDrive = 0
        }
        $UseAltCreds = $true
    }

    # Import ActiveDirectory module
    If ($Method -eq 'ADWS')
    {
        If (Get-Module -ListAvailable -Name ActiveDirectory)
        {
            Try
            {
                # Suppress verbose output on module import
                $SaveVerbosePreference = $script:VerbosePreference;
                $script:VerbosePreference = 'SilentlyContinue';
                Import-Module ActiveDirectory -WarningAction Stop -ErrorAction Stop | Out-Null
                If ($SaveVerbosePreference)
                {
                    $script:VerbosePreference = $SaveVerbosePreference
                    Remove-Variable SaveVerbosePreference
                }
            }
            Catch
            {
                Write-Warning "[Invoke-ADRecon] Error importing ActiveDirectory Module from RSAT (Remote Server Administration Tools) ... Continuing with LDAP"
                $Method = 'LDAP'
                If ($SaveVerbosePreference)
                {
                    $script:VerbosePreference = $SaveVerbosePreference
                    Remove-Variable SaveVerbosePreference
                }
                Write-Verbose "[EXCEPTION] $($_.Exception.Message)"
            }
        }
        Else
        {
            Write-Warning "[Invoke-ADRecon] ActiveDirectory Module from RSAT (Remote Server Administration Tools) is not installed ... Continuing with LDAP"
            $Method = 'LDAP'
        }
    }

    # Compile C# code
    # Suppress Debug output
    $SaveDebugPreference = $script:DebugPreference
    $script:DebugPreference = 'SilentlyContinue'
    Try
    {
        $Advapi32 = Add-Type -MemberDefinition $Advapi32Def -Name "Advapi32" -Namespace ADRecon -PassThru
        $Kernel32 = Add-Type -MemberDefinition $Kernel32Def -Name "Kernel32" -Namespace ADRecon -PassThru
        $CLR = ([System.Reflection.Assembly]::GetExecutingAssembly().ImageRuntimeVersion)[1]
        If ($Method -eq 'ADWS')
        {
            If ($PSVersionTable.PSEdition -eq "Core")
            {
                # Beginning in PowerShell 6, ReferencedAssemblies doesn't include the default .NET assemblies. You must include a specific reference to them in the value passed to this parameter.
                # https://docs.microsoft.com/en-gb/powershell/module/Microsoft.PowerShell.Utility/Add-Type?view=powershell-7

                <#
                TODO: Instead of all assemblies, identify which ones are required.
                $refFolder = Split-Path ([PSObject].Assembly.Location)
                $refAssemblies = Get-ChildItem -Path $refFolder -Filter "*.dll" | Select-Object -Expand FullName

                Add-Type -TypeDefinition $($ADWSSource + $PingCastleSMBScannerSource) -ReferencedAssemblies $($refAssemblies + ([System.Reflection.Assembly]::LoadWithPartialName("Microsoft.ActiveDirectory.Management")).Location + ([System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")).Location + ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location)

                Remove-Variable refFolder
                Remove-Variable refAssemblies
                #>

                $refFolder = Join-Path -Path (Split-Path([PSObject].Assembly.Location)) -ChildPath "ref"
                Add-Type -TypeDefinition $($ADWSSource + $PingCastleSMBScannerSource) -ReferencedAssemblies ([System.String[]]@(
                    (Join-Path -Path $refFolder -ChildPath "System.Collections.dll")
                    (Join-Path -Path $refFolder -ChildPath "System.Collections.NonGeneric.dll")
                    (Join-Path -Path $refFolder -ChildPath "System.Threading.dll")
                    (Join-Path -Path $refFolder -ChildPath "System.Threading.Thread.dll")
                    (Join-Path -Path $refFolder -ChildPath "System.Diagnostics.TraceSource.dll")
                    ([System.Reflection.Assembly]::LoadWithPartialName("mscorlib")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Linq")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Private.Xml")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Security.AccessControl")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Net.Sockets")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Net.Primitives")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal.Windows")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.IO.FileSystem.AccessControl")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Console")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("Microsoft.ActiveDirectory.Management")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location
                ))
                Remove-Variable refFolder
            }
            If ($CLR -eq "4")
            {
                Add-Type -TypeDefinition $($ADWSSource+$PingCastleSMBScannerSource) -ReferencedAssemblies ([System.String[]]@(
                    ([System.Reflection.Assembly]::LoadWithPartialName("Microsoft.ActiveDirectory.Management")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.XML")).Location
                ))
            }
            Else
            {
                Add-Type -TypeDefinition $($ADWSSource+$PingCastleSMBScannerSource) -ReferencedAssemblies ([System.String[]]@(
                    ([System.Reflection.Assembly]::LoadWithPartialName("Microsoft.ActiveDirectory.Management")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.XML")).Location
                )) -Language CSharpVersion3
            }
        }

        If ($Method -eq 'LDAP')
        {
            If ($PSVersionTable.PSEdition -eq "Core")
            {
                # Beginning in PowerShell 6, ReferencedAssemblies doesn't include the default .NET assemblies. You must include a specific reference to them in the value passed to this parameter.
                # https://docs.microsoft.com/en-gb/powershell/module/Microsoft.PowerShell.Utility/Add-Type?view=powershell-7

                <#
                # TODO: Instead of all assemblies, identify which ones are required.

                $refFolder = Join-Path ( Split-Path ([PSObject].Assembly.Location) ) "ref"
                $refAssemblies = Get-ChildItem -Path $refFolder -Filter "*.dll" | Select-Object -Expand FullName
                Add-Type -TypeDefinition $($LDAPSource + $PingCastleSMBScannerSource) -ReferencedAssemblies $( $refAssemblies + ([System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")).Location + ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location )

                Remove-Variable refFolder
                Remove-Variable refAssemblies
                #>

                $refFolder = Join-Path -Path (Split-Path([PSObject].Assembly.Location)) -ChildPath "ref"
                Add-Type -TypeDefinition $($LDAPSource + $PingCastleSMBScannerSource) -ReferencedAssemblies ([System.String[]]@(
                    (Join-Path -Path $refFolder -ChildPath "System.Collections.dll")
                    (Join-Path -Path $refFolder -ChildPath "System.Collections.NonGeneric.dll")
                    (Join-Path -Path $refFolder -ChildPath "System.Threading.dll")
                    (Join-Path -Path $refFolder -ChildPath "System.Threading.Thread.dll")
                    (Join-Path -Path $refFolder -ChildPath "System.Diagnostics.TraceSource.dll")
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Linq")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Private.Xml")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Security.AccessControl")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Net.Sockets")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Net.Primitives")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Security.Principal.Windows")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.IO.FileSystem.AccessControl")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Net.NameResolution")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Console")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location
                ))
                Remove-Variable refFolder
            }
            If ($CLR -eq "4")
            {
                Add-Type -TypeDefinition $($LDAPSource+$PingCastleSMBScannerSource) -ReferencedAssemblies ([System.String[]]@(
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.XML")).Location
                ))
            }
            Else
            {
                Add-Type -TypeDefinition $($LDAPSource+$PingCastleSMBScannerSource) -ReferencedAssemblies ([System.String[]]@(
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices")).Location
                    ([System.Reflection.Assembly]::LoadWithPartialName("System.XML")).Location
                )) -Language CSharpVersion3
            }
        }
    }
    Catch
    {
        Write-Output "[Invoke-ADRecon] $($_.Exception.Message)"
        Return $null
    }
    If ($SaveDebugPreference)
    {
        $script:DebugPreference = $SaveDebugPreference
        Remove-Variable SaveDebugPreference
    }

    # Allow running using RUNAS from a non-domain joined machine
    # runas /user:<Domain FQDN>\<Username> /netonly powershell.exe
    If (($Method -eq 'LDAP') -and ($UseAltCreds) -and ($DomainController -eq "") -and ($Credential -eq [Management.Automation.PSCredential]::Empty))
    {
        Try
        {
            $objDomain = [ADSI]""
            If(!($objDomain.name))
            {
                Write-Verbose "[Invoke-ADRecon] RUNAS Check, LDAP bind Unsuccessful"
            }
            $UseAltCreds = $false
            $objDomain.Dispose()
        }
        Catch
        {
            $UseAltCreds = $true
        }
    }

    If ($UseAltCreds -and (($DomainController -eq "") -or ($Credential -eq [Management.Automation.PSCredential]::Empty)))
    {

        If (($DomainController -ne "") -and ($Credential -eq [Management.Automation.PSCredential]::Empty))
        {
            Try
            {
                $Credential = Get-Credential
            }
            Catch
            {
                Write-Output "[Invoke-ADRecon] $($_.Exception.Message)"
                Return $null
            }
        }
        Else
        {
            Write-Output "Run Get-Help .\ADRecon.ps1 -Examples for additional information."
            Write-Output "[Invoke-ADRecon] Use the -DomainController and -Credential parameter."`n
            Return $null
        }
    }

    If ($Credential -ne [Management.Automation.PSCredential]::Empty)
    {
        $Username = $($Credential.UserName)
    }
    Else
    {
        $Username = $([Environment]::UserName)
    }

    Write-Output "[*] Running on $RanonComputer as $Username"

    Remove-Variable Username

    Switch ($Collect)
    {
        'Forest' { $ADRForest = $true }
        'Domain' {$ADRDomain = $true }
        'Trusts' { $ADRTrust = $true }
        'Sites' { $ADRSite = $true }
        'Subnets' { $ADRSubnet = $true }
        'SchemaHistory' { $ADRSchemaHistory = $true }
        'PasswordPolicy' { $ADRPasswordPolicy = $true }
        'FineGrainedPasswordPolicy' { $ADRFineGrainedPasswordPolicy = $true }
        'DomainControllers' { $ADRDomainControllers = $true }
        'Users' { $ADRUsers = $true }
        'UserSPNs' { $ADRUserSPNs = $true }
        'PasswordAttributes' { $ADRPasswordAttributes = $true }
        'Groups' {$ADRGroups = $true }
        'GroupChanges' { $ADRGroupChanges = $true }
        'GroupMembers' { $ADRGroupMembers = $true }
        'OUs' { $ADROUs = $true }
        'GPOs' { $ADRGPOs = $true }
        'gPLinks' { $ADRgPLinks = $true }
        'DNSZones' { $ADRDNSZones = $true }
        'DNSRecords' { $ADRDNSRecords = $true }
        'Printers' { $ADRPrinters = $true }
        'Computers' { $ADRComputers = $true }
        'ComputerSPNs' { $ADRComputerSPNs = $true }
        'LAPS' { $ADRLAPS = $true }
        'BitLocker' { $ADRBitLocker = $true }
        'ACLs' { $ADRACLs = $true }
        'GPOReport'
        {
            $ADRGPOReport = $true
            $ADRCreate = $true
        }
        'Kerberoast' { $ADRKerberoast = $true }
        'DomainAccountsusedforServiceLogon' { $ADRDomainAccountsusedforServiceLogon = $true }
        'Default'
        {
            $ADRForest = $true
            $ADRDomain = $true
            $ADRTrust = $true
            $ADRSite = $true
            $ADRSubnet = $true
            $ADRSchemaHistory = $true
            $ADRPasswordPolicy = $true
            $ADRFineGrainedPasswordPolicy = $true
            $ADRDomainControllers = $true
            $ADRUsers = $true
            $ADRUserSPNs = $true
            $ADRPasswordAttributes = $true
            $ADRGroups = $true
            $ADRGroupMembers = $true
            $ADRGroupChanges = $true
            $ADROUs = $true
            $ADRGPOs = $true
            $ADRgPLinks = $true
            $ADRDNSZones = $true
            $ADRDNSRecords = $true
            $ADRPrinters = $true
            $ADRComputers = $true
            $ADRComputerSPNs = $true
            $ADRLAPS = $true
            $ADRBitLocker = $true
            #$ADRACLs = $true
            $ADRGPOReport = $true
            #$ADRKerberoast = $true
            #$ADRDomainAccountsusedforServiceLogon = $true

            If ($OutputType -eq "Default")
            {
                [array] $OutputType = "CSV","Excel"
            }
        }
    }

    Switch ($OutputType)
    {
        'STDOUT' { $ADRSTDOUT = $true }
        'CSV'
        {
            $ADRCSV = $true
            $ADRCreate = $true
        }
        'XML'
        {
            $ADRXML = $true
            $ADRCreate = $true
        }
        'JSON'
        {
            $ADRJSON = $true
            $ADRCreate = $true
        }
        'HTML'
        {
            $ADRHTML = $true
            $ADRCreate = $true
        }
        'Excel'
        {
            $ADRExcel = $true
            $ADRCreate = $true
        }
        'All'
        {
            #$ADRSTDOUT = $true
            $ADRCSV = $true
            $ADRXML = $true
            $ADRJSON = $true
            $ADRHTML = $true
            $ADRExcel = $true
            $ADRCreate = $true
            [array] $OutputType = "CSV","XML","JSON","HTML","Excel"
        }
        'Default'
        {
            [array] $OutputType = "STDOUT"
            $ADRSTDOUT = $true
        }
    }

    If ( ($ADRExcel) -and (-Not $ADRCSV) )
    {
        $ADRCSV = $true
        [array] $OutputType += "CSV"
    }

    $returndir = Get-Location
    $date = Get-Date

    # Create Output dir
    If ( ($ADROutputDir) -and ($ADRCreate) )
    {
        If (!(Test-Path $ADROutputDir))
        {
            New-Item $ADROutputDir -type directory | Out-Null
            If (!(Test-Path $ADROutputDir))
            {
                Write-Output "[Invoke-ADRecon] Error, invalid OutputDir Path ... Exiting"
                Return $null
            }
        }
        $ADROutputDir = $((Convert-Path $ADROutputDir).TrimEnd("\"))
        Write-Verbose "[*] Output Directory: $ADROutputDir"
    }
    ElseIf ($ADRCreate)
    {
        $ADROutputDir =  -join($returndir,'\','ADRecon-Report-',$(Get-Date -UFormat %Y%m%d%H%M%S))
        New-Item $ADROutputDir -type directory | Out-Null
        If (!(Test-Path $ADROutputDir))
        {
            Write-Output "[Invoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        $ADROutputDir = $((Convert-Path $ADROutputDir).TrimEnd("\"))
        Remove-Variable ADRCreate
    }
    Else
    {
        $ADROutputDir = $returndir
    }

    If ($ADRCSV)
    {
        $CSVPath = [System.IO.DirectoryInfo] -join($ADROutputDir,'\','CSV-Files')
        New-Item $CSVPath -type directory | Out-Null
        If (!(Test-Path $CSVPath))
        {
            Write-Output "[Invoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        Remove-Variable ADRCSV
    }

    If ($ADRXML)
    {
        $XMLPath = [System.IO.DirectoryInfo] -join($ADROutputDir,'\','XML-Files')
        New-Item $XMLPath -type directory | Out-Null
        If (!(Test-Path $XMLPath))
        {
            Write-Output "[Invoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        Remove-Variable ADRXML
    }

    If ($ADRJSON)
    {
        $JSONPath = [System.IO.DirectoryInfo] -join($ADROutputDir,'\','JSON-Files')
        New-Item $JSONPath -type directory | Out-Null
        If (!(Test-Path $JSONPath))
        {
            Write-Output "[Invoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        Remove-Variable ADRJSON
    }

    If ($ADRHTML)
    {
        $HTMLPath = [System.IO.DirectoryInfo] -join($ADROutputDir,'\','HTML-Files')
        New-Item $HTMLPath -type directory | Out-Null
        If (!(Test-Path $HTMLPath))
        {
            Write-Output "[Invoke-ADRecon] Error, could not create output directory"
            Return $null
        }
        Remove-Variable ADRHTML
    }

    # AD Login
    If ($UseAltCreds -and ($Method -eq 'ADWS'))
    {
        If (!(Test-Path ADR:))
        {
            Try
            {
                New-PSDrive -PSProvider ActiveDirectory -Name ADR -Root "" -Server $DomainController -Credential $Credential -ErrorAction Stop | Out-Null
            }
            Catch
            {
                Write-Output "[Invoke-ADRecon] $($_.Exception.Message)"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
        }
        Else
        {
            Remove-PSDrive ADR
            Try
            {
                New-PSDrive -PSProvider ActiveDirectory -Name ADR -Root "" -Server $DomainController -Credential $Credential -ErrorAction Stop | Out-Null
            }
            Catch
            {
                Write-Output "[Invoke-ADRecon] $($_.Exception.Message)"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
        }
        Set-Location ADR:
        Write-Debug "ADR PSDrive Created"
        #return $null
    }

    If ($Method -eq 'LDAP')
    {
        If ($UseAltCreds)
        {
            Try
            {
                $objDomain = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)", $Credential.UserName,$Credential.GetNetworkCredential().Password
                $objDomainRootDSE = New-Object System.DirectoryServices.DirectoryEntry "LDAP://$($DomainController)/RootDSE", $Credential.UserName,$Credential.GetNetworkCredential().Password
            }
            Catch
            {
                Write-Output "[Invoke-ADRecon] $($_.Exception.Message)"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
            If(!($objDomain.name))
            {
                Write-Output "[Invoke-ADRecon] LDAP bind Unsuccessful"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
            Else
            {
                Write-Output "[*] LDAP bind Successful"
            }
        }
        Else
        {
            $objDomain = [ADSI]""
            $objDomainRootDSE = ([ADSI] "LDAP://RootDSE")
            If(!($objDomain.name))
            {
                Write-Output "[Invoke-ADRecon] LDAP bind Unsuccessful"
                If ($ADROutputDir)
                {
                    Remove-EmptyADROutputDir $ADROutputDir $OutputType
                }
                Return $null
            }
        }
        Write-Debug "LDAP Bing Successful"
        #return $null
    }

    Write-Output "[*] Commencing - $date"
    If ($ADRDomain)
    {
        Write-Output "[-] Domain"
        $ADRObject = Get-ADRDomain -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Domain"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRDomain
    }
    If ($ADRForest)
    {
        Write-Output "[-] Forest"
        $ADRObject = Get-ADRForest -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Forest"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRForest
    }
    If ($ADRTrust)
    {
        Write-Output "[-] Trusts"
        $ADRObject = Get-ADRTrust -Method $Method -objDomain $objDomain
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Trusts"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRTrust
    }
    If ($ADRSite)
    {
        Write-Output "[-] Sites"
        $ADRObject = Get-ADRSite -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Sites"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRSite
    }
    If ($ADRSubnet)
    {
        Write-Output "[-] Subnets"
        $ADRObject = Get-ADRSubnet -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Subnets"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRSubnet
    }
    If ($ADRSchemaHistory)
    {
        Write-Output "[-] SchemaHistory - May take some time"
        $ADRObject = Get-ADRSchemaHistory -Method $Method -objDomain $objDomain -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "SchemaHistory"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRSchemaHistory
    }
    If ($ADRPasswordPolicy)
    {
        Write-Output "[-] Default Password Policy"
        $ADRObject = Get-ADRDefaultPasswordPolicy -Method $Method -objDomain $objDomain
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "DefaultPasswordPolicy"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRPasswordPolicy
    }
    If ($ADRFineGrainedPasswordPolicy)
    {
        Write-Output "[-] Fine Grained Password Policy - May need a Privileged Account"
        $ADRObject = Get-ADRFineGrainedPasswordPolicy -Method $Method -objDomain $objDomain
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "FineGrainedPasswordPolicy"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRFineGrainedPasswordPolicy
    }
    If ($ADRDomainControllers)
    {
        Write-Output "[-] Domain Controllers"
        $ADRObject = Get-ADRDomainController -Method $Method -objDomain $objDomain -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "DomainControllers"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRDomainControllers
    }
    If ($ADRUsers -or $ADRUserSPNs)
    {
        If (!$ADRUserSPNs)
        {
            Write-Output "[-] Users - May take some time"
            $ADRUserSPNs = $false
        }
        ElseIf (!$ADRUsers)
        {
            Write-Output "[-] User SPNs"
            $ADRUsers = $false
        }
        Else
        {
            Write-Output "[-] Users and SPNs - May take some time"
        }
        Get-ADRUser -Method $Method -date $date -objDomain $objDomain -DormantTimeSpan $DormantTimeSpan -PageSize $PageSize -Threads $Threads -ADRUsers $ADRUsers -ADRUserSPNs $ADRUserSPNs -OnlyEnabled $OnlyEnabled
        Remove-Variable ADRUsers
        Remove-Variable ADRUserSPNs
    }
    If ($ADRPasswordAttributes)
    {
        Write-Output "[-] PasswordAttributes - Experimental"
        $ADRObject = Get-ADRPasswordAttributes -Method $Method -objDomain $objDomain -PageSize $PageSize
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "PasswordAttributes"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRPasswordAttributes
    }
    If ($ADRGroups -or $ADRGroupChanges)
    {
        If (!$ADRGroupChanges)
        {
            Write-Output "[-] Groups - May take some time"
            $ADRGroupChanges = $false
        }
        ElseIf (!$ADRGroups)
        {
            Write-Output "[-] Group Membership Changes - May take some time"
            $ADRGroups = $false
        }
        Else
        {
            Write-Output "[-] Groups and Membership Changes - May take some time"
        }
        Get-ADRGroup -Method $Method -date $date -objDomain $objDomain -PageSize $PageSize -Threads $Threads -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRGroups $ADRGroups -ADRGroupChanges $ADRGroupChanges
        Remove-Variable ADRGroups
        Remove-Variable ADRGroupChanges
    }
    If ($ADRGroupMembers)
    {
        Write-Output "[-] Group Memberships - May take some time"

        $ADRObject = Get-ADRGroupMember -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "GroupMembers"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRGroupMembers
    }
    If ($ADROUs)
    {
        Write-Output "[-] OrganizationalUnits (OUs)"
        $ADRObject = Get-ADROU -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "OUs"
            Remove-Variable ADRObject
        }
        Remove-Variable ADROUs
    }
    If ($ADRGPOs)
    {
        Write-Output "[-] GPOs"
        $ADRObject = Get-ADRGPO -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "GPOs"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRGPOs
    }
    If ($ADRgPLinks)
    {
        Write-Output "[-] gPLinks - Scope of Management (SOM)"
        $ADRObject = Get-ADRgPLink -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "gPLinks"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRgPLinks
    }
    If ($ADRDNSZones -or $ADRDNSRecords)
    {
        If (!$ADRDNSRecords)
        {
            Write-Output "[-] DNS Zones"
            $ADRDNSRecords = $false
        }
        ElseIf (!$ADRDNSZones)
        {
            Write-Output "[-] DNS Records"
            $ADRDNSZones = $false
        }
        Else
        {
            Write-Output "[-] DNS Zones and Records"
        }
        Get-ADRDNSZone -Method $Method -objDomain $objDomain -DomainController $DomainController -Credential $Credential -PageSize $PageSize -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRDNSZones $ADRDNSZones -ADRDNSRecords $ADRDNSRecords
        Remove-Variable ADRDNSZones
    }
    If ($ADRPrinters)
    {
        Write-Output "[-] Printers"
        $ADRObject = Get-ADRPrinter -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Printers"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRPrinters
    }
    If ($ADRComputers -or $ADRComputerSPNs)
    {
        If (-Not $ADRComputerSPNs)
        {
            Write-Output "[-] Computers - May take some time"
            $ADRComputerSPNs = $false
        }
        ElseIf (-Not $ADRComputers)
        {
            Write-Output "[-] Computer SPNs"
            $ADRComputers = $false
        }
        Else
        {
            Write-Output "[-] Computers and SPNs - May take some time"
        }

        Get-ADRComputer -Method $Method -date $date -objDomain $objDomain -DormantTimeSpan $DormantTimeSpan -PassMaxAge $PassMaxAge -PageSize $PageSize -Threads $Threads -ADRComputers $ADRComputers -ADRComputerSPNs $ADRComputerSPNs -OnlyEnabled $OnlyEnabled

        Remove-Variable ADRComputers
        Remove-Variable ADRComputerSPNs
    }
    If ($ADRLAPS)
    {
        Write-Output "[-] LAPS - Needs Privileged Account to get the passwords"

        $ADRLAPSCheck = Get-ADRLAPSCheck -Method $Method -objDomainRootDSE $objDomainRootDSE -DomainController $DomainController -Credential $Credential

        If ($ADRLAPSCheck)
        {
            $ADRObject = Get-ADRLAPS -Method $Method -objDomain $objDomain -PageSize $PageSize -Threads $Threads
        }
        Else
        {
            Write-Warning "[*] LAPS is not implemented."
        }

        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "LAPS"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRLAPS
    }
    If ($ADRBitLocker)
    {
        Write-Output "[-] BitLocker Recovery Keys - Needs Privileged Account"
        $ADRObject = Get-ADRBitLocker -Method $Method -objDomain $objDomain -DomainController $DomainController -Credential $Credential
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "BitLockerRecoveryKeys"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRBitLocker
    }
    If ($ADRACLs)
    {
        Write-Output "[-] ACLs - May take some time"
        $ADRObject = Get-ADRACL -Method $Method -objDomain $objDomain -DomainController $DomainController -Credential $Credential -PageSize $PageSize -Threads $Threads
        Remove-Variable ADRACLs
    }
    If ($ADRGPOReport)
    {
        Write-Output "[-] GPOReport - May take some time"
        Get-ADRGPOReport -Method $Method -UseAltCreds $UseAltCreds -ADROutputDir $ADROutputDir
        Remove-Variable ADRGPOReport
    }
    If ($ADRKerberoast)
    {
        Write-Output "[-] Kerberoast"
        $ADRObject = Get-ADRKerberoast -Method $Method -objDomain $objDomain -Credential $Credential -PageSize $PageSize
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "Kerberoast"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRKerberoast
    }
    If ($ADRDomainAccountsusedforServiceLogon)
    {
        Write-Output "[-] Domain Accounts used for Service Logon - Needs Privileged Account"
        $ADRObject = Get-ADRDomainAccountsusedforServiceLogon -Method $Method -objDomain $objDomain -Credential $Credential -PageSize $PageSize -Threads $Threads
        If ($ADRObject)
        {
            Export-ADR -ADRObj $ADRObject -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "DomainAccountsusedforServiceLogon"
            Remove-Variable ADRObject
        }
        Remove-Variable ADRDomainAccountsusedforServiceLogon
    }

    $TotalTime = "{0:N2}" -f ((Get-DateDiff -Date1 (Get-Date) -Date2 $date).TotalMinutes)

    $AboutADRecon = Get-ADRAbout -Method $Method -date $date -ADReconVersion $ADReconVersion -Credential $Credential -RanonComputer $RanonComputer -TotalTime $TotalTime

    If ( ($OutputType -Contains "CSV") -or ($OutputType -Contains "XML") -or ($OutputType -Contains "JSON") -or ($OutputType -Contains "HTML") )
    {
        If ($AboutADRecon)
        {
            Export-ADR -ADRObj $AboutADRecon -ADROutputDir $ADROutputDir -OutputType $OutputType -ADRModuleName "AboutADRecon"
        }
        Write-Output "[*] Total Execution Time (mins): $($TotalTime)"
        Write-Output "[*] Output Directory: $ADROutputDir"
        $ADRSTDOUT = $false
    }

    Switch ($OutputType)
    {
        'STDOUT'
        {
            If ($ADRSTDOUT)
            {
                Write-Output "[*] Total Execution Time (mins): $($TotalTime)"
            }
        }
        'HTML'
        {
            Export-ADR -ADRObj $(New-Object PSObject) -ADROutputDir $ADROutputDir -OutputType $([array] "HTML") -ADRModuleName "Index"
        }
        'EXCEL'
        {
            Export-ADRExcel -ExcelPath $ADROutputDir -Logo $Logo
        }
    }
    Remove-Variable TotalTime
    Remove-Variable AboutADRecon
    Set-Location $returndir
    Remove-Variable returndir

    If (($Method -eq 'ADWS') -and $UseAltCreds)
    {
        Remove-PSDrive ADR
    }

    If ($Method -eq 'LDAP')
    {
        $objDomain.Dispose()
        $objDomainRootDSE.Dispose()
    }

    If ($ADROutputDir)
    {
        Remove-EmptyADROutputDir $ADROutputDir $OutputType
    }

    Remove-Variable ADReconVersion
    Remove-Variable RanonComputer
}

If ($Log)
{
    Start-Transcript -Path "$(Get-Location)\ADRecon-Console-Log.txt"
}

Invoke-ADRecon -GenExcel $GenExcel -Method $Method -Collect $Collect -DomainController $DomainController -Credential $Credential -OutputType $OutputType -ADROutputDir $OutputDir -DormantTimeSpan $DormantTimeSpan -PassMaxAge $PassMaxAge -PageSize $PageSize -Threads $Threads -OnlyEnabled $OnlyEnabled -Logo $Logo

If ($Log)
{
    Stop-Transcript
}
