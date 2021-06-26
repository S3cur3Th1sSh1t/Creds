using System;
using System.Net;
using DnsClient;

namespace Nslookup
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length > 2 || args.Length == 0 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("WinBinReplacements: nslookup.exe <hostname> [dns_server]");
                return;
            }
            LookupClient client = new LookupClient();
            IDnsQueryResponse result = null;
            NameServer ns = null;
            if (args.Length == 2)
            {
                try
                {
                    ns = new NameServer(IPAddress.Parse(args[1]));
                    client = new LookupClient(ns);
                }
                catch
                {
                    Console.WriteLine("[!] Error: nameserver is not an IP address: " + args[1]);
                    return;
                }
            }
            try
            {
                result = client.Query(args[0], QueryType.A);
            }
            catch(DnsResponseException)
            {
                Console.WriteLine("[!] Error: DNS server could not be contacted");
                return;
            }
            
            foreach(var answer in result.Answers)
            {
                Console.WriteLine(answer);
            }
            if(result.Answers.Count == 0)
            {
                Console.WriteLine("[!] Error: no matching records found for " + args[0]);
            }
        }
    }
}
