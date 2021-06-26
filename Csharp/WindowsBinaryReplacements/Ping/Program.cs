using System;
using System.Net.NetworkInformation;

namespace Ping
{
    public class Program
    {
        public static void Main(string[] args)
        {
            if (args.Length != 1 || args[0] == "-h" || args[0] == "/?" || args[0] == "/h" || args[0] == "--help")
            {
                Console.WriteLine("WinBinReplacements: ping.exe <IP_or_hostname>");
                return;
            }
            if(PingHost(args[0]))
            {
                Console.WriteLine("[*] Host is reachable: " + args[0]);
            }
            else
            {
                Console.WriteLine("[!] Host is unreachable: " + args[0]);
            }
        }  

        public static bool PingHost(string nameOrAddress)
        {
            bool pingable = false;
            System.Net.NetworkInformation.Ping pinger = null;

            try
            {
                pinger = new System.Net.NetworkInformation.Ping();
                PingReply reply = pinger.Send(nameOrAddress);
                pingable = reply.Status == IPStatus.Success;
            }
            catch(PingException) { }
            finally
            {
                if (pinger != null)
                {
                    pinger.Dispose();
                }
            }
            return pingable;
        }
    }
}
