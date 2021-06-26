using System;
using System.Net;
using System.Net.NetworkInformation;

namespace Netstat
{
    public class Program
    {
        public static void Main(string[] args) // Work in progress. Need to add behaviour of -ano flags (mostly PID)
        {
            IPGlobalProperties ip = IPGlobalProperties.GetIPGlobalProperties();
            Console.WriteLine("Local Address          Remote Address         State");
            Console.WriteLine("=============          ==============         =====");
            foreach (IPEndPoint tcp in ip.GetActiveTcpListeners())
            {
                Console.WriteLine(tcp.Address + ":" + tcp.Port + new string(' ', 22 - (tcp.Address.ToString().Length + tcp.Port.ToString().Length)) + "0.0.0.0" + new string(' ', 16) + "LISTENING");
            }
            
            foreach (var tcp in ip.GetActiveTcpConnections())
            {
                Console.WriteLine(tcp.LocalEndPoint + new string(' ', 23 - tcp.LocalEndPoint.ToString().Length) + tcp.RemoteEndPoint + new string(' ', 23 - tcp.RemoteEndPoint.ToString().Length) + "ESTABLISHED");
            }
        }
    }
}
