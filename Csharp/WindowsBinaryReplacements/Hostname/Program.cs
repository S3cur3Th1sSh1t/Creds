using System;
using System.Net;

namespace Hostname
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Console.WriteLine("NetBios name:  " + Environment.MachineName);
            Console.WriteLine("DNS name:      " + Dns.GetHostName());
        }
    }
}
