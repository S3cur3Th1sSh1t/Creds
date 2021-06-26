using System;
using System.Collections.Generic;
using System.DirectoryServices.ActiveDirectory;

namespace Dclist
{
    public class Program
    {
        public static void Main(string[] args)
        {
            Domain userDomain = null;
            Domain computerDomain = null;
            try
            {
                userDomain = Domain.GetCurrentDomain();
            }
            catch (ActiveDirectoryOperationException)
            {
                Console.WriteLine("[!] Error: the current user does not appear to be in a domain context");
                return;
            }
            try
            {
                computerDomain = Domain.GetComputerDomain();
            }
            catch
            {
                Console.WriteLine("[!] Error: the current computer does not appear to be in a domain context");
                return;
            }
            if (userDomain.Name == computerDomain.Name)
            {
                Console.WriteLine("Current Domain: " + userDomain.Name);
            }
            else
            {
                Console.WriteLine("User Domain:     " + userDomain.Name);
                Console.WriteLine("Computer Domain: " + computerDomain.Name);
            }

            int dclongest = 7;
            int iplongest = 10;
            Dictionary<string, string> dcs1 = new Dictionary<string, string>();
            Dictionary<string, string> dcs2 = new Dictionary<string, string>();
            foreach (DomainController dc in userDomain.DomainControllers)
            {
                dcs1.Add(dc.Name, dc.IPAddress);
                dcs2.Add(dc.Name, dc.OSVersion);
                if (dc.Name.Length > dclongest)
                {
                    dclongest = dc.Name.Length;
                }
                if (dc.IPAddress.Length > iplongest)
                {
                    iplongest = dc.IPAddress.Length;
                }
            }
            Console.WriteLine("\nDC Name" + new string(' ', dclongest - 4) + "IP Address" + new string(' ', iplongest - 7) + "Operating System");
            Console.WriteLine(new string('=', dclongest) + "   " + new string('=', 12) + "   " + new string('=', 30));
            foreach (var dc in dcs1)
            {
                var len = dc.Key.Length;
                Console.WriteLine(dc.Key + new string(' ', dclongest - len + 3) + dc.Value + new string(' ', iplongest - dc.Value.Length + 3) + dcs2[dc.Key]);
            }
        }
    }
}