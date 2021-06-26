using System;
using System.IO;

namespace Pwd
{
    public class Program
    {
        public static void Main(string[] args)
        {
            try
            {
                Console.WriteLine(Directory.GetCurrentDirectory());
            }
            catch { }
        }
    }
}
