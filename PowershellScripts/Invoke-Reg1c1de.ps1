function Invoke-Reg1c1de
{

    [CmdletBinding()]
    Param (
        [String]
        $Command = " "

    )

$regicide = @"
using System;
using System.Security.Principal;
using System.Collections.Generic;
using Microsoft.Win32;

namespace Reg1c1de
{
        public class Regicide
        {
            static int tested = 0;
            static bool info = true;
            static string outfile = "";
            static bool debug = false;
            static bool performwritetest = false;
            static bool filefinder_opt = true;
            static List<string> fails = new List<string>();
            static List<string> vulnerable = new List<string>();
            static List<string> unsuccessfuls = new List<string>();
            static List<string> writeablefiles = new List<string>();
            static string basekey = "Software";
            static string uniquestring = "sn0wflake_str1ng_";
            static RegistryKey hive = Registry.LocalMachine;
            static bool entirehive;

            static string[] extensions = { 
            ".dll",".exe",".wll",".inf",".ini"
            };

            static bool hasext(string fname)
            {
                foreach(string ext in extensions)
                {
                    if (fname.Contains(ext))
                    {
                        return true;
                    }
                }
                return false;
            }

            static bool doihavewrite(string filename)
            {
                try
                {
                    if (!System.IO.File.Exists(filename)){
                        return false;
                    }
                    System.IO.File.OpenWrite(filename);
                    return true;
                } catch (System.UnauthorizedAccessException){
                    return false;
                } catch 
                {
                    // in case 
                    return false;
                }
            }

            static void filefinder(string[] filenames,string keyname)
            {

               foreach(string fname in filenames)
                {
                    if (hasext(fname))
                    {
                        if (doihavewrite(fname))
                        {
                            Console.WriteLine("[+]Writeable File: {0} with associated key: {1}", fname,keyname);
                            if (!writeablefiles.Contains(fname + "|" + keyname))
                            {
                                writeablefiles.Add(fname + "|" + keyname);
                            }

                        }

                    }



                } 

            }

            static void printusage()
            {
                Console.WriteLine("Description:\n" +
                    "Reg1c1de is a tool that scans specified registry hives and reports on any keys where the user has write permissions\n" +
                    "In addition, if any registry values are found that contain file paths with certain file extensions and they are writeable, these will be reported as well.\n" +
                    "These keys should be investigated further as they could potentially lead to a path to privilege escalation or other evil\n");
                Console.WriteLine("Arguments: (THESE ARE ALL OPTIONAL!)\n" +
                    "-h \tshow this help message\n" +
                    "-vv\tenable debug output (more verbose)\n" +
                    "-e \tscan the entire specified hive, this is disabled by default\n" +
                    "-o \tfilename to write the vulnerable keys to csv, example -o=filename\n" +
                    "-k \tbase key to enumerate from under the hive, default=Software, example -k=Software\n" +
                    "-df\tdisables writeable file checking, in case you don't want to make thousands of access denied file open attempts\n" +
                    "-r \tfour letter shorthand of the root hive to enumerate from, default=HKLM, example -r=HKLM\n" +
                    "\tAcceptable values are: HKCU, HKLM, HKCR, HKCC, HKU\n\n"+
                    "-writetests\tenabling this flag will enable write tests, which will write a dummy registry key and value to every discovered " +
                    "instance of write access to a key.\nI DO NOT recommend using this, especially if you cannot make a registry backup, nevertheless " +
                    "it is here.\n");
                Console.WriteLine("Example Usage:\n" +
                    "Reg1c1de.exe -v -o=outputfile -r=HKLM -e ");
            }
            static void banner()
            {
                Console.WriteLine("++++++++++++++Reg1c1de++++++++++++++++");
                Console.WriteLine("+author: @deadjakk | http://shell.rip+");
                Console.WriteLine("++++++++++++++++++++++++++++++++++++++\n\n");
            }
            public static void Main(string[] args)
            {
                banner();

                if (args.Length == 0)
                {
                    Console.WriteLine("Reg1c1de -h to see list of args...");
                    Console.WriteLine("To continue without args hit enter, or Ctrl + C to cancel");
                    Console.Read();
                }
                else
                {
                    int argresult = argparser(args);
                    if (argresult != 0)
                    {
                        return;
                    }
                }


                int result = regdive();

                if (result == 9)
                {
                    Console.WriteLine("Do not run this as admin, that's kind of pointless");
                    return;
                }
                if (result != 0)
                {
                    return;
                }

                Console.WriteLine("Finished, tested {1} keys, potentially vulnerable keys found: {0}", vulnerable.Count, tested);
                if (fails.Count > 0)
                {
                    Console.WriteLine("Created keys that were created but could not be deleted: {0}", fails);
                }
                if (outfile != "")
                {
                    writeoutput();
                }

            }

            static void writeoutput()
            {
                List<string> output = new List<string>();
                outfile = outfile.Replace(".csv", "");
                using (System.IO.StreamWriter writer = new System.IO.StreamWriter(outfile+"_"+hive.Name+".csv"))
                {
                    writer.WriteLine("result,keyname");
                    foreach (string wfile in writeablefiles)
                    {
                        if (filefinder_opt) { 
                            writer.WriteLine("WRITEABLEFILE," + wfile);
                        }
                    }
                    foreach (string vuln in vulnerable)
                    {
                        writer.WriteLine("VULNERABLE," + vuln);
                    }
                    foreach (string fail in fails)
                    {
                        writer.WriteLine("ERROR," + fail);
                    }
                    foreach (string item in unsuccessfuls)
                    {
                        writer.WriteLine("ACCESSDENIED," + item);
                    }
                    Console.WriteLine("Output was written to: {0}_{1}.csv", outfile, hive.Name);
                }
            }

            static int argparser(string[] args)
            {
                foreach (var arg in args)
                {
                    if (arg == "-h" || arg == "--help")
                    {
                        printusage();
                        return 10;
                    }
                    else if (arg == "-vv" || arg == "-v")
                    {
                        Console.WriteLine("[+]config: output set to debug");
                        debug = true;
                    }
                    else if (arg == "-e")
                    {
                        Console.WriteLine("[+]config: scanning entire hive");
                        entirehive = true;
                    }
                    else if (arg == "-df")
                    {
                        Console.WriteLine("[+]config: disabled file path checking");
                        filefinder_opt = false;
                    }
                    else if (arg.Contains("-o"))
                    {
                        try
                        {
                            outfile = arg.Split('=')[1];
                            if (outfile == "")
                            {
                                Console.WriteLine("filename is empty, please provide an actual filename, for example: -o=stuff.txt");
                                return 3;
                            }
                        }
                        catch
                        {
                            Console.WriteLine("\nError parsing outfile argument make sure there are no spaces\nRequired format: -o=filename.txt");
                            return 1;
                        }
                    }
                    else if (arg.Contains("-r"))
                    {
                        try
                        {
                            string arg_ = arg.Split('=')[1];
                            if (arg_ == "")
                            {
                                Console.WriteLine("key arg value is empty, please provide something, for example: -r=HKCU");
                                return 4;
                            }
                            int res = selecthive(arg_);
                            if (res != 0)
                            {
                                return 98;
                            }
                        }
                        catch
                        {
                            Console.WriteLine("\nError parsing -r argument make sure it follows the format: -r=VALUE");
                            return 1;
                        }
                    }
                    else if (arg.Contains("-k"))
                    {
                        try
                        {
                            basekey = arg.Split('=')[1];
                            if (basekey == "")
                            {
                                Console.WriteLine("key arg value is empty, please provide something, for example: -k=System");
                                return 3;
                            }
                        }
                        catch
                        {
                            Console.WriteLine("\nError parsing -k argument make sure it follows the format: -k=VALUE");
                            return 1;
                        }
                    }
                    else if (arg == "-writetests")
                    {
                        Console.WriteLine("[!!!]Write tests flag selected, there is a (high) chance that some of " +
                            "the keys that are created may not be removed properly or some other craziness happens\n" +
                            " consider backing up registry if you can, or using without -writetests flag.");
                        Console.Write("please confirm you would like to attempt a write and delete on all potentially" +
                            "vulnerable keys discovered. [y/N]: ");
                        string response = Console.ReadLine();
                        if (response.ToUpper().Contains("Y"))
                        {
                            performwritetest = true;
                            info = true;
                            Console.WriteLine("Write tests enabled, good luck");
                        }
                        else
                        {
                            return 2;
                        }

                    }
                    else
                    {
                        Console.WriteLine("Unknown arg: {0}, skipping it", arg);
                    }
                }
                return 0;

            }
        static int selecthive(string shorthand)
        {
            if (shorthand.ToUpper() == ("HKLM"))
            {
                // do nothing, this is default
            }
            else if (shorthand.ToUpper() == ("HKCC"))
            {
                hive = Registry.CurrentConfig;
            }
            else if (shorthand.ToUpper() == ("HKCR"))
            {
                hive = Registry.ClassesRoot;
            }
            else if (shorthand.ToUpper() == ("HKU"))
            {
                hive = Registry.Users;
            }
            else if (shorthand.ToUpper() == ("HKCU"))
            {
                hive = Registry.CurrentUser;
            }
            else
            {
                Console.WriteLine("invalid hive selection");
                Console.WriteLine("-r value must be: HKCU, HKLM, HKCR, HKCC, HKU");
                    return 1;
            }

            return 0;
        }

            static void iprint(string inp)
            {
                if (debug || info)
                {
                    Console.WriteLine("[I]{0}", inp);
                }
            }
            static void dprint(string inp)
            {
                if (debug)
                {
                    Console.WriteLine("[D]{0}", inp);
                }
            }

            static void writetest(RegistryKey key)
            {
                //double checking
                if (key.Name.Contains(uniquestring))
                {
                    return;
                }
                RegistryKey nkey = key.CreateSubKey(uniquestring, true); // unique string
                nkey.SetValue("dead", "jakk");
                iprint("[+]successfully wrote a key to " + key.Name);
                try
                {
                    iprint("Removing key we created: " + nkey.Name);
                    foreach (String value in nkey.GetValueNames())
                    {
                        nkey.DeleteValue(value);
                    }
                    key.DeleteSubKey(uniquestring);
                    iprint("key successfully removed");
                }
                catch
                {
                    Console.WriteLine("[!]Error deleting key {0}\tFOLLOW-UP", nkey.Name);
                    fails.Add(nkey.Name);
                }
            }

            static bool isempty(RegistryKey testkey)
            {
                if (testkey.GetSubKeyNames().Length == 0)
                {
                    return true;
                }

                return false;
            }
            static void checkrights(RegistryKey pkey, string subkey)
            {
                if (filefinder_opt)
                {
                    RegistryKey tempKey = pkey.OpenSubKey(subkey, false);
                    List<string> tList = new List<string>();
                    foreach(string vname in tempKey.GetValueNames())
                    {
                        tList.Add(tempKey.GetValue(vname).ToString());
                    }

                    string[] alist = tList.ToArray();
                    filefinder(alist,pkey.Name + "\\" + subkey);
                    tempKey.Dispose();

                }

                if (subkey.Contains(uniquestring))
                {
                    return;
                }
                if (vulnerable.Contains(pkey.Name))
                {
                    // we already found this key
                    return;
                }
                tested++;
                try
                {
                    //Testing our privilges
                    RegistryKey key = pkey.OpenSubKey(subkey, true);
                    Console.WriteLine("[+]Writeable Key: {0}, may have weak permissions", key.Name);
                    vulnerable.Add(key.Name);
                    //dprint("Testing " + key.Name);
                    try
                    {
                        if (performwritetest)
                        {
                            writetest(key);
                        }
                    }
                    catch
                    {
                        Console.WriteLine("[?]Got an error trying to create a dummy key under {0} after obtaining write permissions", key.Name);
                    }

                    // TODO check if the values beneath have something interesting

                }
                catch (System.UnauthorizedAccessException) {
                    dprint("Access denied: couldn't write to key: " + pkey.Name + "\\" + subkey);
                    unsuccessfuls.Add(pkey.Name + "\\" + subkey);
                } catch (System.Security.SecurityException) {
                    dprint("Access denied: couldn't write to key: " + pkey.Name + "\\" + subkey);
                    unsuccessfuls.Add(pkey.Name + "\\" + subkey);
                } catch (Exception e) {
                    Console.WriteLine("Exception : {0}", e);
                }
            }

            static void keycursion(RegistryKey pkey, string subkey)
            {
                RegistryKey rootkey = pkey.OpenSubKey(subkey);
                bool empty = isempty(rootkey);
                if (!empty)
                {
                    foreach (var v in rootkey.GetSubKeyNames())
                    {

                        try
                        {
                            keycursion(rootkey, v);
                        }
                        catch (System.Security.SecurityException)
                        {

                        }
                    }
                }
                checkrights(pkey, subkey);
            }

            //https://stackoverflow.com/questions/3600322/check-if-the-current-user-is-administrator
            public static bool IsAdministrator()
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    return principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }

            static int regdive()
            {
                if (IsAdministrator())
                {
                    return 9;
                }

                try
                {
                    RegistryKey bottomkey = hive;
                    if (!entirehive)
                    {
                        bottomkey = hive.OpenSubKey(basekey);
                    }
                    Console.WriteLine("\nSearching through keys...");
                    foreach (var subkey in bottomkey.GetSubKeyNames())

                    {
                        dprint(subkey);
                        try
                        {
                            keycursion(bottomkey, subkey);
                        }
                        catch (System.Security.SecurityException)
                        {
                            dprint("[-]security exception on " + subkey);
                        }
                        catch (System.ObjectDisposedException)
                        {
                            dprint("[-]disposed exception");
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine("[-]Error occured : {0}", e);
                        }
                    }

                    return 0;
                }
                catch(System.NullReferenceException)
                {
                    Console.WriteLine("\n[-]Base Key provided was invalid");
                    Console.WriteLine("Try one of the following (based on your provided -r arg):");
                    foreach(string name in hive.GetSubKeyNames())
                        {
                            Console.WriteLine(name);
                        }
                    return 1;

                }
            }
        }


}
"@

Add-Type -TypeDefinition $regicide -Language CSharp
[Reg1c1de.Regicide]::Main($Command.Split(" "))
}
