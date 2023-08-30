import winim
import strutils
import ptr_math
import os

proc ConvertToString(CharArr :array[256,char]): string =
    var index = 0
    while CharArr[index] != '\x00':
        result.add(CharArr[index])
        index += 1

proc GetRemoteModuleHandle(hProcess:HANDLE, ModuleName: string): HMODULE =
    var 
        modEntry : MODULEENTRY32A
        snapshot : HANDLE

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE,GetProcessId(hProcess))
    if snapshot != INVALID_HANDLE_VALUE:
        modEntry.dwSize = DWORD(sizeof(MODULEENTRY32A))
        if Module32FirstA(snapshot, addr modEntry):
            while Module32NextA(snapshot, addr modEntry):
                if toLowerAscii(ConvertToString(modEntry.szModule)) == toLowerAscii(ModuleName):
                    return modEntry.hModule
    CloseHandle(snapshot)
    return 0

proc getTextSectionStart(moduleBase: LPVOID): LPVOID =
    var textSectionStart: LPVOID = moduleBase + 0x1000
    echo "textSectionStart: ", repr(textSectionStart)
    return textSectionStart

when isMainModule:
    var pid: DWORD = DWORD(parse_int(paramStr(1)))
    echo "PID: ", pid
    var processHandle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid)
    echo "processHandle: ", processHandle
    var modName: string = "amsi.dll"
    var moduleBase: LPVOID = cast[LPVOID](GetRemoteModuleHandle(processHandle, modName))
    echo "moduleBase: ", repr(moduleBase)
    var textSectionStart: LPVOID = getTextSectionStart(moduleBase)
    echo "textSectionStart: ", repr(textSectionStart)

