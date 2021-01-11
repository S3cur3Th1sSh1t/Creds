import nimcrypto
import nimcrypto/sysrand
import base64
import os
import strutils

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

# read file from argument
let entireFile = readFile(paramStr(1))

var
    data: seq[byte] = toByteSeq(entireFile)
    envkey: string = "TARGETDOMAIN"

    ectx, dctx: CTR[aes256]
    key: array[aes256.sizeKey, byte]
    iv: array[aes256.sizeBlock, byte]
    plaintext = newSeq[byte](len(data))
    enctext = newSeq[byte](len(data))
    dectext = newSeq[byte](len(data))

# Set static IV
iv = [byte 183, 142, 238, 156, 42, 43, 248, 100, 125, 249, 192, 254, 217, 222, 133, 149]

copyMem(addr plaintext[0], addr data[0], len(data))

# Expand key to 32 bytes using SHA256 as the KDF
var expandedkey = sha256.digest(envkey)
copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))

ectx.init(key, iv)
ectx.encrypt(plaintext, enctext)
ectx.clear()

#base64 encode encrypted assembly
let encodedcrypted = encode(enctext)

echo "Writing encrypted base64 encoded assembly to: enc.txt "

writeFile("enc.txt", encodedcrypted)
