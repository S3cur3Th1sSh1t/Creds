# stolen from https://gist.github.com/ajpc500/a9695eca6a660d1fb5ec30a2e356f33e
from uuid import UUID
import os
import sys

# Usage: python3 binToUUIDs.py shellcode.bin [--print]

print("""
  ____  _    _______    _    _ _    _ _____ _____       
 |  _ \(_)  |__   __|  | |  | | |  | |_   _|  __ \      
 | |_) |_ _ __ | | ___ | |  | | |  | | | | | |  | |___  
 |  _ <| | '_ \| |/ _ \| |  | | |  | | | | | |  | / __| 
 | |_) | | | | | | (_) | |__| | |__| |_| |_| |__| \__ \ 
 |____/|_|_| |_|_|\___/ \____/ \____/|_____|_____/|___/
\n""")

with open(sys.argv[1], "rb") as f:
	bin = f.read()

if len(sys.argv) > 2 and sys.argv[2] == "--print":
	outputMapping = True
else:
	outputMapping = False

offset = 0

print("Length of shellcode: {} bytes\n".format(len(bin)))

out = ""

while(offset < len(bin)):
	countOfBytesToConvert = len(bin[offset:])
	if countOfBytesToConvert < 16:
		ZerosToAdd = 16 - countOfBytesToConvert
		byteString = bin[offset:] + (b'\x00'* ZerosToAdd)
		uuid = UUID(bytes_le=byteString)
	else:
		byteString = bin[offset:offset+16]
		uuid = UUID(bytes_le=byteString)
	offset+=16

	out += "\"{}\",\n".format(uuid)
	
	if outputMapping:
		print("{} -> {}".format(byteString, uuid))

with open(sys.argv[1] + "UUIDs", "w") as f:
	f.write(out)

print("Outputted to: {}".format(sys.argv[1] + "UUIDs"))
