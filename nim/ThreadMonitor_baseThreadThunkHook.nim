import winim
import ptr_math
import strutils

 

proc TestThread(): void =
  echo "Test Thread created..."
  
proc toString(bytes: openarray[byte]): string =
  result = newString(bytes.len)
  copyMem(result[0].addr, bytes[0].unsafeAddr, bytes.len)

var Kernel32ThreadInitThunkFunction: ULONG_PTR
var fn = cast[ULONG_PTR](GetProcAddress(GetModuleHandleA("kernel32"), "BaseThreadInitThunk"))

type
    OldBaseThreadInitThunk = proc(LdrReserved: DWORD, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: LPVOID): void {.stdcall.}

proc BaseThreadInitThunk(LdrReserved: DWORD, lpStartAddress: LPTHREAD_START_ROUTINE, lpParameter: LPVOID): void =
  echo "New Thread created..."
  echo "Thread ID: ", GetCurrentThreadId()
  discard InterlockedCompareExchangePointer(cast[ptr PVOID](Kernel32ThreadInitThunkFunction), cast[PVOID](fn), cast[PVOID](BaseThreadInitThunk))
  var oldBaseThreadInitThunk: OldBaseThreadInitThunk = cast[OldBaseThreadInitThunk](fn)
  oldBaseThreadInitThunk(LdrReserved, lpStartAddress, lpParameter)

proc main(): void =
  var m = GetModuleHandleA("ntdll")
  var nt = cast[PIMAGE_NT_HEADERS](m + cast[PIMAGE_DOS_HEADER](m).e_lfanew)
  var sh = IMAGE_FIRST_SECTION(nt)

  var ds: ptr ULONG_PTR = nil #cast[ptr ULONG_PTR](m + sh.VirtualAddress)[]
  var cnt: int #= nil #sh.Misc.VirtualSize div sizeof(ULONG_PTR)
  var low: uint16 = 0
  for sh in low ..< nt.FileHeader.NumberOfSections:
    var ntdllSectionHeader = cast[PIMAGE_SECTION_HEADER](cast[DWORD_PTR](IMAGE_FIRST_SECTION(nt)) + cast[DWORD_PTR](IMAGE_SIZEOF_SECTION_HEADER * sh))
    if ".data" in toString(ntdllSectionHeader.Name):
      ds = cast[ptr ULONG_PTR](m + ntdllSectionHeader.VirtualAddress)
      cnt = ntdllSectionHeader.Misc.VirtualSize div sizeof(ULONG_PTR)
      break

  echo "Searching for kernel32!BaseThreadInitThunk in ntdll.dll: ", toHex(fn)
  for i in 0 ..< cnt:
    if(ds[i] == fn):
      echo "Found ntdll!Kernel32ThreadInitThunkFunction @ ", toHex(cast[ULONG_PTR](&ds[i]))
      Kernel32ThreadInitThunkFunction = cast[ULONG_PTR](&ds[i])
      break
  
  # Overwrite with our function
  
  discard InterlockedCompareExchangePointer(cast[ptr PVOID](Kernel32ThreadInitThunkFunction), cast[PVOID](BaseThreadInitThunk), cast[PVOID](fn))

  # Create new thread that executes our function indirectly
  echo "Current Thread ID: ", GetCurrentThreadId()
  CloseHandle(CreateThread(nil, 0, cast[LPTHREAD_START_ROUTINE](TestThread), nil, 0, nil))

  echo "Press any key to continue..."
  var input = readLine(stdin)

  
when isMainModule:
  main()
