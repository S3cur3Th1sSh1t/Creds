# Still need to check, which functions are needed to minimize the imports for winim
import winim # tested with Winim Version 3.9.0
import ptr_math
import std/random
import std/heapqueue

type
  USTRING* {.bycopy.} = object
    Length*: DWORD
    MaximumLength*: DWORD
    Buffer*: PVOID

randomize()

type
  INNER_C_STRUCT_heap_5* {.bycopy.} = object
    Settable*: SIZE_T
    TagIndex*: USHORT
    AllocatorBackTraceIndex*: USHORT
    Reserved*: array[2, ULONG]

  INNER_C_STRUCT_heap_6* {.bycopy.} = object
    CommittedSize*: ULONG
    UnCommittedSize*: ULONG
    FirstEntry*: PVOID
    LastEntry*: PVOID

  INNER_C_UNION_heap_4* {.bycopy, union.} = object
    Block*: INNER_C_STRUCT_heap_5
    Segment*: INNER_C_STRUCT_heap_6

  RTL_HEAP_WALK_ENTRY* {.bycopy.} = object
    DataAddress*: PVOID
    DataSize*: SIZE_T
    OverheadBytes*: UCHAR
    SegmentIndex*: UCHAR
    Flags*: USHORT
    ano_heap_7*: INNER_C_UNION_heap_4

  PRTL_HEAP_WALK_ENTRY* = ptr RTL_HEAP_WALK_ENTRY

##  Pass 0 as the targetProcessId to suspend threads in the current process

proc DoSuspendThreads*(targetProcessId: DWORD; targetThreadId: DWORD) =
  var h: HANDLE = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
  if h != INVALID_HANDLE_VALUE:
    var te: THREADENTRY32
    te.dwSize = DWORD(sizeof((te)))
    if Thread32First(h, addr(te)):
      while true:
        if (te.th32OwnerProcessID == targetProcessId) and (te.th32ThreadID != targetThreadId):
          var hThread: HANDLE = OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID)
          if hThread != 0:
            SuspendThread(hThread)
            CloseHandle(hThread)
        if not Thread32Next(h, addr(te)):
          break
        



proc RtlWalkHeap*(hHeap: HANDLE, LPPROCESS_HEAP_ENTRY : PRTL_HEAP_WALK_ENTRY): BOOL 
  {.discardable, stdcall, dynlib: "ntdll", importc: "RtlWalkHeap".}

proc SystemFunction032*(data: LPVOID, key : LPVOID): NTSTATUS 
  {.discardable, stdcall, dynlib: "advapi32", importc: "SystemFunction032".}

# Somehow the encryption even if non busy heap segments breaks the executable at some point, I guess somehow due to the Nim GC, but I'm not sure about this yet.
# Had not enough time yet to dig deeper
proc encryptHeap*(Key: USTRING): VOID =
  var S32Key: USTRING = Key
  var S32Data: USTRING
  var Entry: RTL_HEAP_WALK_ENTRY
  RtlSecureZeroMemory(addr(Entry), sizeof((Entry)))
  var asd : int = 0
  write(stdout, "This is the prompt -> ")
  var input = readLine(stdin)
  while NT_SUCCESS(RtlWalkHeap(GetProcessHeap(), addr(Entry))):
    if (Entry.Flags and 0x0001 #[RTL_PROCESS_HEAP_ENTRY_BUSY]#) != 0x0000:
      echo "Entry not busy, encrypting"
      echo repr(Entry.Flags and 0x0001)
      echo toHex(Entry.Flags and 0x0001)
      echo Entry.Flags
      echo toHex(Entry.Flags)
      #inc(asd)
      #if(asd == 13):
      #  break
      S32Data.Length = DWORD(Entry.DataSize)
      S32Data.MaximumLength = DWORD(Entry.DataSize)
      S32Data.Buffer = cast[PBYTE](Entry.DataAddress)
      SystemFunction032(addr(S32Data), addr(S32Key))
  RtlSecureZeroMemory(addr(S32Data), sizeof((S32Data)))
  RtlSecureZeroMemory(addr(S32Key), sizeof((S32Key)))
  RtlSecureZeroMemory(addr(Entry), sizeof((Entry)))

proc EkkoObf*(SleepTime: DWORD): VOID
proc EkkoObf*(SleepTime: DWORD): VOID =
  var CtxThread: CONTEXT
  var RopProtRW: CONTEXT
  var RopMemEnc: CONTEXT
  var RopDelay: CONTEXT
  var RopMemDec: CONTEXT
  var RopProtRX: CONTEXT
  var RopSetEvt: CONTEXT
  var hTimerQueue: HANDLE
  var hNewTimer: HANDLE
  var hEvent: HANDLE
  var ImageBase: PVOID = nil
  var ImageSize: DWORD = 0
  var OldProtect: DWORD = 0
  ##  Random Key per Round
  
  var KeyBuf: array[16, CHAR] = [CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)),
                            CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255)), CHAR(rand(255))]
  var Key: USTRING = USTRING(Length: 0)
  var Img: USTRING = USTRING(Length: 0)
  var NtContinue: PVOID = nil
  var SysFunc032: PVOID = nil
  hEvent = CreateEventW(nil, 0, 0, nil)
  hTimerQueue = CreateTimerQueue()
  NtContinue = GetProcAddress(GetModuleHandleA("Ntdll"), "NtContinue")
  SysFunc032 = GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032")
  ImageBase = cast[PVOID](GetModuleHandleA(LPCSTR(nil)))
  ImageSize = (cast[PIMAGE_NT_HEADERS](ImageBase +
      (cast[PIMAGE_DOS_HEADER](ImageBase)).e_lfanew)).OptionalHeader.SizeOfImage
  Key.Buffer = KeyBuf.addr
  Key.Length = 16
  Key.MaximumLength = 16
  Img.Buffer = ImageBase
  Img.Length = ImageSize
  Img.MaximumLength = ImageSize
  echo "Suspend Threads"
  DoSuspendThreads(GetCurrentProcessId(), GetCurrentThreadId())
  echo "Encrypting Heap"
  encryptHeap(Key)
  
  if CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](RtlCaptureContext),
                          addr(CtxThread), 0, 0, WT_EXECUTEINTIMERTHREAD):
    WaitForSingleObject(hEvent, 0x32)
    copyMem(addr(RopProtRW), addr(CtxThread), sizeof((CONTEXT)))
    copyMem(addr(RopMemEnc), addr(CtxThread), sizeof((CONTEXT)))
    copyMem(addr(RopDelay), addr(CtxThread), sizeof((CONTEXT)))
    copyMem(addr(RopMemDec), addr(CtxThread), sizeof((CONTEXT)))
    copyMem(addr(RopProtRX), addr(CtxThread), sizeof((CONTEXT)))
    copyMem(addr(RopSetEvt), addr(CtxThread), sizeof((CONTEXT)))
    ##  VirtualProtect( ImageBase, ImageSize, PAGE_READWRITE, &OldProtect );
    dec(RopProtRW.Rsp, 8)
    var VirtualProtectAddr = GetProcAddress(GetModuleHandleA("kernel32"), "VirtualProtect")
    RopProtRW.Rip = cast[DWORD64](VirtualProtectAddr)
    RopProtRW.Rcx = cast[DWORD64](ImageBase)
    RopProtRW.Rdx = cast[DWORD64](ImageSize)
    RopProtRW.R8 = PAGE_READWRITE
    RopProtRW.R9 = cast[DWORD64](addr(OldProtect))
    ##  SystemFunction032( &Key, &Img );
    dec(RopMemEnc.Rsp, 8)
    RopMemEnc.Rip = cast[DWORD64](SysFunc032)
    RopMemEnc.Rcx = cast[DWORD64](addr(Img))
    RopMemEnc.Rdx = cast[DWORD64](addr(Key))
    ##  WaitForSingleObject( hTargetHdl, SleepTime );
    dec(RopDelay.Rsp, 8)
    RopDelay.Rip = cast[DWORD64](WaitForSingleObject)
    var ntCurrentProc: HANDLE = -1
    RopDelay.Rcx = cast[DWORD64](ntCurrentProc)
    RopDelay.Rdx = SleepTime
    ##  SystemFunction032( &Key, &Img );
    dec(RopMemDec.Rsp, 8)
    RopMemDec.Rip = cast[DWORD64](SysFunc032)
    RopMemDec.Rcx = cast[DWORD64](addr(Img))
    RopMemDec.Rdx = cast[DWORD64](addr(Key))
    ##  VirtualProtect( ImageBase, ImageSize, PAGE_EXECUTE_READWRITE, &OldProtect );
    dec(RopProtRX.Rsp, 8)
    RopProtRX.Rip = cast[DWORD64](VirtualProtectAddr)
    RopProtRX.Rcx = cast[DWORD64](ImageBase)
    RopProtRX.Rdx = cast[DWORD64](ImageSize)
    RopProtRX.R8 = PAGE_EXECUTE_READWRITE
    RopProtRX.R9 = cast[DWORD64](addr(OldProtect))
    ##  SetEvent( hEvent );
    dec(RopSetEvt.Rsp, 8)
    RopSetEvt.Rip = cast[DWORD64](SetEvent)
    RopSetEvt.Rcx = cast[DWORD64](hEvent)
    echo "[INFO] Queue timers"
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopProtRW), 100, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopMemEnc), 200, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue), addr(RopDelay),
                          300, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopMemDec), 400, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopProtRX), 500, 0, WT_EXECUTEINTIMERTHREAD)
    CreateTimerQueueTimer(addr(hNewTimer), hTimerQueue, cast[WAITORTIMERCALLBACK](NtContinue),
                          addr(RopSetEvt), 600, 0, WT_EXECUTEINTIMERTHREAD)
    echo "[INFO] Wait for hEvent"
    WaitForSingleObject(hEvent, INFINITE)
    echo "[INFO] Finished waiting for event"
  DeleteTimerQueue(hTimerQueue)
  echo "Decrypting Heap"
  encryptHeap(Key)

proc asd(): void =
  write(stdout, "This is the prompt -> ")
  var input = readLine(stdin)
  #let heap = initHeapQueue[0]()
  EkkoObf(20000)
  echo "Sleeping, everything should be unencrypted"
  Sleep(20000)

when isMainModule:
  asd()
