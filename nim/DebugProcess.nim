import winim
import strutils

# declare delegates for NtCreateDebugObject and NtDebugActiveProcess

type
  NtCreateDebugObject = proc(
    DebugObjectHandle: PHandle,
    DesiredAccess: AccessMask,
    PObjectAttributes: PObjectAttributes,
    Flags: BOOL
  ): NTSTATUS {.stdcall.}

  NtDebugActiveProcess = proc(
    ProcessHandle: Handle,
    DebugObjectHandle: Handle
  ): NTSTATUS {.stdcall.}


# get Handle for ntdll.dll
var ntdll = LoadLibraryA("ntdll.dll")

if(ntdll == 0):
  echo "Failed to load ntdll.dll"
  quit(1)

# get addresses of NtCreateDebugObject and NtDebugActiveProcess
var
  NtCreateDebugObjectAddr = GetProcAddress(ntdll, "NtCreateDebugObject")
  NtDebugActiveProcessAddr = GetProcAddress(ntdll, "NtDebugActiveProcess")

if(NtCreateDebugObjectAddr == nil or NtDebugActiveProcessAddr == nil):
  echo "Failed to get addresses of NtCreateDebugObject or NtDebugActiveProcess"
  quit(1)

# cast addresses to delegates
let  MyNtCreateDebugObject = cast[NtCreateDebugObject](NtCreateDebugObjectAddr)
let  MyNtDebugActiveProcess = cast[NtDebugActiveProcess](NtDebugActiveProcessAddr)

# create debug object
var
  DebugObjectHandle: Handle
  ObjectAttributes: ObjectAttributes

InitializeObjectAttributes(&ObjectAttributes, nil, 0, 0, nil)
var Status = MyNtCreateDebugObject(&DebugObjectHandle, 0x001F, &ObjectAttributes, FALSE)

# check if debug object was created successfully
if Status != 0:
  echo "NtCreateDebugObject failed with status: ", toHex(Status)
  quit(1)

# get PID from User input

echo "Enter PID to debug: "
var PIDString = readLine(stdin)
var PID = PIDString.parseInt()

# get handle to process
var ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, cast[DWORD](PID))

Status = MyNtDebugActiveProcess(ProcessHandle, DebugObjectHandle)

# check if we were successfully debugged
if Status != 0:
  echo "NtDebugActiveProcess failed with status: ", toHex(Status)
  quit(1)
