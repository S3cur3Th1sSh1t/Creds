import winim

var remoteProcID: DWORD

proc StartProcess(): void =
    var 
        lpSize: SIZE_T
        tProcess: HANDLE
        pi: PROCESS_INFORMATION
        ps: SECURITY_ATTRIBUTES
        si: STARTUPINFOEX
        status: WINBOOL
        tHandle: HANDLE
        tProcPath: WideCString
        ts: SECURITY_ATTRIBUTES
    
    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint
    si.StartupInfo.cb = sizeof(si).cint


    tProcPath = newWideCString(r"C:\windows\system32\calc.exe")
    # Just some testing for DLL-Hijacking which didn't work at all for any tested executables.
    var environment: WideCstring = newWideCString(r"C:\temp\")

    status = CreateProcess(
        cast[LPWSTR](tProcPath),
        environment,
        ps,
        ts, 
        FALSE,
        CREATE_SUSPENDED or EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        environment,
        addr si.StartupInfo,
        addr pi)

    tProcess = pi.hProcess
    remoteProcID = pi.dwProcessId
    tHandle = pi.hThread

StartProcess()
