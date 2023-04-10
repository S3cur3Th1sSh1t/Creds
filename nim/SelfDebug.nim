# Thanks and Credit to Mr-Un1k0d3r for the idea - https://github.com/Mr-Un1k0d3r/RedTeamCCode/blob/main/byebyedll.c

import winim
import os


# Create a Thread of the current Process itself as CreateProcess(argv[0], args, NULL, NULL, TRUE, DEBUG_ONLY_THIS_PROCESS | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si, &pi); so that we can receive debug events

proc ThreadFunc(): void =
    echo "ThreadFunc"


if(paramCount() == 0):
    
    var 
        lpSize: SIZE_T
        pi: PROCESS_INFORMATION
        ps: SECURITY_ATTRIBUTES
        si: STARTUPINFOEX
        status: WINBOOL
        tHandle: HANDLE
        tProcPath: WideCString
        ts: SECURITY_ATTRIBUTES

    # Initialize the STARTUPINFOEX structure
    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint
    si.StartupInfo.cb = sizeof(si).cint

    # Get the current Executables directory via win32 GetModuleFileName
    var currentDir: WideCString = newWideCString(MAX_PATH)
    GetModuleFileNameW(0, currentDir, MAX_PATH)
    echo "Current Dir: " & $currentDir

    CreateProcess(currentDir, newWideCString("anyargs"), nil, nil, TRUE, DEBUG_ONLY_THIS_PROCESS or EXTENDED_STARTUPINFO_PRESENT, nil, nil, cast[LPSTARTUPINFOW](addr si), addr pi)

    echo "Process Created"
    echo "PID: " & $pi.dwProcessId
    echo "TID: " & $pi.dwThreadId


    # The function here will continuisly wait for debug events and check them for new Thread Creation Events

    proc debug(): void =
        var
            dwState: DWORD
            bExit: BOOL = FALSE
            event: DEBUG_EVENT
            hDll: HANDLE
            hProcess: HANDLE
        
        while(not bExit):
            if(not WaitForDebugEvent(addr event, INFINITE)):
                echo "WaitForDebugEvent failed"
                echo "Error:" & $GetLastError()
            
            echo "Debug Event:" & $event.dwDebugEventCode

            case event.dwDebugEventCode:
                of CREATE_PROCESS_DEBUG_EVENT:
                    echo "CREATE_PROCESS_DEBUG_EVENT"
                    hProcess = event.u.CreateProcessInfo.hProcess
                    CloseHandle(hProcess)
                    dwState = DBG_CONTINUE
                    bExit = FALSE
        
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, dwState)
        dwState = DBG_CONTINUE
                
    debug()

else:
    # This code will actually not get called at all because we will get the CREATE_PROCESS_DEBUG_EVENT notification first.
    var hThread:HANDLE
    hThread = CreateThread(nil, 0, cast[PTHREAD_START_ROUTINE](ThreadFunc), nil, 0, nil)

    Sleep(10000)
