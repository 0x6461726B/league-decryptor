// dllmain.cpp : Defines the entry point for the DLL application
#include "Decrypt.h";

HMODULE g_hModule = NULL; 


bool RestoreOriginalBytes(const char* functionName, BYTE originalBytes[], size_t byteCount) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) {
        return false; 
    }

    auto functionAddress = reinterpret_cast<DWORD_PTR>(GetProcAddress(ntdll, functionName));
    if (!functionAddress) {
        return false; 
    }

    DWORD oldProtect;
    
    if (VirtualProtect(reinterpret_cast<LPVOID>(functionAddress), byteCount, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        memcpy(reinterpret_cast<void*>(functionAddress), originalBytes, byteCount);
        VirtualProtect(reinterpret_cast<LPVOID>(functionAddress), byteCount, oldProtect, &oldProtect); // Restore original protection.
        return true;
    }
    return false;
}


bool RestoreNtProtectVirtualMemory() {
    BYTE originalBytes[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x50, 0x00, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01 };
    return RestoreOriginalBytes("NtProtectVirtualMemory", originalBytes, sizeof(originalBytes));
}

bool RestoreZwQueryVirtualMemory() {
    BYTE originalBytes[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x23, 0x00, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01 };
    return RestoreOriginalBytes("ZwQueryVirtualMemory", originalBytes, sizeof(originalBytes));
}

bool RestoreZwSuspendThread() {
    BYTE originalBytes[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0xCC, 0x01, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01 };
    return RestoreOriginalBytes("NtSuspendThread", originalBytes, sizeof(originalBytes));
}

bool RestoreNtContinue() {
    BYTE originalBytes[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x43, 0x00, 0x00, 0x00, 0xF6, 0x04, 0x25, 0x08, 0x03, 0xFE, 0x7F, 0x01 };
    return RestoreOriginalBytes("NtContinue", originalBytes, sizeof(originalBytes));
}

DWORD WINAPI main(LPVOID lpParamtere) {

   
	RestoreNtProtectVirtualMemory();
	RestoreZwQueryVirtualMemory();
    RestoreZwSuspendThread();
	RestoreNtContinue();

	Beep(300, 300);

    LeagueDecrypt decryptor;
    auto data = decryptor.decryptAll();



    std::wstring message = L"Total Decrypted: " + std::to_wstring(data.totalSuccessDecrypted) +
                           L"\nTotal Failed: " + std::to_wstring(data.totalFailedDecrypted);

    MessageBox(NULL, message.c_str(), L"Decryption Results", MB_OK);

    FreeLibraryAndExitThread(g_hModule, 0);
    return 0;


}




BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: {
       DisableThreadLibraryCalls(hModule);
       g_hModule = hModule;
       CreateThread(NULL, 0, main, NULL, 0, NULL);
       break;
    }
    case DLL_PROCESS_DETACH: 
        break;

   }
    return TRUE;
}

