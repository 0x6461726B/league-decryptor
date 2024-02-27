#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <fstream>
#include <filesystem>



bool fileExists(const std::wstring& filename) {
    std::ifstream file(filename.c_str());
    return file.good();
}



DWORD getProcessId(const wchar_t* processName)
{
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating snapshot: " << GetLastError() << "\n" <<  std::endl;
        return 0;
    }

    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);

    if (!Process32First(snapshot, &entry)) {
        std::cerr << "Error getting the first process: " << GetLastError() << "\n" << std::endl;
        CloseHandle(snapshot);
        return 0;
    }

    do {
        if (_wcsicmp(entry.szExeFile, processName) == 0) {
            pid = entry.th32ProcessID;
            break;
        }
    } while (Process32Next(snapshot, &entry));

    CloseHandle(snapshot);
    return pid;
}

bool InjectDLL(DWORD processID, const std::wstring& dllPath)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    if (!hProcess) {
        std::cerr << "Error opening target process: " << GetLastError() << "\n" << std::endl;
        return false;
    }

    size_t Size = (dllPath.length() + 1) * sizeof(wchar_t);

    void* pDllPath = VirtualAllocEx(hProcess, 0, Size, MEM_COMMIT, PAGE_READWRITE);
    if (!pDllPath) {
        std::cerr << "Error allocating memory in target process: " << GetLastError() << "\n" << std::endl;
        CloseHandle(hProcess);
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(), Size, nullptr)) {
        std::cerr << "Error writing to target process memory: " << GetLastError() << "\n" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    const HMODULE hModule = GetModuleHandleA("kernel32.dll");

    if (hModule == INVALID_HANDLE_VALUE || hModule == nullptr)
        return false;


    const FARPROC lpFunctionAddress = GetProcAddress(hModule, "LoadLibraryW");
    if (lpFunctionAddress == nullptr) {
        std::cerr << "Loadlibrary failed!" << "\n";
        return false;
    }


    HANDLE hLoadThread = CreateRemoteThread(hProcess, NULL, 0,
        (PTHREAD_START_ROUTINE)lpFunctionAddress,
        pDllPath, 0, NULL);

  //  std::cout << "Error code " << GetLastError() << "\n";

    if (hLoadThread == INVALID_HANDLE_VALUE) {
        std::cerr << "Error creating remote thread in target process: " << GetLastError() << "\n" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    WaitForSingleObject(hLoadThread, INFINITE);
    
    DWORD exitCode = -1;
    if (GetExitCodeThread(hLoadThread, &exitCode) && exitCode == 0) {
        std::cerr << "LoadLibraryW failed in remote process. " << "\n";
        CloseHandle(hLoadThread);
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);  // Free the allocated memory
        CloseHandle(hProcess);

        return false;
    }

   

    return true;
}

int main()
{
   
    std::wstring dllName =  (std::filesystem::current_path() / + "Decryptor.dll").wstring();


    if (fileExists(dllName)) {
        std::wcout << L"File exists at: " << dllName << std::endl;
    }
    else {
        std::wcerr << L"File does not exist at: " << dllName << std::endl;
        return 1;
    }


    DWORD pid = getProcessId(L"League of Legends.exe");

    if (!pid) {
        std::cerr << "Couldn't find target process!" << "\n" << std::endl;
        system("pause");
        return 1;  
    }

    std::cout << "PID: " << pid << "\n";

    if (!InjectDLL(pid, dllName)) {
        std::cerr << "Couldn't inject!" << "\n" << std::endl;
        system("pause");
        return 1;  
    }

   


    std::cout << "Successfully injected!" << "\n";
    system("pause");


    return 0;
}
