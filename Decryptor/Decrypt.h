#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "framework.h"


struct LeagueDecryptData
{
    int totalSuccessDecrypted = 0;
    int totalSuccess_PAGE_NOACCESS = 0;
    int totalSuccess_EXCEPTION_CONTINUE_EXECUTION = 0;
    int totalFailedDecrypted = 0;
    int64_t debug = NULL;
    LeagueDecryptData& operator+=(const LeagueDecryptData& ldd) {
        totalSuccessDecrypted += ldd.totalSuccessDecrypted;
        totalSuccess_PAGE_NOACCESS += ldd.totalSuccess_PAGE_NOACCESS;
        totalSuccess_EXCEPTION_CONTINUE_EXECUTION += ldd.totalSuccess_EXCEPTION_CONTINUE_EXECUTION;
        totalFailedDecrypted += ldd.totalFailedDecrypted;
        debug = ldd.debug;
        return *this; // return the result by reference
    }
};
struct ImageSectionInfo
{
    char SectionName[IMAGE_SIZEOF_SHORT_NAME];//the macro is defined WinNT.h
    DWORD64 SectionAddress;
    DWORD64 SectionSize;
    ImageSectionInfo(const char* name)
    {
        strcpy_s(SectionName, name);
    }
};

class LeagueDecrypt {
public:

    LeagueDecrypt();

    int decrypt(PVOID address);
    LeagueDecryptData decryptAll();

 
private:
    SYSTEM_INFO sysInfo;
    void ProcessSection(uintptr_t sectionStart, size_t sectionSize, LeagueDecryptData& ldd);
    
};


template<typename T, typename... Args_t>
T CallFunction(uintptr_t Func, Args_t... args)
{
    using Func_t = T(__fastcall*)(Args_t...);
    return reinterpret_cast<Func_t>(Func)(std::forward<Args_t>(args)...);
}