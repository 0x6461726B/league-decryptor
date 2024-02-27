#include "Decrypt.h"
#include "helper.h"

LeagueDecrypt::LeagueDecrypt() {

    GetSystemInfo(&sysInfo);

};

inline void triggerVeh(uint64_t address)
{
    auto funcAddy = reinterpret_cast<int64_t>(GetModuleHandle(NULL)) + 0xE64560;
    CallFunction<void, uint64_t>(funcAddy, address - 0x8);
}

BOOL LeagueDecrypt::decrypt(PVOID address)
{

    __try {
       triggerVeh(reinterpret_cast<uint64_t>(address));
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return TRUE;
    }

    return FALSE;
}
LeagueDecryptData LeagueDecrypt::decryptAll() {
    const std::string sectionName = ".text";
    LeagueDecryptData ldd{};

    uint64_t dllImageBase = reinterpret_cast<uint64_t>(GetModuleHandle(NULL));

    if (!dllImageBase) {
        return ldd; 
    }

   
     IMAGE_NT_HEADERS* ntHeaders = ImageNtHeader(reinterpret_cast<void*>(dllImageBase));
     IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
     for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader) {
         if (std::strncmp(reinterpret_cast<const char*>(sectionHeader->Name), sectionName.c_str(), sectionName.size()) == 0) {
             uintptr_t sectionStart = dllImageBase + sectionHeader->VirtualAddress;
             size_t sectionSize = sectionHeader->Misc.VirtualSize;

             ProcessSection(sectionStart, sectionSize, ldd);
             break; 
         }
     }

     return ldd;
    
}



void LeagueDecrypt::ProcessSection(uintptr_t sectionStart, size_t sectionSize, LeagueDecryptData& ldd) {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t currentAddress = sectionStart;
    uintptr_t sectionEnd = sectionStart + sectionSize;

    // LOG("Current address %p", currentAddress);
    while (currentAddress < sectionEnd) {
        // Query the memory region starting from the current address
        if (VirtualQuery(reinterpret_cast<LPCVOID>(currentAddress), &mbi, sizeof(mbi)) == 0) {
            break;
        }




        if (mbi.Protect != PAGE_NOACCESS) {
            uintptr_t page = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            uintptr_t pageEnd = page + mbi.RegionSize;

           
            for (; page < pageEnd; page += sysInfo.dwPageSize) { 
                if (decrypt(reinterpret_cast<void*>(page))) {
                    // LOG("Decrypted %p", page);
                    ldd.totalSuccessDecrypted++;
                }
                else {
                    // LOG("Failed to decrypt %p", page);
                    ldd.totalFailedDecrypted++;
                }
            }
        }
        else {
            ldd.totalSuccess_PAGE_NOACCESS;
            // LOG("Skipping region: State %lu, Protect %lu", mbi.State, mbi.Protect);
        }


        // Move to the next memory region
        currentAddress = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;

        if (reinterpret_cast<uintptr_t>(mbi.BaseAddress) >= currentAddress) {
            break;
        }

    }
}