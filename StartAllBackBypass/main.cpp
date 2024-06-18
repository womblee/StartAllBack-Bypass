#include <windows.h>
#include <psapi.h>
#include "MinHook.h" // Include MinHook header

#pragma comment(lib, "psapi.lib")

/*
SigMakerEx: Finding function signature.
Function SIG: 0x00000180001CDC, 32 bytes 0, wildcards.
IDA: "48 8B C4 48 89 58 08 48 89 70 10 48 89 78 18 55 41 54 41 55 41 56 41 57 48 8D 68 A1 48 81 EC F0"
*/
BYTE pattern[] = { 0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0x48, 0x89, 0x70, 0x10, 0x48, 0x89, 0x78, 0x18, 0x55, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x8D, 0x68, 0xA1, 0x48, 0x81, 0xEC, 0xF0 };
const char* mask = "xxxxxxxxxxxxxxxxxxxxxxxxxxxx";

// Function to scan for the pattern
void* FindPattern(BYTE* base, SIZE_T size, BYTE* pattern, const char* mask)
{
    SIZE_T patternLength = strlen(mask);

    for (SIZE_T i = 0; i < size - patternLength; i++)
    {
        bool found = true;
        for (SIZE_T j = 0; j < patternLength; j++)
        {
            if (mask[j] != 'x')
                continue;
            if (pattern[j] != base[i + j])
            {
                found = false;
                break;
            }
        }
        if (found)
            return (void*)(base + i);
    }
    return NULL;
}

typedef char(__fastcall* sub_180001CDC_t)(PUCHAR pbInput, char* Buf2, DWORD* a3);
sub_180001CDC_t original_sub_180001CDC = NULL;

char __fastcall hooked_sub_180001CDC(PUCHAR pbInput, char* Buf2, DWORD* a3)
{
    if (a3)
        *a3 = 1; // Set a3 to indicate license ownership

    // Always return 1 to indicate success
    return 1;
}

void InitializeHook()
{
    // Get the base address and size of the module
    HMODULE hModule = GetModuleHandle(NULL);
    MODULEINFO modInfo;
    GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));

    // Find the pattern in the module
    void* targetAddress = FindPattern((BYTE*)modInfo.lpBaseOfDll, modInfo.SizeOfImage, pattern, mask);
    if (!targetAddress)
    {
        MessageBox(NULL, L"Pattern not found!", L"Error", MB_OK);
        return;
    }

    // Initialize MinHook
    if (MH_Initialize() != MH_OK)
    {
        MessageBox(NULL, L"MinHook initialization failed!", L"Error", MB_OK);
        return;
    }

    // Create a hook for the found function address
    if (MH_CreateHook(targetAddress, (LPVOID)&hooked_sub_180001CDC, reinterpret_cast<LPVOID*>(&original_sub_180001CDC)) != MH_OK)
    {
        MessageBox(NULL, L"Failed to create hook!", L"Error", MB_OK);
        return;
    }

    // Enable the hook
    if (MH_EnableHook(targetAddress) != MH_OK)
    {
        MessageBox(NULL, L"Failed to enable hook!", L"Error", MB_OK);
        return;
    }

    MessageBox(NULL, L"Hook installed successfully!", L"Success", MB_OK);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InitializeHook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        MH_Uninitialize();
        break;
    }
    return TRUE;
}