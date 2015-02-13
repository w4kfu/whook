#include "modules.h"

std::list<MODULEENTRY64> GetModuleList64(DWORD dwPid)
{
    PROCESS_BASIC_INFORMATION64 pbi64;
    HANDLE HProcess = NULL;
    ULONG64 Ldr64 = 0;
    PEB_LDR_DATA64 LdrData64;
    LDR_DATA_TABLE_ENTRY64 LdrDataTable64;
    wchar_t unicodeBuffer[MAX_PATH] = {0};
    MODULEENTRY64 mod;
    std::list<MODULEENTRY64> lModule;
    size_t ReturnValue;

    if ((HProcess = GetHandleProcess(dwPid)) == NULL)
        return lModule;
    pbi64 = GetRemotePEB64(HProcess);
    // +0x018 Ldr              : Ptr64 _PEB_LDR_DATA
    if (ReadMemory(HProcess, (PVOID64)(pbi64.PebBaseAddress + 0x18), &Ldr64, 8) == FALSE) {
        return lModule;
    }
    if (ReadMemory(HProcess, (PVOID64)(Ldr64), &LdrData64, sizeof (PEB_LDR_DATA64)) == FALSE) {
        return lModule;
    }
    if (ReadMemory(HProcess, (PVOID64)(LdrData64.InLoadOrderModuleList.Flink), &LdrDataTable64, sizeof (LDR_DATA_TABLE_ENTRY64)) == FALSE) {
        return lModule;
    }
    if (ReadMemory(HProcess, (PVOID64)(LdrDataTable64.BaseDllName.Buffer), unicodeBuffer, LdrDataTable64.BaseDllName.Length) == FALSE) {
        return lModule;
    }
    mod.DllBase = LdrDataTable64.DllBase;
    mod.EntryPoint = LdrDataTable64.EntryPoint;
    mod.SizeOfImage = LdrDataTable64.SizeOfImage;
    wcstombs_s(&ReturnValue, mod.BaseDllName, sizeof (mod.BaseDllName), unicodeBuffer, sizeof (mod.BaseDllName) - 1);
    mod.Flags = LdrDataTable64.Flags;
    mod.LoadCount = LdrDataTable64.LoadCount; 
    lModule.push_back(mod);
    while (LdrData64.InLoadOrderModuleList.Flink != LdrDataTable64.InLoadOrderModuleList.Flink) {
        if (ReadMemory(HProcess, (PVOID64)(LdrDataTable64.InLoadOrderModuleList.Flink), &LdrDataTable64, sizeof (LDR_DATA_TABLE_ENTRY64)) == FALSE) {
            return lModule;
        }
        if (LdrData64.InLoadOrderModuleList.Flink == LdrDataTable64.InLoadOrderModuleList.Flink)
            break;
        memset(unicodeBuffer, 0, sizeof (unicodeBuffer));
        if (ReadMemory(HProcess, (PVOID64)(LdrDataTable64.BaseDllName.Buffer), unicodeBuffer, LdrDataTable64.BaseDllName.Length) == FALSE) {
            return lModule;
        }
        mod.DllBase = LdrDataTable64.DllBase;
        mod.EntryPoint = LdrDataTable64.EntryPoint;
        mod.SizeOfImage = LdrDataTable64.SizeOfImage;
        wcstombs_s(&ReturnValue, mod.BaseDllName, sizeof (mod.BaseDllName), unicodeBuffer, sizeof (mod.BaseDllName) - 1);
        mod.Flags = LdrDataTable64.Flags;
        mod.LoadCount = LdrDataTable64.LoadCount; 
        lModule.push_back(mod);
    }
    return lModule;
}

std::list<MODULEENTRY32> GetModuleList(DWORD dwPid)
{
    MODULEENTRY32 mod;
    HANDLE TH32S;
    std::list<MODULEENTRY32> lModule;

    if ((Is64bitOS() == TRUE) && (IsWow64(dwPid) == FALSE)) {
        printf("[-] Please use GetModuleList64!\n");
        ExitProcess(42);
    }
    TH32S = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
    if (TH32S == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] GetModuleList - CreateToolhelp32Snapshot failed: %lu\n", GetLastError());
        return lModule;
    }
    mod.dwSize = sizeof (MODULEENTRY32);
    Module32First(TH32S, &mod);
    do
    {
        lModule.push_back(mod);
    } while (Module32Next(TH32S, &mod));
    return lModule;
}

BOOL IsModuleExist(DWORD dwPid, char *szModuleName)
{
    MODULEENTRY32 mod;
    HANDLE TH32S;

    TH32S = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPid);
    mod.dwSize = sizeof (MODULEENTRY32);
    Module32First(TH32S, &mod);
    do
    {
        if (!_stricmp(szModuleName, mod.szModule))
            return TRUE;
    } while (Module32Next(TH32S, &mod));
    return FALSE;
}

std::list<MODULEENTRY32> GetModuleList(char *szModuleName)
{
    DWORD dwPID;
    std::list<MODULEENTRY32> lModule;

    dwPID = GetPidProcess(szModuleName);
    if (!dwPID)
        return lModule;
    return GetModuleList(dwPID);
}
