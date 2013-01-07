#include "modules.h"

std::list<MODULEENTRY32> GetModuleList(DWORD dwPid)
{
    MODULEENTRY32 mod;
    HANDLE TH32S;
    std::list<MODULEENTRY32> lModule;

    TH32S = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, dwPid);
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

    TH32S = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE32 | TH32CS_SNAPMODULE, dwPid);
    mod.dwSize = sizeof (MODULEENTRY32);
    Module32First(TH32S, &mod);
    do
    {
        if (!strcmp(szModuleName, mod.szModule))
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
