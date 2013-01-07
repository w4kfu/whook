#include "info.h"

void PrintProcessList(std::list<PROCESSENTRY32> lProcess)
{
    std::list<PROCESSENTRY32>::const_iterator it;

    for (it = lProcess.begin(); it != lProcess.end(); ++it)
    {
        printf("szExeFile : %s\n", (*it).szExeFile);
        printf("\tth32ProcessID : %d (0x%X)\tcntThreads : %d\n", (*it).th32ProcessID, (*it).th32ProcessID, (*it).cntThreads);
    }
}

void PrintPidProcess(char *szModuleName, DWORD dwPid)
{
    printf("szModuleName : %s, PID : %d (0x%X)\n", szModuleName, dwPid, dwPid);
}

void PrintModulesList(std::list<MODULEENTRY32> lModules)
{
    std::list<MODULEENTRY32>::const_iterator it;

    for (it = lModules.begin(); it != lModules.end(); ++it)
    {
        printf("szModule : %s\n", (*it).szModule);
        printf("\tszExePath : %s\n", (*it).szExePath);
        printf("\tmodBaseAddr : %08X\tmodBaseSize\n", (*it).modBaseAddr, (*it).modBaseSize);
    }
}

void PrintMemoryInfo(std::list<MEMORY_BASIC_INFORMATION> lMemBI)
{
    std::list<MEMORY_BASIC_INFORMATION>::const_iterator it;

    for (it = lMemBI.begin(); it != lMemBI.end(); ++it)
    {
        printf("BaseAddress : %08X\tRegionSize : %08X\tProtect : %08X\n", (*it).BaseAddress, (*it).RegionSize, (*it).Protect);
    }
}

void PrintThreadsInfo(std::list<THREADENTRY32> lThreads)
{
    std::list<THREADENTRY32>::const_iterator it;

    for (it = lThreads.begin(); it != lThreads.end(); ++it)
    {
        printf("th32ThreadID : %08X\ttpBasePri : %08X\ttpDeltaPri : %08X\n", (*it).th32ThreadID, (*it).tpBasePri, (*it).tpDeltaPri);
    }
}
