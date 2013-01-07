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
