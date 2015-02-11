#include <stdio.h>
#include <windows.h>

#include "process.h"
#include "info.h"
#include "utils.h"
#include "pestuff.h"

int main(int argc, char *argv[])
{
    std::list<PROCESSENTRY32> lProcess;
    DWORD dwPid;
    (void)argc;
    (void)argv;
    
    if (!EnablePrivilege(SE_DEBUG_NAME, TRUE)) {
        printf("[-] SeDebugPrivilege failed : %u\n", GetLastError());
        return -1;
    }    
    
    printf("[+] Is64bitOS : %d\n", Is64bitOS());
    printf("[+] IsWow64(GetCurrentProcess()) : %d\n", IsWow64(GetCurrentProcess()));
    
    lProcess = GetProcessList();
    PrintProcessList(lProcess);    
    printf("%d\n", IsInProcessList(lProcess, "calc.exe"));
    dwPid = GetPidProcess("calc.exe");
    printf("%08X\n", GetHandleProcess(dwPid));
    printf("%llX\n", GetRemoteBaseAddress(dwPid));
    return 0;
}