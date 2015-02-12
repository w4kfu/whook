#include <stdio.h>

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "process.h"
#include "info.h"
#include "utils.h"
#include "pestuff.h"
#include "network.h"

int main(int argc, char *argv[])
{
    std::list<PROCESSENTRY32> lProcess;
    std::list<MIB_TCPROW_OWNER_PID> lMib;
    std::list<MIB_UDPROW_OWNER_PID> lMuib;
    std::list<MIB_TCP6ROW_OWNER_PID> lMibv6;
    std::list<MIB_UDP6ROW_OWNER_PID> lMuibv6;
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
    
    lMib = GetTCPConnections();
    PrintTCPConnections(lMib);
    lMuib = GetUDPConnections();
    PrintUDPConnections(lMuib);
    lMibv6 = GetTCPConnectionsv6();
    PrintTCPConnectionsv6(lMibv6);
    lMuibv6 = GetUDPConnectionsv6();
    PrintUDPConnectionsv6(lMuibv6);
    
    CloseTCPConnectionRemote(lMib, "88.198.127.131", 13337);
    
    return 0;
}