#include "info.h"

void PrintProcessList(std::list<PROCESSENTRY32> lProcess)
{
    std::list<PROCESSENTRY32>::const_iterator it;
    CHAR Name[25];
    
    printf("Image Name                PID      NBTHREAD\n");
    printf("========================= ======== =========\n");
    for (it = lProcess.begin(); it != lProcess.end(); ++it) {
        strncpy_s(Name, sizeof (Name), (*it).szExeFile, sizeof (Name) - 1);
        printf("%-25s %8d %9d\n", Name, (*it).th32ProcessID, (*it).cntThreads);
    }
}

void PrintTCPConnections(std::list<MIB_TCPROW_OWNER_PID> mib)
{
    std::list<MIB_TCPROW_OWNER_PID>::const_iterator it;
    struct sockaddr_in adr_inet;
    CHAR Temp[0x100] = {0};
    
    printf("LocalAddress          Foreign Address       State     PID     \n");
    printf("===================== ===================== ========= ========\n");
    for (it = mib.begin(); it != mib.end(); ++it) {
        adr_inet.sin_addr.s_addr = (*it).dwLocalAddr;
        sprintf_s(Temp, sizeof (Temp) - 1, "%s:%d", inet_ntoa(adr_inet.sin_addr), htons((short)(*it).dwLocalPort));
        adr_inet.sin_addr.s_addr = (*it).dwRemoteAddr;
        printf("%-22s", Temp);
        sprintf_s(Temp, sizeof (Temp) - 1, "%s:%d", inet_ntoa(adr_inet.sin_addr), htons((short)(*it).dwRemotePort));
        printf("%-22s", Temp);
        printf("%9d %8d\n", (*it).dwState, (*it).dwOwningPid);
    }
}

void PrintTCPConnectionsv6(std::list<MIB_TCP6ROW_OWNER_PID> mib)
{
    std::list<MIB_TCP6ROW_OWNER_PID>::const_iterator it;
    typedef LPTSTR (__stdcall *lpfn_RtlIpv6AddressToStringA)(IN6_ADDR*,LPTSTR);
    lpfn_RtlIpv6AddressToStringA RtlIpv6AddressToStringA; 
    CHAR Temp[0x100] = {0};
    IN6_ADDR addr;
    CHAR saddr[50];
    
    RtlIpv6AddressToStringA = (lpfn_RtlIpv6AddressToStringA)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlIpv6AddressToStringA"); 
    if (RtlIpv6AddressToStringA == NULL) {
        fprintf(stderr, "[-] PrintTCPConnectionsv6 - GetProcAddress failed: %lu\n", GetLastError());
        return;
    }
    printf("LocalAddress                                      Foreign Address                                   State     PID     \n");
    printf("================================================= ================================================= ========= ========\n");
    for (it = mib.begin(); it != mib.end(); ++it) {
        memcpy(addr.u.Byte, (*it).ucLocalAddr, 16);
        RtlIpv6AddressToStringA(&addr, saddr);
        sprintf_s(Temp, sizeof (Temp) - 1, "[%s]:%d", saddr, htons((short)(*it).dwLocalPort));
        printf("%-50s", Temp);
        memcpy(addr.u.Byte, (*it).ucRemoteAddr, 16);
        RtlIpv6AddressToStringA(&addr, saddr);
        sprintf_s(Temp, sizeof (Temp) - 1, "[%s]:%d", saddr, htons((short)(*it).dwRemotePort));
        printf("%-50s", Temp);
        printf("%9d %8d\n", (*it).dwState, (*it).dwOwningPid);
    }
}

void PrintUDPConnections(std::list<MIB_UDPROW_OWNER_PID> mib)
{
    std::list<MIB_UDPROW_OWNER_PID>::const_iterator it;
    struct sockaddr_in adr_inet;
    CHAR Temp[0x100] = {0};
    
    printf("LocalAddress          Foreign Address       PID     \n");
    printf("===================== ===================== ========\n");
    for (it = mib.begin(); it != mib.end(); ++it) {
        adr_inet.sin_addr.s_addr = (*it).dwLocalAddr;
        sprintf_s(Temp, sizeof (Temp) - 1, "%s:%d", inet_ntoa(adr_inet.sin_addr), htons((short)(*it).dwLocalPort));
        printf("%-22s", Temp);
        sprintf_s(Temp, sizeof (Temp) - 1, "*:*");
        printf("%-22s", Temp);
        printf("%8d\n", (*it).dwOwningPid);
    }
}

void PrintUDPConnectionsv6(std::list<MIB_UDP6ROW_OWNER_PID> mib)
{
    std::list<MIB_UDP6ROW_OWNER_PID>::const_iterator it;
    typedef LPTSTR (__stdcall *lpfn_RtlIpv6AddressToStringA)(IN6_ADDR*,LPTSTR);
    lpfn_RtlIpv6AddressToStringA RtlIpv6AddressToStringA; 
    CHAR Temp[0x100] = {0};
    IN6_ADDR addr;
    CHAR saddr[50];
    
    RtlIpv6AddressToStringA = (lpfn_RtlIpv6AddressToStringA)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlIpv6AddressToStringA"); 
    if (RtlIpv6AddressToStringA == NULL) {
        fprintf(stderr, "[-] PrintTCPConnectionsv6 - GetProcAddress failed: %lu\n", GetLastError());
        return;
    }
    printf("LocalAddress                                      Foreign Address       PID     \n");
    printf("================================================= ===================== ========\n");
    for (it = mib.begin(); it != mib.end(); ++it) {
        memcpy(addr.u.Byte, (*it).ucLocalAddr, 16);
        RtlIpv6AddressToStringA(&addr, saddr);
        sprintf_s(Temp, sizeof (Temp) - 1, "[%s]:%d", saddr, htons((short)(*it).dwLocalPort));
        printf("%-50s", Temp);
        sprintf_s(Temp, sizeof (Temp) - 1, "*:*");
        printf("%-22s", Temp);
        printf("%8d\n", (*it).dwOwningPid);
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

void PrintPatternMatch(std::list<LPCVOID> lAddress)
{
    std::list<LPCVOID>::const_iterator it;

    for (it = lAddress.begin(); it != lAddress.end(); ++it)
    {
        printf("Address : %08X\n", *it);
    }
}

void PrintDosHeader(PIMAGE_DOS_HEADER pDosHeader)
{
    printf("e_magic : %04X\n", pDosHeader->e_magic);
    // ...
    printf("e_lfanew : %04X\n", pDosHeader->e_lfanew);
}

void PrintNTHeader(PIMAGE_NT_HEADERS pNTHeader)
{
    printf("Signature : %04X\n", pNTHeader->Signature);
    printf("NumberOfSections : %04X\n", pNTHeader->FileHeader.NumberOfSections);

}
