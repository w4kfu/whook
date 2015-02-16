#ifndef __INFO_H__
#define __INFO_H__

#include <stdio.h>

#include "process.h"
#include "modules.h"
#include "network.h"

void PrintProcessList(std::list<PROCESSENTRY32> lProcess);
void PrintTCPConnections(std::list<MIB_TCPROW_OWNER_PID> mib);
void PrintTCPConnectionsv6(std::list<MIB_TCP6ROW_OWNER_PID> mib);
void PrintUDPConnections(std::list<MIB_UDPROW_OWNER_PID> mib);
void PrintUDPConnectionsv6(std::list<MIB_UDP6ROW_OWNER_PID> mib);


void PrintPidProcess(char *szModuleName, DWORD dwPid);
void PrintModulesList(std::list<MODULEENTRY32> lModules);
void PrintModulesList(std::list<MODULEENTRY64> lModules);
void PrintExportEntry(std::list<EXPORTENTRY> lExport);


void PrintMemoryInfo(std::list<MEMORY_BASIC_INFORMATION32> lMemBI);
void PrintMemoryInfo(std::list<MEMORY_BASIC_INFORMATION64> lMemBI);

//void PrintMemoryInfo(std::list<MEMORY_BASIC_INFORMATION> lMemBI);
void PrintThreadsInfo(std::list<THREADENTRY32> lThreads);
void PrintPatternMatch(std::list<LPCVOID> lAddress);
void PrintDosHeader(PIMAGE_DOS_HEADER pDosHeader);
void PrintNTHeader(PIMAGE_NT_HEADERS pNTHeader);

#endif // __INFO_H__
