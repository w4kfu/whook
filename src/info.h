#ifndef __INFO_H__
#define __INFO_H__

#include <stdio.h>

#include "process.h"
#include "modules.h"

void PrintProcessList(std::list<PROCESSENTRY32> lProcess);
void PrintPidProcess(char *szModuleName, DWORD dwPid);
void PrintModulesList(std::list<MODULEENTRY32> lModules);

void PrintMemoryInfo(std::list<MEMORY_BASIC_INFORMATION> lMemBI);

#endif // __INFO_H__
