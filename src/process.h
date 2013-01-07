#ifndef __PROCESS_H__
#define __PROCESS_H__

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <list>

#include "modules.h"

#pragma comment(lib,"Psapi.lib")

std::list<PROCESSENTRY32> GetProcessList(void);
HANDLE GetHandleProcess(DWORD dwPid);
PROCESSENTRY32 GetPE32(DWORD dwPid);
DWORD GetPidProcess(char *szModuleName);

#endif // __PROCESS_H__
