#ifndef __PROCESS_H__
#define __PROCESS_H__

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <list>

#include "modules.h"

#pragma comment(lib,"Psapi.lib")

std::list<PROCESSENTRY32> GetProcessList(void);

BOOL IsInProcessList(std::list<PROCESSENTRY32> lProcess, LPCSTR ImageName);
BOOL IsInProcessList(LPCSTR ImageName);

DWORD GetPidProcess(std::list<PROCESSENTRY32> lProcess, LPCSTR ImageName);
DWORD GetPidProcess(LPCSTR ImageName);


HANDLE GetHandleProcess(DWORD dwPid);
PROCESSENTRY32 GetPE32(DWORD dwPid);

#endif // __PROCESS_H__
