#ifndef __THREADS_H__
#define __THREADS_H__

#include <windows.h>
#include <tlhelp32.h>
#include <list>

std::list<THREADENTRY32> GetThreadsList(DWORD dwPID);
HANDLE GetHandleThread(DWORD dwTid);
BOOL SuspendAllThread(DWORD dwPID);
BOOL ResumeAllThread(DWORD dwPID);

#endif // __THREADS_H__
