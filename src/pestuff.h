#ifndef __PESTUFF_H__
#define __PESTUFF_H__

#include <windows.h>
#include <list>

#include "process.h"
#include "memory.h"

#if !defined NTSTATUS
typedef LONG NTSTATUS;
#endif

#define STATUS_SUCCESS 0

#if !defined PROCESSINFOCLASS
typedef LONG PROCESSINFOCLASS;
#endif

#if !defined PPEB
typedef struct _PEB *PPEB;
#endif

#if !defined PROCESS_BASIC_INFORMATION
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PPEB PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;
#endif;

NTSTATUS (__stdcall *ZwQueryInformationProcess)(
  HANDLE  ProcessHandle,
  PROCESSINFOCLASS  ProcessInformationClass,
  PVOID  ProcessInformation,
  ULONG  ProcessInformationLength,
  PULONG  ReturnLength  OPTIONAL
  );


PROCESS_BASIC_INFORMATION GetRemotePEB(DWORD dwPid);
DWORD GetRemoteBaseAddress(DWORD dwPid);


#endif // __PESTUFF_H__
