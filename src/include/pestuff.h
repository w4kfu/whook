#ifndef __PESTUFF_H__
#define __PESTUFF_H__

#include <windows.h>
#include <list>

#include "process.h"
#include "memory.h"
#include "utils.h"

#if !defined NTSTATUS
typedef LONG NTSTATUS;
#endif

typedef LONG		KPRIORITY;

#define STATUS_SUCCESS 0

#if !defined PROCESSINFOCLASS
typedef LONG PROCESSINFOCLASS;
#endif

#if !defined PPEB
typedef struct _PEB *PPEB;
#endif

typedef struct _PROCESS_BASIC_INFORMATION32
{
	NTSTATUS	ExitStatus;
	ULONG		PebBaseAddress;
	ULONG		AffinityMask;
	KPRIORITY	BasePriority;
	ULONG		uUniqueProcessId;
	ULONG		uInheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32, *PPROCESS_BASIC_INFORMATION32;

typedef struct _PROCESS_BASIC_INFORMATION64
{
	NTSTATUS	ExitStatus;
	ULONG		Reserved0;
	ULONG64		PebBaseAddress;
	ULONG64		AffinityMask;
	KPRIORITY	BasePriority;
	ULONG		Reserved1;
	ULONG64		uUniqueProcessId;
	ULONG64		uInheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION64, *PPROCESS_BASIC_INFORMATION64;

PROCESS_BASIC_INFORMATION32 GetRemotePEB32(HANDLE HProcess);
PROCESS_BASIC_INFORMATION64 GetRemotePEB64(HANDLE HProcess);
ULONG64 GetRemoteBaseAddress(DWORD dwPid);
IMAGE_DOS_HEADER GetDosHeader(DWORD dwPid);
IMAGE_NT_HEADERS GetNTHeader(DWORD dwPid);


#endif // __PESTUFF_H__
