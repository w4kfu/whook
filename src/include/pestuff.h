#ifndef __PESTUFF_H__
#define __PESTUFF_H__

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
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

typedef struct _PEB_LDR_DATA64
{
	ULONG			Length;
	BOOLEAN			Initialized;
	ULONG64			SsHandle;
	LIST_ENTRY64	InLoadOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InLoadOrderModuleList
	LIST_ENTRY64	InMemoryOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InMemoryOrderModuleList
	LIST_ENTRY64	InInitializationOrderModuleList; // ref. to PLDR_DATA_TABLE_ENTRY->InInitializationOrderModuleList
} PEB_LDR_DATA64, *PPEB_LDR_DATA64;

enum CHAMP_SECTION
{
    SEC_NAME = 0,
    SEC_VIRT_SIZE,
    SEC_VIRT_ADDR,
    SEC_RAW_SIZE,
    SEC_RAW_ADDR,
    SEC_CHARAC
};

typedef struct _EXPORTENTRY
{
    WORD Ordinal;
    ULONG FunctionRVA;
    CHAR FunctionName[256];
} EXPORTENTRY, *PEXPORTENTRY;

PROCESS_BASIC_INFORMATION32 GetRemotePBI32(HANDLE HProcess);
PROCESS_BASIC_INFORMATION64 GetRemotePBI64(HANDLE HProcess);
ULONG64 GetRemoteBaseAddress(DWORD dwPid);
ULONG64 GetRemoteBaseAddress(HANDLE HProcess);

BOOL IsPE64Bit(HMODULE hModule);
std::list<EXPORTENTRY> GetExport(HMODULE hModule);

//IMAGE_DOS_HEADER GetDosHeader(DWORD dwPid);
//IMAGE_NT_HEADERS GetNTHeader(DWORD dwPid);


#endif // __PESTUFF_H__
