#ifndef __MODULES_H__
#define __MODULES_H__

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <Tlhelp32.h>
#include <list>

#include "process.h"
#include "utils.h"
#include "pestuff.h"

typedef struct _UNICODE_STRING64 
{
    USHORT	Length;
    USHORT	MaximumLength;
	ULONG	Reserved;
    ULONG64 Buffer;
} UNICODE_STRING64, *PUNICODE_STRING64;

typedef struct _LDR_DATA_TABLE_ENTRY64
{
    LIST_ENTRY64		InLoadOrderModuleList;
    LIST_ENTRY64		InMemoryOrderModuleList;
    LIST_ENTRY64		InInitializationOrderModuleList;
    ULONG64				DllBase;
    ULONG64				EntryPoint;
    ULONG				SizeOfImage;
	UNICODE_STRING64	FullDllName;
    UNICODE_STRING64	BaseDllName;
	ULONG				Flags;
	USHORT				LoadCount;
} LDR_DATA_TABLE_ENTRY64, *PLDR_DATA_TABLE_ENTRY64;

typedef struct _MODULEENTRY64
{
    ULONG64				DllBase;
    ULONG64				EntryPoint;
    ULONG				SizeOfImage;
    CHAR                FullDllName[MAX_PATH];
    CHAR                BaseDllName[MAX_PATH]; 
	ULONG				Flags;
	USHORT				LoadCount;
} MODULEENTRY64, *PMODULEENTRY64;

std::list<MODULEENTRY64> GetModuleList64(DWORD dwPid);
std::list<MODULEENTRY32> GetModuleList(DWORD dwPid);
BOOL IsModuleExist(DWORD dwPid, char *szModuleName);
std::list<MODULEENTRY32> GetModuleList(char *szModuleName);
ULONG64 GetModuleSize(DWORD dwPid, ULONG64 BaseAddress);

#endif // __MODULES_H__
