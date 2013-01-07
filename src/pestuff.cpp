#include "pestuff.h"

PROCESS_BASIC_INFORMATION GetRemotePEB(DWORD dwPid)
{
	PROCESS_BASIC_INFORMATION pbi;
	HANDLE HProcess;

	memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));

	ZwQueryInformationProcess = (long (__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll"),"ZwQueryInformationProcess");

	if (!ZwQueryInformationProcess)
	{
		fprintf(stderr, "[-] GetProcAddress() failed : %X\n", GetLastError());
		return pbi;
	}
	if ((HProcess = GetHandleProcess(dwPid)) == NULL)
        return pbi;
	if (ZwQueryInformationProcess(HProcess, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL) != 0)
    {
		fprintf(stderr, "[-] ZwQueryInformation failed : %X\n", GetLastError());
		return pbi;
    }
    return pbi;
}

DWORD GetRemoteBaseAddress(DWORD dwPid)
{
	PROCESS_BASIC_INFORMATION pbi;
	DWORD dwImageBase;

	pbi = GetRemotePEB(dwPid);
	if (pbi.UniqueProcessId != dwPid)
        return 0;
	if (ReadMemory(dwPid, (BYTE*)pbi.PebBaseAddress + 8, &dwImageBase, 4) == FALSE)
	{
		return 0;
	}
	return dwImageBase;
}
