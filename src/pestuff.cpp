#include "pestuff.h"

PROCESS_BASIC_INFORMATION GetRemotePEB(DWORD dwPid)
{
    PROCESS_BASIC_INFORMATION pbi;
    HANDLE HProcess;
    NTSTATUS (__stdcall *ZwQueryInformationProcess)(
                HANDLE  ProcessHandle,
                PROCESSINFOCLASS  ProcessInformationClass,
                PVOID  ProcessInformation,
                ULONG  ProcessInformationLength,
                PULONG  ReturnLength  OPTIONAL
        );


    memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION));
    ZwQueryInformationProcess = (long (__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll"), "ZwQueryInformationProcess");
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

IMAGE_DOS_HEADER GetDosHeader(DWORD dwPid)
{
    IMAGE_DOS_HEADER DosHeader;
    DWORD dwImageBase;

    memset(&DosHeader, 0, sizeof (DosHeader));
    dwImageBase = GetRemoteBaseAddress(dwPid);
    if (ReadMemory(dwPid, (BYTE*)dwImageBase, &DosHeader, sizeof (DosHeader)) == FALSE)
    {
        return DosHeader;
    }
    return DosHeader;
}

IMAGE_NT_HEADERS GetNTHeader(DWORD dwPid)
{
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS NTHeader;
    DWORD dwImageBase;

    memset(&NTHeader, 0, sizeof (NTHeader));
    DosHeader = GetDosHeader(dwPid);
    dwImageBase = GetRemoteBaseAddress(dwPid);
    if (ReadMemory(dwPid, (BYTE*)dwImageBase + DosHeader.e_lfanew, &NTHeader, sizeof (NTHeader)) == FALSE)
    {
        return NTHeader;
    }
    return NTHeader;
}
