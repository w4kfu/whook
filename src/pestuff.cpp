#include "pestuff.h"

PROCESS_BASIC_INFORMATION32 GetRemotePEB32(HANDLE HProcess)
{
    PROCESS_BASIC_INFORMATION32 pbi;
    NTSTATUS (__stdcall *ZwQueryInformationProcess)(
                HANDLE  ProcessHandle,
                PROCESSINFOCLASS  ProcessInformationClass,
                PVOID  ProcessInformation,
                ULONG  ProcessInformationLength,
                PULONG  ReturnLength  OPTIONAL
        );

    memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION32));
    ZwQueryInformationProcess = (long (__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll"), "ZwQueryInformationProcess");
    if (!ZwQueryInformationProcess) {
        fprintf(stderr, "[-] GetRemotePEB - GetProcAddress() failed : %X\n", GetLastError());
        return pbi;
    }
    if (ZwQueryInformationProcess(HProcess, 0, &pbi, sizeof(PROCESS_BASIC_INFORMATION32), NULL) != 0) {
        fprintf(stderr, "[-] GetRemotePEB - ZwQueryInformation failed : %X\n", GetLastError());
        return pbi;
    }
    return pbi;
}

PROCESS_BASIC_INFORMATION64 GetRemotePEB64(HANDLE HProcess)
{
    PROCESS_BASIC_INFORMATION64 pbi;
    NTSTATUS (__stdcall *ZwQueryInformationProcess)(
                HANDLE  ProcessHandle,
                PROCESSINFOCLASS  ProcessInformationClass,
                PVOID  ProcessInformation,
                ULONG  ProcessInformationLength,
                PULONG  ReturnLength  OPTIONAL
        );

    memset(&pbi, 0, sizeof(PROCESS_BASIC_INFORMATION64));
    ZwQueryInformationProcess = (long (__stdcall *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG))GetProcAddress(GetModuleHandleA("ntdll"), "NtWow64QueryInformationProcess64");
    if (!ZwQueryInformationProcess) {
        fprintf(stderr, "[-] GetRemotePEB - GetProcAddress() failed : %lu\n", GetLastError());
        return pbi;
    }
    if (ZwQueryInformationProcess(HProcess, 0, &pbi, sizeof(pbi), NULL) != 0) {
        fprintf(stderr, "[-] GetRemotePEB - ZwQueryInformation failed : %lu\n", GetLastError());
        return pbi;
    }
    return pbi;
}

ULONG64 GetRemoteBaseAddress(DWORD dwPid)
{
    PROCESS_BASIC_INFORMATION32 pbi32;
    PROCESS_BASIC_INFORMATION64 pbi64;
    ULONG64 dwImageBase = 0;
    HANDLE HProcess = NULL;

    if ((HProcess = GetHandleProcess(dwPid)) == NULL)
        return 0;
    if ((Is64bitOS() == TRUE) && (IsWow64(HProcess) == FALSE)) {
        pbi64 = GetRemotePEB64(HProcess);
        printf("%I64X\n", pbi64.PebBaseAddress);
        if (ReadMemory(HProcess, (PVOID64)(pbi64.PebBaseAddress + 0x10), &dwImageBase, 8) == FALSE) {
            return 0;
        }
    }
    else {
        pbi32 = GetRemotePEB32(HProcess);
        if (pbi32.uUniqueProcessId != dwPid)
            return 0;
        if (ReadMemory(HProcess, (LPCVOID)(pbi32.PebBaseAddress + 8), &dwImageBase, 4) == FALSE) {
            return 0;
        }    
    }
    return dwImageBase;
}

/*IMAGE_DOS_HEADER GetDosHeader(DWORD dwPid)
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
}*/

/*IMAGE_NT_HEADERS GetNTHeader(DWORD dwPid)
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
}*/
