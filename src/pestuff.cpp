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

PVOID GetSectionInfo(HMODULE hModule, DWORD dwAddr, DWORD dwChamp)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT32;
    PIMAGE_NT_HEADERS64 pNT64;
    PIMAGE_SECTION_HEADER pSection;
    WORD NumberOfSections;
    
    pDos = (PIMAGE_DOS_HEADER)hModule;
    if (IsPE64Bit(hModule)) {
        pNT64 = (PIMAGE_NT_HEADERS64)((DWORD)hModule + pDos->e_lfanew);
        pSection = (PIMAGE_SECTION_HEADER)((DWORD)pNT64 + sizeof(IMAGE_NT_HEADERS64));
        NumberOfSections = pNT64->FileHeader.NumberOfSections;
    }
    else {
        pNT32 = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
        pSection = (PIMAGE_SECTION_HEADER)((DWORD)pNT32 + sizeof(IMAGE_NT_HEADERS));
        NumberOfSections = pNT32->FileHeader.NumberOfSections;
    }
    for (WORD i = 0; i < NumberOfSections; i++) {
        if ((pSection->VirtualAddress <= dwAddr) && (dwAddr <= (pSection->VirtualAddress + pSection->Misc.VirtualSize))) {
            switch (dwChamp)
            {
                case SEC_NAME:
                    return (PVOID)pSection->Name;
                case SEC_VIRT_SIZE:
                    return (PVOID)pSection->Misc.VirtualSize;
                case SEC_VIRT_ADDR:
                    return (PVOID)pSection->VirtualAddress;
                case SEC_RAW_SIZE:
                    return (PVOID)pSection->SizeOfRawData;
                case SEC_RAW_ADDR:
                    return (PVOID)pSection->PointerToRawData;
                case SEC_CHARAC:
                    return (PVOID)pSection->Characteristics;
            }
        }
        pSection++;
    }
    return NULL;
}

DWORD RVA2Offset(HMODULE hModule, DWORD dwVA)
{
    DWORD VirtualAddress;
    DWORD PointerToRawData;

    VirtualAddress = (DWORD)GetSectionInfo(hModule, dwVA, SEC_VIRT_ADDR);
    PointerToRawData = (DWORD)GetSectionInfo(hModule, dwVA, SEC_RAW_ADDR);
	return ((dwVA - VirtualAddress) + PointerToRawData);
}

std::list<EXPORTENTRY> GetExport(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT32;
    PIMAGE_NT_HEADERS64 pNT64;
    PIMAGE_EXPORT_DIRECTORY pExport;
    WORD NameOrdinal;
    ULONG_PTR FunctionRVA;
    EXPORTENTRY Export;
    std::list<EXPORTENTRY> lExport;
    
    pDos = (PIMAGE_DOS_HEADER)hModule;
    if (IsPE64Bit(hModule)) {
        pNT64 = (PIMAGE_NT_HEADERS64)((DWORD)hModule + pDos->e_lfanew);
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNT64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else {
        pNT32 = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
        pExport = (PIMAGE_EXPORT_DIRECTORY)(pNT32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    pExport = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hModule, RVA2Offset(hModule, (DWORD)pExport) + (DWORD)hModule);
    PUSHORT pOrdinals = (PUSHORT)(RVA2Offset(hModule, pExport->AddressOfNameOrdinals) + (DWORD)hModule);
	PULONG pAddress = (PULONG)(RVA2Offset(hModule, pExport->AddressOfFunctions) + (DWORD)hModule);
	PULONG pApiNames = (PULONG)(RVA2Offset(hModule, pExport->AddressOfNames) + (DWORD)hModule);
    for (DWORD index = 0; index < pExport->NumberOfFunctions; index++) {
        NameOrdinal = pOrdinals[index];
        if (NameOrdinal >= pExport->NumberOfNames || NameOrdinal >= pExport->NumberOfFunctions)
            continue;
        FunctionRVA = pAddress[NameOrdinal];
        Export.Ordinal = NameOrdinal;
        Export.FunctionRVA = FunctionRVA;
        memset(Export.FunctionName, 0, 256);
        if (index >= pExport->NumberOfNames) {
            sprintf_s(Export.FunctionName, 256, "Ordinal_0x%08X", NameOrdinal);
        }
        else {
            strncpy_s(Export.FunctionName, 256, (char*)(RVA2Offset(hModule, pApiNames[index]) + (DWORD)hModule), 256 - 1);
        }
        lExport.push_back(Export);
    }
    return lExport;
}

BOOL IsPE64Bit(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT;
    
    pDos = (PIMAGE_DOS_HEADER)hModule;
    pNT = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
	if (pNT->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
		return FALSE;
	return TRUE;
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
