#include "dump.h"

DWORD AlignSize(DWORD size, DWORD alignement)
{
    return (size % alignement == 0) ? size : ((size / alignement) + 1 ) * alignement;
}

PBYTE AllocEnough(HMODULE hModule, DWORD *dwAllocSize)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT32;
    PIMAGE_NT_HEADERS64 pNT64;
    PIMAGE_SECTION_HEADER pSection;
    PBYTE pDump = NULL;

    pDos = (PIMAGE_DOS_HEADER)hModule;
    if (IsPE64Bit(hModule)) {
        pNT64 = (PIMAGE_NT_HEADERS64)((DWORD)hModule + pDos->e_lfanew);
        pSection = (PIMAGE_SECTION_HEADER)((DWORD)pNT64 + sizeof(IMAGE_NT_HEADERS64));
        *dwAllocSize = pSection[pNT64->FileHeader.NumberOfSections - 1].VirtualAddress + pSection[pNT64->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
    }
    else {
        pNT32 = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
        pSection = (PIMAGE_SECTION_HEADER)((DWORD)pNT32 + sizeof(IMAGE_NT_HEADERS));
        *dwAllocSize = pSection[pNT32->FileHeader.NumberOfSections - 1].VirtualAddress + pSection[pNT32->FileHeader.NumberOfSections - 1].Misc.VirtualSize;
    }
    pDump = (PBYTE)VirtualAlloc(NULL, *dwAllocSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDump)
        return NULL;
    return pDump;
}

DUMPED_PE GetRemotePE(DWORD dwPid)
{
    ULONG64 dwBaseAddress = 0;
    ULONG64 dwImageSize = 0;
    HANDLE HProcess;
    DUMPED_PE DumpedPE;

    DumpedPE.pDump = NULL;
    DumpedPE.dwImageSize = 0;
    if ((HProcess = GetHandleProcess(dwPid)) == NULL)
        return DumpedPE;
    dwBaseAddress = GetRemoteBaseAddress(HProcess);
    dwImageSize = GetModuleSize(dwPid, dwBaseAddress);
    printf("[+] dwBaseAddress : 0x%016llX\n", dwBaseAddress);
    printf("[+] dwImageSize : 0x%016llX\n", dwImageSize);
    DumpedPE.dwImageSize = dwImageSize;
    DumpedPE.pDump = (PBYTE)VirtualAlloc(NULL, (SIZE_T)dwImageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    printf("[+] VirtualAlloc: %08X\n", DumpedPE.pDump);
    printf("[+] dwImageSize: %08X\n", dwImageSize);
    printf("[+] VirtualAlloc + dwImageSize: %08X\n", (DWORD)DumpedPE.pDump + dwImageSize);
    if (DumpedPE.pDump == NULL) {
        fprintf(stderr, "[-] VirtualAlloc failed\n");
        return DumpedPE;
    }
    if (Is64BitProcess(HProcess) == TRUE) {
        if (ReadMemory(HProcess, (PVOID64)(dwBaseAddress), DumpedPE.pDump, (SIZE_T)dwImageSize) == FALSE) {
            fprintf(stderr, "[-] GetRemotePE - ReadMemory failed\n");
            VirtualFree(DumpedPE.pDump, (SIZE_T)dwImageSize, 0);
            DumpedPE.pDump = NULL;
            return DumpedPE;
        }   
    }
    else {
        if (ReadMemory(HProcess, (LPCVOID)(dwBaseAddress), DumpedPE.pDump, (SIZE_T)dwImageSize) == FALSE) {
            fprintf(stderr, "[-] GetRemotePE - ReadMemory failed\n");
            VirtualFree(DumpedPE.pDump, (SIZE_T)dwImageSize, 0);
            DumpedPE.pDump = NULL;
            return DumpedPE;
        }    
    }
    return DumpedPE;
}

BOOL DumpPE(HMODULE hModule, LPCSTR dumpFileName)
{
    PIMAGE_DOS_HEADER pDos;
    PIMAGE_NT_HEADERS pNT32;
    PIMAGE_NT_HEADERS64 pNT64;
    PIMAGE_SECTION_HEADER pSection;
    PBYTE pDump = NULL;
    DWORD dwAllocSize = 0;
    DWORD dwFinalSize = 0;
    DWORD NumberOfSections = 0;
    DWORD FileAlignment = 0;
    DWORD dwAlign = 0;

	pDump = AllocEnough(hModule, &dwAllocSize);
	if (!pDump) {
        fprintf(stderr, "[-] AllocEnough failed\n");
        return FALSE;
    }
    
    /* Copy DOS HEADER */
    memcpy(pDump, (LPVOID)hModule, sizeof (IMAGE_DOS_HEADER));
	dwFinalSize += sizeof (IMAGE_DOS_HEADER);
    pDos = (PIMAGE_DOS_HEADER)hModule;
    if (IsPE64Bit(hModule)) {
        pNT64 = (PIMAGE_NT_HEADERS64)((DWORD)hModule + pDos->e_lfanew);
        /* Copy PADDING */
        memcpy(pDump + dwFinalSize, (LPVOID)((DWORD)hModule + dwFinalSize), (DWORD)pNT64 - (DWORD)((DWORD)pDos + sizeof (IMAGE_DOS_HEADER)));
        dwFinalSize += (DWORD)pNT64 - (DWORD)((DWORD)pDos + sizeof (IMAGE_DOS_HEADER));
        /* Copy NT HEADER */
        memcpy(pDump + dwFinalSize, (LPVOID)pNT64, sizeof (IMAGE_FILE_HEADER) + pNT64->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
        dwFinalSize += sizeof (IMAGE_FILE_HEADER) + pNT64->FileHeader.SizeOfOptionalHeader + sizeof(DWORD);          
        NumberOfSections = pNT64->FileHeader.NumberOfSections;
        FileAlignment = pNT64->OptionalHeader.FileAlignment;
        pSection = (PIMAGE_SECTION_HEADER)((DWORD)pNT64 + sizeof(IMAGE_NT_HEADERS64));
    }
    else {
        pNT32 = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDos->e_lfanew);
        /* Copy PADDING */
        memcpy(pDump + dwFinalSize, (LPVOID)((DWORD)hModule + dwFinalSize), (DWORD)pNT32 - (DWORD)((DWORD)pDos + sizeof (IMAGE_DOS_HEADER)));
        dwFinalSize += (DWORD)pNT32 - (DWORD)((DWORD)pDos + sizeof (IMAGE_DOS_HEADER));        
        /* Copy NT HEADER */
        memcpy(pDump + dwFinalSize, (LPVOID)pNT32, sizeof (IMAGE_FILE_HEADER) + pNT32->FileHeader.SizeOfOptionalHeader + sizeof(DWORD));
        dwFinalSize += sizeof (IMAGE_FILE_HEADER) + pNT32->FileHeader.SizeOfOptionalHeader + sizeof(DWORD);       
        NumberOfSections = pNT32->FileHeader.NumberOfSections;
        FileAlignment = pNT32->OptionalHeader.FileAlignment;
        pSection = (PIMAGE_SECTION_HEADER)((DWORD)pNT32 + sizeof(IMAGE_NT_HEADERS));
    }    
    /* Copy Sections */
	memcpy(pDump + dwFinalSize, (LPVOID)pSection, sizeof (IMAGE_SECTION_HEADER) * NumberOfSections);
	dwFinalSize += sizeof (IMAGE_SECTION_HEADER) * NumberOfSections;  
    dwAlign = AlignSize(dwFinalSize, FileAlignment);
	for (; dwFinalSize < dwAlign; dwFinalSize++)
		*(pDump + dwFinalSize) = 0;  
    for (DWORD i = 0; i < NumberOfSections; i++) {
        printf("%08X\n", pSection[i].VirtualAddress);
        printf("%08X\n", hModule + pSection[i].VirtualAddress);
        printf("%08X\n", pSection[i].SizeOfRawData);
        memcpy(pDump + dwFinalSize, (LPVOID)((DWORD)hModule + pSection[i].VirtualAddress), pSection[i].SizeOfRawData);
        dwFinalSize += pSection[i].SizeOfRawData;
        dwAlign = AlignSize(dwFinalSize, FileAlignment);
        for (; dwFinalSize < dwAlign; dwFinalSize++)
            *(pDump + dwFinalSize) = 0;
    }
    return Write2File(dumpFileName, pDump, dwFinalSize);
}

VOID DumpPE(DWORD dwPid, LPCSTR dumpFileName)
{
    /*DWORD dwBaseAddress;
    IMAGE_DOS_HEADER Dos;
    IMAGE_NT_HEADERS NT32;
    HANDLE HProcess;*/
    DUMPED_PE DumpedPE;
    
    (void)dumpFileName;
    
    DumpedPE = GetRemotePE(dwPid);
    if (DumpedPE.pDump == NULL) {
        printf("DumpPE - GetRemotePE failed\n");
        return;
    }
    DumpPE((HMODULE)DumpedPE.pDump, dumpFileName);
    /*if ((HProcess = GetHandleProcess(dwPid)) == NULL)
        return;
    if (Is64BitProcess(HProcess) == TRUE) {
        printf("[+] NOT IMPLEMENTED!\n");
        return;
    }
    dwBaseAddress = (DWORD)GetRemoteBaseAddress(HProcess);
    printf("[+] dwBaseAddress: %08X\n", dwBaseAddress);
    if (ReadMemory(HProcess, (LPCVOID)(dwBaseAddress), &Dos, sizeof (IMAGE_DOS_HEADER)) == FALSE) {
        fprintf(stderr, "[-] DumpPE - ReadMemory failed\n");
        return;
    }*/
}