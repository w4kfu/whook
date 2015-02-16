#include "memory.h"

BOOL ReadMemory(DWORD dwPid, PVOID64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
{
    HANDLE HProcess;

    HProcess = GetHandleProcess(dwPid);
    if (HProcess == NULL)
        return FALSE;
    if (ReadMemory(HProcess, lpBaseAddress, lpBuffer, nSize) == FALSE) {
        CloseHandle(HProcess);
        return FALSE;
    }
    CloseHandle(HProcess);
    return TRUE;
}

BOOL ReadMemory(DWORD dwPid, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
{
    HANDLE HProcess;

    HProcess = GetHandleProcess(dwPid);
    if (HProcess == NULL)
        return FALSE;
    if (ReadMemory(HProcess, lpBaseAddress, lpBuffer, nSize) == FALSE) {
        CloseHandle(HProcess);
        return FALSE;
    }
    CloseHandle(HProcess);
    return TRUE;
}

BOOL ReadMemory(HANDLE hProcess, PVOID64 lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
{
    ULONGLONG lpNumberOfBytesRead = 0;
    NTSTATUS (__stdcall *NtWow64ReadVirtualMemory64)(
    HANDLE ProcessHandle,
    PVOID64 BaseAddress,
    PVOID Buffer,
    ULONGLONG BufferSize,
    PULONGLONG NumberOfBytesRead
        );
        
    NtWow64ReadVirtualMemory64 = (NTSTATUS(__stdcall *)(HANDLE, PVOID64, PVOID, ULONGLONG, PULONGLONG))GetProcAddress(GetModuleHandleA("ntdll"), "NtWow64ReadVirtualMemory64");
    if (!NtWow64ReadVirtualMemory64) {
        fprintf(stderr, "[-] ReadMemory - GetProcAddress() failed : %lu\n", GetLastError());
        return FALSE;
    }
    if (NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesRead)) {
        fprintf(stderr, "[-] ReadMemory - NtWow64ReadVirtualMemory64(..., lpBaseAddress = %I64X, ..., nSize = %08X, ... ) failed : %lu\n", lpBaseAddress, nSize, GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL ReadMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
{
    ULONG lpNumberOfBytesRead;

    if (!ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesRead)) {
        fprintf(stderr, "[-] ReadMemory - ReadProcessMemory(..., lpBaseAddress = %08X, ..., nSize = %08X, ... ) failed : %lu\n", lpBaseAddress, nSize, GetLastError());
        return FALSE;
    }
    return TRUE;
}

std::list<MEMORY_BASIC_INFORMATION32> GetMemoryInformation32(DWORD dwPID)
{
    std::list<MEMORY_BASIC_INFORMATION32> lMemBI;
    MEMORY_BASIC_INFORMATION32 MBInfo;
    HANDLE HProcess;
    PBYTE PBAddress = 0;

    if ((HProcess = GetHandleProcess(dwPID)) == NULL)
        return lMemBI;
    while (VirtualQueryEx(HProcess, PBAddress, (PMEMORY_BASIC_INFORMATION)&MBInfo, sizeof(MEMORY_BASIC_INFORMATION32)) != 0) {
        //if ((MBInfo.State & MEM_COMMIT) /*&& (MBInfo.Protect & WRITABLE)*/) {
            lMemBI.push_back(MBInfo);
        //}
        PBAddress = (PBYTE)MBInfo.BaseAddress + MBInfo.RegionSize;
    }
    CloseHandle(HProcess);
    return lMemBI;
}

std::list<MEMORY_BASIC_INFORMATION64> GetMemoryInformation64(DWORD dwPID)
{
    NTSTATUS (__stdcall *NtWow64QueryVirtualMemory64)(
        HANDLE ProcessHandle,
        PVOID64 BaseAddr,
        MEMORY_INFORMATION_CLASS MemoryInformationClass,
        PVOID MemoryInformation, /* NB must be 64bit aligned */
        ULONGLONG Length,
        PULONGLONG ReturnLength);
    HANDLE HProcess;
    std::list<MEMORY_BASIC_INFORMATION64> lMemBI;
    BYTE bOut[0x50];
    ULONGLONG ReturnLength;
    MEMORY_BASIC_INFORMATION64 mbi;
    ULONGLONG AddrStruct = ((ULONGLONG)(&bOut) + 0x8) & ~(8 - 1); 
    ULONGLONG StartAddr = 0;
    
    NtWow64QueryVirtualMemory64 = (NTSTATUS(__stdcall *)(HANDLE, PVOID64, MEMORY_INFORMATION_CLASS, PVOID, ULONGLONG, PULONGLONG))GetProcAddress(GetModuleHandleA("ntdll"), "NtWow64QueryVirtualMemory64");
    if (!NtWow64QueryVirtualMemory64) {
        fprintf(stderr, "[-] GetMemoryInformation64 - GetProcAddress() failed : %lu\n", GetLastError());
        return lMemBI;
    }
    if ((HProcess = GetHandleProcess(dwPID)) == NULL)
        return lMemBI;
    memset(bOut, 0, sizeof (bOut));
    while (NtWow64QueryVirtualMemory64(HProcess, (PVOID64)StartAddr, MemoryBasicInformation,
        (PVOID)AddrStruct, sizeof (MEMORY_BASIC_INFORMATION64), &ReturnLength) == 0) {
        
        memcpy(&mbi, (PVOID)AddrStruct, sizeof (MEMORY_BASIC_INFORMATION64));
        lMemBI.push_back(mbi); 
        StartAddr = (ULONGLONG)mbi.BaseAddress + mbi.RegionSize;
    }
    CloseHandle(HProcess);
    return lMemBI;
}
//        
//    /*ULONGLONG lpNumberOfBytesRead = 0;
//    
//    NTSTATUS (__stdcall *NtWow64QueryVirtualMemory64)(
//        HANDLE ProcessHandle,
//        PVOID BaseAddressLow,
//        PVOID BaseAddressHigh,
//        MEMORY_INFORMATION_CLASS MemoryInformationClass,
//        PVOID MemoryInformation, /* NB must be 64bit aligned */
//       /* ULONG LengthLow,
//        ULONG LengthHigh,
//        PULONGLONG ReturnLength OPTIONAL
//    );
//
//    std::list<MEMORY_BASIC_INFORMATION64> lMemBI;
//    MEMORY_BASIC_INFORMATION64 MBInfo;
//    HANDLE HProcess;
//    ULONGLONG PBAddress = 0;
//
//
//    
//    if ((HProcess = GetHandleProcess(dwPID)) == NULL)
//        return lMemBI;
//    /*while (VirtualQueryEx(HProcess, PBAddress, (PMEMORY_BASIC_INFORMATION)&MBInfo, sizeof(MEMORY_BASIC_INFORMATION64)) != 0) {
//        ////if ((MBInfo.State & MEM_COMMIT) /*&& (MBInfo.Protect & WRITABLE)*/) {
//            //lMemBI.push_back(MBInfo);
//        //}
//        //PBAddress = (PBYTE)MBInfo.BaseAddress + MBInfo.RegionSize;
//    //}
//    //CloseHandle(HProcess);
//   // return lMemBI;
////}
//
/////*BOOL WriteMemory(DWORD dwPid, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
////{
////    HANDLE HProcess;
////
////    HProcess = GetHandleProcess(dwPid);
////    if (HProcess == NULL)
////        return FALSE;
////    if (WriteMemory(HProcess, lpBaseAddress, lpBuffer, nSize) == FALSE)
////    {
////        CloseHandle(HProcess);
////        return FALSE;
////    }
////    CloseHandle(HProcess);
////    return TRUE;
////}
////
////BOOL WriteMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
////{
////    SIZE_T lpNumberOfBytesWritten;
////
////    if (!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesWritten))
////    {
////        fprintf(stderr, "[-] WriteProcessMemory() failed : %X\n", GetLastError());
////        return FALSE;
////    }
////    return TRUE;
////}
////
////
////std::list<LPCVOID> ScanPattern(LPCVOID lpPattern, SIZE_T nSize, DWORD dwPid)
////{
////    std::list<LPCVOID> lAddress;
////    std::list<MEMORY_BASIC_INFORMATION> lMemBI;
////    std::list<MEMORY_BASIC_INFORMATION>::const_iterator it;
////    PBYTE pBuff = NULL;
////
////    if (SuspendAllThread(dwPid) == FALSE)
////        return lAddress;
////    lMemBI = GetMemoryInformation(dwPid);
////    for (it = lMemBI.begin(); it != lMemBI.end(); ++it)
////    {
////        pBuff = (PBYTE)VirtualAlloc(NULL, (*it).RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
////        if (!pBuff)
////        {
////            fprintf(stderr, "[-] VirtualAlloc() failed : %X\n", GetLastError());
////            return lAddress;
////        }
////        if (ReadMemory(dwPid, (*it).BaseAddress, pBuff, (*it).RegionSize) == FALSE)
////        {
////            // hmm
////            VirtualFree(pBuff, 0, MEM_RELEASE);
////            continue;
////        }
////        if (nSize > (*it).RegionSize)
////        {
////            // WTF
////            VirtualFree(pBuff, 0, MEM_RELEASE);
////            continue;
////        }
////        for (DWORD dwCount = 0; dwCount < ((*it).RegionSize - nSize); dwCount++)
////        {
////            if (!memcmp(lpPattern, pBuff + dwCount, nSize))
////                lAddress.push_back((PBYTE)(*it).BaseAddress + dwCount);
////        }
////        VirtualFree(pBuff, 0, MEM_RELEASE);
////    }
////    ResumeAllThread(dwPid);
////    return lAddress;
////}*/
