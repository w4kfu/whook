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
    if (NtWow64ReadVirtualMemory64(hProcess, lpBaseAddress, lpBuffer, 8, &lpNumberOfBytesRead)) {
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

///*BOOL WriteMemory(DWORD dwPid, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
//{
//    HANDLE HProcess;
//
//    HProcess = GetHandleProcess(dwPid);
//    if (HProcess == NULL)
//        return FALSE;
//    if (WriteMemory(HProcess, lpBaseAddress, lpBuffer, nSize) == FALSE)
//    {
//        CloseHandle(HProcess);
//        return FALSE;
//    }
//    CloseHandle(HProcess);
//    return TRUE;
//}
//
//BOOL WriteMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
//{
//    SIZE_T lpNumberOfBytesWritten;
//
//    if (!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesWritten))
//    {
//        fprintf(stderr, "[-] WriteProcessMemory() failed : %X\n", GetLastError());
//        return FALSE;
//    }
//    return TRUE;
//}
//
//std::list<MEMORY_BASIC_INFORMATION> GetMemoryInformation(DWORD dwPID)
//{
//    std::list<MEMORY_BASIC_INFORMATION> lMemBI;
//    MEMORY_BASIC_INFORMATION MBInfo;
//    HANDLE HProcess;
//    PBYTE PBAddress = 0;
//
//    if ((HProcess = GetHandleProcess(dwPID)) == NULL)
//        return lMemBI;
//    while (VirtualQueryEx (HProcess, PBAddress, &MBInfo, sizeof(MBInfo)) == 0)
//    {
//        //if (VirtualQueryEx (HProcess, PBAddress, &MBInfo, sizeof(MBInfo)) == 0)
//        //{
//        //    break;
//        //}
//        if ((MBInfo.State & MEM_COMMIT) /*&& (MBInfo.Protect & WRITABLE)*/)
//        /*{
//            lMemBI.push_back(MBInfo);
//        }
//        PBAddress = (PBYTE)MBInfo.BaseAddress + MBInfo.RegionSize;
//    }
//    CloseHandle(HProcess);
//    return lMemBI;
//}
//
//std::list<LPCVOID> ScanPattern(LPCVOID lpPattern, SIZE_T nSize, DWORD dwPid)
//{
//    std::list<LPCVOID> lAddress;
//    std::list<MEMORY_BASIC_INFORMATION> lMemBI;
//    std::list<MEMORY_BASIC_INFORMATION>::const_iterator it;
//    PBYTE pBuff = NULL;
//
//    if (SuspendAllThread(dwPid) == FALSE)
//        return lAddress;
//    lMemBI = GetMemoryInformation(dwPid);
//    for (it = lMemBI.begin(); it != lMemBI.end(); ++it)
//    {
//        pBuff = (PBYTE)VirtualAlloc(NULL, (*it).RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
//        if (!pBuff)
//        {
//            fprintf(stderr, "[-] VirtualAlloc() failed : %X\n", GetLastError());
//            return lAddress;
//        }
//        if (ReadMemory(dwPid, (*it).BaseAddress, pBuff, (*it).RegionSize) == FALSE)
//        {
//            // hmm
//            VirtualFree(pBuff, 0, MEM_RELEASE);
//            continue;
//        }
//        if (nSize > (*it).RegionSize)
//        {
//            // WTF
//            VirtualFree(pBuff, 0, MEM_RELEASE);
//            continue;
//        }
//        for (DWORD dwCount = 0; dwCount < ((*it).RegionSize - nSize); dwCount++)
//        {
//            if (!memcmp(lpPattern, pBuff + dwCount, nSize))
//                lAddress.push_back((PBYTE)(*it).BaseAddress + dwCount);
//        }
//        VirtualFree(pBuff, 0, MEM_RELEASE);
//    }
//    ResumeAllThread(dwPid);
//    return lAddress;
//}*/
