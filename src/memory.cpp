#include "memory.h"

BOOL ReadMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
{
    SIZE_T lpNumberOfBytesRead;

    if (!ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesRead))
    {
        fprintf(stderr, "[-] ReadProcessMemory() failed : %X\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

BOOL WriteMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize)
{
    SIZE_T lpNumberOfBytesWritten;

    if (!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, &lpNumberOfBytesWritten))
    {
        fprintf(stderr, "[-] WriteProcessMemory() failed : %X\n", GetLastError());
        return FALSE;
    }
    return TRUE;
}

std::list<MEMORY_BASIC_INFORMATION> GetMemoryInformation(DWORD dwPID)
{
    std::list<MEMORY_BASIC_INFORMATION> lMemBI;
    MEMORY_BASIC_INFORMATION MBInfo;
    HANDLE HProcess;
    PBYTE PBAddress = 0;

    if (!(HProcess = GetHandleProcess(dwPID)))
        return lMemBI;
    while (1)
    {
        if (VirtualQueryEx (HProcess, PBAddress, &MBInfo, sizeof(MBInfo)) == 0)
        {
            break;
        }
        if ((MBInfo.State & MEM_COMMIT) && (MBInfo.Protect & WRITABLE))
        {
            lMemBI.push_back(MBInfo);
        }
        PBAddress = (PBYTE)MBInfo.BaseAddress + MBInfo.RegionSize;
    }
    CloseHandle(HProcess);
    return lMemBI;
}
