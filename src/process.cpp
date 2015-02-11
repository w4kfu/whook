#include "process.h"

std::list<PROCESSENTRY32> GetProcessList(void)
{
    HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
    std::list<PROCESSENTRY32> lProcess;
    PROCESSENTRY32 pe32;

    memset(&pe32, 0, sizeof (PROCESSENTRY32));
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] GetProcessList - CreateToolhelp32Snapshot() failed : %lu\n", GetLastError());
        return lProcess;
    }
    pe32.dwSize = sizeof (PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        fprintf(stderr, "[-] GetProcessList - Process32First() failed : %lu\n", GetLastError());
        CloseHandle(hProcessSnap);
        return lProcess;
    }
    do {
        lProcess.push_back(pe32);
    } while(Process32Next(hProcessSnap, &pe32));
    CloseHandle(hProcessSnap);
    return lProcess;
}

BOOL IsInProcessList(std::list<PROCESSENTRY32> lProcess, LPCSTR ImageName)
{
    std::list<PROCESSENTRY32>::const_iterator it;

    for (it = lProcess.begin(); it != lProcess.end(); ++it) {
        if (!_stricmp((*it).szExeFile, ImageName))
            return TRUE;
    }
    return FALSE;
}

BOOL IsInProcessList(LPCSTR ImageName)
{
    std::list<PROCESSENTRY32> lProcess;

    lProcess = GetProcessList();
    return IsInProcessList(lProcess, ImageName);
}

DWORD GetPidProcess(std::list<PROCESSENTRY32> lProcess, LPCSTR ImageName)
{
    std::list<PROCESSENTRY32>::const_iterator it;

    for (it = lProcess.begin(); it != lProcess.end(); ++it) {
        if (!_stricmp((*it).szExeFile, ImageName))
            return (*it).th32ProcessID;
    }
    return DWORD(-1);
}

DWORD GetPidProcess(LPCSTR ImageName)
{
    std::list<PROCESSENTRY32> lProcess;

    lProcess = GetProcessList();
    return GetPidProcess(lProcess, ImageName);
}

HANDLE GetHandleProcess(DWORD dwPid)
{
    HANDLE HProcess = NULL;

    HProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPid);
    if (HProcess == NULL) {
        fprintf(stderr, "[-] GetHandleProcess - OpenProcess() failed : %X\n", GetLastError());
        return NULL;
    }
    return HProcess;
}

PROCESSENTRY32 GetPE32(DWORD dwPid)
{
    HANDLE hProcessSnap = INVALID_HANDLE_VALUE;
    PROCESSENTRY32 pe32;

    memset(&pe32, 0, sizeof (PROCESSENTRY32));
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] GetPE32 - CreateToolhelp32Snapshot() failed : %X\n", GetLastError());
        goto error_getpe32;
    }
    pe32.dwSize = sizeof (PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32)) {
        fprintf(stderr, "[-] GetPE32 - Process32First() failed : %X\n", GetLastError());
        CloseHandle(hProcessSnap);
        goto error_getpe32;
    }
    do
    {
        if (pe32.th32ProcessID == dwPid)
            goto end_getpe32;
    } while(Process32Next(hProcessSnap, &pe32));

error_getpe32:
    memset(&pe32, 0, sizeof (PROCESSENTRY32));
end_getpe32:
    CloseHandle(hProcessSnap);
    return pe32;
}

/*DWORD GetPidProcess(char *szModuleName)
{
    DWORD dwProcesses[2048]; // enough ?
    DWORD dwCBNeeded;

    if (!EnumProcesses(dwProcesses, sizeof(dwProcesses), &dwCBNeeded))
        return 0;
    for (DWORD i = 0; i < (dwCBNeeded / sizeof (DWORD)); i++) {
        if(dwProcesses[i] != 0) {
            if (IsModuleExist(dwProcesses[i], szModuleName))
                return dwProcesses[i];
        }
    }
    return 0;
}*/
