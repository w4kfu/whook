#include "threads.h"

std::list<THREADENTRY32> GetThreadsList(DWORD dwPID)
{
    HANDLE hProcessSnap;
    std::list<THREADENTRY32> lThreads;
    THREADENTRY32 te32;

    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        fprintf(stderr, "[-] CreateToolhelp32Snapshot() failed : %X\n", GetLastError());
        return lThreads;
    }
    te32.dwSize = sizeof (THREADENTRY32);
    if (!Thread32First(hProcessSnap, &te32))
    {
        fprintf(stderr, "[-] Thread32First() failed : %X\n", GetLastError());
        CloseHandle(hProcessSnap);
        return lThreads;
    }
    do
    {
        if (te32.th32OwnerProcessID == dwPID)
            lThreads.push_back(te32);
    } while(Thread32Next(hProcessSnap, &te32));

    CloseHandle(hProcessSnap);
    return lThreads;
}


HANDLE GetHandleThread(DWORD dwTid)
{
    HANDLE    HThread;

    HThread = OpenThread(THREAD_ALL_ACCESS, 0, dwTid);
    if (HThread == NULL)
    {
        fprintf(stderr, "[-] OpenThread() failed : %X\n", GetLastError());
        return NULL;
    }
    return HThread;
}

BOOL SuspendAllThread(DWORD dwPID)
{
    std::list<THREADENTRY32> lThreads;
    std::list<THREADENTRY32>::const_iterator it;
    HANDLE HThread;

    lThreads = GetThreadsList(dwPID);
    if (lThreads.size() == 0)
        return FALSE;
    for (it = lThreads.begin(); it != lThreads.end(); ++it)
    {
        HThread = GetHandleThread((*it).th32ThreadID);
        if (SuspendThread(HThread) == -1)
        {
            fprintf(stderr, "[-] SuspendThread(%X) failed : %X\n", (*it).th32ThreadID, GetLastError());
        }
        CloseHandle(HThread);
    }
    return TRUE;
}

BOOL ResumeAllThread(DWORD dwPID)
{
    std::list<THREADENTRY32> lThreads;
    std::list<THREADENTRY32>::const_iterator it;
    HANDLE HThread;

    lThreads = GetThreadsList(dwPID);
    if (lThreads.size() == 0)
        return FALSE;
    for (it = lThreads.begin(); it != lThreads.end(); ++it)
    {
        HThread = GetHandleThread((*it).th32ThreadID);
        if (ResumeThread(HThread) == -1)
        {
            fprintf(stderr, "[-] ResumeThread(%X) failed : %X\n", (*it).th32ThreadID, GetLastError());
        }
        CloseHandle(HThread);
    }
    return TRUE;
}
