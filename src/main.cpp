#include <Windows.h>
#include <stdio.h>

#include "process.h"
#include "modules.h"
#include "info.h"
#include "memory.h"
#include "threads.h"
#include "pestuff.h"

void init_console(void)
{
  int Mode;
  struct _CONSOLE_SCREEN_BUFFER_INFO sbi;
  HANDLE    Hstd;
  FILE      *stream;

  Hstd = GetStdHandle(STD_INPUT_HANDLE);
  AllocConsole();
  GetConsoleMode(Hstd, (LPDWORD)&Mode);
  SetConsoleMode(Hstd, Mode & 0xFFFFFFEF);
  GetConsoleScreenBufferInfo(Hstd, &sbi);
  sbi.dwSize.Y = 4096;
  SetConsoleScreenBufferSize(Hstd, sbi.dwSize);
  freopen_s(&stream, "conin$", "r", stdin);
  freopen_s(&stream, "conout$", "w", stdout);
  freopen_s(&stream, "conout$", "w", stderr);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	DisableThreadLibraryCalls(GetModuleHandleA("whook.dll"));
	return 1;
}

__declspec(dllexport) BOOL run(void)
{
    init_console();
    return 1;
}

void test(void)
{
    std::list<PROCESSENTRY32>  lProcess;
    std::list<MODULEENTRY32> lModules;
    DWORD   dwPid = 0;
    std::list<MEMORY_BASIC_INFORMATION> lMemBI;
    std::list<THREADENTRY32> lThreads;
    std::list<LPCVOID> lAddress;
    DWORD dwBaseAddress = 0;
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS NTHeader;

    lProcess = GetProcessList();

    PrintProcessList(lProcess);

    dwPid = GetPidProcess("notepad++.exe");
    PrintPidProcess("notepad++.exe", dwPid);

    lModules = GetModuleList(dwPid);
    PrintModulesList(lModules);

    lMemBI = GetMemoryInformation(dwPid);
    PrintMemoryInfo(lMemBI);

    lThreads = GetThreadsList(dwPid);
    PrintThreadsInfo(lThreads);

    SuspendAllThread(dwPid);
    Sleep(1000);
    ResumeAllThread(dwPid);

    lAddress = ScanPattern("\x42\x42\x42", 3, dwPid);
    PrintPatternMatch(lAddress);

    dwBaseAddress = GetRemoteBaseAddress(dwPid);
    printf("BaseAddress = %08X\n", dwBaseAddress);

    DosHeader = GetDosHeader(dwPid);
    PrintDosHeader(&DosHeader);

    NTHeader = GetNTHeader(dwPid);
    PrintNTHeader(&NTHeader);
}

int main(void)
{
    // Test
    test();
    system("pause");
    return 0;
}
