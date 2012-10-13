#include <Windows.h>
#include <stdio.h>

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
