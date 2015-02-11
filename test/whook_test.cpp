#include <stdio.h>
#include <windows.h>

#include "process.h"
#include "info.h"

int main(int argc, char *argv[])
{
    std::list<PROCESSENTRY32> lProcess;
    (void)argc;
    (void)argv;
    
    lProcess = GetProcessList();
    PrintProcessList(lProcess);    
    printf("%d\n", IsInProcessList(lProcess, "calc.exe"));
    printf("%d\n", GetPidProcess("calc.exe"));
    return 0;
}