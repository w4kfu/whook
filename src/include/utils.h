#ifndef __UTILS_H__
#define __UTILS_H__

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

void hexdump(void *data, int size);
BOOL Is64bitOS();
BOOL IsWow64(HANDLE hProcess);
BOOL EnablePrivilege(PCSTR PrivilegeName, BOOLEAN Acquire);

#endif // __UTILS_H__

