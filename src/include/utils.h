#ifndef __UTILS_H__
#define __UTILS_H__

#include <windows.h>
#include <stdio.h>

void hexdump(void *data, int size);
BOOL Is64bitOS();
BOOL IsWow64(HANDLE hProcess);

#endif // __UTILS_H__

