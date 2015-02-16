#ifndef __DUMP_H__
#define __DUMP_H__

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "modules.h"
#include "file.h"

typedef struct _DUMPED_PE
{
    PBYTE pDump;
    ULONG64 dwImageSize;
} DUMPED_PE, *PDUMPED_PE;

VOID DumpPE(DWORD pid, LPCSTR dumpFileName);

#endif // __DUMP_H__

