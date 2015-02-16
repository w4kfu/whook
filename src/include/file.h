#ifndef __FILE_H__
#define __FILE_H__

#ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct _WHOOK_FILE
{
    CHAR filename[MAX_PATH];
    BYTE *buf;
    DWORD dwLength;
    DWORD pos;
    HANDLE hFile;
    HANDLE hMap;
} WHOOK_FILE, *PWHOOK_FILE;

WHOOK_FILE WhookFileOpen(const char *filename);

BOOL Write2File(LPCSTR FileName, PBYTE pBuffer, SIZE_T Size);

#endif // __FILE_H__

