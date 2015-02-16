#include "file.h"

WHOOK_FILE WhookFileOpen(const char *filename)
{
    WHOOK_FILE wFile;

    strncpy_s(wFile.filename, sizeof (wFile.filename), filename, sizeof (wFile.filename) - 1);
    if (filename == NULL)
        return wFile;
    wFile.hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (wFile.hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[-] WhookFileOpen - CreateFileA failed: %lu\n", GetLastError());
        return wFile;
    }
    wFile.dwLength = GetFileSize(wFile.hFile, NULL);
    wFile.hMap = CreateFileMapping(wFile.hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (wFile.hMap == 0) {
        fprintf(stderr, "[-] WhookFileOpen - CreateFileMapping failed: %lu\n", GetLastError());
        CloseHandle(wFile.hFile);
        return wFile;
    }
    wFile.buf = (BYTE*)MapViewOfFile(wFile.hMap, FILE_MAP_READ, 0, 0, 0);
    if (wFile.buf == 0) {
        fprintf(stderr, "[-] WhookFileOpen - CreateFileMapping failed: %lu\n", GetLastError());
        CloseHandle(wFile.hMap);
        CloseHandle(wFile.hFile);
        return wFile;
    }
    return wFile;
}

BOOL Write2File(LPCSTR FileName, PBYTE pBuffer, SIZE_T Size)
{
    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD dwWritten = 0;

    if ((hFile = CreateFileA(FileName, (GENERIC_READ | GENERIC_WRITE),
                             FILE_SHARE_READ | FILE_SHARE_READ,
                             NULL, CREATE_ALWAYS, 0, NULL)) == INVALID_HANDLE_VALUE) {
        return FALSE;
	}
    WriteFile(hFile, pBuffer, Size, &dwWritten, NULL);
    if (dwWritten != Size) {
        CloseHandle(hFile);
        return FALSE;
    }
	CloseHandle(hFile);
    return TRUE;
}