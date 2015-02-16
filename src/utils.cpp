#include "utils.h"

void hexdump(void *data, int size)
{
    unsigned char *p = (unsigned char*)data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[16 * 3 + 5] = {0};
    char charstr[16 * 1 + 5] = {0};

    for(n = 1; n <= size; n++) {
        if (n % 16 == 1) {
            sprintf_s(addrstr, sizeof(addrstr), "%.4x", ((unsigned int) p - (unsigned int)data));
        }
        c = *p;
        if (isalnum(c) == 0) {
            c = '.';
        }
        sprintf_s(bytestr, sizeof (bytestr), "%02X ", *p);
        strncat_s(hexstr, sizeof (hexstr) - 1, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);
        sprintf_s(bytestr, sizeof (bytestr), "%c", c);
        strncat_s(charstr, sizeof (charstr) - 1, bytestr, sizeof(charstr) - strlen(charstr) - 1);
        if (n % 16 == 0) {
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if (n % 8 == 0) {
            strncat_s(hexstr, sizeof (hexstr) - 1, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat_s(charstr, sizeof (charstr) - 1, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++;
    }
    if (strlen(hexstr) > 0) {
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

BOOL Is64bitOS()
{
    return IsWow64(GetCurrentProcess());
}

BOOL IsWow64(HANDLE hProcess)
{
    BOOL bIsWow64 = FALSE;
    typedef BOOL (APIENTRY *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process;
    const char funcName[] = "IsWow64Process";
    HMODULE module = GetModuleHandleA("kernel32");

    fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(module, funcName);
    if(fnIsWow64Process != NULL)
    {
        if (!fnIsWow64Process(hProcess, &bIsWow64)) {
            fprintf(stderr, "[-] IsWow64 - IsWow64Process failed: %lu\n", GetLastError());
            return FALSE;
        }
    }
    return bIsWow64 != FALSE;
}

BOOL IsWow64(DWORD dwPid)
{
    HANDLE HProcess = NULL;
    BOOL bRet = FALSE;
    
    if ((HProcess = GetHandleProcess(dwPid)) == NULL)
        return 0;
    bRet = IsWow64(HProcess);
    CloseHandle(HProcess);
    return bRet;
}

BOOL Is64BitProcess(DWORD dwPid)
{
    if ((Is64bitOS() == TRUE) && (IsWow64(dwPid) == FALSE)) {
        return TRUE;
    }
    return FALSE;
}

BOOL Is64BitProcess(HANDLE HProcess)
{
    if ((Is64bitOS() == TRUE) && (IsWow64(HProcess) == FALSE)) {
        return TRUE;
    }
    return FALSE;
}

BOOL EnablePrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) 
{
	TOKEN_PRIVILEGES tp;
	LUID luid;
    HANDLE hToken;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
        fprintf(stderr, "[-] EnablePrivilege - OpenProcessToken() failed: %lu\n", GetLastError());
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
		fprintf(stderr, "[-] EnablePrivilege - LookupPrivilegeValue failed: %lu\n", GetLastError()); 
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;
	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES) NULL, (PDWORD)NULL)) {
		fprintf(stderr, "[-] EnablePrivilege - AdjustTokenPrivileges failed: %lu\n", GetLastError()); 
		return FALSE; 
	} 
	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
		fprintf(stderr, "[-] The token does not have the specified privilege\n");
		return FALSE;
	} 
	return TRUE;
}

BOOL IsElevated(VOID) 
{
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    TOKEN_ELEVATION Elevation;
    DWORD cbSize;
    
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        cbSize = sizeof( TOKEN_ELEVATION );
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof (Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}