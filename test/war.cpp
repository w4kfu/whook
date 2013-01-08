#include "war.h"

void left_Side(DWORD dwWarPid, DWORD dwCPlayer_offset)
{
    DWORD dwMov = 0x09;

    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0x60), &dwMov, 1);
}

void Right_Side(DWORD dwWarPid, DWORD dwCPlayer_offset)
{
    DWORD dwMov = 0x0A;

    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0x60), &dwMov, 1);
}

void Left_Straf(DWORD dwWarPid, DWORD dwCPlayer_offset)
{
    DWORD dwMov = 0x02;

    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0x62), &dwMov, 1);
}

void Right_Straf(DWORD dwWarPid, DWORD dwCPlayer_offset)
{
    DWORD dwMov = 0x04;

    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0x62), &dwMov, 1);
}

void forward(DWORD dwWarPid, DWORD dwCPlayer_offset)
{
    DWORD dwMov = 0x40;

    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0x63), &dwMov, 1);


    dwMov = 0x3F80;
    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0xAA), &dwMov, 2);
}

void backward(DWORD dwWarPid, DWORD dwCPlayer_offset)
{
    DWORD dwMov = 0x80;

    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0x63), &dwMov, 1);
    dwMov = 0xBF80;
    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0xAA), &dwMov, 2);
}


void Reset_Mov(DWORD dwWarPid, DWORD dwCPlayer_offset)
{
    DWORD dwMov = 0x00;

    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0x60), &dwMov, 1);
    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0x62), &dwMov, 1);
    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0x63), &dwMov, 1);
    WriteMemory(dwWarPid, (BYTE*)(dwCPlayer_offset + 0xAA), &dwMov, 2);
}

DWORD Search_Cplayer(DWORD dwWarPid)
{
    DWORD dwBaseAddress = 0;
    IMAGE_DOS_HEADER DosHeader;
    IMAGE_NT_HEADERS NTHeader;
    std::list<LPCVOID> lAddress;
    std::list<LPCVOID>::const_iterator it;
    BYTE bInstru;
    DWORD dwAddr;


    lAddress = ScanPattern(SIG_PLAYER, 5, dwWarPid);
    PrintPatternMatch(lAddress);

    dwBaseAddress = GetRemoteBaseAddress(dwWarPid);
    printf("BaseAddress = %08X\n", dwBaseAddress);

    DosHeader = GetDosHeader(dwWarPid);
    PrintDosHeader(&DosHeader);

    NTHeader = GetNTHeader(dwWarPid);
    PrintNTHeader(&NTHeader);
    for (it = lAddress.begin(); it != lAddress.end(); ++it)
    {
        if (((DWORD)*it > dwBaseAddress) && ((DWORD)*it < (dwBaseAddress + NTHeader.OptionalHeader.SizeOfImage)))
        {
            ReadMemory(dwWarPid, (BYTE*)*it + 0x20, &bInstru, 1);
            if (bInstru == 0xA3)
            {
                // Cplayer
                ReadMemory(dwWarPid, (BYTE*)*it + 0x21, &dwAddr, 4);
                // *CPlayer
                ReadMemory(dwWarPid, (BYTE*)dwAddr, &dwAddr, 4);
                return dwAddr;
            }
        }

    }
    return 0;
}

void dump_info(DWORD dwWarPid, LPCVOID lpAddress, SIZE_T nSize)
{
    PBYTE pBuff = NULL;

    pBuff = (PBYTE)VirtualAlloc(NULL, nSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pBuff)
    {
        fprintf(stderr, "[-] VirtualAlloc() failed : %X\n", GetLastError());
        return;
    }
    ReadMemory(dwWarPid, lpAddress, pBuff, nSize);
    hex_dump(pBuff, nSize);
    VirtualFree(pBuff, 0, MEM_RELEASE);
}

void launch_war(void)
{
    std::list<MODULEENTRY32> lWarModuleList;
    DWORD dwWarPid = 0;
    DWORD CPlayer_offset = 0;

    dwWarPid = GetPidProcess("war.exe");
    if (dwWarPid == 0)
    {
        fprintf(stderr, "[-] Can't find warhammer executable\n");
        return;
    }
    lWarModuleList = GetModuleList(dwWarPid);
    printf("[+] ModuleList Warhammer Online\n");
    PrintModulesList(lWarModuleList);

    CPlayer_offset = (DWORD)Search_Cplayer(dwWarPid);
    printf("[+] Cplayer_offset = %08X\n", CPlayer_offset);
    dump_info(dwWarPid, (LPCVOID)CPlayer_offset, 200);

    left_Side(dwWarPid, CPlayer_offset);
    Sleep(1000);
    Right_Side(dwWarPid, CPlayer_offset);
    Sleep(1000);
    Reset_Mov(dwWarPid, CPlayer_offset);
    Left_Straf(dwWarPid, CPlayer_offset);
    Sleep(1000);
    Right_Straf(dwWarPid, CPlayer_offset);
    Sleep(1000);
    Reset_Mov(dwWarPid, CPlayer_offset);
    forward(dwWarPid, CPlayer_offset);
    Sleep(3000);
    backward(dwWarPid, CPlayer_offset);
    Sleep(3000);
    Reset_Mov(dwWarPid, CPlayer_offset);
}
