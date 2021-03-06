#include "network.h"

std::list<MIB_TCPROW_OWNER_PID> GetTCPConnections(void)
{
    std::list<MIB_TCPROW_OWNER_PID> lmib;
    PMIB_TCPTABLE_OWNER_PID pmib;
    DWORD dwSize = 0;
    DWORD dwRetVal;
    
    pmib = (PMIB_TCPTABLE_OWNER_PID)malloc(sizeof (MIB_TCPTABLE_OWNER_PID));
    if (pmib == NULL) {
        fprintf(stderr, "[-] GetTCPConnections - malloc failed\n");
        return lmib;
    }
    dwSize = sizeof (MIB_TCPTABLE_OWNER_PID);
    if ((dwRetVal = GetExtendedTcpTable(pmib, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) == ERROR_INSUFFICIENT_BUFFER) {
        free(pmib);
        pmib = (PMIB_TCPTABLE_OWNER_PID)malloc(dwSize);
        if (pmib == NULL) {
            fprintf(stderr, "[-] GetTCPConnections - malloc failed\n");
            return lmib;
        }
    }
    dwRetVal = GetExtendedTcpTable(pmib, &dwSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (dwRetVal != 0) {
        fprintf(stderr, "[-] GetTCPConnections - GetExtendedTcpTable failed : %lu\n", GetLastError());
        return lmib;
    }
    for (DWORD i = 0; i < pmib->dwNumEntries; i++) {
        lmib.push_back(pmib->table[i]);
    }
    free(pmib);
    return lmib;
}

std::list<MIB_TCP6ROW_OWNER_PID> GetTCPConnectionsv6(void)
{
    std::list<MIB_TCP6ROW_OWNER_PID> lmib;
    PMIB_TCP6TABLE_OWNER_PID pmib;
    DWORD dwSize = 0;
    DWORD dwRetVal;
    
    pmib = (PMIB_TCP6TABLE_OWNER_PID)malloc(sizeof (MIB_TCP6ROW_OWNER_PID));
    if (pmib == NULL) {
        fprintf(stderr, "[-] GetTCPConnections - malloc failed\n");
        return lmib;
    }
    dwSize = sizeof (MIB_TCP6ROW_OWNER_PID);
    if ((dwRetVal = GetExtendedTcpTable(pmib, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0)) == ERROR_INSUFFICIENT_BUFFER) {
        free(pmib);
        pmib = (PMIB_TCP6TABLE_OWNER_PID)malloc(dwSize);
        if (pmib == NULL) {
            fprintf(stderr, "[-] GetTCPConnections - malloc failed\n");
            return lmib;
        }
    }
    dwRetVal = GetExtendedTcpTable(pmib, &dwSize, TRUE, AF_INET6, TCP_TABLE_OWNER_PID_ALL, 0);
    if (dwRetVal != 0) {
        fprintf(stderr, "[-] GetTCPConnections - GetExtendedTcpTable failed : %lu\n", GetLastError());
        return lmib;
    }
    for (DWORD i = 0; i < pmib->dwNumEntries; i++) {
        lmib.push_back(pmib->table[i]);
    }
    free(pmib);
    return lmib;
}

std::list<MIB_UDPROW_OWNER_PID> GetUDPConnections(void)
{
    std::list<MIB_UDPROW_OWNER_PID> lmib;
    PMIB_UDPTABLE_OWNER_PID pmib;
    DWORD dwSize = 0;
    DWORD dwRetVal;
    
    pmib = (PMIB_UDPTABLE_OWNER_PID)malloc(sizeof (MIB_UDPTABLE_OWNER_PID));
    if (pmib == NULL) {
        fprintf(stderr, "[-] GetUDPConnections - malloc failed\n");
        return lmib;
    }
    dwSize = sizeof (MIB_UDPTABLE_OWNER_PID);
    if ((dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) == ERROR_INSUFFICIENT_BUFFER) {
        free(pmib);
        pmib = (PMIB_UDPTABLE_OWNER_PID)malloc(dwSize);
        if (pmib == NULL) {
            fprintf(stderr, "[-] GetUDPConnections - malloc failed\n");
            return lmib;
        }
    }
    dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    if (dwRetVal != 0) {
        fprintf(stderr, "[-] GetUDPConnections - GetExtendedUdpTable failed : %lu\n", GetLastError());
        return lmib;
    }
    for (DWORD i = 0; i < pmib->dwNumEntries; i++) {
        lmib.push_back(pmib->table[i]);
    }
    free(pmib);
    return lmib;
}

std::list<MIB_UDP6ROW_OWNER_PID> GetUDPConnectionsv6(void)
{
    std::list<MIB_UDP6ROW_OWNER_PID> lmib;
    PMIB_UDP6TABLE_OWNER_PID pmib;
    DWORD dwSize = 0;
    DWORD dwRetVal;
    
    pmib = (PMIB_UDP6TABLE_OWNER_PID)malloc(sizeof (MIB_UDP6ROW_OWNER_PID));
    if (pmib == NULL) {
        fprintf(stderr, "[-] GetUDPConnections - malloc failed\n");
        return lmib;
    }
    dwSize = sizeof (MIB_UDP6ROW_OWNER_PID);
    if ((dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0)) == ERROR_INSUFFICIENT_BUFFER) {
        free(pmib);
        pmib = (PMIB_UDP6TABLE_OWNER_PID)malloc(dwSize);
        if (pmib == NULL) {
            fprintf(stderr, "[-] GetUDPConnections - malloc failed\n");
            return lmib;
        }
    }
    dwRetVal = GetExtendedUdpTable(pmib, &dwSize, TRUE, AF_INET6, UDP_TABLE_OWNER_PID, 0);
    if (dwRetVal != 0) {
        fprintf(stderr, "[-] GetUDPConnections - GetExtendedUdpTable failed : %lu\n", GetLastError());
        return lmib;
    }
    for (DWORD i = 0; i < pmib->dwNumEntries; i++) {
        lmib.push_back(pmib->table[i]);
    }
    free(pmib);
    return lmib;
}

BOOL CloseTCPConnection(DWORD dwLocalAddr, DWORD dwLocalPort, DWORD dwRemoteAddr, DWORD dwRemotePort)
{
    DWORD dwRetVal;
    MIB_TCPROW mibrow;
    
    mibrow.dwState = MIB_TCP_STATE_DELETE_TCB;
    mibrow.dwLocalAddr = dwLocalAddr;
    mibrow.dwLocalPort = dwLocalPort;
    mibrow.dwRemoteAddr = dwRemoteAddr;
    mibrow.dwRemotePort = dwRemotePort;
    if ((dwRetVal = SetTcpEntry(&mibrow)) != 0) {
        fprintf(stderr, "[-] CloseTPCConnection - SetTcpEntry failed: %lu\n", dwRetVal);
        return FALSE;
    }
    return TRUE;
}

BOOL CloseTCPConnectionRemote(std::list<MIB_TCPROW_OWNER_PID> mib, u_short RemotePort)
{
    std::list<MIB_TCPROW_OWNER_PID>::const_iterator it;
    
    for (it = mib.begin(); it != mib.end(); ++it) {
        if (htons((short)(*it).dwRemotePort) == RemotePort) {
            return CloseTCPConnection((*it).dwLocalAddr, (*it).dwLocalPort, (*it).dwRemoteAddr, (*it).dwRemotePort);
        }
    }
    return FALSE;
}

BOOL CloseTCPConnectionRemote(std::list<MIB_TCPROW_OWNER_PID> mib, char *RemoteAddr)
{
    std::list<MIB_TCPROW_OWNER_PID>::const_iterator it;
    DWORD dwRemoteAddr = inet_addr(RemoteAddr);
    
    for (it = mib.begin(); it != mib.end(); ++it) {
        if ((*it).dwRemoteAddr == dwRemoteAddr) {
            return CloseTCPConnection((*it).dwLocalAddr, (*it).dwLocalPort, (*it).dwRemoteAddr, (*it).dwRemotePort);
        }
    }
    return FALSE;
}

BOOL CloseTCPConnectionRemote(std::list<MIB_TCPROW_OWNER_PID> mib, char *RemoteAddr, u_short RemotePort)
{
    std::list<MIB_TCPROW_OWNER_PID>::const_iterator it;
    DWORD dwRemoteAddr = inet_addr(RemoteAddr);
    
    for (it = mib.begin(); it != mib.end(); ++it) {
        if ((*it).dwRemoteAddr == dwRemoteAddr && htons((short)(*it).dwRemotePort) == RemotePort) {
            return CloseTCPConnection((*it).dwLocalAddr, (*it).dwLocalPort, (*it).dwRemoteAddr, (*it).dwRemotePort);
        }
    }
    return FALSE;
}

BOOL CloseTCPConnectionLocal(std::list<MIB_TCPROW_OWNER_PID> mib, u_short LocalPort)
{
    std::list<MIB_TCPROW_OWNER_PID>::const_iterator it;
        
    for (it = mib.begin(); it != mib.end(); ++it) {
        if (htons((short)(*it).dwLocalPort) == LocalPort) {
            return CloseTCPConnection((*it).dwLocalAddr, (*it).dwLocalPort, (*it).dwRemoteAddr, (*it).dwRemotePort);
        }
    }
    return FALSE;
}