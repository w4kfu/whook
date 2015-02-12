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