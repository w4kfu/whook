#ifndef __NETWORK_H__
#define __NETWORK_H__

#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <list>

std::list<MIB_TCPROW_OWNER_PID> GetTCPConnections(void);
std::list<MIB_TCP6ROW_OWNER_PID> GetTCPConnectionsv6(void);
std::list<MIB_UDPROW_OWNER_PID> GetUDPConnections(void);
std::list<MIB_UDP6ROW_OWNER_PID> GetUDPConnectionsv6(void);

BOOL CloseTCPConnectionRemote(std::list<MIB_TCPROW_OWNER_PID> mib, char *RemoteAddr);
BOOL CloseTCPConnectionRemote(std::list<MIB_TCPROW_OWNER_PID> mib, u_short RemotePort);
BOOL CloseTCPConnectionRemote(std::list<MIB_TCPROW_OWNER_PID> mib, char *RemoteAddr, u_short RemotePort);
BOOL CloseTCPConnectionLocal(std::list<MIB_TCPROW_OWNER_PID> mib, u_short LocalPort);

#endif // __NETWORK_H__

