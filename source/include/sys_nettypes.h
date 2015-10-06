/*

  BSD LICENSE 

  Copyright(c) 2006-2011 Intel Corporation. All rights reserved.

  Redistribution and use in source and binary forms, with or without 
  modification, are permitted provided that the following conditions 
  are met:

    * Redistributions of source code must retain the above copyright 
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in 
      the documentation and/or other materials provided with the 
      distribution.
    * Neither the name of Intel Corporation nor the names of its 
      contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef _SYS_NETTYPES_H_
#define _SYS_NETTYPES_H_

/***************************************************************************/
/*! \file sys_nettypes.h
    \brief The file defines networking types and sizes
****************************************************************************/

#include <netinet/in.h>   /* for definition  INET_ADDRSTRLEN, INET6_ADDRSTRLEN, 
                             struct in_addr, struct in6_addr, htonl(), htons(), ntohl(), ntohs() */
#include <net/if.h>       /* for definition  IF_NAMESIZE */
#include <string.h>       /* for memcmp */
#include "sys_ptypes.h"   /* for definition primitives types  */

/*! \def MAX_NUMBER_OF_SYSTEM_INTERFACE
 *  \brief Maximum number of system network interfaces
 */
#define MAX_NUMBER_OF_SYSTEM_INTERFACE  32

/*! \def INET_ADDRLEN
 *  \brief Unknown addr type
 */
#ifndef INET_ADDR_TYPE_UNKNOWN
#define INET_ADDR_TYPE_UNKNOWN      0
#endif

/*! \def INET_ADDR_TYPE_IPV4
 *  \brief IPv4 address type
 */
#ifndef INET_ADDR_TYPE_IPV4
#define INET_ADDR_TYPE_IPV4         1
#endif

/*! \def INET_ADDR_TYPE_IPV6
 *  \brief IPv6 address type
 */
#ifndef INET_ADDR_TYPE_IPV6
#define INET_ADDR_TYPE_IPV6         2
#endif

/*! \def FAMILY_TYPE_AF_UNSPEC
 *  \brief unknown address family
 */
#ifndef FAMILY_TYPE_AF_UNSPEC
#define FAMILY_TYPE_AF_UNSPEC       AF_UNSPEC
#endif

/*! \def IP_ADDR_LIST_MAX_SIZE
 *  \brief mx size of address list
 */
#ifndef IP_ADDR_LIST_MAX_SIZE
#define IP_ADDR_LIST_MAX_SIZE 	16u
#endif

/*! \def INET_ADDRLEN
 *  \brief The length of an IPv4 address
 */
#ifndef INET_ADDRLEN
    #define INET_ADDRLEN		sizeof( struct in_addr )    
#endif

/*! \def INET6_ADDRLEN
 *  \brief The length of an IPv6 address
 */
#ifndef INET6_ADDRLEN
    #define INET6_ADDRLEN		sizeof( struct in6_addr )   
#endif

/*! \def INET6_ADDRLEN
 *  \brief The maximum length of an IP address
 */
#ifndef MAX_INET_ADDRLEN
    #define MAX_INET_ADDRLEN	INET6_ADDRLEN   
#endif

/*! \def INET_ADDRSTRLEN
 *  \brief The string length of an IPv4 address
 */
#ifndef INET_ADDRSTRLEN
    #define INET_ADDRSTRLEN     16
#endif

/*! \def INET6_ADDRSTRLEN
 *  \brief The string length of an IPv6 address
 */
#ifndef INET6_ADDRSTRLEN
    #define INET6_ADDRSTRLEN    46
#endif

/*! \def MAX_INET_ADDRSTRLEN
 *  \brief The maximum string length of an IP address
 */
#ifndef MAX_INET_ADDRSTRLEN
    #define MAX_INET_ADDRSTRLEN    INET6_ADDRSTRLEN
#endif

/*! \def IF_NAMESIZE
 *  \brief The maximum string length of a network interface name
 */
#ifndef IF_NAMESIZE
    #define IF_NAMESIZE    16
#endif

/*! \def MAC_ADDR_LEN
 *  \brief The length of the hardware address of a network interface
 */
#ifndef MAC_ADDR_LEN
    #define MAC_ADDR_LEN    6
#endif

/*! \struct macaddr_t
 *  \brief MAC (hardware) address of a network interface type
 */
/* Type for carry the MAC address */
typedef struct mac_addr 
{
    Uint8 hw[ MAC_ADDR_LEN ];

} macaddr_t;

/*! \def MAC_CMP( pa, pb )
 *  \brief The macros returns an integer less than, equal to, 
 *      or greater than zero if the first mac(hardware) address ("pa")
 *      is found, respectively, to be less than, to match, or be greater
 *      than the second  mac(hardware) address ("pb")
 */
#define MAC_CMP( pa, pb ) ( memcmp( (pa)->hw, (pb)->hw, MAC_ADDR_LEN ) )


/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
/*                      IP Addressing macros                              */
/*~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~*/
/**************************************************************************/
/*! \fn GetInetAddrLenByFamily(F) 
        GetInetAddrFamilyByLen(L) 
        GetInetAddrType(F) 
        InetAddrTypeToFamily(T) 
 **************************************************************************
 *  \brief Type convertor macros for SNMP protocol and IP MIB supporting.
 *    GetInetAddrLenByFamily(F) - convert socket address family to Ip address length
 *    GetInetAddrFamilyByLen(L) - convert Ip address length tp socket address family
 *    GetInetAddrType(F)        - convert socket address family to INET address type(rfc4001)
 *    InetAddrTypeToFamily(T)   - convert INET address type(rfc4001)to socket address family
 *
 *  \param[in] F - family of the IP address.
 *  \param[in] L - length of the IP address.
 *  \param[in] T - type(rfc4001)to IP address.
 ***************************************************************************/
#define GetInetAddrLenByFamily(F)  (((F)==AF_INET6) ? INET6_ADDRLEN : \
                                    ((F)==AF_INET) ? INET_ADDRLEN : 0)

#define GetInetAddrFamilyByLen(L) (((L)==INET_ADDRLEN)?AF_INET: \
              ((L)==INET6_ADDRLEN)?AF_INET6:FAMILY_TYPE_AF_UNSPEC)

#define GetInetAddrType(F)  (((F)==AF_INET6)?INET_ADDR_TYPE_IPV6: \
                          ((F)==AF_INET)?INET_ADDR_TYPE_IPV4:INET_ADDR_TYPE_UNKNOWN)

#define InetAddrTypeToFamily(T) (((T)==INET_ADDR_TYPE_IPV6)?AF_INET6: \
              ((T)==INET_ADDR_TYPE_IPV4)?AF_INET:FAMILY_TYPE_AF_UNSPEC)

/**************************************************************************/
/*                   Network address ( IPv4 / IPv6 )                      */
/**************************************************************************/

/**************************************************************************/
/*! \var typedef struct InetAddr InetAddr_t 
 **************************************************************************
 * \brief This structure carries all needed information about network address.
 *        It is large enough to contain information about IPv4 or IPv6 addresses
 *        and may be used for fills the standard OS structures for network 
 *        communications like sockaddr, sockaddr_in, sockaddr_in6.
 * \param  Uint8 addr[]  - the network address ( INET_ADDRLEN for IPv4 / INET6_ADDRLEN for IPv6 )
 * \param  Uint8 family  - socet protocol family(type) of the  network address ( IPv4 / IPv6 )
 * \param  Uint32 subnet - subnet mask for IPv4 address
 * \param  Uint32 pref   - prefix for Ipv6 address
 *---------------------------------------------------------------------------
 *  \param[in] P - pointer to the InetAddr_t variable.
 *  \param[in] V - variable Uint32 types to put to the InetAddr_t variable.
 *  \param[in] A - network address in the network format in the Uint8* type
 *                 for write to the InetAddr_t variable.
 *  \param[in] L - length ot the address in the InetAddr_t variable.
 ***************************************************************************/
typedef struct InetAddr
{
    union
    {
        Uint32 u_subnet;
        Uint32 u_pref;
    } field_u;
    Uint8 addr[MAX_INET_ADDRLEN];
    Uint8 family;
} InetAddr_t;

/**************************************************************************/
/*! \var Macros for works with the InetAddr_t type 
 **************************************************************************
 *   ResetInetAddr(P) 
 *   GetInetAddrIpAddr(P)
 *   GetInetAddrIpAddrLen(P)
 *   SetInetAddrIpAddr(P,A,L)
 *   GetInetAddrFamilyP(P)
 *   GetInetAddrFamily(P)
 *   SetInetAddrFamily(P,V)
 *   GetInetAddrSubnetP(P)
 *   GetInetAddrSubnet(P)
 *   SetInetAddrSubnet(P,V)
 *   GetInetAddrPrefixP(P)
 *   GetInetAddrPrefix(P)
 *   SetInetAddrPrefix(P,V)
 *   SetInetAddrByLen(P,A,L,V)
 *   SetInetAddrByFamily(P,A,F,V)
 ***************************************************************************/
#define ResetInetAddr(P) ( bzero((char *)(P), sizeof(InetAddr_t)) )

#define GetInetAddrIpAddr(P) ((P)->addr)
#define GetInetAddrIpAddrLen(P) (GetInetAddrLenByFamily((P)->family))
#define SetInetAddrIpAddr(P,A,L) (memcpy((Uint8*)(P)->addr, (Uint8*)(A), (L)))

#define GetInetAddrFamilyP(P) (&((P)->family))
#define GetInetAddrFamily(P) ((P)->family)
#define SetInetAddrFamily(P,V) ((P)->family = (V))

#define GetInetAddrSubnetP(P) (&((P)->field_u.u_subnet))
#define GetInetAddrSubnet(P) ((P)->field_u.u_subnet)
#define SetInetAddrSubnet(P,V) ((P)->field_u.u_subnet = (V))

#define GetInetAddrPrefixP(P) (&((P)->field_u.u_pref))
#define GetInetAddrPrefix(P) ((P)->field_u.u_pref)
#define SetInetAddrPrefix(P,V) ((P)->field_u.u_pref = (V))

#define SetInetAddrByLen(P,A,L,V) if((L) == INET_ADDRLEN || (L) == INET6_ADDRLEN) \
                             SetInetAddrIpAddr(P,A,L), \
                             SetInetAddrFamily(P,GetInetAddrFamilyByLen(L)), \
                             SetInetAddrSubnet(P,V)

#define SetInetAddrByFamily(P,A,F,V) if((F) == AF_INET || (F) == AF_INET6) \
                             SetInetAddrIpAddr(P,A,GetInetAddrLenByFamily(F)), \
                             SetInetAddrFamily(P,F), \
                             SetInetAddrSubnet(P,V)

/**************************************************************************/
/*! \var typedef struct InetAddrList_t 
 **************************************************************************
 *  \brief This structure defined for keeps a list of network addresses
 *         Address List length MUST be set previously any other InetAddrList 
 *         macros operations.
 *   \param InetAddr_t addrList[] - pointer to array of the network addresses
 *   \param Uint32 addrListLen - the number fo elements in the array
 *   \param Uint32 curInd - the index of the current element
 *---------------------------------------------------------------------------
 *  \param[in] P - pointer to the InetAddr_t variable.
 *  \param[in] V - variable Uint32 types to put to the InetAddr_t variable.
 *  \param[in] A - network address in the network format in the Uint8* type
 *                 for write to the InetAddr_t variable.
 *  \param[in] L - length ot the address in the InetAddr_t variable.
 ***************************************************************************/

typedef struct InetAddrList
{
    InetAddr_t addrList[IP_ADDR_LIST_MAX_SIZE];
    Uint32 addrListLen;
    Uint32 curInd;
}InetAddrList_t;


/**************************************************************************/
/*! \var Macros for works with the InetAddrList_t type 
 **************************************************************************
 *   GetAddrListLen(P)
 *   SetAddrListLen(P,V) 
 *   GetAddrListCurInd(P)
 *   SetAddrListCurInd(P,V)
 *   GetAddrListInetAddrP(P,I)
 *   GetAddrListInetAddrNextP(P)
 *   GetAddrListInetAddr(P,I,A)
 *   SetAddrListInetAddr(P,I,A)
 **************************************************************************/
#define ResetAddrList(P) (memset((char *)(P), 0, sizeof(InetAddrList_t)))

/*************************************************************************** 
 * Address List length MUST be set previously any other InetAddrList macros
 *  operations.
 ***************************************************************************/
#define GetAddrListLen(P) ((P)->addrListLen)
#define SetAddrListLen(P,V) if((V)<IP_ADDR_LIST_MAX_SIZE + 1) \
                                (P)->addrListLen = (V), \
                                (P)->curInd = (((P)->curInd + 1 > (V))? 0:(P)->curInd )
#define GetAddrListCurInd(P) ((P)->curInd)
#define SetAddrListCurInd(P,V) if((V)<(P)->addrListLen) (P)->curInd = (V)

#define GetAddrListInetAddrP(P,I) (((I)<(P)->addrListLen) ? &((P)->addrList[(I)]):NULL )
#define GetAddrListInetAddrNextP(P) ((P)->curInd = ((P)->curInd + 1 < (P)->addrListLen) ? \
                                     (P)->curInd + 1 : 0, &((P)->addrList[(P)->curInd]))

#define GetAddrListInetAddr(P,I,A) if((I)<(P)->addrListLen) (A)=(P)->addrList[(I)]
#define SetAddrListInetAddr(P,I,A) if((I)<(P)->addrListLen) (P)->addrList[(I)] = (A)

#endif /* _SYS_NETTYPES_H_ */

