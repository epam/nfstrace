//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition of Ethernet family protocol headers.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef ETHERNET_HEADER_H
#define ETHERNET_HEADER_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <arpa/inet.h>  // for ntohs()
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace ethernet
{

// Ethernet II (aka DIX v2.0 Ethernet)
struct ethernet_header
{
    enum { ADDR_LEN = 6 };

    enum EtherType
    {
        PUP     = 0x0200,   // Xerox PUP
        SPRITE  = 0x0500,   // Sprite
        IP      = 0x0800,   // IP
        ARP     = 0x0806,   // Address resolution
        REVARP  = 0x8035,   // Reverse ARP
        AT      = 0x809B,   // AppleTalk protocol
        AARP    = 0x80F3,   // AppleTalk ARP
        VLAN    = 0x8100,   // IEEE 802.1Q VLAN tagging
        IPX     = 0x8137,   // IPX
        IPV6    = 0x86dd,   // IP protocol version 6
        LOOPBACK= 0x9000    // used to test interfaces
    };

    uint8_t  eth_dhost[ADDR_LEN];   // destination host address
    uint8_t  eth_shost[ADDR_LEN];   // source host address
    uint16_t eth_type;              // protocol (EtherType values)
} __attribute__((packed));

struct EthernetHeader : private ethernet_header
{
    inline const uint8_t*  dst() const { return eth_dhost;       }
    inline const uint8_t*  src() const { return eth_shost;       }
    inline uint16_t       type() const { return ntohs(eth_type); }
} __attribute__ ((__packed__));

} // namespace ethernet
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//ETHERNET_HEADER_H
//------------------------------------------------------------------------------
