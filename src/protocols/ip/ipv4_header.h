//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition of IP version 4 header and constants.
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
#ifndef IPV4_HEADER_H
#define IPV4_HEADER_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <arpa/inet.h>  // for ntohs()/ntohl()
#include <netinet/in.h> // for in_addr_t
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace ip
{

// Internet Protocol, version 4
struct ipv4_header
{
    enum TOS
    {
        LOWDELAY    = 0x10,
        THROUGHPUT  = 0x08,
        RELIABILITY = 0x04,
        LOWCOST     = 0x02
    };

    enum Fragmentation
    {
        RF      = 0x8000, // reserved fragment flag
        DF      = 0x4000, // dont fragment flag
        MF      = 0x2000, // more fragments flag
        OFFMASK = 0x1fff  // mask for fragmenting bits
    };

    uint8_t ipv4_vhl;           // header length and version
    uint8_t ipv4_tos;           // type of service
    uint16_t ipv4_len;          // total length
    uint16_t ipv4_id;           // identification
    uint16_t ipv4_fragmentation;// fragmentation
    uint8_t ipv4_ttl;           // time to live
    uint8_t ipv4_protocol;      // protocol
    uint16_t ipv4_checksum;     // checksum
    in_addr_t ipv4_src;         // source address
    in_addr_t ipv4_dst;         // destination address
} __attribute__ ((__packed__));

struct IPv4Header : private ipv4_header
{
    inline uint8_t  version()  const { return ipv4_vhl >> 4;        }
    inline uint8_t  ihl()      const { return (ipv4_vhl & 0x0f) << 2 /* *4 */; } // return number of bytes
    inline uint16_t length()   const { return ntohs(ipv4_len);      }
    inline uint16_t offset()   const { return (ntohs(ipv4_fragmentation) & OFFMASK) << 3 /* *8 */; } // return number of bytes
    inline uint8_t  protocol() const { return ipv4_protocol;        }
    inline in_addr_t src()     const { return ipv4_src;             }
    inline in_addr_t dst()     const { return ipv4_dst;             }
    inline uint16_t checksum() const { return ntohs(ipv4_checksum); }

    inline bool is_fragmented() const { return ipv4_fragmentation & 0xff3f /*0xff3f == htons(MF | OFFMASK)*/; }
    inline bool is_fragmented_and_not_the_first_part() const
    {
        return ipv4_fragmentation & 0xff1f /*offset() != 0*/;
    }
} __attribute__ ((__packed__));

} // namespace ip
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//IPV4_HEADER_H
//------------------------------------------------------------------------------
