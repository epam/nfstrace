//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition of IP version 6 header and constants. RFC 2460.
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
#ifndef IPV6_HEADER_H
#define IPV6_HEADER_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <arpa/inet.h>  // for ntohs()/ntohl()
#include <netinet/in.h> // for in6_addr
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace ip
{
typedef uint8_t in6_addr_t[16];

static_assert(sizeof(in6_addr) == sizeof(in6_addr_t), "sizeof in6_addr should be 16 bytes");

// Internet Protocol, version 6
struct ipv6_header
{
    uint32_t   ipv6_vtcflow; // version(4), traffic class(8), flow label(20)
    uint16_t   ipv6_plen;    // size of payload, including any extension header
    uint8_t    ipv6_nexthdr; // next header type
    uint8_t    ipv6_hlimit;  // hop limit
    in6_addr_t ipv6_src;     // source address
    in6_addr_t ipv6_dst;     // destination address
} __attribute__((__packed__));

// Hop-by-Hop options header
struct ipv6_hbh
{
    uint8_t hbh_nexthdr; // next header type
    uint8_t hbh_len;     // length in units of 8 octets
    // addition data
} __attribute__((__packed__));

// Destination options header
struct ipv6_dest
{
    uint8_t dest_nexthdr; // next header type
    uint8_t dest_len;     // length in units of 8 octets
    // addition data
} __attribute__((__packed__));

// Routing header
struct ipv6_route
{
    uint8_t route_nexthdr; // next header
    uint8_t route_len;     // length in units of 8 octets
    uint8_t route_type;    // routing type
    uint8_t route_segleft; // segments left
    // routing type specific data
} __attribute__((__packed__));

// Fragment header
struct ipv6_frag
{
    enum Fragmentation : uint16_t
    {
        MORE     = 0x0001, // more-fragments flag
        RESERVED = 0x0006, // mask out reserved bits
        OFFSET   = 0xfff8  // mask out offset from frag_offlg
    };

    uint8_t  frag_nexthdr;  // next header
    uint8_t  frag_reserved; // reserved field
    uint16_t frag_offlg;    // offset, reserved, and flag
    uint32_t frag_ident;    // identification
} __attribute__((__packed__));

struct IPv6Header : private ipv6_header
{
    uint8_t           version() const { return ntohl(ipv6_vtcflow) >> 28; }
    uint8_t           tclass() const { return (ntohl(ipv6_vtcflow) >> 20) & 0xFF; }
    uint32_t          flowid() const { return ntohl(ipv6_vtcflow) & 0xFFFFF; }
    uint16_t          payload_len() const { return ntohs(ipv6_plen); }
    uint8_t           nexthdr() const { return ipv6_nexthdr; }
    const in6_addr_t& src() const { return ipv6_src; }
    const in6_addr_t& dst() const { return ipv6_dst; }
} __attribute__((__packed__));

} // namespace ip
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif // IPV6_HEADER_H
//------------------------------------------------------------------------------
