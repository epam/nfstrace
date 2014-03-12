//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition of IP version 4 header and constants.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef IPV4_HEADER_H
#define IPV4_HEADER_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <arpa/inet.h>  // for ntohs()/ntohl()
#include <netinet/in.h> // for in_addr
//------------------------------------------------------------------------------
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
    enum Protocol
    {
        IP      = 0,   // Dummy protocol for TCP
        HOPOPTS = 0,   // IPv6 Hop-by-Hop options
        ICMP    = 1,   // Internet Control Message Protocol
        IGMP    = 2,   // Internet Group Management Protocol
        IPIP    = 4,   // IPIP tunnels (older KA9Q tunnels use 94)
        TCP     = 6,   // Transmission Control Protocol
        EGP     = 8,   // Exterior Gateway Protocol
        PUP     = 12,  // PUP protocol
        UDP     = 17,  // User Datagram Protocol
        IDP     = 22,  // XNS IDP protocol
        TP      = 29,  // SO Transport Protocol Class 4
        DCCP    = 33,  // Datagram Congestion Control Protocol
        IPV6    = 41,  // IPv6 header
        ROUTING = 43,  // IPv6 routing header
        FRAGMENT= 44,  // IPv6 fragmentation header
        RSVP    = 46,  // Reservation Protocol
        GRE     = 47,  // General Routing Encapsulation
        ESP     = 50,  // encapsulating security payload
        AH      = 51,  // authentication header
        ICMPV6  = 58,  // ICMPv6
        NONE    = 59,  // IPv6 no next header
        DSTOPTS = 60,  // IPv6 destination options
        MTP     = 92,  // Multicast Transport Protocol
        ENCAP   = 98,  // Encapsulation Header
        PIM     = 103, // Protocol Independent Multicast
        COMP    = 108, // Compression Header Protocol
        SCTP    = 132, // Stream Control Transmission Protocol
        UDPLITE = 136, // UDP-Lite protocol
        RAW     = 255  // Raw IP packets
    };

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
    struct in_addr ipv4_src;    // source address
    struct in_addr ipv4_dst;    // destination address
} __attribute__ ((__packed__));

struct IPv4Header : private ipv4_header
{
    inline uint8_t  version()  const { return (ipv4_vhl & 0xf0) >> 4; }
    inline uint8_t  ihl()      const { return (ipv4_vhl & 0x0f) << 2 /* *4 */; } // return number of bytes
    inline uint16_t length()   const { return ntohs(ipv4_len);      }
    inline uint16_t offset()   const { return (ntohs(ipv4_fragmentation) & OFFMASK) << 3 /* *8 */; } // return number of bytes
    inline uint8_t  protocol() const { return ipv4_protocol;        }
    inline uint32_t src()      const { return ntohl(ipv4_src.s_addr); }
    inline uint32_t dst()      const { return ntohl(ipv4_dst.s_addr); }
    inline uint16_t checksum() const { return ntohs(ipv4_checksum); }

    inline uint32_t network_bo_src() const { return ipv4_src.s_addr; }
    inline uint32_t network_bo_dst() const { return ipv4_dst.s_addr; }

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
