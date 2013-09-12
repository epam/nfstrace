//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition of UDP header and constants.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef UDP_HEADER_H
#define UDP_HEADER_H
//------------------------------------------------------------------------------
#include <stdint.h>
#include <arpa/inet.h>  // for ntohs()
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace udp
{

// User Datagram Protocol RFC 768
struct udp_header
{
    uint16_t udp_sport;     // source port, optional, may be 0
    uint16_t udp_dport;     // destination port
    uint16_t udp_len;       // length of the datagram, minimum value is 8
    uint32_t udp_sum;       // checksum of IP pseudo header, the UDP header, and the data
} __attribute__ ((__packed__));

struct UDPHeader : private udp_header
{
    inline uint16_t sport()    const { return ntohs(udp_sport); }
    inline uint16_t dport()    const { return ntohs(udp_dport); }
    inline uint32_t length()   const { return ntohs(udp_len);   }
    inline uint32_t checksum() const { return ntohs(udp_sum);   }
} __attribute__ ((__packed__));

} //namespace tcp
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//TCP_HEADER_H
//------------------------------------------------------------------------------
