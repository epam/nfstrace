//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Definition of UDP header and constants.
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
#ifndef UDP_HEADER_H
#define UDP_HEADER_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <arpa/inet.h>  // for ntohs()
#include <netinet/in.h> // for in_port_t
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace udp
{

// User Datagram Protocol RFC 768
struct udp_header
{
    in_port_t udp_sport;    // source port, optional, may be 0
    in_port_t udp_dport;    // destination port
    uint16_t udp_len;       // length of the datagram, minimum value is 8
    uint16_t udp_sum;       // checksum of IP pseudo header, the UDP header, and the data
} __attribute__ ((__packed__));

struct UDPHeader : private udp_header
{
    inline in_port_t sport()    const { return udp_sport; }
    inline in_port_t dport()    const { return udp_dport; }
    inline uint16_t length()   const { return ntohs(udp_len);   }
    inline uint16_t checksum() const { return ntohs(udp_sum);   }
} __attribute__ ((__packed__));

} // namespace udp
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//UDP_HEADER_H
//------------------------------------------------------------------------------
