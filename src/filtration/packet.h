//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Represents captured pcap packet i.e. PacketInfo + captured data
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
#ifndef PACKET_H
#define PACKET_H
//------------------------------------------------------------------------------
#include <algorithm>    // for std::min()
#include <cassert>
#include <cstring>      // for memcpy()

#include <pcap/pcap.h>

#include "protocols/ethernet/ethernet_header.h"
#include "protocols/ip/ip_header.h"
#include "protocols/tcp/tcp_header.h"
#include "protocols/udp/udp_header.h"
#include "utils/sessions.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

using namespace NST::protocols;
using namespace NST::protocols::ethernet;
using namespace NST::protocols::ip;
using namespace NST::protocols::tcp;
using namespace NST::protocols::udp;

// Structure of pointers to captured pcap packet's headers. WITHOUT data.
struct PacketInfo
{
    using Direction = NST::utils::Session::Direction;

    inline PacketInfo(const pcap_pkthdr* h, const uint8_t* p, const uint32_t datalink)
    : header   {h}
    , packet   {p}
    , eth      {nullptr}
    , ipv4     {nullptr}
    , ipv6     {nullptr}
    , tcp      {nullptr}
    , udp      {nullptr}
    , data     {packet}
    , dlen     {header->caplen}
    , direction{Direction::Unknown}
    {
        switch(datalink)
        {
        case DLT_EN10MB:    check_eth(); break;
        case DLT_LINUX_SLL: check_sll(); break;
        }
    }
    PacketInfo(const PacketInfo&)            = delete;
    PacketInfo& operator=(const PacketInfo&) = delete;
    void* operator new   (size_t ) = delete;   // only on stack
    void* operator new[] (size_t ) = delete;   // only on stack
    void  operator delete  (void*) = delete;   // only on stack
    void  operator delete[](void*) = delete;   // only on stack

    inline void check_eth()
    {
        if(dlen < sizeof(EthernetHeader)) return;
        auto header = reinterpret_cast<const EthernetHeader*>(data);

        data += sizeof(EthernetHeader);
        dlen -= sizeof(EthernetHeader);

        switch(header->type())
        {
        case ethernet_header::IP:   check_ipv4(); break;
        case ethernet_header::IPV6: check_ipv6(); break;
        default:
            return;
        }

        eth = header;
    }

    inline void check_sll()
    {
    // TODO: add support Linux cooked sockets
    }

    inline void check_ipv4() __attribute__((always_inline))
    {
        if(dlen < sizeof(IPv4Header)) return;
        auto header = reinterpret_cast<const IPv4Header*>(data);

        if(header->version() != 4)  return;

        /*
            IP packet may be fragmented by NIC or snaplen parameter of libpcap
            IP is fragmented AND it is first part of original (offset == 0)
            - Ok, pass it.

            IP is fragmented AND it is not first part of it (offset != 0)
             - DISCARD IT! We do not reassemble fragmented IP packets at all
        */
        if(header->is_fragmented_and_not_the_first_part())
        {
            return; // discard tail of fragmented ip packets
        }

        const uint32_t ihl = header->ihl();
        if(dlen < ihl) return; // truncated packet

        data += ihl;
        dlen = (std::min((uint16_t)dlen, header->length())) - ihl;  // trunk data to length of IP packet

        switch(header->protocol())
        {
        case ip::NextProtocol::TCP: check_tcp(); break;
        case ip::NextProtocol::UDP: check_udp(); break;
        default:
            return;
        }

        ipv4 = header;
    }

    inline void check_ipv6() __attribute__((always_inline))
    {
        if(dlen < sizeof(IPv6Header)) return;
        auto header = reinterpret_cast<const IPv6Header*>(data);

        if(header->version() != 6)  return;

        data += sizeof(IPv6Header);
        dlen -= sizeof(IPv6Header);

        const uint32_t payload = header->payload_len();
        if(payload == 0) return; // The length is set to zero when a Hop-by-Hop extension header carries a Jumbo Payload option
        if(dlen < payload) return; // truncated packet

        dlen = payload; // skip padding at the end
        // handling optional headers
        uint8_t htype = header->nexthdr();
        switch_type:    // TODO: remove ugly goto
        switch(htype)
        {
        case ip::NextProtocol::TCP: check_tcp(); break;
        case ip::NextProtocol::UDP: check_udp(); break;

        case ip::NextProtocol::HOPOPTS:
        {
            auto hbh = reinterpret_cast<const ipv6_hbh*>(data);
            const unsigned int size{1U + hbh->hbh_len};

            if(dlen < size) return; // truncated packet

            data += size;
            dlen -= size;

            htype = hbh->hbh_nexthdr;
            goto switch_type;
        }

        case ip::NextProtocol::DSTOPTS:
        {
            auto dest = reinterpret_cast<const ipv6_dest*>(data);
            const unsigned int size{1U + dest->dest_len};

            if(dlen < size) return; // truncated packet

            data += size;
            dlen -= size;

            htype = dest->dest_nexthdr;
            goto switch_type;
        }

        case ip::NextProtocol::ROUTING:
        {
            auto route = reinterpret_cast<const ipv6_route*>(data);
            const unsigned int size{1U + route->route_len};

            if(dlen < size) return; // truncated packet

            data += size;
            dlen -= size;

            htype = route->route_nexthdr;
            goto switch_type;
        }

        case ip::NextProtocol::FRAGMENT:
        {
            auto frag = reinterpret_cast<const ipv6_frag*>(data);

            // isn't first fragment (offset != 0)
            if((ntohs(frag->frag_offlg) & ipv6_frag::OFFSET) != 0) return;

            const unsigned int size{sizeof(ipv6_frag)};

            if(dlen < size) return; // truncated packet

            data += size;
            dlen -= size;

            htype = frag->frag_nexthdr;
            goto switch_type;
        }
        case ip::NextProtocol::NONE:
        default:    // unknown header
            return;
        }

        ipv6 = header;
    }

    inline void check_tcp() __attribute__((always_inline))
    {
        if(dlen < sizeof(TCPHeader)) return;   // truncated TCP header
        auto header = reinterpret_cast<const TCPHeader*>(data);

        uint8_t offset = header->offset();
        if(offset < 20 || offset > 60) return; // invalid length of TCP header

        if(dlen < offset) return; // truncated packet

        // RFC-793 Section 3.1 Header Format says:
        //    A TCP must implement all options.
        // Here we skip them all

        data += offset;
        dlen -= offset;

        tcp = header;
    }

    inline void check_udp() __attribute__((always_inline))
    {
        if(dlen < sizeof(UDPHeader)) return;   // fragmented UDP header
        const UDPHeader* header = reinterpret_cast<const UDPHeader*>(data);

        data += sizeof(UDPHeader);
        dlen -= sizeof(UDPHeader);

        udp = header;
    }

    // libpcap structures
    const pcap_pkthdr*              header;
    const uint8_t*                  packet; // real length is in header->caplen

    // all pointers point to packet array

    // Data Link Layer
    // Ethernet II
    const ethernet::EthernetHeader* eth;

    // Internet Layer
    // IP version 4
    const ip::IPv4Header*           ipv4;
    // IP version 6
    const ip::IPv6Header*           ipv6;

    // Transport Layer
    // TCP
    const tcp::TCPHeader*           tcp;
    // UDP
    const udp::UDPHeader*           udp;

    const uint8_t*                  data;  // pointer to packet data
    uint32_t                        dlen;  // length of packet data

    // Packet transmission direction, set after match packet to session
    Direction                  direction;

    struct Dumped // marker of dumped packet
    {
    private:
        friend class Dumping;
        friend class Packet;

    public:
        Dumped() : dumped{false}{};
        Dumped(const Dumped& in)     = delete;
        ~Dumped(){};

    private:
        inline operator bool() const { return dumped; }
        inline void operator=(const bool in) const { dumped = in; }
        mutable bool dumped;
    } IsDumped;
};

// PCAP packet in dynamic allocated memory
struct Packet: public PacketInfo
{
    Packet()                         = delete;
    Packet(const Packet&)            = delete;
    Packet& operator=(const Packet&) = delete;

    Packet* next;     // pointer to next packet or nullptr

    static Packet* create(const PacketInfo& info, Packet* next)
    {
        assert(info.direction != Direction::Unknown);

        // allocate memory for Packet structure and PCAP packet data
        // TODO: performance drop! improve data alignment!
        uint8_t* memory    =  new uint8_t[sizeof(Packet) + sizeof(pcap_pkthdr) + info.header->caplen];

        Packet* fragment   = (Packet*)      ((uint8_t*)memory                                       );
        pcap_pkthdr* header= (pcap_pkthdr*) ((uint8_t*)memory + sizeof(Packet)                      );
        uint8_t*  packet   = (uint8_t*)     ((uint8_t*)memory + sizeof(Packet) + sizeof(pcap_pkthdr));

        // copy data
        *header = *info.header;                           // copy packet header
        memcpy(packet, info.packet, info.header->caplen); // copy packet data

        fragment->header = header;
        fragment->packet = packet;

        // fix pointers from PacketInfo to point to owned copy of packet data
        fragment->eth   = info.eth  ? (const ethernet::EthernetHeader*) (packet + ( ((const uint8_t*)info.eth ) - info.packet)) : nullptr;
        fragment->ipv4  = info.ipv4 ? (const ip::IPv4Header*)           (packet + ( ((const uint8_t*)info.ipv4) - info.packet)) : nullptr;
        fragment->ipv6  = info.ipv6 ? (const ip::IPv6Header*)           (packet + ( ((const uint8_t*)info.ipv6) - info.packet)) : nullptr;
        fragment->tcp   = info.tcp  ? (const tcp::TCPHeader*)           (packet + ( ((const uint8_t*)info.tcp ) - info.packet)) : nullptr;
        fragment->udp   = info.udp  ? (const udp::UDPHeader*)           (packet + ( ((const uint8_t*)info.udp ) - info.packet)) : nullptr;

        fragment->data  = packet + (info.data - info.packet);
        fragment->dlen  = info.dlen;
        fragment->direction = info.direction;
        fragment->IsDumped = false;

        fragment->next  = next;

        return fragment;
    }

    static void destroy(Packet* fragment)
    {
        uint8_t* ptr = (uint8_t*)fragment;
        delete[] ptr;
    }
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_H
//------------------------------------------------------------------------------
