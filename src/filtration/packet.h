//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Represents captured pcap packet i.e. PacketInfo + captured data
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PACKET_H
#define PACKET_H
//------------------------------------------------------------------------------
#include <algorithm>    // for std::min()
#include <cassert>
#include <cstring>      // for memcpy()

#include <pcap/pcap.h>

#include "protocols/ethernet/ethernet_header.h"
#include "protocols/ip/ipv4_header.h"
#include "protocols/tcp/tcp_header.h"
#include "protocols/udp/udp_header.h"
#include "utils/session.h"
//------------------------------------------------------------------------------
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
        case ethernet_header::IPV6: // TODO: implement IPv6
        default:
            return;
        }

        eth = header;
    }

    inline void check_sll()
    {
    // TODO: add support Linux cooked sockets
    }

    inline void check_ipv4()
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
        case ipv4_header::TCP: check_tcp(); break;
        case ipv4_header::UDP: check_udp(); break;
        default:
            return;
        }

        ipv4 = header;
    }

    inline void check_tcp()
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

    inline void check_udp()
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
    // TODO: add IPv6 support

    // Transport Layer
    // TCP
    const tcp::TCPHeader*           tcp;
    // UDP
    const udp::UDPHeader*           udp;

    const uint8_t*                  data;  // pointer to packet data
    uint32_t                        dlen;  // length of packet data

    // Packet transmission direction, set after match packet to session
    Direction                  direction;
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
        fragment->tcp   = info.tcp  ? (const tcp::TCPHeader*)           (packet + ( ((const uint8_t*)info.tcp ) - info.packet)) : nullptr;
        fragment->udp   = info.udp  ? (const udp::UDPHeader*)           (packet + ( ((const uint8_t*)info.udp ) - info.packet)) : nullptr;

        fragment->data  = packet + (info.data - info.packet);
        fragment->dlen  = info.dlen;
        fragment->direction = info.direction;

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
