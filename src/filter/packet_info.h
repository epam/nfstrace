//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structure of pointers to captured pcap packet:
//              protocols, offset and known headers. WITHOUT data.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PACKET_INFO_H
#define PACKET_INFO_H
//------------------------------------------------------------------------------
#include <cassert>

#include <pcap/pcap.h>

#include "ethernet/ethernet_header.h"
#include "ip/ipv4_header.h"
#include "tcp/tcp_header.h"
//------------------------------------------------------------------------------
using namespace NST::filter::ethernet;
using namespace NST::filter::ip;
using namespace NST::filter::tcp;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

struct PacketInfo
{
    inline PacketInfo(const pcap_pkthdr* h, const uint8_t* p, const uint32_t datalink):header(h),packet(p)
    {
        eth  = NULL;
        ipv4 = NULL;
        tcp  = NULL;
        data = packet;
        dlen = header->caplen;

        switch(datalink)
        {
        case DLT_EN10MB:    check_eth(); break;
        case DLT_LINUX_SLL: check_sll(); break;
        }
    }

    inline void check_eth()
    {
        if(dlen < sizeof(EthernetHeader)) return;
        const EthernetHeader* header = reinterpret_cast<const EthernetHeader*>(data);

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

        const IPv4Header* header = reinterpret_cast<const IPv4Header*>(data);

        if(header->version()  != 4) return;
        if(header->length() > dlen) return; // fragmented payload

        const uint32_t ihl = header->ihl();
        if(ihl < 20 || ihl > 60) return;    // invalid IPv4  header length

        data += ihl;
        dlen = header->length() - ihl;  // trunk data to length of IP packet

        switch(header->protocol())
        {
        case ipv4_header::TCP: check_tcp(); break;
        case ipv4_header::UDP: // TODO: implement UDP
        default:
            return;
        }

        ipv4 = header;
    }

    inline void check_tcp()
    {
        if(dlen < sizeof(TCPHeader)) return;   // fragmented TCP header

        TCPHeader* header = (TCPHeader*)data;
        uint8_t offset = header->offset();
        if(offset < 20 || offset > 60) return; // invalid length of TCP header

        if(dlen < offset) return;

        data += offset;
        dlen -= offset;

        tcp = header;
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
    // TODO: add UDP support

    const uint8_t*                  data;   // pointer to payload data
    uint32_t                        dlen;   // length of payload data

private:
    PacketInfo(const PacketInfo&);      // undefined
    void operator=(const PacketInfo&);  // undefined
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_INFO_H
//------------------------------------------------------------------------------
