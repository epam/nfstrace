//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structure of pointers to captured pcap packet:
//                 protocols, offset and known headers. WITHOUT data.
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
#include "rpc/rpc_header.h"
//------------------------------------------------------------------------------
using namespace NST::filter::ethernet;
using namespace NST::filter::ip;
using namespace NST::filter::tcp;
using namespace NST::filter::rpc;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

struct PacketInfo
{
    inline PacketInfo(const pcap_pkthdr* h, const uint8_t* p):header(h),packet(p)
    {
        eth  = NULL;
        ipv4 = NULL;
        tcp  = NULL;
        rpc  = NULL;
        data = packet;
        dlen = header->caplen;
    }

    inline const EthernetHeader* check_eth()
    {
        if(dlen < sizeof(EthernetHeader)) return NULL;
        eth = reinterpret_cast<const EthernetHeader*>(data);

        data += sizeof(EthernetHeader);
        dlen -= sizeof(EthernetHeader);

        switch(eth->type())
        {
        case ethernet_header::IP:   check_ipv4(); break;
        case ethernet_header::IPV6: // TODO: implement IPv6
        default:
            return NULL;
        }

        return eth;
    }

    inline const IPv4Header* check_ipv4()
    {
        if(dlen < sizeof(IPv4Header)) return NULL;

        const IPv4Header* header = reinterpret_cast<const IPv4Header*>(data);

        if(header->version()  != 4) return NULL;
        if(header->length() > dlen) return NULL; // fragmented payload

        const uint32_t ihl = header->ihl();
        if(ihl < 20 || ihl > 60) return NULL; // invalid IPv4  header length

        ipv4 = header;

        data += ihl;
        dlen = header->length() - ihl;  // trunk data to length of IP packet

        switch(ipv4->protocol())
        {
        case ipv4_header::TCP: check_tcp(); break;
        case ipv4_header::UDP: // TODO: implement UDP
        default:
            return NULL;
        }

        return ipv4;
    }

    inline const TCPHeader* check_tcp()
    {
        if(dlen < sizeof(TCPHeader)) return NULL;   // fragmented TCP header

        TCPHeader* header = (TCPHeader*)data;
        uint8_t offset = header->offset();
        if(offset < 20 || offset > 60) return NULL; // invalid length of TCP header

        if(dlen < offset) return NULL;

        tcp = header;

        data += offset;
        dlen -= offset;

        return tcp;
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

    // Application Layer
    // Sun RPC
    const rpc::MessageHeader*       rpc;

    const uint8_t*                  data;   // pointer to payload data
    uint32_t                        dlen;   // length of payload data
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_INFO_H
//------------------------------------------------------------------------------
