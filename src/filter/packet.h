//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Represents captured pcap packet i.e. PacketInfo + captured data
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PACKET_H
#define PACKET_H
//------------------------------------------------------------------------------
#include <cstring> // for memcpy()

#include "packet_info.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

// Captured data of PCAP packet followed by this structure in memory
struct Packet: public PacketInfo
{
    Packet* next;     // pointer to next packet or NULL

    static Packet* create(const PacketInfo& info)
    {
        // allocate memory for Packet structure and PCAP packet data
        // TODO: performance drop! improve data alignment!
        uint8_t* memory    =  new uint8_t[sizeof(Packet) + sizeof(pcap_pkthdr) + info.header->caplen];
        Packet* fragment   = (Packet*)      ((uint8_t*)memory                                       );
        pcap_pkthdr* header= (pcap_pkthdr*) ((uint8_t*)memory + sizeof(Packet)                      );
        uint8_t*  packet   = (uint8_t*)     ((uint8_t*)memory + sizeof(Packet) + sizeof(pcap_pkthdr));

        // copy data
        *header = *info.header;                           // copy packet header
        memcpy(packet, info.packet, info.header->caplen); // copy packet data

        fragment->header   = header;
        fragment->packet   = packet;

        // fix pointers from PacketInfo to point to owned copy of packet data
        fragment->eth   = info.eth  ? (const ethernet::EthernetHeader*) (packet + ( ((const uint8_t*)info.eth ) - info.packet)) : NULL;
        fragment->ipv4  = info.ipv4 ? (const ip::IPv4Header*)           (packet + ( ((const uint8_t*)info.ipv4) - info.packet)) : NULL;
        fragment->tcp   = info.tcp  ? (const tcp::TCPHeader*)           (packet + ( ((const uint8_t*)info.tcp ) - info.packet)) : NULL;

        fragment->data  = packet + (info.data - info.packet);
        fragment->dlen  = info.dlen;

        fragment->next  = NULL;

        return fragment;
    }

    static void destroy(Packet* fragment)
    {
        uint8_t* ptr = (uint8_t*)fragment;
        delete[] ptr;
    }

private:
    Packet();                       // undefiend
    Packet(const Packet&);          // undefined
    void operator=(const Packet&);  // undefined
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_H
//------------------------------------------------------------------------------
