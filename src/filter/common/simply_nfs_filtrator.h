//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Implements dummy filtrator for NFS Calls and Replies.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SIMPLY_NFS_FILTRATOR_H
#define SIMPLY_NFS_FILTRATOR_H
//------------------------------------------------------------------------------
#include <memory> // for std::auto_ptr
#include <string>

#include <pcap/pcap.h>

#include "../pcap/packet_dumper.h"

#include "../ethernet/ethernet_header.h"
#include "../ip/ipv4_header.h"
#include "../rpc/rpc_message.h"
#include "../tcp/tcp_header.h"
//------------------------------------------------------------------------------
using NST::filter::pcap::PacketDumper;

using namespace NST::filter::rpc;
using NST::filter::ethernet::ethernet_header;
using NST::filter::ip::ipv4_header;
using NST::filter::tcp::tcp_header;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class SimplyNFSFiltrator
{
public:
    SimplyNFSFiltrator(const std::string& path):file(path), captured(0), discarded(0)
    {
    }
    ~SimplyNFSFiltrator()
    {
    }

    void before_callback(pcap_t* handle)
    {
        // prepare packet dumper
        packets.reset(new PacketDumper(handle, file.c_str()));
        captured    = 0;
        discarded   = 0;
    }

    void after_callback(pcap_t* handle)
    {
        // destroy packet dumper
        packets.release();
    }

    u_char* get_user()
    {
        return (u_char*)this;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        SimplyNFSFiltrator& processor = *(SimplyNFSFiltrator*) user;

        processor.discarded++;

        uint32_t len = pkthdr->len;
        uint32_t iplen = validate_eth_frame(len, packet);
        if(!iplen)
        {
            return;
        }

        uint32_t tcplen = validate_ip_packet(iplen, packet + (len - iplen));
        if(!tcplen)
        {;
            return;
        }

        uint32_t sunrpclen = validate_tcp_packet(tcplen, packet + (len - tcplen));
        if(!sunrpclen)
        {;
            return;
        }

        uint32_t authlen = validate_sunrpc_nfsv3_2049_packet(sunrpclen, packet + (len - sunrpclen));
        if(!authlen)
        {
            return;
        }

        processor.captured++;
        processor.discarded--;
        processor.packets->dump(pkthdr, packet);
    }

    // validation methods return packet length without header they validate or 0 on error
    static uint32_t validate_eth_frame(uint32_t framelen, const u_char *packet)
    {
        ethernet_header *ehdr = (ethernet_header*)packet;
        if(ntohs(ehdr->eth_type) != ethernet_header::IP)
            return 0;
        return framelen - sizeof(ethernet_header) > 0 ? framelen - sizeof(ethernet_header) : 0;
    }

    static uint32_t validate_ip_packet(uint32_t packetlen, const u_char *packet)
    {
        ipv4_header *ippacket = (ipv4_header*)packet;
        uint32_t iphdrlen = (ippacket->ipv4_vhl & 0x0f) * 4;
        if(ippacket->ipv4_protocol != ipv4_header::TCP)
            return 0;
        return packetlen - iphdrlen > 0 ? packetlen - iphdrlen : 0;
    }

    static uint32_t validate_tcp_packet(uint32_t packetlen, const u_char *packet)
    {
        struct tcp_header *tcppacket = (tcp_header*)packet;
        uint32_t tcphdrlen = (tcppacket->tcp_rsrvd_off & 0xf0) >> 2;
        return packetlen - tcphdrlen > 0 ? packetlen - tcphdrlen : 0;
    }

    static uint32_t validate_sunrpc_nfsv3_2049_packet(uint32_t packetlen, const u_char *packet)
    {
        if(packetlen < sizeof(RecordMark)) return 0;
        packetlen -= sizeof(RecordMark);

        const RecordMark* rm = (RecordMark*)packet;

        if(packetlen < rm->fragment_len()) return 0; // RPC message are fragmented

        const MessageHeader* msg = rm->fragment();
        switch(msg->type())
        {
            case SUNRPC_CALL:
            {
                const CallHeader* call = static_cast<const CallHeader*>(msg);

                uint32_t rpcvers = call->rpcvers();
                uint32_t prog = call->prog();
                uint32_t vers = call->vers();
                //uint32_t proc = call->proc();

                if(rpcvers != 2)    return 0;
                if(prog != 100003)  return 0;  // portmap NFS v3 TCP 2049
                if(vers != 3)       return 0;  // NFS v3

                std::cout << *call << std::endl;

            }
            break;
            case SUNRPC_REPLY:
            {
                const ReplyHeader* reply = static_cast<const ReplyHeader*>(msg);
                switch(reply->stat())
                {
                    case SUNRPC_MSG_ACCEPTED:
                    {
                        // TODO: check accepted reply
                    }
                    break;
                    case SUNRPC_MSG_DENIED:
                    {
                        // TODO: check rejected reply
                    }
                    break;
                }
            }
            break;
        }

        return packetlen;
    }

private:

    std::string file;
    std::auto_ptr<PacketDumper> packets;

    uint64_t captured;
    uint32_t discarded;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//SIMPLY_NFS_FILTRATOR_H
//------------------------------------------------------------------------------
