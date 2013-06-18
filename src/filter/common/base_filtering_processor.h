//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Generic data structures for filtration raw pcap packets.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BASE_FILTERING_PROCESSOR_H
#define BASE_FILTERING_PROCESSOR_H
//------------------------------------------------------------------------------
#include <string>

#include <pcap/pcap.h>

#include "../ethernet/ethernet_header.h"
#include "../ip/ipv4_header.h"
#include "../rpc/rpc_message.h"
#include "../tcp/tcp_header.h"
//------------------------------------------------------------------------------
using namespace NST::filter::rpc;
using namespace NST::filter::ethernet;
using namespace NST::filter::ip;
using namespace NST::filter::tcp;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class BaseFilteringProcessor
{
public:

    struct FiltrationData
    {
        // libpcap structures
        const pcap_pkthdr*          header;
        const uint8_t*              packet;
        // TODO: WARNING!All pointers points to packet array!

        // TCP
        const tcp::TCPHeader*       tcp_header;

        // Sun RPC
        const rpc::MessageHeader*   rpc_header;
        size_t                      rpc_length;
    };

    BaseFilteringProcessor()
    {
    }
    virtual ~BaseFilteringProcessor()
    {
    }

    virtual void before_callback(pcap_t* handle){}
    virtual void after_callback (pcap_t* handle){}

    virtual void discard(const FiltrationData& data)=0;
    virtual void collect(const FiltrationData& data)=0;

    u_char* get_user()
    {
        return (u_char*)this;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        BaseFilteringProcessor* processor = (BaseFilteringProcessor*) user;

        FiltrationData data = {0};

        data.header = pkthdr;
        data.packet = packet;

        uint32_t len = pkthdr->len;
        uint32_t iplen = validate_eth_frame(pkthdr->len, packet);
        if(!iplen)
        {
            return processor->discard(data);
        }

        uint32_t tcplen = validate_ip_packet(iplen, packet + (len - iplen));
        if(!tcplen)
        {;
            return processor->discard(data);
        }

        uint32_t sunrpclen = validate_tcp(data, tcplen, packet + (len - tcplen));
        if(!sunrpclen)
        {;
            return processor->discard(data);
        }

        uint32_t nfslen = validate_sunrpc(data, sunrpclen, packet + (len - sunrpclen));
        if(!nfslen)
        {
            return processor->discard(data);
        }

        processor->collect(data);
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

    static uint32_t validate_tcp(FiltrationData& data/*out*/, uint32_t len, const uint8_t* packet)
    {
        if(len < sizeof(TCPHeader)) return 0;   // fragmented TCP header

        TCPHeader* header = (TCPHeader*)packet;
        uint8_t offset = header->offset();
        if(offset < 20 || offset > 60) return 0; // invalid length of TCP header

        if(len < offset) return 0;

        // fill out
        data.tcp_header = header;

        return len - offset;
    }

    static uint32_t validate_sunrpc(FiltrationData& data/*out*/, uint32_t len, const uint8_t* packet)
    {
        if(len < sizeof(RecordMark)) return 0;
        len -= sizeof(RecordMark);

        const RecordMark* rm = (RecordMark*)packet;

        // TODO: Now skip fragmented messages, it isnt well
        if(len < rm->fragment_len()) return 0; // RPC message are fragmented

        const MessageHeader* msg = rm->fragment();
        switch(msg->type())
        {
            case SUNRPC_CALL:
            {
                const CallHeader* call = static_cast<const CallHeader*>(msg);

                uint32_t rpcvers = call->rpcvers();
                uint32_t prog = call->prog();
                uint32_t vers = call->vers();

                if(rpcvers != 2)    return 0;
                if(prog != 100003)  return 0;  // portmap NFS v3 TCP 2049
                if(vers != 3)       return 0;  // NFS v3

            }
            break;
            case SUNRPC_REPLY:
            {
                // TODO: check reply via XID before passing replies further
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
            default: return 0;  // unknown RPC message
        }

        // fill out
        data.rpc_header = msg;
        data.rpc_length = len;

        return len;
    }

private:

};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//BASE_FILTERING_PROCESSOR_H
//------------------------------------------------------------------------------
