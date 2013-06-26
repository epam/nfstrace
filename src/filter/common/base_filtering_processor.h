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
        const pcap_pkthdr*              header;
        const uint8_t*                  packet;
        // TODO: WARNING!All pointers points to packet data!

        // Ethernet II
        const ethernet::EthernetHeader* eth_header;

        // IP version 4
        const ip::IPv4Header*           ipv4_header;

        // TCP
        const tcp::TCPHeader*           tcp_header;

        // Sun RPC
        const rpc::MessageHeader*       rpc_header;
        size_t                          rpc_length;
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

        // TODO: THIS CODE MUST BE TOTALLY REFACTORED!
        // TODO: 1) Design and implement the Readers for each layer
        //       2) Manage separate reades for each session
        //       3) Detect placement of NFS Op data and drop it ASAP
        //       4) Pass filtered NFS Op headers (RPC messages) to Analysis

        FiltrationData data = {0};

        data.header = pkthdr;
        data.packet = packet;

        const uint32_t len = pkthdr->len;

        // parse Data Link Layer
        uint32_t payload = validate_eth(data, len, packet);
        if(!payload)
        {
            return processor->discard(data);
        }

        // parse Internet Layer
        switch(data.eth_header->type())
        {
        case ethernet_header::IP:
            payload = validate_ipv4(data, payload, packet + (len - payload));
            break;
        case ethernet_header::IPV6: // TODO: implement IPv6
        default:
            payload = 0;
        }
        if(!payload)
        {
            return processor->discard(data);
        }

        // parse Transport Layer
        switch(data.ipv4_header->protocol())
        {
        case ipv4_header::TCP:
            payload = validate_tcp(data, payload, packet + (len - payload));
            break;
        case ipv4_header::UDP: // TODO: implement UDP
        default:
            payload = 0;
        }
        if(!payload)
        {
            return processor->discard(data);
        }

        // parse Application Layer
        payload = validate_sunrpc(data, payload, packet + (len - payload));
        if(!payload)
        {
            return processor->discard(data);
        }

        processor->collect(data);
    }

    // validation methods return packet length without header they validate or 0 on error
    static uint32_t validate_eth(FiltrationData& data/*out*/, uint32_t len, const uint8_t* packet)
    {
        if(len < sizeof(EthernetHeader)) return 0;

        EthernetHeader* header = (EthernetHeader*)packet;

        // fill out
        data.eth_header = header;

        return len - sizeof(EthernetHeader);
    }

    static uint32_t validate_ipv4(FiltrationData& data/*out*/, uint32_t len, const uint8_t* packet)
    {
        if(len < sizeof(IPv4Header)) return 0;   // fragmented IPv4 header
        
        IPv4Header* header = (IPv4Header*)packet;
        
        const uint16_t total_len = header->length();

        if(header->version() != 4 || total_len > len) // fragmented payload
        {
            return 0;
        }

        // fill out
        data.ipv4_header = header;

        return len - header->ihl();
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

        // TODO: handle fragmented messages
        const uint32_t fraglen = rm->fragment_len();
        if(len < fraglen || fraglen == 0 || !rm->is_last()) return 0; // RPC message are fragmented or invalid

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
