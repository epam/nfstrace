//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Push NFSData to queue filtered packets to .pcap file
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef QUEUEING_PROCESSOR_H
#define QUEUEING_PROCESSOR_H
//------------------------------------------------------------------------------
#include <algorithm> // for std::min()
#include <memory> // for std::auto_ptr
#include <string>

#include <iostream>

#include <pcap/pcap.h>

#include "base_filtering_processor.h"
#include "../../analyzer/nfs_data.h"
//------------------------------------------------------------------------------
using NST::analyzer::NFSData;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class QueueingProcessor : public BaseFilteringProcessor
{
public:
    QueueingProcessor()
    {
    }
    ~QueueingProcessor()
    {
    }

    virtual void before_callback(pcap_t* handle)
    {
        /*NFSData nfs;
        
        std::cout << "sizeof(NFSData): " << sizeof(nfs) << std::endl;
        std::cout << "sizeof(NFSData.timestamp): " << sizeof(nfs.timestamp) << std::endl;
        std::cout << "sizeof(NFSData.session.ip): " << sizeof(nfs.session.ip) << std::endl;
        */
    }

    virtual void after_callback (pcap_t* handle)
    {
    }

    virtual void discard(const FiltrationData& data)
    {
    }

    virtual void collect(const FiltrationData& data)
    {
        NFSData nfs;

        nfs.timestamp = data.header->ts;

        // TODO: addresses and ports must be ordered for correct TCP sessions matching
        if(data.ipv4_header)
        {
            nfs.session.ip_type = NFSData::Session::v4;
            nfs.session.ip.v4.addr[0] = data.ipv4_header->src();
            nfs.session.ip.v4.addr[1] = data.ipv4_header->dst();
        }

        if(data.tcp_header)
        {
            nfs.session.type = NFSData::Session::TCP;
            nfs.session.port[0] = data.tcp_header->sport();
            nfs.session.port[1] = data.tcp_header->dport();
        }

        nfs.rpc_len = std::min(data.rpc_length, sizeof(nfs.rpc_message));
        memcpy(nfs.rpc_message, data.rpc_header, nfs.rpc_len);

        // std::cout << "queued RPC bytes: " << nfs.rpc_len << std::endl;
        // std::cout << "port: " << nfs.session.port[0] << " " << nfs.session.port[1] << std::endl;
        // TODO:push data to queue
    }

private:

};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUEING_PROCESSOR_H
//------------------------------------------------------------------------------
