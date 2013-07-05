//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Push NFSData to buffer for further processing.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef QUEUEING_TRANSMISSION_H
#define QUEUEING_TRANSMISSION_H
//------------------------------------------------------------------------------
#include <algorithm> // for std::min()
#include <memory> // for std::auto_ptr
#include <string>

#include <iostream>

#include "filtration_processor.h"
#include "../../analyzer/nfs_data.h"
#include "../../auxiliary/queue.h"
//------------------------------------------------------------------------------
using NST::analyzer::NFSData;
using NST::auxiliary::Queue;

typedef NST::analyzer::NFSData::Session NFSSession;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class QueueingTransmission
{
    typedef Queue<NFSData> Buffer;
public:
    QueueingTransmission(Buffer& b) : buffer(b)
    {
    }
    ~QueueingTransmission()
    {
    }

    void discard(const FiltrationData& data)
    {
    }

    void collect(const FiltrationData& data)
    {
        NFSData* nfs = buffer.allocate();

        nfs->timestamp = data.header->ts;

        // TODO: addresses and ports must be ordered for correct TCP sessions matching
        if(data.ipv4_header)
        {
            nfs->session.ip_type = NFSData::Session::v4;
            nfs->session.ip.v4.addr[0] = data.ipv4_header->src();
            nfs->session.ip.v4.addr[1] = data.ipv4_header->dst();
        }

        if(data.tcp_header)
        {
            nfs->session.type = NFSData::Session::TCP;
            nfs->session.port[0] = data.tcp_header->sport();
            nfs->session.port[1] = data.tcp_header->dport();
        }

        nfs->rpc_len = std::min(data.rpc_length, sizeof(nfs->rpc_message));
        memcpy(nfs->rpc_message, data.rpc_header, nfs->rpc_len);

        buffer.push(nfs);
    }

    void collect(Nodes::Direction d, const Nodes& key, RPCReader& reader)
    {
        Queue<NFSData>::Allocated nfs(buffer);

        nfs->session.ip_type = NFSData::Session::v4;
        nfs->session.ip.v4.addr[0] = key.src_address(d);
        nfs->session.ip.v4.addr[1] = key.dst_address(d);

        nfs->session.type = NFSData::Session::TCP;
        nfs->session.port[0] = key.src_port(d);
        nfs->session.port[1] = key.dst_port(d);

        nfs->rpc_len = sizeof(nfs->rpc_message);
        
        uint32_t& size = nfs->rpc_len;

        reader.readto(size, (uint8_t*)nfs->rpc_message);

        //nfs->timestamp = data.header->ts;
    }

private:
    QueueingTransmission(const QueueingTransmission&);            // undefined
    QueueingTransmission& operator=(const QueueingTransmission&); // undefined

    Buffer& buffer;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUEING_TRANSMISSION_H
//------------------------------------------------------------------------------
