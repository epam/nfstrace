//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Push NFSData to buffer for further processing.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef QUEUEING_TRANSMISSION_H
#define QUEUEING_TRANSMISSION_H
//------------------------------------------------------------------------------
#include <algorithm> // for std::min()
#include <string>

#include "../../auxiliary/filtered_data.h"
#include "filtration_processor.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredData;
using NST::auxiliary::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class QueueingTransmission
{
public:
    QueueingTransmission(FilteredDataQueue& q) : queue(q)
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
        FilteredDataQueue::ElementPtr nfs(queue);

        nfs->timestamp = data.header->ts;

        // TODO: addresses and ports must be ordered for correct TCP sessions matching
        if(data.ipv4_header)
        {
            nfs->session.ip_type = FilteredData::Session::v4;
            nfs->session.ip.v4.addr[0] = data.ipv4_header->src();
            nfs->session.ip.v4.addr[1] = data.ipv4_header->dst();
        }

        if(data.tcp_header)
        {
            nfs->session.type = FilteredData::Session::TCP;
            nfs->session.port[0] = data.tcp_header->sport();
            nfs->session.port[1] = data.tcp_header->dport();
        }

        nfs->dlen = std::min(data.rpc_length, sizeof(nfs->data));
        memcpy(nfs->data, data.rpc_header, nfs->dlen);

        nfs.push();
    }

    void collect(Nodes::Direction d, const Nodes& key, RPCReader& reader)
    {
        FilteredDataQueue::ElementPtr nfs(queue);

        nfs->session.ip_type = FilteredData::Session::v4;
        nfs->session.ip.v4.addr[0] = key.src_address(d);
        nfs->session.ip.v4.addr[1] = key.dst_address(d);

        nfs->session.type = FilteredData::Session::TCP;
        nfs->session.port[0] = key.src_port(d);
        nfs->session.port[1] = key.dst_port(d);

        nfs->dlen = sizeof(nfs->data);

        if(reader.readto(nfs))
        {
            nfs.push();
        }
    }

private:
    QueueingTransmission(const QueueingTransmission&);            // undefined
    QueueingTransmission& operator=(const QueueingTransmission&); // undefined

    FilteredDataQueue& queue;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUEING_TRANSMISSION_H
//------------------------------------------------------------------------------
