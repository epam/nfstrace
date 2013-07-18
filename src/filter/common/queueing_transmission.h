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

#include "../../auxiliary/session.h"
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

    void collect(Conversation::Direction d, const Conversation& key, RPCReader& reader)
    {
        FilteredDataQueue::ElementPtr nfs(queue);

        if(!nfs)
        {
            std::clog << "free elements of the Queue are exhausted" << std::endl;
            return;
        }
        
        nfs->session = key.get_session();

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
