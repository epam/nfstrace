//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Push NFSData to queue filtered packets to .pcap file
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef QUEUEING_PROCESSOR_H
#define QUEUEING_PROCESSOR_H
//------------------------------------------------------------------------------
#include <memory> // for std::auto_ptr
#include <string>

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
    }

    virtual void after_callback (pcap_t* handle)
    {
    }

    virtual void discard(const FiltrationData& data)
    {
    }

    virtual void collect(const FiltrationData& data)
    {
        //NFSData nfs;
        // TODO:push data to queue
    }

private:

};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUEING_PROCESSOR_H
//------------------------------------------------------------------------------
