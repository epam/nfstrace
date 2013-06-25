//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Dump filtered packets to .pcap file
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef DUMPING_PROCESSOR_H
#define DUMPING_PROCESSOR_H
//------------------------------------------------------------------------------
#include <memory> // for std::auto_ptr
#include <string>

#include <pcap/pcap.h>

#include "base_filtering_processor.h"
#include "../pcap/handle.h"
#include "../pcap/packet_dumper.h"
//------------------------------------------------------------------------------
using NST::filter::pcap::Handle;
using NST::filter::pcap::PacketDumper;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class DumpingProcessor : public BaseFilteringProcessor
{
public:
    DumpingProcessor(const Handle& handle, const std::string& path)
    {
        dumper.reset(new PacketDumper(handle, path.c_str()));
    }
    ~DumpingProcessor()
    {
    }

    virtual void discard(const FiltrationData& data)
    {
    }

    virtual void collect(const FiltrationData& data)
    {
        dumper->dump(data.header, data.packet);
    }

private:
    std::auto_ptr<PacketDumper> dumper;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//DUMPING_PROCESSOR_H
//------------------------------------------------------------------------------
