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
#include "../pcap/packet_dumper.h"
//------------------------------------------------------------------------------
using NST::filter::pcap::PacketDumper;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class DumpingProcessor : public BaseFilteringProcessor
{
public:
    DumpingProcessor(const std::string& path) : file(path)
    {
    }
    ~DumpingProcessor()
    {
    }

    virtual void before_callback(pcap_t* handle)
    {
        // prepare packet dumper
        dumper.reset(new PacketDumper(handle, file.c_str()));
    }

    virtual void after_callback (pcap_t* handle)
    {
        // destroy packet dumper
        dumper.release();
    }

    virtual void discard(const FiltrationData& data)
    {
    }

    virtual void collect(const FiltrationData& data)
    {
        dumper->dump(data.header, data.packet);
    }

private:

    std::string file;
    std::auto_ptr<PacketDumper> dumper;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//DUMPING_PROCESSOR_H
//------------------------------------------------------------------------------
