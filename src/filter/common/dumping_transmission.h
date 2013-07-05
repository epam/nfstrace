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

#include "filtration_processor.h"
#include "../pcap/handle.h"
#include "../pcap/packet_dumper.h"

#include "../../analyzer/nfs_data.h"
//------------------------------------------------------------------------------
using NST::filter::pcap::Handle;
using NST::filter::pcap::PacketDumper;

typedef NST::analyzer::NFSData::Session NFSSession;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class DumpingTransmission
{
public:
    DumpingTransmission(const Handle& handle, const std::string& path)
    {
        dumper.reset(new PacketDumper(handle, path.c_str()));
    }
    ~DumpingTransmission()
    {
    }

    void discard(const FiltrationData& data)
    {
    }

    void collect(const FiltrationData& data)
    {
        dumper->dump(data.header, data.packet);
    }

    void collect(const NFSSession& session, const FiltrationData& data)
    {
        dumper->dump(data.header, data.packet);
    }
    
    void collect(Nodes::Direction d, const Nodes& key, RPCReader& reader)
    {
    }

private:
    DumpingTransmission(const DumpingTransmission&);            // undefined
    DumpingTransmission& operator=(const DumpingTransmission&); // undefined

    std::auto_ptr<PacketDumper> dumper;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//DUMPING_PROCESSOR_H
//------------------------------------------------------------------------------
