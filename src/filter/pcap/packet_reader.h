//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Interface for passing info from file to Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PACKET_READER
#define PACKET_READER
//------------------------------------------------------------------------------
#include <pcap/pcap.h>
#include <iostream>

#include "base_reader.h"
#include "handle.h"
#include "bpf.h"
#include "pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

class PacketReader : public BaseReader
{
public:
    PacketReader(const std::string& file);
    ~PacketReader();

    inline FILE* get_file() { return pcap_file(handle); }
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_READER
//------------------------------------------------------------------------------
