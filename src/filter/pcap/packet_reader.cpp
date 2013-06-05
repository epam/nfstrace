//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Interface for passing info from file to Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "packet_reader.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{
PacketReader::PacketReader(const std::string& file, const std::string& filter, int netmask) throw (PcapError)
    :BaseReader()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // storage of error description
    const char* path = file.c_str();

    // open device
    handle = pcap_open_offline(path, errbuf);
    if(!handle)
    {
        throw PcapError("pcap_open_live", errbuf);
    }
}

PacketReader::~PacketReader()
{
}

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
