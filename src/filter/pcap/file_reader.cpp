//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Interface for passing data from file to filtration.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "file_reader.h"
#include "pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

FileReader::FileReader(const std::string& file) : BaseReader()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // storage of error description

    // open pcap device for reading from file in file system
    handle = pcap_open_offline(file.c_str(), errbuf);
    if(!handle)
    {
        throw PcapError("pcap_open_live", errbuf);
    }
}

FileReader::FileReader(FILE* rb_stream) : BaseReader()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // storage of error description

    // open pcap device for reading from existing FILE*
    handle = pcap_fopen_offline(rb_stream, errbuf);
    if(!handle)
    {
        throw PcapError("pcap_fopen_live", errbuf);
    }
}

FileReader::~FileReader()
{
}

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
