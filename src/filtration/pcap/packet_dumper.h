//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Dumping pcap frames to a file.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PACKET_DUMPER_H
#define PACKET_DUMPER_H
//------------------------------------------------------------------------------
#include <pcap/pcap.h>

#include "filtration/pcap/pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

class PacketDumper
{
public:
    PacketDumper(pcap_t* handle, const char* path)
    : dumper{ pcap_dump_open(handle, path) }
    {
        if(NULL == dumper)
        {
            throw PcapError{"pcap_dump_open", pcap_geterr(handle)};
        }
    }
    PacketDumper(pcap_t* handle, FILE* wb_stream)
    : dumper{ pcap_dump_fopen(handle, wb_stream) }
    {
        if(NULL == dumper)
        {
            throw PcapError{"pcap_dump_fopen", pcap_geterr(handle)};
        }
    }
    PacketDumper(const PacketDumper&)            = delete;
    PacketDumper& operator=(const PacketDumper&) = delete;
    ~PacketDumper()
    {
        pcap_dump_close(dumper);
    }

    inline void dump(const pcap_pkthdr *h, const u_char *sp)
    {
        pcap_dump((u_char*)dumper, h, sp);
    }

    inline void                flush() { pcap_dump_flush(dumper); }
    inline pcap_dumper_t* get_dumper() { return dumper; }
    inline FILE*          get_stream() { return pcap_dump_file(dumper); }

    void truncate_all_pcap_data_and_header()
    {
        pcap_dump_flush(dumper);
        FILE* stream = pcap_dump_file(dumper);
        rewind(stream); // truncate a file to zero
        pcap_dump_flush(dumper);
    }

private:
    pcap_dumper_t* dumper;
};

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_DUMPER_H
//------------------------------------------------------------------------------
