//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Dumping pcap frames to a file.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PACKET_DUMPER_H
#define PACKET_DUMPER_H
//------------------------------------------------------------------------------
#include <pcap/pcap.h>

#include "pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

class PacketDumper
{
public:
    PacketDumper(pcap_t* handle, const char* path):dumper(NULL), stream(NULL)
    {
        dumper = pcap_dump_open(handle, path);
        if(NULL == dumper)
        {
            throw PcapError("pcap_dump_open", pcap_geterr(handle));
        }

        stream = pcap_dump_file(dumper);
    }

    ~PacketDumper()
    {
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
    }

    inline void dump(const pcap_pkthdr *h, const u_char *sp)
    {
        pcap_dump((u_char*)dumper, h, sp);
    }

    inline void dump(const void* ptr, size_t size)
    {
        if(fwrite(ptr, size, 1, stream) != 1)
        {
            throw PcapError("fwrite", "Error writing to dumping file");
        }
    }

private:
    PacketDumper(const PacketDumper&);                  // undefined
    const PacketDumper& operator=(const PacketDumper&); // undefined

    pcap_dumper_t* dumper;
    FILE* stream;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_DUMPER_H
//------------------------------------------------------------------------------
