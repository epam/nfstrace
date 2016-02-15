//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Dumping pcap frames to a file.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef PACKET_DUMPER_H
#define PACKET_DUMPER_H
//------------------------------------------------------------------------------
#include <pcap/pcap.h>

#include "filtration/pcap/pcap_error.h"
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
        : dumper{pcap_dump_open(handle, path)}
    {
        if(dumper == nullptr)
        {
            throw PcapError{"pcap_dump_open", pcap_geterr(handle)};
        }
    }
    PacketDumper(const PacketDumper&) = delete;
    PacketDumper& operator=(const PacketDumper&) = delete;
    ~PacketDumper()
    {
        pcap_dump_close(dumper);
    }

    inline void dump(const pcap_pkthdr* h, const u_char* sp)
    {
        pcap_dump((u_char*)dumper, h, sp);
    }

    inline void           flush() { pcap_dump_flush(dumper); }
    inline pcap_dumper_t* get_dumper() { return dumper; }
    inline FILE*          get_stream() { return pcap_dump_file(dumper); }
    void                  truncate_all_pcap_data_and_header()
    {
        pcap_dump_flush(dumper);
        FILE* stream{pcap_dump_file(dumper)};
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
#endif // PACKET_DUMPER_H
//------------------------------------------------------------------------------
