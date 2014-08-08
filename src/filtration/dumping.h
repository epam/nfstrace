//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Dump filtered packets to .pcap file
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
#ifndef DUMPING_H
#define DUMPING_H
//------------------------------------------------------------------------------
#include <cstring> // memcpy()
#include <memory>
#include <string>

#include <sys/time.h>

#include "filtration/packet.h"
#include "filtration/pcap/handle.h"
#include "filtration/pcap/packet_dumper.h"
#include "utils/log.h"
#include "utils/sessions.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

class Dumping
{
public:

    class Collection
    {
    public:
        inline Collection()
        : dumper {nullptr}
        {
            reset();
            timerclear(&last);
        }
        inline Collection(Dumping* d, utils::NetworkSession* /*unused*/)
        : dumper {d}
        {
            reset();
            timerclear(&last);
        }
        inline ~Collection()
        {
        }
        Collection(Collection&&)                 = delete;
        Collection(const Collection&)            = delete;
        Collection& operator=(const Collection&) = delete;

        inline void set(Dumping& d, utils::NetworkSession* /*unused*/)
        {
            dumper = &d;
            reset();
        }

        inline void allocate()
        {
            // we have a reference to dumper, just do reset
            reset();
        }

        inline void reset()
        {
            payload_len = 0;
        }

        inline void push(const PacketInfo& info, const uint32_t len)
        {
            if(timercmp(&last, &info.header->ts, !=)) // timestamps aren't equal
            {
                last = info.header->ts;
                // direct dumping without waiting completeness of analysis and complete() call
                dumper->dump(info.header, info.packet);
            }
            else
            {
                TRACE("The packet was collected before");
            }

            // copy payload
            memcpy(payload+payload_len, info.data, len);
            payload_len += len;
        }

        inline void prestart() //for difference initialization
        {
            reset();
        }

        inline void skip_first(const uint32_t /*len*/)
        {
        }

        inline void complete(const PacketInfo& /*info*/)
        {
            assert(dumper);
            reset();
        }

        inline       uint32_t size() const { return payload_len;       }
        inline const uint8_t* data() const { return payload;           }
        inline       operator bool() const { return dumper != nullptr; }

    private:
        Dumping* dumper;
        uint8_t payload[4096];
        uint32_t payload_len;
        struct  timeval last;   // use timestamp as unique ID of last packet
    };

    struct Params
    {
        std::string output_file{ };
        std::string command    { };
        uint32_t    size_limit {0};
    };

    Dumping(const pcap::Handle& h, const Params& params);
    ~Dumping();
    Dumping(const Dumping&)            = delete;
    Dumping& operator=(const Dumping&) = delete;

    inline void dump(const pcap_pkthdr* header, const u_char* packet)
    {
        if(limit)
        {
            if(size + sizeof(pcap_pkthdr) + header->caplen > limit)
            {
                close_dumping_file();

                ++part;
                char suffix[64];
                sprintf(suffix, "-%u", part);
                name = base + /*'-' + std::to_string(part)*/ suffix;
                size = 0;
                open_dumping_file(name);

                // new part of dump file shouldn't have ./pcap header
                dumper->truncate_all_pcap_data_and_header();
            }
            size += sizeof(pcap_pkthdr) + header->caplen;
        }

        dumper->dump(header, packet);
    }

private:
    void open_dumping_file(const std::string& file_path);
    void close_dumping_file();
    void exec_command() const;

    std::unique_ptr<pcap::PacketDumper> dumper;
    const pcap::Handle& handle;
    std::string         base;
    std::string         name;
    std::string         command;
    const uint32_t      limit;
    uint32_t            part;
    uint32_t            size;
};

std::ostream& operator<<(std::ostream& out, const Dumping::Params& params);

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//DUMPING_H
//------------------------------------------------------------------------------
