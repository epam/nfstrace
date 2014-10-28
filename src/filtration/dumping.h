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
    private:
        const static int cache_size {4096};

        inline void resize(uint32_t amount)
        {
            buff_size = amount;
            uint8_t* buff {new uint8_t[amount]};
            memcpy(buff, payload, payload_len);
            if(payload != cache)
                delete[] payload;
            payload = buff;
        }

    public:
        inline Collection()
        : dumper      {nullptr}
        , buff_size   {cache_size}
        , payload     {cache}
        , payload_len {0}
        {
        }
        inline Collection(Dumping* d, utils::NetworkSession* /*unused*/)
        : dumper      {d}
        , buff_size   {cache_size}
        , payload     {cache}
        , payload_len {0}
        {
        }
        inline ~Collection()
        {
            if(payload != cache)
                delete[] payload;
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
            if(info.dumped)  // if this packet not dumped yet
            {
                TRACE("The packet was collected before");
            }
            else
            {
                // direct dumping without waiting completeness of analysis and complete() call
                dumper->dump(info.header, info.packet);
                info.dumped = true;  // set marker of damped packet
            }
            if((payload_len + len) > capacity())
            {
                resize(payload_len + len);
            }
            // copy payload
            memcpy(payload+payload_len, info.data, len);
            payload_len += len;
        }

        inline void skip_first(const uint32_t /*len*/)
        {
        }

        inline void complete(const PacketInfo& /*info*/)
        {
            assert(dumper);
            reset();
        }

        inline uint32_t data_size() const  { return payload_len; }
        inline uint32_t capacity() const   { return buff_size; }
        inline const uint8_t* data() const { return payload;           }
        inline       operator bool() const { return dumper != nullptr; }

    private:
        Dumping* dumper;
        uint32_t buff_size;
        uint8_t* payload;
        uint8_t cache[cache_size];
        uint32_t payload_len;
    };

    struct Params
    {
        std::string output_file{ };
        std::string command    { };
        uint32_t    size_limit {0};
    };

    Dumping(pcap_t*const h, const Params& params);
    ~Dumping();
    Dumping(const Dumping&)            = delete;
    Dumping& operator=(const Dumping&) = delete;

    inline void dump(const pcap_pkthdr* header, const u_char* packet)
    {
        if(limit)
        {
            if( (size + sizeof(pcap_pkthdr) + header->caplen) > limit )
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
    pcap_t* const       handle;
    const std::string   base;
    std::string         name;
    const std::string   command;
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
