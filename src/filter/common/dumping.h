//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Dump filtered packets to .pcap file
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef DUMPING_H
#define DUMPING_H
//------------------------------------------------------------------------------
#include <memory> // for std::auto_ptr
#include <string>

#include <sys/time.h>

#include "../../auxiliary/exception.h"
#include "../../auxiliary/logger.h"
#include "../pcap/handle.h"
#include "../pcap/packet_dumper.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Exception;
using NST::filter::pcap::Handle;
using NST::filter::pcap::PacketDumper;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class Dumping
{
public:

    class Collection
    {
    public:
        inline Collection():dumper(NULL)
        {
            reset();
            timerclear(&last);
        }

        inline void operator=(const Dumping& t) // initialization
        {
            dumper = t.dumper.get();
            reset();
        }
        inline ~Collection()
        {
        }

//        Collection(const Collection&);            // undefiend
//        Collection& operator=(const Collection&); // undefiend
        inline Collection(const Collection& p) // move
        {

        }
        inline Collection& operator=(const Collection& p) // move
        {
            return *this;
        }

        inline void reset()
        {
            payload_len = 0;
        }

        inline void push(const PacketInfo& info, const uint32_t len)
        {
            if(timercmp(&last, &info.header->ts, !=))  // timestamps aren't equal
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

        inline void skip_first(const uint32_t len)
        {
        }

        void complete(const PacketInfo& info)
        {
            assert(dumper);
            reset();
            dumper = NULL;
        }

        inline const uint32_t    size() const { return payload_len;    }
        inline const uint8_t*    data() const { return payload;        }
        inline    operator bool const() const { return dumper != NULL; }

    private:
        PacketDumper* dumper;
        uint8_t payload[4096];
        uint32_t payload_len;
        struct  timeval last;   // use timestamp as unique ID of packet
    };

    Dumping(const Handle& handle, const std::string& path, bool compression, uint32_t limit)
    {
        dumper.reset(new PacketDumper(handle, path.c_str()));
    }
    ~Dumping()
    {
    }

private:
    Dumping(const Dumping&);            // undefined
    Dumping& operator=(const Dumping&); // undefined

    std::auto_ptr<PacketDumper> dumper;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//DUMPING_H
//------------------------------------------------------------------------------
