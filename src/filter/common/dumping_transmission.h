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

class DumpingTransmission
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

        inline void operator=(const DumpingTransmission& t) // initialization
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
            packets_len = 0;
        }

        inline void push(const PacketInfo& info, const uint32_t len)
        {
            if(timercmp(&last, &info.header->ts, !=))  // timestamps aren't equal
            {
                last = info.header->ts;

                // copy packet for dumping to file because it hasn't been seen before
                //TRACE("payload_len: %u packets_len: %u len: %u", payload_len, packets_len, len);
                assert(sizeof(packets) >= (packets_len + sizeof(pcap_pkthdr) + info.header->caplen));

                memcpy(packets+packets_len, info.header, sizeof(pcap_pkthdr));
                packets_len += sizeof(pcap_pkthdr);
                memcpy(packets+packets_len, info.packet, info.header->caplen);
                packets_len += info.header->caplen;
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

            // dump packets to file stream
            uint32_t i = 0;
            while(i < packets_len)
            {
                const pcap_pkthdr* h = reinterpret_cast<pcap_pkthdr*>(packets + i);
                const uint8_t*     p = reinterpret_cast<uint8_t*>    (packets + i + sizeof(pcap_pkthdr));
                dumper->dump(h, p);
                i += sizeof(pcap_pkthdr) + h->caplen;
            }

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
        uint8_t packets[128 * 1024]; // 128k
        uint32_t packets_len;
        struct  timeval last;   // use timestamp as unique ID of packet
    };

    DumpingTransmission(const Handle& handle, const std::string& path)
    {
        dumper.reset(new PacketDumper(handle, path.c_str()));
    }
    ~DumpingTransmission()
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
