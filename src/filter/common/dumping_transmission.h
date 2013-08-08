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

#include "../pcap/handle.h"
#include "../pcap/packet_dumper.h"
#include "filtration_processor.h"
//------------------------------------------------------------------------------
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
        inline Collection()
        {
        }

        inline void operator=(const DumpingTransmission& t) // initialization
        {
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
        }

        inline void push(const PacketInfo& info)
        {

        }

        inline void push(const PacketInfo& info, const uint32_t len)
        {

        }

        inline void skip_first(const uint32_t len)
        {
        }

        void complete(const PacketInfo& info)
        {

        }

        inline const uint32_t    size() const { return 0; }
        inline uint8_t*          data() const { return NULL; }
        inline    operator bool const() const { return false; }

    private:
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
