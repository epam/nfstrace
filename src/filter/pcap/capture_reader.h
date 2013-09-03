//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Move data from interface passing info Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CAPTURE_READER_H
#define CAPTURE_READER_H
//------------------------------------------------------------------------------
#include <string>
#include <ostream>

#include "base_reader.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

class CaptureReader : public BaseReader
{
public:
    enum Direction
    {
        IO = PCAP_D_INOUT,
        I  = PCAP_D_IN,
        O  = PCAP_D_OUT
    };

    CaptureReader(const std::string& interface, const std::string& filter, int snaplen, int to_ms, int buffer_size);
    ~CaptureReader();

    inline void set_direction(Direction d) { pcap_setdirection(handle,(pcap_direction_t)d); }
    void        print_statistic(std::ostream& out) const;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//CAPTURE_READER_H
//------------------------------------------------------------------------------
