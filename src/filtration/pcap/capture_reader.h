//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Move data from interface passing info Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CAPTURE_READER_H
#define CAPTURE_READER_H
//------------------------------------------------------------------------------
#include "filtration/pcap/base_reader.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

class CaptureReader : public BaseReader
{
public:
    enum class Direction
    {
        IO = PCAP_D_INOUT,
        I  = PCAP_D_IN,
        O  = PCAP_D_OUT
    };

    CaptureReader(const std::string& interface,
                  const std::string& filtration,
                  int snaplen,
                  int to_ms,
                  int buffer_size);
    ~CaptureReader() = default;

    inline void set_direction(Direction direction)
    {
        pcap_setdirection(handle, static_cast<pcap_direction_t>(direction));
    }
    void print_statistic(std::ostream& out) const override;
};

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//CAPTURE_READER_H
//------------------------------------------------------------------------------
