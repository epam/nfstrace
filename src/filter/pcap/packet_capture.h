//------------------------------------------------------------------------------
// Author: Pavel Karneliuk (Dzianis Huznou)
// Description: Move data from interface passing info Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PACKET_CAPTURE
#define PACKET_CAPTURE
//------------------------------------------------------------------------------
#include <pcap/pcap.h>
#include <iostream>

#include "base_reader.h"
#include "handle.h"
#include "bpf.h"
#include "pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

class PacketCapture : public BaseReader
{
public:
    enum Direction
    {
        IO = PCAP_D_INOUT,
        I  = PCAP_D_IN,
        O  = PCAP_D_OUT,
    };

    PacketCapture(const std::string& interface, const std::string& filter, int snaplen, int to_ms) throw (PcapError);
    ~PacketCapture();

    inline bool set_buffer_size(int size) { return 0 == pcap_set_buffer_size(handle, size); }
    inline void set_direction(Direction d) { pcap_setdirection(handle,(pcap_direction_t)d); }

    inline int  datalink       () { return pcap_datalink(handle); }
    void        print_statistic(std::ostream& out) const throw (PcapError);
    void        print_datalink (std::ostream& out) const;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_CAPTURE
//------------------------------------------------------------------------------
