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

#include "i_packet_reader.h"
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
class PacketCapture : public IPacketReader
{
public:
    PacketCapture(const std::string& interface, const std::string& filter, int snaplen, int to_ms) throw (PcapError);
    ~PacketCapture();

    bool set_buffer_size(int size);

    inline int  datalink  () { return pcap_datalink(handle); }
    void        print_statistic(std::ostream& out) const throw (PcapError);
    void        print_datalink (std::ostream& out) const;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//PACKET_CAPTURE
//------------------------------------------------------------------------------
