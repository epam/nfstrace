//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class for capturing libpcap packets and pass them to a Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "packet_capture.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

PacketCapture::PacketCapture(const std::string& interface, const std::string& filter, int snaplen, int to_ms) throw (PcapError) 
    :BaseReader()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // storage of error description
    const char* device = interface.c_str();

    bpf_u_int32 localnet, netmask;
    if(pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0)
    {
        throw PcapError("pcap_lookupnet", errbuf);
    }

    // open device
    handle = pcap_open_live(device, snaplen, 0, to_ms, errbuf);
    if(!handle)
    {
        throw PcapError("pcap_open_live", errbuf);
    }

    // creating BPF
    BPF bpf(handle, filter.c_str(), netmask);

    //set BPF
    if(pcap_setfilter(handle, bpf) < 0)
    {
        throw PcapError("pcap_setfilter", pcap_geterr(handle));
    }
}

PacketCapture::~PacketCapture()
{
}

void PacketCapture::print_statistic(std::ostream& out) const throw (PcapError)
{
    struct pcap_stat stat;
    if(pcap_stats(handle, &stat) < 0)
    {
        throw PcapError("pcap_stats", pcap_geterr(handle));
    }
    else
    {
        out << stat.ps_recv   << " packets received by filter"   << std::endl
            << stat.ps_drop   << " packets dropped by kernel"    << std::endl
            << stat.ps_ifdrop << " packets dropped by interface" << std::endl;
    }
}

void PacketCapture::print_datalink(std::ostream& out) const
{
    const int dlt = pcap_datalink(handle);

    out << "datalink type:" << pcap_datalink_val_to_name(dlt) << std::endl;
    out << "datalink description:" << pcap_datalink_val_to_description(dlt) << std::endl;
}

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
