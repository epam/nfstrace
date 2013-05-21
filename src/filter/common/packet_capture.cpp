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

PacketCapture::PacketCapture(const std::string& interface, const std::string& filter, int snaplen, int to_ms) throw (PcapError) 
    :handle(NULL)
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
    PacketCapture::BPF bpf(handle, filter.c_str(), netmask);

    //set BPF
    if(pcap_setfilter(handle, bpf) < 0)
    {
        throw PcapError("pcap_setfilter", pcap_geterr(handle));
    }
}

PacketCapture::~PacketCapture()
{
}

bool PacketCapture::loop(void* user, pcap_handler callback, unsigned int count) throw (PcapError)
{
    int err = pcap_loop(handle, count, callback, (u_char*)user);
    if(err == -1)
    {
        throw PcapError("pcap_loop", pcap_geterr(handle));
    }
    if(err == -2)   // pcap_breakloop() called
    {
        return false;
    }
    return true; // count iterations are done
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
        out << stat.ps_recv << " packets received by filter" << std::endl
            << stat.ps_drop << " packets dropped by kernel" << std::endl;
    }
}

const std::string PacketCapture::get_default_device() throw (PcapError)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char* device = pcap_lookupdev(errbuf);
    if(NULL == device)
    {
        throw PcapError("pcap_lookupdev", errbuf);
    }
    return device;
}

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
