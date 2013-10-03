//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class for capturing libpcap packets and pass them to filtration
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "bpf.h"
#include "capture_reader.h"
#include "pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{

CaptureReader::CaptureReader(const std::string& interface,
                             const std::string& filter,
                             int snaplen,
                             int timeout_ms,
                             int buffer_size)
    :BaseReader()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // storage of error description
    const char* device = interface.c_str();

    // create device
    handle = pcap_create(device, errbuf);
    if(!handle)
    {
        throw PcapError("pcap_create", errbuf);
    }

    if(int status = pcap_set_snaplen(handle, snaplen))
    {
        throw PcapError("pcap_set_snaplen", pcap_statustostr(status));
    }

    if(int status = pcap_set_promisc(handle, 1 /*set*/))
    {
        throw PcapError("pcap_set_promisc", pcap_statustostr(status));
    }

    if(int status = pcap_set_timeout(handle, timeout_ms))
    {
        throw PcapError("pcap_set_timeout", pcap_statustostr(status));
    }

    if(int status = pcap_set_buffer_size(handle, buffer_size))
    {
        throw PcapError("pcap_set_buffer_size", pcap_statustostr(status));
    }

    if(int status = pcap_activate(handle))
    {
        throw PcapError("pcap_activate", pcap_statustostr(status));
    }

    bpf_u_int32 localnet, netmask;
    if(pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0)
    {
        throw PcapError("pcap_lookupnet", errbuf);
    }

    // creating BPF
    BPF bpf(handle, filter.c_str(), netmask);

    // set BPF
    if(pcap_setfilter(handle, bpf) < 0)
    {
        throw PcapError("pcap_setfilter", pcap_geterr(handle));
    }
}

CaptureReader::~CaptureReader()
{
}

void CaptureReader::print_statistic(std::ostream& out) const
{
    struct pcap_stat stat;
    if(pcap_stats(handle, &stat) == 0)
    {
        out << stat.ps_recv   << " packets received by filter"   << std::endl
            << stat.ps_drop   << " packets dropped by kernel"    << std::endl
            << stat.ps_ifdrop << " packets dropped by interface" << std::endl;
    }
    else
    {
        throw PcapError("pcap_stats", pcap_geterr(handle));
    }
}

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
