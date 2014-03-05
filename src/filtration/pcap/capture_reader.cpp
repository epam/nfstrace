//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class for capturing libpcap packets and pass them to filtration
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "filtration/pcap/bpf.h"
#include "filtration/pcap/capture_reader.h"
#include "filtration/pcap/pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

CaptureReader::CaptureReader(const std::string& interface,
                             const std::string& filtration,
                             int snaplen,
                             int timeout_ms,
                             int buffer_size)
    : BaseReader()
{
    char errbuf[PCAP_ERRBUF_SIZE]; // storage of error description
    const char* device = interface.c_str();

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

    BPF bpf(handle, filtration.c_str(), netmask);

    if(pcap_setfilter(handle, bpf) < 0)
    {
        throw PcapError("pcap_setfiltration", pcap_geterr(handle));
    }
}

void CaptureReader::print_statistic(std::ostream& out) const
{
    struct pcap_stat stat={0,0,0};
    if(pcap_stats(handle, &stat) == 0)
    {
        out << stat.ps_recv   << " packets received by filtration\n"
            << stat.ps_drop   << " packets dropped by kernel\n"
            << stat.ps_ifdrop << " packets dropped by interface\n";
    }
    else
    {
        throw PcapError("pcap_stats", pcap_geterr(handle));
    }
}

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
