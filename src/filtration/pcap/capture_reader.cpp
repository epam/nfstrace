//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Capture packets from NIC by libpcap.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#include "filtration/pcap/bpf.h"
#include "filtration/pcap/capture_reader.h"
#include "filtration/pcap/pcap_error.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

CaptureReader::CaptureReader(const Params& params) : BaseReader{params.interface}
{
    char errbuf[PCAP_ERRBUF_SIZE]; // storage of error description
    const char* device = source.c_str();
    handle = pcap_create(device, errbuf);
    if(!handle)
    {
        throw PcapError("pcap_create", errbuf);
    }

    if(int status = pcap_set_snaplen(handle, params.snaplen))
    {
        throw PcapError("pcap_set_snaplen", pcap_statustostr(status));
    }

    if(int status = pcap_set_promisc(handle, params.promisc ? 1 : 0))
    {
        throw PcapError("pcap_set_promisc", pcap_statustostr(status));
    }

    if(int status = pcap_set_timeout(handle, params.timeout_ms))
    {
        throw PcapError("pcap_set_timeout", pcap_statustostr(status));
    }

    if(int status = pcap_set_buffer_size(handle, params.buffer_size))
    {
        throw PcapError("pcap_set_buffer_size", pcap_statustostr(status));
    }

    if(int status = pcap_activate(handle))
    {
        throw PcapError("pcap_activate", pcap_statustostr(status));
    }

    pcap_direction_t diection = PCAP_D_INOUT;
    switch(params.direction)
    {
        using Direction = CaptureReader::Direction;
        case Direction::IN   : diection = PCAP_D_IN;    break;
        case Direction::OUT  : diection = PCAP_D_OUT;   break;
        case Direction::INOUT: diection = PCAP_D_INOUT; break;
    }
    if(int status = pcap_setdirection(handle, diection))
    {
        throw PcapError("pcap_setdirection", pcap_statustostr(status));
    }

    bpf_u_int32 localnet, netmask;
    if(pcap_lookupnet(device, &localnet, &netmask, errbuf) < 0)
    {
        throw PcapError("pcap_lookupnet", errbuf);
    }

    BPF bpf(handle, params.filter.c_str(), netmask);

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
        out << "Statistic from interface: " << source << '\n'
            << "  packets received by filtration: " << stat.ps_recv << '\n'
            << "  packets dropped by kernel     : " << stat.ps_drop << '\n'
            << "  packets dropped by interface  : " << stat.ps_ifdrop;
    }
    else
    {
        throw PcapError("pcap_stats", pcap_geterr(handle));
    }
}

std::ostream& operator<<(std::ostream& out, const CaptureReader::Params& params)
{
    out << "Read from interface: " << params.interface << '\n'
        << "  BPF filter  : " << params.filter << '\n'
        << "  snapshot len: " << params.snaplen << " bytes\n"
        << "  read timeout: " << params.timeout_ms << " ms\n"
        << "  buffer size : " << params.buffer_size << " bytes\n"
        << "  promiscuous mode: " << (params.promisc ? "on" : "off") << '\n'
        << "  capture traffic : ";
        switch(params.direction)
        {
            using Direction = CaptureReader::Direction;
            case Direction::IN   : out << "in";    break;
            case Direction::OUT  : out << "out";   break;
            case Direction::INOUT: out << "inout"; break;
        }
    return out;
}

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
