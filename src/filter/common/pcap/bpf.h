//------------------------------------------------------------------------------
// Author: Pavel Karneliuk (Dzianis Huznou)
// Description: High level interface for passing info Processor.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BPF2_H
#define BPF2_H
//------------------------------------------------------------------------------
#include <pcap/pcap.h>

#include "pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{
namespace pcap
{
class BPF
{
public:
    BPF(pcap_t* handle, const char* filter, bpf_u_int32 netmask) throw(PcapError)
    {
        if(pcap_compile(handle, &bpf, filter, 1 /*optimize*/, netmask) < 0)
        {
            throw PcapError("pcap_compile", pcap_geterr(handle));
        }
    }
    ~BPF()
    {
        pcap_freecode(&bpf);
    }
    BPF(const BPF&);            // undefined
    BPF& operator=(const BPF&); // undefined

    inline operator bpf_program*() { return &bpf; }

private:
    bpf_program bpf;
};

} // namespace pcap
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//BPF2_H
//------------------------------------------------------------------------------
