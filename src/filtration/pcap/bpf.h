//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Berkeley Packet Filter compilation
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BPF_H
#define BPF_H
//------------------------------------------------------------------------------
#include <pcap/pcap.h>

#include "filtration/pcap/pcap_error.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{

class BPF
{
public:
    BPF(pcap_t* handle, const char* filtration, bpf_u_int32 netmask)
    {
        if(pcap_compile(handle, &bpf, filtration, 1 /*optimize*/, netmask) < 0)
        {
            throw PcapError("pcap_compile", pcap_geterr(handle));
        }
    }
    BPF(const BPF&)            = delete;
    BPF& operator=(const BPF&) = delete;
    ~BPF()
    {
        pcap_freecode(&bpf);
    }

    inline operator bpf_program*() { return &bpf; }

private:
    bpf_program bpf;
};

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//BPF_H
//------------------------------------------------------------------------------
