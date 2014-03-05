//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Enumerates list of network devices, available to use in libpcap.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NETWORK_INTERFACES_H
#define NETWORK_INTERFACES_H
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

class NetworkInterfaces
{
public:

    class iterator
    {
        friend class NetworkInterfaces;
    public:

        inline    operator bool() const { return ptr != nullptr; }
        inline const char* name() const { return ptr->name; }
        inline const char* dscr() const { return ptr->description; }
        inline bool is_loopback() const { return ptr->flags & PCAP_IF_LOOPBACK; }

        void next(){ ptr = ptr->next; }

        iterator(const iterator& i) : ptr{i.ptr}{}
    private:
        iterator(pcap_if_t* p) : ptr{p}{}
        iterator& operator=(const iterator&) = delete;

        pcap_if_t* ptr;
    };

    inline NetworkInterfaces() : interfaces(nullptr)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        if(pcap_findalldevs(&interfaces, errbuf) == -1)
        {
            throw PcapError("pcap_findalldevs", errbuf);
        }
    }
    inline ~NetworkInterfaces()
    {
        pcap_freealldevs(interfaces);
    }

    const iterator first() const { return iterator(interfaces); }

private:
    pcap_if_t* interfaces;
};


} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//NETWORK_INTERFACES_H
//------------------------------------------------------------------------------
