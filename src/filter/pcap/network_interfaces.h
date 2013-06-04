//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Enumerates list of network devices, available to use in libpcap.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NETWORK_INTERFACES_H
#define NETWORK_INTERFACES_H
//------------------------------------------------------------------------------
#include <pcap/pcap.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
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

        operator bool() const { return ptr != NULL; }
        inline const char* name() const { return ptr->name; }
        inline const char* dscr() const { return ptr->description; }
        inline bool is_loopback() const { return ptr->flags & PCAP_IF_LOOPBACK; }

        iterator& next(){ ptr = ptr->next; }
    private:

        iterator(pcap_if_t* p):ptr(p){}
        iterator(const iterator&);
        iterator& operator=(const iterator&);

        pcap_if_t* ptr;
    };

    inline NetworkInterfaces():interfaces(NULL)
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
} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//NETWORK_INTERFACES_H
//------------------------------------------------------------------------------
