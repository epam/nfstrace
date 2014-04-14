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

    class Interface
    {
        friend class NetworkInterfaces;
    public:

        inline const char* name() const noexcept { return ptr->name; }
        inline const char* dscr() const noexcept { return ptr->description; }
        inline bool is_loopback() const noexcept { return ptr->flags & PCAP_IF_LOOPBACK; }

        inline      operator bool() const noexcept { return ptr != nullptr; }
        inline void operator   ++() const noexcept { ptr = ptr->next; }
        inline bool operator   !=(const Interface& i) const noexcept { return ptr != i.ptr; }
        inline const Interface operator*() const noexcept { return *this; }

        Interface(const Interface& i) : ptr{i.ptr}{}
    private:
        Interface(pcap_if_t* p) : ptr{p}{}

        mutable pcap_if_t* ptr;
    };

    inline NetworkInterfaces() noexcept : interfaces{nullptr}
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        if(pcap_findalldevs(&interfaces, errbuf) == -1)
        {
            throw PcapError("pcap_findalldevs", errbuf);
        }
    }
    inline ~NetworkInterfaces() noexcept
    {
        pcap_freealldevs(interfaces);
    }

    const Interface begin() const noexcept { return Interface{interfaces}; }
    const Interface   end() const noexcept { return Interface{nullptr};    }

private:
    pcap_if_t* interfaces;
};

std::ostream& operator <<(std::ostream& out, const NetworkInterfaces::Interface& i)
{
    out << i.name();
    const char* dscr = i.dscr();
    if(dscr)
    {
        out << " (" << dscr << ')';
    }
    if(i.is_loopback())
    {
        out << " (loopback)";
    }
    return out;
}

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//NETWORK_INTERFACES_H
//------------------------------------------------------------------------------
