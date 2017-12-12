//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Enumerates list of network devices, available to use in libpcap.
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
#ifndef NETWORK_INTERFACES_H
#define NETWORK_INTERFACES_H
//------------------------------------------------------------------------------
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pcap/pcap.h>
#include <sys/socket.h>

#include "filtration/pcap/pcap_error.h"
#include "utils/noncopyable.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
namespace pcap
{
class NetworkInterfaces final : utils::noncopyable
{
public:
    class Interface;
    class Address final
    {
        friend class Interface;

    public:
        inline sockaddr* address() const noexcept { return addr->addr; }
        inline sockaddr* netmask() const noexcept { return addr->netmask; }
        inline sockaddr* broadaddr() const noexcept { return addr->broadaddr; }
        inline sockaddr* destaddr() const noexcept { return addr->dstaddr; }
        Address&         operator=(const Address&) = delete;
        void operator&()                           = delete;
        void* operator new(size_t)                 = delete;
        void operator delete(void*)                = delete;

        inline operator bool() const noexcept { return addr != nullptr; }
        inline void operator++() noexcept { addr = addr->next; }
        inline bool operator!=(const Address& a) const noexcept { return addr != a.addr; }
        inline const Address operator*() const noexcept { return *this; }
        Address(const Address& a)
            : addr{a.addr}
        {
        }

    private:
        Address(pcap_addr_t* a)
            : addr{a}
        {
        }
        pcap_addr_t* addr;
    };

    class Interface final
    {
        friend class NetworkInterfaces;

    public:
        inline const char* name() const noexcept { return ptr->name; }
        inline const char* dscr() const noexcept { return ptr->description; }
        inline bool        is_loopback() const noexcept { return ptr->flags & PCAP_IF_LOOPBACK; }
        Interface&         operator=(const Interface&) = delete;
        void operator&()                               = delete;
        void* operator new(size_t)                     = delete;
        void operator delete(void*)                    = delete;

        inline operator bool() const noexcept { return ptr != nullptr; }
        inline void operator++() noexcept { ptr = ptr->next; }
        inline bool operator!=(const Interface& i) const noexcept { return ptr != i.ptr; }
        inline const Interface operator*() const noexcept { return *this; }
        Interface(const Interface& i)
            : ptr{i.ptr}
        {
        }

        const Address begin() const noexcept { return Address{ptr->addresses}; }
        const Address end() const noexcept { return Address{nullptr}; }
    private:
        Interface(pcap_if_t* p)
            : ptr{p}
        {
        }
        pcap_if_t* ptr;
    };

    inline NetworkInterfaces()
        : interfaces{nullptr}
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

    inline static std::string default_device()
    {
        NST::filtration::pcap::NetworkInterfaces interfaces;

        for(const auto& interface : interfaces)
        {
            for(const auto& address : interface)
            {
                // Do not compare string for appropriate IP4/IP6 address.
                // If pointer to address is not null expect it has valid address.
                if(address.address() != nullptr)
                {
                    return interface.name();
                }
            }
        }

        throw std::runtime_error{"No suitable device found.\n Note: reading an ip address of a network device may require special privileges."};
    }

    void operator&()                                       = delete;
    void* operator new(size_t)                             = delete;
    void operator delete(void*)                            = delete;

    const Interface begin() const noexcept { return Interface{interfaces}; }
    const Interface end() const noexcept { return Interface{nullptr}; }
private:
    pcap_if_t* interfaces;
};

std::ostream& operator<<(std::ostream& out, const NetworkInterfaces::Interface& i)
{
    out.width(8);
    out << std::left << i.name();
    const char* dscr{i.dscr()};
    if(dscr)
    {
        out << '(' << dscr << ')';
    }
    if(i.is_loopback())
    {
        out << "(loopback)";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const NetworkInterfaces::Address& a)
{
    sockaddr* s_address{a.address()};
    sockaddr* s_netmask{a.netmask()};
    if(s_address)
    {
        switch(s_address->sa_family)
        {
        case AF_INET:
        {
            char ip[INET_ADDRSTRLEN]{};
            char netmask[INET_ADDRSTRLEN]{};

            inet_ntop(AF_INET,
                      &(reinterpret_cast<sockaddr_in*>(s_address)->sin_addr),
                      ip,
                      sizeof(ip));
            out << "inet " << ip;
            inet_ntop(AF_INET,
                      &(reinterpret_cast<sockaddr_in*>(s_netmask)->sin_addr),
                      netmask,
                      sizeof(netmask));
            out << " netmask " << netmask;

            sockaddr* s_broadaddr{a.broadaddr()};
            if(s_broadaddr)
            {
                char broadaddr[INET_ADDRSTRLEN]{};
                inet_ntop(AF_INET,
                          &(reinterpret_cast<sockaddr_in*>(s_broadaddr)->sin_addr),
                          broadaddr,
                          sizeof(broadaddr));
                out << " broadcast " << broadaddr;
            }

            sockaddr* s_destaddr{a.destaddr()};
            if(s_destaddr)
            {
                char destaddr[INET_ADDRSTRLEN]{};
                inet_ntop(AF_INET,
                          &(reinterpret_cast<sockaddr_in*>(s_destaddr)->sin_addr),
                          destaddr,
                          sizeof(destaddr));
                out << " destadrr " << destaddr;
            }
            break;
        }
        case AF_INET6:
        {
            char ip6[INET6_ADDRSTRLEN]{};
            char netmask6[INET6_ADDRSTRLEN]{};
            inet_ntop(AF_INET6,
                      &(reinterpret_cast<sockaddr_in6*>(s_address)->sin6_addr),
                      ip6,
                      sizeof(ip6));
            out << "inet6 " << ip6;
            out << " scopeid " << std::showbase << std::hex
                << reinterpret_cast<sockaddr_in6*>(s_address)->sin6_scope_id << std::dec;

            inet_ntop(AF_INET6,
                      &(reinterpret_cast<sockaddr_in6*>(s_netmask)->sin6_addr),
                      netmask6,
                      sizeof(netmask6));
            out << " netmask " << netmask6;
            break;
        }
        default:
        {
            out << "Unsupported address family("
                << static_cast<uint32_t>(s_address->sa_family)
                << ')';
        }
        }
    }
    return out;
}

} // namespace pcap
} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif // NETWORK_INTERFACES_H
//------------------------------------------------------------------------------
