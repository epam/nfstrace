//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structs for sessions.
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
#include <sstream>

#include <arpa/inet.h> // for inet_ntop(), ntohs()
#include <netdb.h>
#include <sys/socket.h> // for AF_INET/AF_INET6

#include "utils/out.h"
#include "utils/sessions.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{
std::ostream& operator<<(std::ostream& out, const ApplicationSession& session);

ApplicationSession::ApplicationSession(const NetworkSession& s, Direction from_client)
    : utils::Session(s)
{
    if(s.direction != from_client)
    {
        //TODO: implement correct swap_src_dst()
        std::swap(port[0], port[1]);
        switch(ip_type)
        {
        case Session::IPType::v4:
            std::swap(ip.v4.addr[0], ip.v4.addr[1]);
            break;
        case Session::IPType::v6:
            std::swap(ip.v6.addr[0], ip.v6.addr[1]);
            break;
        }
    }

    // TODO: print network addresses in human readable form and
    //       potential host name lookup may be expensive, to try to use
    //       std::future(async | deferred, ...) and std::promise, to perform
    //       this operation asynchronously
    std::stringstream stream(std::ios_base::out);
    stream << *this;
    session_str = stream.str();
}

namespace
{
std::ostream& operator<<(std::ostream& out, const Session::Type type)
{
    switch(type)
    {
    case Session::Type::TCP:
        return out << " [TCP]";
    case Session::Type::UDP:
        return out << " [UDP]";
    }
    return out;
}

void print_ipv4_port(std::ostream& out, in_addr_t ipv4, in_port_t port)
{
    static_assert(sizeof(ipv4) == sizeof(struct in_addr), "they must be equal");
    char buf[INET_ADDRSTRLEN];

    const char* str{inet_ntop(AF_INET, &ipv4, buf, sizeof(buf))};
    out << (str ? str : "Invalid IPv4 address")
        << ':' << ntohs(port);
}

void print_ipv6_port(std::ostream& out, const uint8_t (&ipv6)[16], in_port_t port)
{
    static_assert(sizeof(ipv6) == sizeof(struct in6_addr), "they must be equal");
    char buf[INET6_ADDRSTRLEN];

    const char* str{inet_ntop(AF_INET6, ipv6, buf, sizeof(buf))};
    out << (str ? str : "Invalid IPv6 address")
        << ':' << ntohs(port);
}

// TODO: getnameinfo call may be expensive
template <typename SockAddr>
void print_sockaddr(std::ostream& out, SockAddr& addr)
{
    char      hostname[1025];
    char      service[65];
    const int err{getnameinfo((sockaddr*)&addr, sizeof(addr),
                              hostname, sizeof(hostname),
                              service, sizeof(service),
                              NI_NAMEREQD)};
    if(err == 0)
    {
        out << '(' << hostname << ':' << service << ')';
    }
}

void print_ipv4_port_as_hostname_service(std::ostream& out,
                                         in_addr_t     ipv4,
                                         in_port_t     port)
{
    sockaddr_in addr;
    addr.sin_family      = AF_INET;
    addr.sin_port        = port;
    addr.sin_addr.s_addr = ipv4;

    print_sockaddr(out, addr);
}

void print_ipv6_port_as_hostname_service(std::ostream& out,
                                         const uint8_t (&ipv6)[16],
                                         in_port_t port)
{
    sockaddr_in6 addr;
    addr.sin6_family   = AF_INET6;
    addr.sin6_port     = port;
    addr.sin6_flowinfo = 0;
    addr.sin6_addr     = (in6_addr&)ipv6;
    addr.sin6_scope_id = 0;

    print_sockaddr(out, addr);
}

} // unnamed namespace

std::ostream& operator<<(std::ostream& out, const Session& session)
{
    print_session(out, session);
    return out;
}

void print_session(std::ostream& out, const Session& session)
{
    switch(session.ip_type)
    {
    case Session::IPType::v4:
    {
        print_ipv4_port(out, session.ip.v4.addr[Session::Source],
                        session.port[Session::Source]);
        out << " --> ";
        print_ipv4_port(out, session.ip.v4.addr[Session::Destination],
                        session.port[Session::Destination]);
    }
    break;
    case Session::IPType::v6:
    {
        print_ipv6_port(out, session.ip.v6.addr[Session::Source],
                        session.port[Session::Source]);
        out << " --> ";
        print_ipv6_port(out, session.ip.v6.addr[Session::Destination],
                        session.port[Session::Destination]);
    }
    break;
    }
    out << session.type;
}

std::ostream& operator<<(std::ostream& out, const ApplicationSession& session)
{
    const bool namelookup{Out::Global::get_level() == Out::Level::All};

    switch(session.ip_type)
    {
    case Session::IPType::v4:
    {
        {
            auto& port = session.port[Session::Source];
            auto& addr = session.ip.v4.addr[Session::Source];

            print_ipv4_port(out, addr, port);
            if(namelookup)
            {
                print_ipv4_port_as_hostname_service(out, addr, port);
            }
        }
        out << " --> ";
        {
            auto& port = session.port[Session::Destination];
            auto& addr = session.ip.v4.addr[Session::Destination];

            print_ipv4_port(out, addr, port);
            if(namelookup)
            {
                print_ipv4_port_as_hostname_service(out, addr, port);
            }
        }
    }
    break;
    case Session::IPType::v6:
    {
        {
            auto& port = session.port[Session::Source];
            auto& addr = session.ip.v6.addr[Session::Source];

            print_ipv6_port(out, addr, port);
            if(namelookup)
            {
                print_ipv6_port_as_hostname_service(out, addr, port);
            }
        }
        out << " --> ";
        {
            auto& port = session.port[Session::Destination];
            auto& addr = session.ip.v6.addr[Session::Destination];

            print_ipv6_port(out, addr, port);
            if(namelookup)
            {
                print_ipv6_port_as_hostname_service(out, addr, port);
            }
        }
    }
    break;
    }
    out << session.type;
    return out;
}

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
