//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structs for sessions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <sstream>

#include <arpa/inet.h> // for inet_ntop(), ntohs()

#include "utils/sessions.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

ApplicationsSession::ApplicationsSession(const NetworkSession& s, Direction from_client)
: utils::Session (s)
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

    std::stringstream stream(std::ios_base::out);
    stream << static_cast<Session&>(*this);
    session_str = stream.str();
}

std::ostream& operator<<(std::ostream& out, const Session::Type type)
{
    switch(type)
    {
        case Session::TCP: return out << " [TCP]";
        case Session::UDP: return out << " [UDP]";
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const Session& session)
{
    switch(session.ip_type)
    {
        case Session::IPType::v4:
        {
            static_assert(sizeof(session.ip.v4.addr[Session::Source]) == sizeof(struct in_addr), "they should be equal");

            char buf[INET_ADDRSTRLEN];
            {
                const char* str = inet_ntop(AF_INET, &(session.ip.v4.addr[Session::Source]), buf, sizeof(buf));
                out << (str ? str : "Invalid IPv4 address of source host")
                    << ':' << ntohs(session.port[Session::Source]);
            }
            out << " --> ";
            {
                const char* str = inet_ntop(AF_INET, &(session.ip.v4.addr[Session::Destination]), buf, sizeof(buf));
                out << (str ? str : "Invalid IPv4 address of destination host")
                    << ':' << ntohs(session.port[Session::Destination]);
            }
        }
        break;
        case Session::IPType::v6:
        {
            static_assert(sizeof(session.ip.v6.addr[Session::Source]) == sizeof(struct in6_addr), "they should be equal");

            char buf[INET6_ADDRSTRLEN];
            {
                const char* str = inet_ntop(AF_INET6, &(session.ip.v6.addr[Session::Source]), buf, sizeof(buf));
                out << (str ? str : "Invalid IPv6 address of source host")
                    << ':' << ntohs(session.port[Session::Source]);
            }
            out << " --> ";
            {
                const char* str = inet_ntop(AF_INET6, &(session.ip.v6.addr[Session::Destination]), buf, sizeof(buf));
                out << (str ? str : "Invalid IPv6 address of destination host")
                    << ':' << ntohs(session.port[Session::Destination]);
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

