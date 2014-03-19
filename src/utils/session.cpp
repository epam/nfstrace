//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Implementation of network session things.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <sstream>

#include "utils/session.h"
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
        std::swap(ip.v4.addr[0], ip.v4.addr[1]);
        std::swap(port[0],       port[1]);
    }

    std::stringstream stream(std::ios_base::out);
    stream << static_cast<Session&>(*this);
    session_str = stream.str();
}

void print_ipv4_address(std::ostream& out, const uint32_t ip)
{
    out << ((ip >> 24) & 0xFF);
    out << '.';
    out << ((ip >> 16) & 0xFF);
    out << '.';
    out << ((ip >> 8) & 0xFF);
    out << '.';
    out << ((ip >> 0) & 0xFF);
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
        case Session::v4:
        {
            print_ipv4_address(out, session.ip.v4.addr[Session::Source]);
            out << ':' << session.port[Session::Source];
        }
            out << " --> ";
        {
            print_ipv4_address(out, session.ip.v4.addr[Session::Destination]);
            out << ':' << session.port[Session::Destination];
        }
        break;
        case Session::v6:
            out << "IPv6 is not supported yet.";
        break;
    }
    out << session.type;
    return out;
}

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------

