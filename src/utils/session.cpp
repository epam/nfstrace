//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Implementation of network session things.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "utils/session.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

std::ostream& operator<<(std::ostream& out, const Session& session)
{
    switch(session.ip_type)
    {
        case Session::v4:
        {
            uint32_t ip = session.ip.v4.addr[Session::Source];
            out << ((ip >> 24) & 0xFF);
            out << '.';
            out << ((ip >> 16) & 0xFF);
            out << '.';
            out << ((ip >> 8) & 0xFF);
            out << '.';
            out << ((ip >> 0) & 0xFF);
            out << ':' << session.port[Session::Source];
        }
            out << " --> ";
        {
            uint32_t ip = session.ip.v4.addr[Session::Destination];
            out << ((ip >> 24) & 0xFF);
            out << '.';
            out << ((ip >> 16) & 0xFF);
            out << '.';
            out << ((ip >> 8) & 0xFF);
            out << '.';
            out << ((ip >> 0) & 0xFF);
            out << ':' << session.port[Session::Destination];
        }
        break;
        case Session::v6:
            out << "IPv6 is not supported yet.";
        break;
    }
    switch(session.type)
    {
        case Session::TCP:
            out << " [TCP]";
            break;
        case Session::UDP:
            out << " [UDP]";
            break;
    }
    return out;
}

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------

