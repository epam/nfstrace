//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Struct represented tcp session.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <sstream>

#include "session.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

std::size_t Session::hash() const
{
    std::size_t key = port[0] + port[1];

    if(ip_type == Session::v4)
    {
        key += ip.v4.addr[0] + ip.v4.addr[1];
    }
    else
    {
        for(int i = 0; i < 16; ++i)
        {
            key += ip.v6.addr[0][i] + ip.v6.addr[1][i];
        }
    }

    if(type == Session::UDP)
    {
        key = ~key;
    }
    return key;
}

bool Session::operator==(const Session& obj) const
{
    if((ip_type != obj.ip_type) || (type != obj.type))
        return false;
    if((port[0] != obj.port[0]) || (port[1] != obj.port[1]))
        return false;
    switch(ip_type)
    {
        case Session::v4:
        {
            if((ip.v4.addr[0] != obj.ip.v4.addr[0]) || (ip.v4.addr[1] != obj.ip.v4.addr[1]))
                return false;
        }
        break;
        case Session::v6:
        {
            for(int i = 0; i < 16; ++i)
            {
                if((ip.v6.addr[0][i] != obj.ip.v6.addr[0][i]) || (ip.v6.addr[1][i] != obj.ip.v6.addr[1][i]))
                    return false;
            }
        }
        break;
    }
    return true;
}

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
        }
        break;
        case Session::v6:
            out << "IPv6 is not supported yet.";
        break;
    }
    switch(session.type)
    {
        case Session::TCP:
            out << "[TCP]";
            break;
        case Session::UDP:
            out << "[UDP]";
            break;
    }
    return out;
}

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------

