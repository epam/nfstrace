//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class represents data transmission from source node to destination node
// The direction of data transmission will be return via constructor argument.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef TRANSMISSION_H
#define TRANSMISSION_H
//------------------------------------------------------------------------------
#include <cstring>

#include "../auxiliary/session.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

struct Transmission : private NST::auxiliary::Session
{
    Transmission(const NST::auxiliary::Session& session, const Session::Direction as_source)
    {
        ip_type = session.ip_type;
        type    = session.type;

        const Direction src =                 as_source;
        const Direction dst = (Direction)(1 - as_source);

        port[src] = session.port[Source];
        port[dst] = session.port[Destination];

        switch(ip_type)
        {
            case v4:
            {
                ip.v4.addr[src] = session.ip.v4.addr[Source];
                ip.v4.addr[dst] = session.ip.v4.addr[Destination];
            }
            break;
            case v6:
            {
                memcpy(&ip.v6.addr[src], &session.ip.v6.addr[Source], 16);
                memcpy(&ip.v6.addr[dst], &session.ip.v6.addr[Destination], 16);
            }
            break;
        }
    }

    Transmission(const Transmission& a)
    {
        memcpy(this, &a, sizeof(Transmission));
    }

    struct Hash
    {
        inline long operator() (const Transmission& a) const { return a.hash(); }
    };

    inline bool operator==(const Transmission& a) const
    {
        return this->NST::auxiliary::Session::operator ==(a);
    }
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//TRANSMISSION_H
//------------------------------------------------------------------------------
