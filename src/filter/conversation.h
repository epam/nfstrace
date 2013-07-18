//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Class represents conversation between two network nodes
// The direction of data transmission will be return via constructor argument.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef CONVERSATION_H
#define CONVERSATION_H
//------------------------------------------------------------------------------
#include <cstring>

#include "../auxiliary/session.h"
#include "packet_info.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

struct Conversation : private NST::auxiliary::Session
{
    enum Direction
    {
        AtoB = 0, // A -> B
        BtoA = 1, // A <- B
    };

    Conversation(const PacketInfo& info, Direction& direction /*out value*/)
    {
        memset(this, 0, sizeof(Conversation));

        if(info.ipv4)
        {
            ip_type = v4;
            ip.v4.addr[0] = info.ipv4->src();
            ip.v4.addr[1] = info.ipv4->dst();
        }
        // TODO: add IPv6 support
        
        if(info.tcp)
        {
            type = TCP;
            port[0] = info.tcp->sport();
            port[1] = info.tcp->dport();
        }
        // TODO: add UDP support

        // calculate direction via comparing addresses and ports
        switch(ip_type)
        {
            case v4:
            {
                if(ip.v4.addr[0] < ip.v4.addr[1]) direction = AtoB;
                else
                if(ip.v4.addr[0] > ip.v4.addr[1]) direction = BtoA;
                else // Ok, addresses are equal, compare ports
                direction = (port[0] < port[1]) ? AtoB : BtoA;
            }
            break;
            case v6:
            {
                int cmp = memcmp( &ip.v6.addr[0], &ip.v6.addr[1], 16);
                if(cmp < 0) direction = AtoB;
                else
                if(cmp > 0) direction = BtoA;
                else // Ok, addresses are equal, compare ports
                direction = (port[0] < port[1]) ? AtoB : BtoA;
            }
            break;
        }
    }

    Conversation(const Conversation& c)
    {
        memcpy(this, &c, sizeof(Conversation));
    }

    const NST::auxiliary::Session& get_session() const { return *this; }    // using slicing effect

    struct Hash
    {
      long operator() (const Conversation& a) const { return a.hash(); }
    };

    bool operator==(const Conversation& a) const
    {
        if((ip_type != a.ip_type) || (type != a.type)) return false;

        switch(ip_type)
        {
            case Session::v4:
            {
                if((port[0] == a.port[0]) &&
                   (port[1] == a.port[1]) &&
                   (ip.v4.addr[0] == a.ip.v4.addr[0]) &&
                   (ip.v4.addr[1] == a.ip.v4.addr[1]))
                    return true;

                if((port[1] == a.port[0]) &&
                   (port[0] == a.port[1]) &&
                   (ip.v4.addr[1] == a.ip.v4.addr[0]) &&
                   (ip.v4.addr[0] == a.ip.v4.addr[1]))
                    return true;
            }
            break;
            case Session::v6:
            {
                if((port[0] == a.port[0]) &&
                   (port[1] == a.port[1]) )
                {
                    int i = 0;
                    for(; i < 16; ++i)
                    {
                        if((ip.v6.addr[0][i] != a.ip.v6.addr[0][i]) ||
                           (ip.v6.addr[1][i] != a.ip.v6.addr[1][i]))
                            break;
                    }
                    if(i == 4) return true;
                }

                if((port[1] == a.port[0]) &&
                   (port[0] == a.port[1]) )
                {
                    int i = 0;
                    for(; i < 16; ++i)
                    {
                        if((ip.v6.addr[1][i] != a.ip.v6.addr[0][i]) ||
                           (ip.v6.addr[0][i] != a.ip.v6.addr[1][i]))
                            break;
                    }
                    if(i == 4) return true;
                }
            }
            break;
        }
        return false;
    }
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//CONVERSATION_H
//------------------------------------------------------------------------------
