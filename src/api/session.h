//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Struct represented network session.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SESSION_H
#define SESSION_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <netinet/in.h> // for in_port_t, in_addr_t types
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{

struct Session
{
    enum Direction
    {
        Source      =0,
        Destination =1,
        Unknown     =0xBAD
    };

    enum Type
    {
        TCP=0,
        UDP=1
    } type   :16;       // 16 bit for alignment following integers

    enum IPType
    {
        v4=0,
        v6=1
    } ip_type:16;       // 16 bit for alignment following integers

    in_port_t port[2];   // 2 ports in network byte order

    union IPAddress
    {
        struct
        {
            in_addr_t addr[2];    // 2 IPv4 addresses in network byte order
        } v4;
        struct
        {
            uint8_t addr[2][16];   // 2 IPv6 addresses in network byte order
        } v6;
    } ip;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//SESSION_H
//------------------------------------------------------------------------------
