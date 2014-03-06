//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Struct represented network session.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SESSION_TYPE_H
#define SESSION_TYPE_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
extern "C"
{

struct Session
{
    enum Direction
    {
        Source      =0,
        Destination =1,
        Uninialized =0xBAD
    };

    enum IPType
    {
        v4=0,
        v6=1
    } ip_type:16;       // 16 bit for alignment following integers

    enum Type
    {
        TCP=0,
        UDP=1
    } type   :16;       // 16 bit for alignment following integers

    uint16_t port[2];   // 2 ports in host byte order

    union IPAddress
    {
        struct
        {
            uint32_t addr[2];   // 2 IPv4 addresses in host byte order
        } v4;
        struct
        {
            uint8_t addr[2][16];// 2 IPv6 addresses in host byte order
        } v6;
    } ip;
};

}
//------------------------------------------------------------------------------
#endif //SESSION_TYPE_H
//------------------------------------------------------------------------------
