//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Session structure.
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
#ifndef SESSION_H
#define SESSION_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <netinet/in.h> // for in_port_t, in_addr_t types
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

    in_port_t port[2];  // 2 ports in network byte order

    union IPAddress
    {
        struct  // 2 IPv4 addresses in network byte order
        {
            in_addr_t addr[2];
        } v4;
        union   // 2 IPv6 addresses in network byte order
        {
            uint8_t  addr       [2][16];
            uint32_t addr_uint32[2][4];
        } __attribute__ ((__packed__)) v6;
    } ip;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif//SESSION_H
//------------------------------------------------------------------------------
