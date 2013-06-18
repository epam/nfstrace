//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structure for passing filtered NFS data to Analyser module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_DATA_H
#define NFS_DATA_H
//------------------------------------------------------------------------------
#include <stdint.h>

#include <sys/time.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

struct NFSData
{
public:

    struct timeval timestamp;

    struct Session
    {
        enum IPType
        {
            v4=0,
            v6=1,
        } ip_type:16;    //16 bit for alignment following integers

        enum Type
        {
            TCP=0,
            UDP=1,
        } type:16;    //16 bit for alignment following integers

        union ip
        {
            struct v4
            {
                uint32_t addr[2];   // 2 IPv4 addresses in host byte order
            };
            struct v6
            {
                uint8_t addr[2][16];// 2 IPv6 addresses in host byte order
            };
        };

        uint16_t port[2];           // 2 ports in host byte order

    } __attribute__ ((__packed__)) session;

    uint32_t rpc_len;   // length of captured RPC message data with NFS payload
    //char rpc_data[rpc_len]
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif //NFS_DATA_H
//------------------------------------------------------------------------------
