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

// TODO: fix memory placement of this structure to align to 4k
struct NFSData
{
public:
    struct timeval timestamp;

    struct Session
    {
        enum Direction
        {
            Source      =0,
            Destination =1
        }:16;

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

        union
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

        uint16_t port[2];           // 2 ports in host byte order

    } __attribute__ ((__packed__)) session;

    uint32_t rpc_len;   // length of captured RPC message with NFS payload

    // a header of RPC message related to NFS procedures (calls and replies)
    char rpc_message[4000]; // raw NFS data in network byte order

} __attribute__ ((__packed__));

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif //NFS_DATA_H
//------------------------------------------------------------------------------
