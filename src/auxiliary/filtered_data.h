//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structure for passing filtered data to Analyser module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FILTERED_DATA_H
#define FILTERED_DATA_H
//------------------------------------------------------------------------------
#include <stdint.h>

#include <sys/time.h>

#include "queue.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

struct FilteredData
{
public:
    struct timeval timestamp;

    struct Session
    {
        enum Direction
        {
            Source      =0,
            Destination =1
        };

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

    uint32_t dlen;       // length of filtered payload
    uint8_t  data[4000]; // raw filtered data in network byte order

} __attribute__ ((__packed__));

typedef Queue<FilteredData> FilteredDataQueue;

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif //FILTERED_DATA_H
//------------------------------------------------------------------------------
