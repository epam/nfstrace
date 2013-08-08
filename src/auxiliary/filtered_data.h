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

#include "session.h"
#include "queue.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Session;
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

struct FilteredData
{
public:
    struct timeval timestamp;

    struct Session __attribute__ ((__packed__)) session;

    uint32_t dlen;  // length of filtered payload
    uint8_t* data;  // pointer to data in memory

    uint8_t  memory[4000]; // raw filtered data in network byte order

    FilteredData(const FilteredData&);              // undefined
    FilteredData& operator=(const FilteredData&);   // undefined
} __attribute__ ((__packed__));

typedef Queue<FilteredData> FilteredDataQueue;

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif //FILTERED_DATA_H
//------------------------------------------------------------------------------
