//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structure for passing filtered data to Analysis module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FILTERED_DATA_H
#define FILTERED_DATA_H
//------------------------------------------------------------------------------
#include <stdint.h>

#include <sys/time.h>

#include "utils/application_session.h"
#include "utils/queue.h"
//------------------------------------------------------------------------------
using NST::utils::Session;
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

struct FilteredData
{
public:
    struct timeval  timestamp;
    struct ApplicationSession* session_ptr; // pointer to immutable session in Filtration


    uint32_t dlen;  // length of filtered data
    uint8_t* data;  // pointer to data in memory

    uint8_t  memory[4000]; // raw filtrationed data in network byte order

    FilteredData(const FilteredData&)            = delete;
    FilteredData& operator=(const FilteredData&) = delete;
};

using FilteredDataQueue = Queue<FilteredData>;

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif //FILTERED_DATA_H
//------------------------------------------------------------------------------
