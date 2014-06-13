//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Structure for passing filtered data to Analysis module.
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
#ifndef FILTERED_DATA_H
#define FILTERED_DATA_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <sys/time.h>

#include "utils/sessions.h"
#include "utils/queue.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

struct FilteredData
{
    using Direction = NST::utils::Session::Direction;
public:
    NetworkSession* session;   // pointer to immutable session in Filtration
    struct timeval  timestamp; // timestamp of last collected packet
    Direction       direction; // direction of data transmission

    uint32_t dlen;  // length of filtered data
    uint8_t* data;  // pointer to data in memory

    uint8_t  memory[4000]; // raw filtrated data in network byte order

    FilteredData(const FilteredData&)            = delete;
    FilteredData& operator=(const FilteredData&) = delete;
};

using FilteredDataQueue = Queue<FilteredData>;

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTERED_DATA_H
//------------------------------------------------------------------------------
