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
#include <cassert>

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
    NetworkSession* session{nullptr};   // pointer to immutable session in Filtration
    struct timeval  timestamp; // timestamp of last collected packet
    Direction       direction; // direction of data transmission

    uint32_t    dlen{0};  // length of filtered data
    uint8_t*    data{cache};  // pointer to data in memory. {Readonly. Always points to proper memory buffer}

private:
    enum: uint32_t {
        CACHE_SIZE = 4000 
    };
    uint8_t     cache[CACHE_SIZE];
    uint8_t*    memory{nullptr};
    uint32_t    memsize{0};
    
public:
    // disable copying
    FilteredData(const FilteredData&)            = delete;
    FilteredData& operator=(const FilteredData&) = delete;

    inline FilteredData(): data{cache} {}
    inline ~FilteredData() {
        if (nullptr != memory)
        {
            delete[] memory;
        }
    }

    inline uint32_t capacity() const
    {
        if (nullptr == memory)
        {
            assert(data == cache);
            return CACHE_SIZE;
        }
        return memsize;
    }

    // Resize capacity with data safety
    void resize(uint32_t newsize)
    {
        if (capacity() >= newsize) // not resize less
        {
            return;
        }

        if (nullptr == memory)
        {
            memory = new uint8_t[newsize];
            memsize = newsize;
            if (dlen > 0)
                memcpy(memory, cache, dlen<=CACHE_SIZE?dlen:CACHE_SIZE);
            data = memory;
        }
        else // have some filled memory
        {
            uint8_t* mem = new uint8_t[newsize];
            if (0 != dlen)
            {
                memcpy(mem, memory, dlen);
            }
            data = mem;
            delete[] memory;
            memory = mem;
            memsize = newsize;
        }
    }

    // Reset data. Release free memory if allocated 
    inline void reset()
    {
        if (nullptr != memory)
        {
            memsize = 0;
            delete[] memory;
            memory = nullptr;
        }
        dlen = 0;
        data = cache;
    }
};

using FilteredDataQueue = Queue<FilteredData>;

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTERED_DATA_H
//------------------------------------------------------------------------------
