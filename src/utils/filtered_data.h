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
#include <cassert>
#include <cstdint>

#include <sys/time.h>

#include "utils/noncopyable.h"
#include "utils/queue.h"
#include "utils/sessions.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{
struct FilteredData final : noncopyable
{
    using Direction = NST::utils::Session::Direction;

public:
    NetworkSession* session{nullptr}; // pointer to immutable session in Filtration
    struct timeval  timestamp;        // timestamp of last collected packet
    Direction       direction;        // direction of data transmission

    uint32_t dlen{0};     // length of filtered data
    uint8_t* data{cache}; // pointer to data in memory. {Readonly. Always points to proper memory buffer}

private:
    const static int CACHE_SIZE{4000};

    uint8_t  cache[CACHE_SIZE];
    uint8_t* memory{nullptr};
    uint32_t memsize{0};

public:
    FilteredData() noexcept
        : data{cache}
    {
    }

    ~FilteredData()
    {
        delete[] memory;
    }

    uint32_t capacity() const
    {
        if(nullptr == memory)
        {
            assert(data == cache);
            return CACHE_SIZE;
        }
        return memsize;
    }

    // Resize capacity with data safety
    void resize(uint32_t newsize)
    {
        if(capacity() >= newsize) return; // not resize less

        if(nullptr == memory)
        {
            memory = new uint8_t[newsize];
            if(dlen)
            {
                memcpy(memory, cache, dlen);
            }
            memsize = newsize;
            data    = memory;
        }
        else // have some filled memory
        {
            uint8_t* mem{new uint8_t[newsize]};
            if(dlen)
            {
                memcpy(mem, memory, dlen);
            }
            data = mem;
            delete[] memory;
            memory  = mem;
            memsize = newsize;
        }
    }

    // Reset data. Release free memory if allocated
    void reset()
    {
        if(nullptr != memory)
        {
            delete[] memory;
            memory = nullptr;
        }
        memsize = 0;
        dlen    = 0;
        data    = cache;
    }
};

using FilteredDataQueue = Queue<FilteredData>;

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif // FILTERED_DATA_H
//------------------------------------------------------------------------------
