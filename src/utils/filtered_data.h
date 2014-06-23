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

    uint32_t dlen{0};  // length of filtered data
    uint8_t* data{nullptr};  // pointer to data in memory

private:
    uint8_t*    memory{nullptr};
    uint32_t    memsize{0};
    
public:
    // disable copying
    //FilteredData(const FilteredData&)            = delete;
    FilteredData& operator=(const FilteredData&) = delete;

    inline ~FilteredData() {
        if (nullptr != memory) {
            //assert(nullptr == memory);
            delete[] memory;
        }
    }
    inline uint32_t capacity() const { return memsize; }
    //inline const uint8_t* memory() const { return memory; }

    /*
     *  Allocate first time :to write message header
     */
    uint8_t* allocate(size_t bytes) 
    {
        //assert(nullptr == memory && data == memory);
        dlen = 0;
        data = nullptr;
        if (memory) {
            memsize = 0;
            delete[] memory;
            memory = nullptr;
        }
        memory = new uint8_t[bytes]; // TODO: bad_alloc processing
        memsize = bytes;
        memset(memory, 0, bytes);
        data = memory;
        return data;
    }
    /*
     *  Allocate further on message exceeds first allocated amount 
     *  (!) Must be called 'allocate' first
     */
    uint8_t* extend(uint32_t exbytes)
    {
        if (nullptr == memory)
            throw std::logic_error(std::string(__FUNCTION__) + ": memory not allocated");
            
        if (0 == exbytes) 
            return data;
        
        uint32_t newsiz = memsize + exbytes;
        uint8_t* newmem = new uint8_t[newsiz]; // TODO: bad_alloc handle
        uint32_t tdlen = dlen;

        if (0 == dlen) {
            assert(dlen > 0);
            memcpy(newmem, memory, memsize);
        }
        else {
            memcpy(newmem, memory, dlen);
        }

        deallocate();   
        memory = newmem;
        memsize = newsiz;
        data = memory;
        dlen = tdlen;

        return data;
    }
    inline void deallocate()
    {
        assert(nullptr != memory && memory == data);
        data = nullptr; dlen = 0;
        memsize = 0;
        delete[] memory;
        memory = nullptr;
    }
    inline void reset()
    {
        assert(nullptr != memory);
        assert(memory == data);
        data = memory; dlen = 0;
    }
};

using FilteredDataQueue = Queue<FilteredData>;

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTERED_DATA_H
//------------------------------------------------------------------------------
