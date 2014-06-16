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
    uint8_t*  memory{nullptr}; // internal dynamic memory buffer, raw filtrated data in network byte order
    size_t memsize{0}; // size of dynamic memory
    
public:
    // disable copying
    FilteredData(const FilteredData&)            = delete;
    FilteredData& operator=(const FilteredData&) = delete;

    inline ~FilteredData() {
        if (nullptr != memory) {
            assert(nullptr == memory);
            //throw std::logic_error(std::string(__FUNCTION__) + ": improper memory deallocation"); 
            delete[] memory;
        }
    }
    inline size_t size() const { return memsize; }

    uint8_t* allocate(size_t bytes) 
    {
        assert(nullptr == data == memory);
        if (memory) {
            //throw std::logic_error(std::string(__FUNCTION__) + ": repeat allocation");
            memsize = 0;
            delete[] memory;
            memory = nullptr;
        }
        dlen = 0;
        data = memory = new uint8_t[bytes]; // TODO: bad_alloc processing
        memsize = bytes;
        memset(memory, 0, bytes);
        return data;
    }
    void deallocate() {
        assert(nullptr != memory == data);
        if (memory) {
            memsize = 0;
            delete[] memory;
            memory = nullptr;
        }
        data = nullptr;
        dlen = 0;
    }
    inline void reset() {
        memsize = 0;
        delete[] memory;
        dlen = 0;
        data = memory = nullptr;
    }
};

using FilteredDataQueue = Queue<FilteredData>;

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTERED_DATA_H
//------------------------------------------------------------------------------
