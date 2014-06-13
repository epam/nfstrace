//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Test for NST:utils::Queue<T>
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
#include <iostream>
#include <cstring>
#include <cassert>

#include "utils/block_allocator.h"

//------------------------------------------------------------------------------
using NST::utils::BlockAllocator;
//------------------------------------------------------------------------------
#define CHUNK_SIZE (128)
#define BLOCK_SIZE (8)
#define MAX_BLOCK_COUNT (3)

int main()
{
    // Test for base functions
    {
        BlockAllocator allocator;
        allocator.init_allocation(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);

        assert(allocator.max_memory() == CHUNK_SIZE * BLOCK_SIZE * MAX_BLOCK_COUNT);
        assert(allocator.max_chunks() == BLOCK_SIZE * MAX_BLOCK_COUNT);
        assert(allocator.max_blocks() == MAX_BLOCK_COUNT);
        assert(allocator.free_chunks() == BLOCK_SIZE);
    }
    // Test for valid allocation
    {
        BlockAllocator allocator;
        allocator.init_allocation(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);
        for(unsigned int i = 0; i < allocator.max_chunks(); ++i)
        {
            assert(allocator.allocate() != NULL); // ERROR! Memory should be enough
        }
        assert(allocator.allocate() == NULL); // ERROR! Extra memory
        assert(allocator.free_chunks() == 0);
    }
    // Test for memory utilization
    {
        BlockAllocator allocator;
        allocator.init_allocation(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);
        assert(allocator.free_chunks() == BLOCK_SIZE);
        void* chunks[BLOCK_SIZE * MAX_BLOCK_COUNT];
        for(unsigned int i = 0; i < allocator.max_chunks(); ++i)
        {
            chunks[i] = allocator.allocate();
        }
        assert(allocator.free_chunks() == 0);
        for(unsigned int i = 0; i < BLOCK_SIZE * MAX_BLOCK_COUNT; ++i)
        {
            allocator.deallocate(chunks[i]);
        }
        assert(allocator.free_chunks() == BLOCK_SIZE * MAX_BLOCK_COUNT);
        for(unsigned int i = 0; i < allocator.max_chunks(); ++i)
        {
            assert(allocator.allocate() != NULL); // ERROR! Memory can not be reused
        }
        assert(allocator.allocate() == NULL); // ERROR! Extra memory appearenced
        assert(allocator.free_chunks() == 0);
    }
    // Test for memory reusability
    {
        BlockAllocator allocator;
        allocator.init_allocation(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);
        void* temp = NULL;
        void* test = NULL;
        for(unsigned int i = 0; i < allocator.max_chunks() / 3; ++i)
        {
            temp = test = allocator.allocate();
        }
        allocator.deallocate(temp);
        temp = allocator.allocate();
        assert(test == temp); // ERROR! We use unexcpected chunk
    }
    // Example of use
    {
        BlockAllocator allocator;
        allocator.init_allocation(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);
        void* chunk = allocator.allocate();
        memcpy(chunk, "Hello", 6);
        assert(strcmp((const char*)chunk, "Hello") == 0); // Allocator cannot be used!!!
        allocator.deallocate(chunk);
    }
    std::cout << "All test passed" << std::endl;
    return 0;
}
