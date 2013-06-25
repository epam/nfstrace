#include <iostream>
#include <cstring>
#include <cassert>

#include "../../src/auxiliary/block_allocator.h"

using NST::auxiliary::BlockAllocator;
#define CHUNK_SIZE (128)
#define BLOCK_SIZE (8)
#define MAX_BLOCK_COUNT (3)

int main(int argc, char** argv)
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
