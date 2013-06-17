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
        BlockAllocator allocator(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);

        assert(allocator.max_memory() == CHUNK_SIZE * BLOCK_SIZE * MAX_BLOCK_COUNT);
        assert(allocator.max_chunks() == BLOCK_SIZE * MAX_BLOCK_COUNT);
        assert(allocator.max_blocks() == MAX_BLOCK_COUNT);
    }
    // Test for valid allocation
    {
        BlockAllocator allocator(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);
        for(int i = 0; i < allocator.max_chunks(); ++i)
        {
            assert(allocator.allocate() != NULL); // ERROR! Memory should be enough
        }
        assert(allocator.allocate() == NULL); // ERROR! Extra memory
    }
    // Test for memory utilization
    {
        BlockAllocator allocator(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);
        BlockAllocator::Chunk* chunks[BLOCK_SIZE * MAX_BLOCK_COUNT];
        for(int i = 0; i < allocator.max_chunks(); ++i)
        {
            chunks[i] = allocator.allocate();
        }
        for(int i = 0; i < BLOCK_SIZE * MAX_BLOCK_COUNT; ++i)
        {
            allocator.deallocate(chunks[i]);
        }
        for(int i = 0; i < allocator.max_chunks(); ++i)
        {
            assert(allocator.allocate() != NULL); // ERROR! Memory can not be reused
        }
        assert(allocator.allocate() == NULL); // ERROR! Extra memory appearenced
    }
    // Test for memory reusability
    {
        BlockAllocator allocator(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);
        BlockAllocator::Chunk* temp = NULL;
        BlockAllocator::Chunk* test = NULL;
        for(int i = 0; i < allocator.max_chunks() / 3; ++i)
        {
            temp = test = allocator.allocate();
        }
        allocator.deallocate(temp);
        temp = allocator.allocate();
        assert(test == temp); // ERROR! We use unexcpected chunk
    }
    // Example of use
    {
        BlockAllocator allocator(CHUNK_SIZE, BLOCK_SIZE, MAX_BLOCK_COUNT);
        BlockAllocator::Chunk* chunk = allocator.allocate();
        memcpy(chunk->ptr(), "Hello", 6);
        assert(strcmp(chunk->ptr(), "Hello") == 0); // Allocator cannot be used!!!
    }
    std::cout << "All test passed" << std::endl;
    return 0;
}
