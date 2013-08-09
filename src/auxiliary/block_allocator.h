//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: BlockAllocator for fixed size Chunks of memory
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BLOCK_ALLOCATOR_H
#define BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
#include <inttypes.h>    // for uintXX_t
#include <cstring>       // for memset()

#include "spinlock.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

// May throw std::bad_alloc() when memory is not enough
class BlockAllocator
{
    struct Chunk
    {
        Chunk* next; // used only for free chunks in list
    };
public:

    BlockAllocator() : chunk(0), block(0), limit(0), nfree(0), allocated(0), blocks(NULL), list(NULL)
    {
    }

    ~BlockAllocator()
    {
        for(uint32_t i = 0; i<allocated; i++)
        {
            delete[] ((char*)blocks[i]);
        }
        delete[] blocks;
    }

    void init_allocation(uint32_t chunk_size, uint32_t block_size, uint32_t block_limit)
    {
        chunk = chunk_size;
        block = block_size;
        limit = block_limit;

        blocks = new Chunk*[limit];
        memset(blocks, 0, sizeof(Chunk*)*limit);
        list = blocks[0] = new_block();
    }

    inline void* allocate()
    {
        Spinlock::Lock lock(spinlock);
            if(list == NULL)
            {
                if(allocated == limit) // all blocks are allocated!
                {
                    increase_blocks_limit();
                }

                list = blocks[allocated] = new_block();
            }

            Chunk* c = list;
            list = list->next;
            --nfree;
            return c;
    }

    inline void deallocate(void* ptr)
    {
        Chunk* c = (Chunk*) ptr;
        Spinlock::Lock lock(spinlock);
            c->next = list;
            list = c;
            ++nfree;
    }

    // limits
    inline const unsigned int max_chunks() const { return block*limit;       }
    inline const unsigned int max_memory() const { return block*limit*chunk; }
    inline const unsigned int max_blocks() const { return limit;             }

    inline const unsigned int free_chunks() const { return nfree; } // TODO: should we lock spinlock?

private:
    Chunk* new_block()
    {
        char* ptr = new char[block*chunk];
        for(uint32_t i = 0; i<block-1; ++i)
        {
            ((Chunk*) &ptr[i * chunk])->next = (Chunk*) &ptr[(i + 1) * chunk];
        }
        ((Chunk*) &ptr[(block - 1) * chunk])->next = NULL;
        ++allocated;
        nfree += block;
        return (Chunk*) ptr;
    }

    void increase_blocks_limit()
    {
        limit *= 2; // increase soft limit by twice

        Chunk** new_blocks = new Chunk*[limit];               // allocate new array of blocks pointers
        memcpy(new_blocks, blocks, sizeof(Chunk*)*allocated); // copy pointers of existing blocks
        memset(&new_blocks[allocated], 0, sizeof(Chunk*)*(limit-allocated)); // fill pointers for new blocks by NULL

        delete[] blocks;        // delete old array of blocks pointers
        blocks = new_blocks;    // set new array
    }

    uint32_t chunk;       // chunk size
    uint32_t block;       // num chunks in block
    uint32_t limit;       // max blocks, soft limit
    uint32_t nfree;       // num of avaliable chunks
    uint32_t allocated;   // num of allocated blocks, up to limit
    Chunk** blocks;       // array of blocks
    Chunk* list;          // list of free chunks

    Spinlock spinlock;    // for allocate/deallocate
};

} // auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
