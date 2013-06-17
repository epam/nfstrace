//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Threadsafe BlockAllocator for fixed length Chunks of memory
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BLOCK_ALLOCATOR_H
#define BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
#include <cstring>       // for memset()
#include <inttypes.h>    // for uintXX_t
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

// Return NULL when limit is reached
// May throw std::bad_alloc() when memory is not enough
class BlockAllocator
{
public:
    struct Chunk
    {
        friend class BlockAllocator;
        inline char*const ptr() const { return (char*)this; }

    private:
        union
        {
            Chunk* next;        // used only for free chunks in list
        } u;
    };

    BlockAllocator(uint32_t chunk_size, uint16_t block_size, uint16_t block_limit) : limit(block_limit), block(block_size), chunk(chunk_size), allocated(0)
    {
        blocks = new Chunk*[limit];
        memset(blocks, 0, sizeof(Chunk*)*limit);
        free = blocks[0] = new_block();
    }

    ~BlockAllocator()
    {
        for(uint16_t i = 0; i<limit; i++)
        {
            delete blocks[i];
        }
        delete blocks;
    }

    inline Chunk* allocate()
    {
        if(free == NULL)
        {
            if(allocated < limit)
            {
                free = blocks[allocated] =  new_block();
            }
            else return NULL; // all blocks are allocated!
        }

        Chunk* c = free;
        free = free->u.next;
        return c;
    }

    inline void deallocate(Chunk* c)
    {
        c->u.next = free;
        free = c;
    }

    // limits
    inline const unsigned int max_chunks() const { return block*limit;       }
    inline const unsigned int max_memory() const { return block*limit*chunk; }
    inline const unsigned int max_blocks() const { return limit;             }

private:
    Chunk* new_block()
    {
        char* ptr = new char[block*chunk];
        for(uint16_t i = 0; i<block-1; ++i)
        {
            ((Chunk*) &ptr[i * chunk])->u.next = (Chunk*) &ptr[(i + 1) * chunk];
        }
        ((Chunk*) &ptr[(block - 1) * chunk])->u.next = NULL;
        ++allocated;
        return (Chunk*) ptr;
    }

    const uint16_t limit;       // max blocks
    const uint16_t block;       // num chunks in block
    const uint32_t chunk;       // chunk size
    uint16_t allocated;         // num of allocated blocks
    Chunk** blocks;             // array of blocks
    Chunk* free;                // free chunks
};

} // auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
