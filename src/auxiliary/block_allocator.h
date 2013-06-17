//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: BlockAllocator for fixed length Chunks of memory
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BLOCK_ALLOCATOR_H
#define BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
#include <inttypes.h>    // for uintXX_t
#include <cstring>       // for memset()
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
        Chunk* next;        // used only for list chunks in list
    };

    BlockAllocator(uint32_t chunk_size, uint16_t block_size, uint16_t block_limit) : limit(block_limit), block(block_size), chunk(chunk_size), allocated(0)
    {
        blocks = new Chunk*[limit];
        memset(blocks, 0, sizeof(Chunk*)*limit);
        list = blocks[0] = new_block();
    }

    BlockAllocator() : limit(0), block(0), chunk(0), allocated(0), blocks(NULL), list(NULL)
    {
    }

    ~BlockAllocator()
    {
        for(uint16_t i = 0; i<limit; i++)
        {
            delete blocks[i];
        }
        delete blocks;
    }

    void init_allocation(uint32_t chunk_size, uint16_t block_size, uint16_t block_limit)
    {
        limit = block_limit;
        block = block_size;
        chunk = chunk_size;

        blocks = new Chunk*[limit];
        memset(blocks, 0, sizeof(Chunk*)*limit);
        list = blocks[0] = new_block();
    }

    inline Chunk* allocate()
    {
        if(list == NULL)
        {
            if(allocated < limit)
            {
                list = blocks[allocated] = new_block();
            }
            else return NULL; // all blocks are allocated!
        }

        Chunk* c = list;
        list = list->next;
        return c;
    }

    inline void deallocate(Chunk* c)
    {
        c->next = list;
        list = c;
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
            ((Chunk*) &ptr[i * chunk])->next = (Chunk*) &ptr[(i + 1) * chunk];
        }
        ((Chunk*) &ptr[(block - 1) * chunk])->next = NULL;
        ++allocated;
        return (Chunk*) ptr;
    }

    uint16_t limit;       // max blocks
    uint16_t block;       // num chunks in block
    uint32_t chunk;       // chunk size
    uint16_t allocated;         // num of allocated blocks
    Chunk** blocks;             // array of blocks
    Chunk* list;                // list chunks
};

} // auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
