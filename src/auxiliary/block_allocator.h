//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Threadsafe BlockAllocator for fixed length Chunks of memory
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BLOCK_ALLOCATOR_H
#define BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
#include <cstring>  // for memset()

#include "spinlock.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

// return NULL when limit is reached
// may throw std::bad_alloc() when memory is not enough
template
<
unsigned int chunk, // len of chunk in bytes
unsigned int limit  // max blocks
>
class BlockAllocator
{
public:
    struct Chunk
    {
    friend class BlockAllocator;

    inline char*const ptr() const { return u.data; }

    private:
        union
        {
            Chunk* next;        // used only for free chunks in list
            char   data[chunk]; // payload
        } u;
    };

    BlockAllocator(unsigned int size):block(size), allocated(0)
    {
        memset(&blocks, 0, sizeof(blocks));
        list = blocks[0] = new_block();
    }

    ~BlockAllocator()
    {
        for(unsigned int i=0; i<limit; i++)
        {
            delete blocks[i];
        }
    }

    inline Chunk* allocate()
    {
        Spinlock::Lock lock(spinlock);
            if(list == NULL)
            {
                unsigned int i = limit - allocated; // index of avaliable block
                if(i)
                {
                    list = blocks[i] = new_block();
                }
                else return NULL; // all blocks are allocated!
            }

            Chunk* c = list;
            list = list->u.next;
            return c;
    }

    inline void deallocate(Chunk* c)
    {
        Spinlock::Lock lock(spinlock);
            c->u.next = list;
            list = c;
    }

    // limits
    inline const unsigned int max_chunks() const { return block*limit;               }
    inline const unsigned int max_memory() const { return block*limit*sizeof(Chunk); }
    inline const unsigned int max_stdnew() const { return limit;                     }

private:

    Chunk* new_block()
    {
        Chunk* ptr = new Chunk[block];
        for(unsigned int i=0; i<block-1; ++i)
        {
            ptr[i].u.next = ptr+i+1;
        }
        ptr[block-1].u.next = NULL; // set last
        ++allocated;
        return ptr;
    }

    Chunk* blocks[limit];       // array of blocks
    const unsigned int block;   // num chunks in block
    unsigned int allocated;     // num of allocated blocks
    Chunk* list;                // free chunks
    Spinlock spinlock;
};

} // auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
