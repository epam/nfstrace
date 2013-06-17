//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: BlockAllocatorManager redirect requests to appropriate 
//              BlockAllocator
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef BLOCK_ALLOCATOR_MANAGER_H
#define BLOCK_ALLOCATOR_MANAGER_H
//------------------------------------------------------------------------------
#include <inttypes.h>    // for uintXX_t
#include <cstring>       // for memset()

#include "block_allocator.h"
#include "exception.h"
#include "spinlock.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

// Return NULL when limit is reached
// May throw std::bad_alloc() when memory is not enough
class BlockAllocatorManager
{
    struct LockedAllocator
    {
        BlockAllocator allocator;
        Spinlock spinlock;
    };

public:
    BlockAllocatorManager(uint32_t min_size, uint32_t step_size, uint32_t step_n, uint16_t block_size = 128, uint16_t block_limit = 8) : min(min_size), step(step_size), count(step_n), pools(NULL)
    {
        pools = new LockedAllocator[count];
        for(uint16_t i = 0; i < count; ++i)
        {
            pools[i].allocator.init_allocation(min + i * step + sizeof(LockedAllocator*), block_size, block_limit);
        }
    }

    ~BlockAllocatorManager()
    {
        delete[] pools;
    }

    inline void* allocate(size_t size)
    {
        int i = (size - min) / step;

        if(i > count)
        {
            return NULL;
        }

        void* ptr = NULL;
        {
            Spinlock::Lock lock(pools[i].spinlock);
            ptr = pools[i].allocator.allocate();
        }

        if(ptr == NULL) return NULL;

        LockedAllocator** lp = ((LockedAllocator**)ptr);
        *lp = &pools[i];
        return lp + 1;
    }

    inline void deallocate(void* ptr)
    {
        LockedAllocator** lp = ((LockedAllocator**)ptr) - 1;
        LockedAllocator* pool = *lp;

        Spinlock::Lock lock(pool->spinlock);
        pool->allocator.deallocate((BlockAllocator::Chunk*) lp);
    }

private:
    uint32_t min;
    uint32_t step;
    uint16_t count;                         // Amount of pools
    LockedAllocator* pools;
};

} // auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//BLOCK_ALLOCATOR_MANAGER_H
//------------------------------------------------------------------------------
