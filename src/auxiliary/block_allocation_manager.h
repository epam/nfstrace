//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: BlockAllocatorManagerManager redirect requests to appropriate 
//              BlockAllocatorManager and make 
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
    BlockAllocatorManager(uint32_t min_size, uint32_t step_size, uint32_t step_n, uint16_t block_size = 128, uint16_t block_limit = 3) : min(min_size), step(step_size), count(step_n)
    {
        pools = new LockedAllocator[count]; 
        for(uint16_t i = 0; i < count; ++i)
        {
            pools[i].allocator.init_allocation(min + i * step + sizeof(BlockAllocator*), block_size, block_limit);
        }
    }

    ~BlockAllocatorManager()
    {
        delete pools;
    }

    inline void* allocate(size_t size)
    {
        int i = 0;
        if(size > min)
        {
            i = (size - min) / step + 1;
        }
        if(i > count)
        {
            return NULL;
        }
        
        void* ptr = NULL;

        {
            Spinlock::Lock lock(pools[i].spinlock);
            ptr = pools[i].allocator.allocate();
        }

        if(!ptr)
            return NULL;
        *(LockedAllocator**)ptr = &pools[i];
        return ((LockedAllocator*)ptr) + 1;
    }

    inline void deallocate(void* ptr)
    {
        LockedAllocator* p = ((LockedAllocator*)ptr) - 1;
        Spinlock::Lock lock(p->spinlock);
        p->allocator.deallocate((BlockAllocator::Chunk*) p);
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
