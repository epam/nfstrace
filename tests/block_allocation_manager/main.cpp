//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Test for BlockAllocatorManager.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <cassert>

#include <iostream>

#include "../../src/auxiliary/block_allocation_manager.h"
//------------------------------------------------------------------------------
using NST::auxiliary::BlockAllocatorManager;
//------------------------------------------------------------------------------
const int MIN_SIZE = 128;
const int STEP_SIZE = 64;
const int COUNT = 16;
const int BLOCK_SIZE = 128;
const int BLOCK_LIMIT = 3;

const int N_CHUNKS = BLOCK_SIZE * BLOCK_LIMIT;
//------------------------------------------------------------------------------

BlockAllocatorManager manager(MIN_SIZE, STEP_SIZE, COUNT, BLOCK_SIZE, BLOCK_LIMIT);
void* ptrs[COUNT * BLOCK_SIZE * BLOCK_LIMIT] = {0};

int allocate_all()
{
    int n = 0;
    for(int i = 0; i < COUNT; ++i)
    {
        size_t s = MIN_SIZE + i * STEP_SIZE;
        for(int j = 0; j < N_CHUNKS; ++j, ++n)
        {
             ptrs[n] = manager.allocate(s);
             assert(ptrs[n]!=NULL);
        }
        assert(manager.allocate(s) == NULL);
    }
    return n;
}

int main(int argc, char** argv)
{
    int n = allocate_all();

    std::cout << "end allocation: " << n <<  std::endl;
    for(int i = 0; i < n; ++i)
    {
        manager.deallocate(ptrs[i]);
        std::cout << "deallocate: " << i<<  std::endl;
    }
    n = allocate_all();
    return 0;
}
//------------------------------------------------------------------------------
