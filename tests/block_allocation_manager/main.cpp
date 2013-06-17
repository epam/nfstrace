#include <cassert>

#include "../../src/auxiliary/block_allocation_manager.h"

using NST::auxiliary::BlockAllocatorManager;

const int MIN_SIZE = 128;
const int STEP_SIZE = 64;
const int COUNT = 16;
const int BLOCK_SIZE = 128;
const int BLOCK_LIMIT = 3;

const int N_CHUNKS = BLOCK_SIZE * BLOCK_LIMIT;

BlockAllocatorManager manager(MIN_SIZE, STEP_SIZE, COUNT, BLOCK_SIZE, BLOCK_LIMIT);
void* ptrs[COUNT * BLOCK_SIZE * BLOCK_LIMIT] = {0};
int t = 0;

void allocate_all()
{
    for(int i = 0; i < COUNT; ++i)
    {
        size_t s = MIN_SIZE + i * STEP_SIZE;
        for(int j = 0; j < N_CHUNKS; ++j, ++t)
        {
             ptrs[t] = manager.allocate(s);
             assert(ptrs[t]!=NULL);
        }
        assert(manager.allocate(s) == NULL);
    }
}
int main(int argc, char** argv)
{
    
    allocate_all();
    for(int i = 0; i < t; ++i)
    {
        manager.deallocate(ptrs[i]);
    }
    allocate_all();
    return 0;
}
