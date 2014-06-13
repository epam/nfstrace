//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: BlockAllocator for fixed size Chunks of memory
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef BLOCK_ALLOCATOR_H
#define BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
#include <cstdint>
#include <cstring> // for memset()
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

// May throw std::bad_alloc() when memory is not enough
class BlockAllocator
{
    struct Chunk
    {
        Chunk* next; // used only for free chunks in list
    };
public:

    BlockAllocator()
    : chunk{0}
    , block{0}
    , limit{0}
    , nfree{0}
    , allocated{0}
    , blocks{nullptr}
    , list{nullptr}
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
        if(list == nullptr)
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
        c->next = list;
        list = c;
        ++nfree;
    }

    // limits
    inline unsigned int max_chunks() const { return block*limit;       }
    inline unsigned int max_memory() const { return block*limit*chunk; }
    inline unsigned int max_blocks() const { return limit;             }

    inline unsigned int free_chunks() const { return nfree; } // TODO: should we lock spinlock?

private:
    Chunk* new_block()
    {
        char* ptr = new char[block*chunk];
        for(uint32_t i = 0; i<block-1; ++i)
        {
            ((Chunk*) &ptr[i * chunk])->next = (Chunk*) &ptr[(i + 1) * chunk];
        }
        ((Chunk*) &ptr[(block - 1) * chunk])->next = nullptr;
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
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
