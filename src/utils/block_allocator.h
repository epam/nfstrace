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
    BlockAllocator() noexcept
        : chunk{0},
          block{0},
          limit{0},
          nfree{0},
          allocated{0},
          blocks{nullptr},
          list{nullptr}
    {
    }

    ~BlockAllocator()
    {
        for(std::size_t i{0}; i < allocated; i++)
        {
            delete[]((char*)blocks[i]);
        }
        delete[] blocks;
    }

    void init_allocation(std::size_t chunk_size,
                         std::size_t block_size,
                         std::size_t block_limit)
    {
        chunk = chunk_size;
        block = block_size;
        limit = block_limit;

        blocks = new Chunk*[limit];
        memset(blocks, 0, sizeof(Chunk*) * limit);
        list = new_block();
    }

    void* allocate()
    {
        if(list == nullptr)
        {
            if(allocated == limit) // all blocks are allocated!
            {
                increase_blocks_limit();
            }

            list = new_block();
        }

        Chunk* c{list};
        list = list->next;
        --nfree;
        return c;
    }

    void deallocate(void* ptr)
    {
        Chunk* c{(Chunk*)ptr};
        c->next = list;
        list    = c;
        ++nfree;
    }

    // limits
    std::size_t max_chunks() const { return block * limit; }
    std::size_t max_memory() const { return block * limit * chunk; }
    std::size_t max_blocks() const { return limit; }
    std::size_t free_chunks() const { return nfree; }
private:
    Chunk* new_block()
    {
        char* ptr{new char[block * chunk]};
        for(std::size_t i{0}; i < block - 1; ++i)
        {
            ((Chunk*)&ptr[i * chunk])->next = (Chunk*)&ptr[(i + 1) * chunk];
        }
        ((Chunk*)&ptr[(block - 1) * chunk])->next = nullptr;
        blocks[allocated]                         = (Chunk*)ptr;
        ++allocated;
        nfree += block;
        return (Chunk*)ptr;
    }

    void increase_blocks_limit()
    {
        const std::size_t new_limit{limit * 2}; // increase soft limit by twice

        Chunk** new_blocks{new Chunk*[new_limit]}; // allocate new array of blocks pointers
        limit = new_limit;
        memcpy(new_blocks, blocks, sizeof(Chunk*) * allocated);                  // copy pointers of existing blocks
        memset(&new_blocks[allocated], 0, sizeof(Chunk*) * (limit - allocated)); // fill pointers for new blocks by NULL

        delete[] blocks;     // delete old array of blocks pointers
        blocks = new_blocks; // set new array
    }

    std::size_t chunk;     // chunk size
    std::size_t block;     // num chunks in block
    std::size_t limit;     // max blocks, soft limit
    std::size_t nfree;     // num of avaliable chunks
    std::size_t allocated; // num of allocated blocks, up to limit
    Chunk**     blocks;    // array of blocks
    Chunk*      list;      // list of free chunks
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif // BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
