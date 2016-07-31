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
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <memory>
#include <vector>
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{
// May throw std::bad_alloc during creation or allocation
class BlockAllocator
{
    struct Chunk // type for linking free chunks of memory in a list
    {
        Chunk* next; // pointer to next chunk in a list
    };

    using Chunks = std::unique_ptr<char[]>;
    using Blocks = std::vector<Chunks>;

public:
    constexpr static std::size_t padding = 16;

    BlockAllocator() = default;
    ~BlockAllocator() noexcept
    {
        assert(max_chunks() == free_chunks());
    }

    void init_allocation(std::size_t chunk_size,
                         std::size_t block_size,
                         std::size_t block_limit)
    {
        chunk = ((chunk_size + padding - 1) / padding) * padding;
        assert(chunk % padding == 0);
        assert(chunk >= chunk_size);
        assert(chunk >= sizeof(Chunk));
        block = block_size;
        assert(block >= 1);
        limit = block_limit;
        assert(limit >= 1);

        blocks.reserve(limit);
        list = preallocate_block();
        assert(list);
    }

    void* allocate()
    {
        if(list == nullptr)
        {
            if(blocks.size() == limit) // all blocks are allocated!
            {
                // soft limit of blocks is reached
            }

            list = preallocate_block();
            ++limit;
        }

        Chunk* chunk = list;
        assert(chunk);
        list = list->next;
        --nfree;
        return chunk;
    }

    void deallocate(void* ptr) noexcept
    {
        assert(ptr);
        assert(std::any_of(std::begin(blocks), std::end(blocks),
                           [&](const Chunks& chunks) {
                               const auto b = reinterpret_cast<void*>(chunks.get());
                               const auto e = reinterpret_cast<void*>(chunks.get() + block * chunk);
                               return (b <= ptr) && (ptr < e);
                           }));
        Chunk* chunk = reinterpret_cast<Chunk*>(ptr);
        chunk->next  = list;
        list         = chunk;
        ++nfree;
    }

    std::size_t max_chunks() const noexcept { return block * limit; }
    std::size_t max_memory() const noexcept { return block * limit * chunk; }
    std::size_t max_blocks() const noexcept { return limit; }
    std::size_t free_chunks() const noexcept { return nfree; }
private:
    Chunk* getof(std::size_t i, const Chunks& chunks) const noexcept
    {
        assert(i < block);
        return reinterpret_cast<Chunk*>(&chunks.get()[i * chunk]);
    }

    Chunk* preallocate_block()
    {
        Chunks chunks(new Chunks::element_type[block * chunk]); // switch to C++14

        // link chunks to a list
        for(std::size_t i = 0; i < block - 1; ++i)
        {
            getof(i, chunks)->next = getof(i + 1, chunks);
        }
        getof(block - 1, chunks)->next = nullptr;
        Chunk* first = getof(0, chunks);
        blocks.emplace_back(std::move(chunks));
        nfree += block;
        return first;
    }

    Chunk*      list  = nullptr; // head of list of free chunks
    std::size_t chunk = 0;       // size of chunk
    std::size_t block = 0;       // num chunks in block
    std::size_t limit = 0;       // max blocks, soft limit
    std::size_t nfree = 0;       // num of avaliable chunks
    Blocks      blocks;          // array of blocks
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif // BLOCK_ALLOCATOR_H
//------------------------------------------------------------------------------
