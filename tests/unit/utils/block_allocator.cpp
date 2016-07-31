//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Unit tests for BlockAllocator
// Copyright (c) 2016 Pavel Karneliuk
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
#include <vector>

#include <gtest/gtest.h>

#include <utils/block_allocator.h>
//------------------------------------------------------------------------------
using namespace NST::utils;
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
TEST(BlockAllocator, testBasicOperations)
{
    BlockAllocator allocator;

    using Item                   = char[64];
    const std::size_t nperblocks = 1024;
    const std::size_t lim_blocks = 1;

    EXPECT_NO_THROW(
        allocator.init_allocation(sizeof(Item), nperblocks, lim_blocks));

    ASSERT_EQ(lim_blocks, allocator.max_blocks());
    ASSERT_EQ(nperblocks, allocator.free_chunks());
    ASSERT_EQ(nperblocks * lim_blocks, allocator.max_chunks());

    std::vector<void*> allocated;
    allocated.reserve(nperblocks + 1);

    { // get all memory chunks from preallocated block
        for(std::size_t i = 0; i < nperblocks; ++i)
        {
            allocated.emplace_back(allocator.allocate());
        }
        ASSERT_EQ(0u, allocator.free_chunks());
    }

    { // increase soft limit implicitly during allocation one new item
        const auto old = allocator.max_blocks();
        allocated.emplace_back(allocator.allocate());
        ASSERT_EQ(old + 1, allocator.max_blocks());
        ASSERT_EQ(nperblocks - 1, allocator.free_chunks());
    }

    { // get last recently deallocated during new allocation
        const auto old = allocator.allocate();
        allocator.deallocate(old);
        const auto same = allocator.allocate();
        ASSERT_EQ(old, same);
        allocated.emplace_back(same);
    }

    for(auto& a : allocated)
    {
        allocator.deallocate(a);
    }
}
//------------------------------------------------------------------------------
