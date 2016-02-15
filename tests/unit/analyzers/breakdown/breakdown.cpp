//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Unit tests
// Copyright (c) 2015 EPAM Systems
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
#include <cstdlib>
#include <ctime>
#include <iostream>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "breakdowncounter.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;

using ::testing::Return;
using ::testing::AtLeast;
using ::testing::_;
//------------------------------------------------------------------------------
namespace
{
class BreakdownTest : public ::testing::Test
{
protected:
    size_t  count;
    timeval t;

public:
    void SetUp()
    {
        std::srand(std::time(0)); //use current time as seed for random generator
        count = std::rand() % 100 + 3;
    }

    void TearDown()
    {
    }
};
}
//------------------------------------------------------------------------------
TEST_F(BreakdownTest, count)
{
    BreakdownCounter break_down(count);

    EXPECT_EQ(0U, break_down.get_total_count());

    break_down[1].add(t);
    break_down[1].add(t);
    break_down[0].add(t);

    EXPECT_EQ(3U, break_down.get_total_count());
}
//------------------------------------------------------------------------------
