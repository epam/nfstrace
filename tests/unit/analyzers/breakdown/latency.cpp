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
#include <iostream>
#include <ctime>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "latencies.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;

using ::testing::Return;
using ::testing::AtLeast;
using ::testing::_;
//------------------------------------------------------------------------------
namespace
{

class LatencyTest : public ::testing::Test
{
protected:
    size_t count;
    timeval t1;
    timeval t2;
public:
    void SetUp()
    {
        t1.tv_sec = 10;
        t2.tv_sec = 2;

        t1.tv_usec = 12;
        t2.tv_usec = 4;

        std::srand(std::time(0)); //use current time as seed for random generator
        count = std::rand() % 100 + 3;
    }

    void TearDown()
    {
    }
};

}
//------------------------------------------------------------------------------
TEST_F(LatencyTest, max_min)
{

    Latencies latency;

    EXPECT_EQ(0U, latency.get_count());

    latency.add(t1);
    latency.add(t2);

    EXPECT_EQ(2U, latency.get_count());

    EXPECT_EQ(t2.tv_sec, latency.get_min().tv_sec);
    EXPECT_EQ(t2.tv_usec, latency.get_min().tv_usec);

    EXPECT_EQ(t1.tv_sec, latency.get_max().tv_sec);
    EXPECT_EQ(t1.tv_usec, latency.get_max().tv_usec);

}

TEST_F(LatencyTest, avg)
{
    Latencies latency;

    EXPECT_EQ(0.0, latency.get_avg());

    latency.add(t1);

    EXPECT_NEAR(10.0, latency.get_avg(), 0.0001);

    latency.add(t2);

    EXPECT_NEAR(6.0, latency.get_avg(), 0.0001);
}
//------------------------------------------------------------------------------
