//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Parsers tests
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

#include "statistics.h"
//------------------------------------------------------------------------------
using namespace NST::breakdown;

using ::testing::Return;
using ::testing::AtLeast;
using ::testing::_;
//------------------------------------------------------------------------------
namespace
{

class Breakdown : public ::testing::Test
{
protected:
    size_t count;
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

class Mock
{
public:
    MOCK_METHOD0(mock_function, void(void));
    virtual ~Mock() {}
};

class Proc
{
public:
    Proc()
        : session(&_session)
        , rtimestamp(&_rtimestamp)
        , ctimestamp(&_ctimestamp)
    {

    }

    Session _session;
    timeval _rtimestamp;
    timeval _ctimestamp;
    const Session* session;
    const timeval* rtimestamp;
    const timeval* ctimestamp;
};

}
//------------------------------------------------------------------------------
TEST_F(Breakdown, statistics)
{

    Statistics stats(count);

    EXPECT_EQ(count, stats.proc_types_count);

    Mock each_procedure_mock;
    EXPECT_CALL(each_procedure_mock, mock_function())
    .Times(count);

    stats.for_each_procedure([&](const BreakdownCounter&, size_t)
    {
        each_procedure_mock.mock_function();
    });
}

TEST_F(Breakdown, sessions_statistics)
{

    Statistics stats(count);
    Mock each_procedure_mock;
    Proc proc;

    EXPECT_CALL(each_procedure_mock, mock_function())
    .Times(1);

    EXPECT_FALSE(stats.has_session());
    stats.account(&proc, 0);
    EXPECT_TRUE(stats.has_session());

    stats.for_each_session([&](const Session&)
    {
        each_procedure_mock.mock_function();
    });
}

TEST_F(Breakdown, statistics_per_session)
{

    Statistics stats(count);
    Mock each_procedure_mock;
    Proc proc;

    EXPECT_CALL(each_procedure_mock, mock_function())
    .Times(count);

    stats.for_each_procedure_in_session(proc._session, [&](const BreakdownCounter&, size_t)
    {
        each_procedure_mock.mock_function();
    });

    stats.account(&proc, 1);

    stats.for_each_procedure_in_session(proc._session, [&](const BreakdownCounter&, size_t)
    {
        each_procedure_mock.mock_function();
    });
}
//------------------------------------------------------------------------------

