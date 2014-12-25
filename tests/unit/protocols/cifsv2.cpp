//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: CIFS v2 tests
// Copyright (c) 2013-2014 EPAM Systems
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
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "api/cifs_commands.h"
//------------------------------------------------------------------------------
using namespace NST::API::SMBv2;
//------------------------------------------------------------------------------
TEST(CIFSv2, bodies)
{
    EXPECT_EQ(49, sizeof(struct WriteRequest));
    EXPECT_EQ(16, sizeof(struct WriteResponse));

    EXPECT_EQ(48, sizeof(struct LockRequest));
    EXPECT_EQ(4,  sizeof(struct LockResponse));
}
//------------------------------------------------------------------------------
