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
    EXPECT_EQ(36, sizeof(struct NegotiateRequest) - sizeof(Dialects));
    EXPECT_EQ(65, sizeof(struct NegotiateResponse));

    EXPECT_EQ(25, sizeof(struct SessionSetupRequest));
    EXPECT_EQ(9,  sizeof(struct SessionSetupResponse));

    EXPECT_EQ(4,  sizeof(struct LogOffRequest));
    EXPECT_EQ(4,  sizeof(struct LogOffResponse));

    EXPECT_EQ(4,  sizeof(struct EchoRequest));
    EXPECT_EQ(4,  sizeof(struct EchoResponse));

    EXPECT_EQ(9,  sizeof(struct TreeConnectRequest));
    EXPECT_EQ(16, sizeof(struct TreeConnectResponse));

    EXPECT_EQ(4,  sizeof(struct TreeDisconnectRequest));
    EXPECT_EQ(4,  sizeof(struct TreeDisconnectResponse));

    EXPECT_EQ(57, sizeof(struct CreateRequest));
    EXPECT_EQ(89, sizeof(struct CreateResponse));

    EXPECT_EQ(24, sizeof(struct CloseRequest));
    EXPECT_EQ(60, sizeof(struct CloseResponse));

    EXPECT_EQ(41, sizeof(struct QueryInfoRequest));
    EXPECT_EQ(9,  sizeof(struct QueryInfoResponse));

    EXPECT_EQ(33, sizeof(struct QueryDirRequest));
    EXPECT_EQ(9,  sizeof(struct QueryDirResponse));

    EXPECT_EQ(24, sizeof(struct FlushRequest));
    EXPECT_EQ(4,  sizeof(struct FlushResponse));

    EXPECT_EQ(49, sizeof(struct ReadRequest));
    EXPECT_EQ(17, sizeof(struct ReadResponse));

    EXPECT_EQ(24, sizeof(struct OplockAcknowledgment));
    EXPECT_EQ(24, sizeof(struct OplockResponse));

    EXPECT_EQ(49, sizeof(struct WriteRequest));
    EXPECT_EQ(16, sizeof(struct WriteResponse));

    EXPECT_EQ(48, sizeof(struct LockRequest));
    EXPECT_EQ(4,  sizeof(struct LockResponse));

    EXPECT_EQ(4,  sizeof(struct CancelRequest));

    EXPECT_EQ(32, sizeof(struct ChangeNotifyRequest));
    EXPECT_EQ(8 + sizeof(struct FileNotifyInformation),  sizeof(struct ChangeNotifyResponse));

    EXPECT_EQ(57, sizeof(struct IoCtlRequest));
    EXPECT_EQ(49, sizeof(struct IoCtlResponse));

    EXPECT_EQ(33, sizeof(struct SetInfoRequest));
    EXPECT_EQ(2,  sizeof(struct SetInfoResponse));
}
//------------------------------------------------------------------------------
