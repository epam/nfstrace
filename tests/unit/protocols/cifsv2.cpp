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
#include <arpa/inet.h>

#include "api/cifs2_commands.h"
#include "api/cifs_commands.h"
#include "protocols/cifs2/cifs2.h"
//------------------------------------------------------------------------------
using namespace NST::API::SMBv2;
using namespace NST::protocols::CIFSv2;
//------------------------------------------------------------------------------
TEST(CIFSv2, parse)
{
    ReadRequest readRequest;

    uint16_t fldStructSize = htons(0xABCD);
    uint32_t fldLength     = htons(0xABCD);
    uint64_t fldOffset     = htobe64(0xDEADBEEF);

    readRequest.structureSize = fldStructSize;
    readRequest.length        = fldLength;
    readRequest.offset        = fldOffset;

    parse(readRequest);

    EXPECT_EQ(readRequest.structureSize,  ntohs(fldStructSize));
    EXPECT_EQ(readRequest.length,         ntohl(fldLength));
    EXPECT_EQ(readRequest.offset,         be64toh(fldOffset));
}

TEST(CIFSv2, bodies)
{
    EXPECT_EQ(36u, sizeof(struct NegotiateRequest) - sizeof(Dialects));
    EXPECT_EQ(65u, sizeof(struct NegotiateResponse));

    EXPECT_EQ(25u, sizeof(struct SessionSetupRequest));
    EXPECT_EQ(9u,  sizeof(struct SessionSetupResponse));

    EXPECT_EQ(4u,  sizeof(struct LogOffRequest));
    EXPECT_EQ(4u,  sizeof(struct LogOffResponse));

    EXPECT_EQ(4u,  sizeof(struct EchoRequest));
    EXPECT_EQ(4u,  sizeof(struct EchoResponse));

    EXPECT_EQ(9u,  sizeof(struct TreeConnectRequest));
    EXPECT_EQ(16u, sizeof(struct TreeConnectResponse));

    EXPECT_EQ(4u,  sizeof(struct TreeDisconnectRequest));
    EXPECT_EQ(4u,  sizeof(struct TreeDisconnectResponse));

    EXPECT_EQ(57u, sizeof(struct CreateRequest));
    EXPECT_EQ(89u, sizeof(struct CreateResponse));

    EXPECT_EQ(24u, sizeof(struct CloseRequest));
    EXPECT_EQ(60u, sizeof(struct CloseResponse));

    EXPECT_EQ(41u, sizeof(struct QueryInfoRequest));
    EXPECT_EQ(9u,  sizeof(struct QueryInfoResponse));

    EXPECT_EQ(33u, sizeof(struct QueryDirRequest));
    EXPECT_EQ(9u,  sizeof(struct QueryDirResponse));

    EXPECT_EQ(24u, sizeof(struct FlushRequest));
    EXPECT_EQ(4u,  sizeof(struct FlushResponse));

    EXPECT_EQ(49u, sizeof(struct ReadRequest));
    EXPECT_EQ(17u, sizeof(struct ReadResponse));

    EXPECT_EQ(24u, sizeof(struct OplockAcknowledgment));
    EXPECT_EQ(24u, sizeof(struct OplockResponse));

    EXPECT_EQ(49u, sizeof(struct WriteRequest));
    EXPECT_EQ(16u, sizeof(struct WriteResponse));

    EXPECT_EQ(48u, sizeof(struct LockRequest));
    EXPECT_EQ(4u,  sizeof(struct LockResponse));

    EXPECT_EQ(4u,  sizeof(struct CancelRequest));

    EXPECT_EQ(32u, sizeof(struct ChangeNotifyRequest));
    EXPECT_EQ(8u + sizeof(struct FileNotifyInformation),  sizeof(struct ChangeNotifyResponse));

    EXPECT_EQ(57u, sizeof(struct IoCtlRequest));
    EXPECT_EQ(49u, sizeof(struct IoCtlResponse));

    EXPECT_EQ(33u, sizeof(struct SetInfoRequest));
    EXPECT_EQ(2u,  sizeof(struct SetInfoResponse));
}
//------------------------------------------------------------------------------
