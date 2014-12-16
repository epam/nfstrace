//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: TCP-endpoint tests
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <net/tcp_endpoint.h>
#include <stdexcept>

#define VALID_HOST TcpEndpoint::LoopbackAddress
#define VALID_PORT 8888
#define INVALID_HOST "трололо"
#define INVALID_PORT -1

using namespace NST::net;

TEST(TcpEndpoint, constructDestruct)
{
    EXPECT_NO_THROW(TcpEndpoint endpoint(VALID_HOST, VALID_PORT));
    EXPECT_THROW(TcpEndpoint endpoint(VALID_HOST, INVALID_PORT), std::runtime_error);
    EXPECT_THROW(TcpEndpoint endpoint(INVALID_HOST, VALID_PORT), std::runtime_error);
    EXPECT_THROW(TcpEndpoint endpoint(INVALID_HOST, INVALID_PORT), std::runtime_error);
}
