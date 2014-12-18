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
//------------------------------------------------------------------------------
#include <stdexcept>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "net/ip_endpoint.h"
//------------------------------------------------------------------------------
using namespace NST::net;

static constexpr const char* ValidHost = IpEndpoint::LoopbackAddress;
static constexpr int ValidPort = 8888;
static constexpr const char* InvalidHost = "invalid_host_name";
static constexpr int InvalidPort = -1;

TEST(TestTcpEndpoint, constructDestruct)
{
    EXPECT_NO_THROW(IpEndpoint endpoint(ValidHost, ValidPort));
    EXPECT_THROW(IpEndpoint endpoint(ValidHost, InvalidPort), std::runtime_error);
    EXPECT_THROW(IpEndpoint endpoint(InvalidHost, ValidPort), std::runtime_error);
    EXPECT_THROW(IpEndpoint endpoint(InvalidHost, InvalidPort), std::runtime_error);
}
