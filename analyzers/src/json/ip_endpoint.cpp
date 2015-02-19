//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: TCP-endpoint class definition
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
#include <cstring>
#include <stdexcept>

#include <sys/socket.h>

#include "ip_endpoint.h"
//------------------------------------------------------------------------------

IpEndpoint::IpEndpoint(const std::string& host, int port, bool hostAsAddress) :
    _addrinfo{}
{
    struct addrinfo hints;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags |= AI_NUMERICSERV;
    std::string serviceStr{std::to_string(port)};
    if (host == WildcardAddress)
    {
        hints.ai_flags |= AI_PASSIVE;
    }
    if ((host != WildcardAddress) && (host != LoopbackAddress))
    {
        hints.ai_flags |= AI_CANONNAME;
        if (hostAsAddress)
        {
            hints.ai_flags |= AI_NUMERICHOST;
        }
    }
    int status = getaddrinfo((host == LoopbackAddress) || (host == WildcardAddress) ? nullptr : host.c_str(),
                             serviceStr.c_str(), &hints, &_addrinfo);
    if (status != 0)
    {
        throw std::runtime_error{gai_strerror(status)};
    }
}

IpEndpoint::~IpEndpoint()
{
    freeaddrinfo(_addrinfo);
}

//------------------------------------------------------------------------------
