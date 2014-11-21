//------------------------------------------------------------------------------
// Author: Ilya Storozhilov
// Description: TCP-endpoint.
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

#ifndef TCP_ENPOINT_H
#define TCP_ENPOINT_H

#include <string>
#include <netdb.h>

namespace NST
{
namespace net
{

//! TCP-endpoint (host:port) helper class to use in socket operations
class TcpEndpoint
{
public:
	//! Loopback address name
	static const char * LoopbackAddress;
	//! Wildcard address name
	static const char * WildcardAddress;
	
	TcpEndpoint() = delete;
	//! Constructs TCP-endpoint
	/*!
	 * \param host Hostname or IP-address of the endpoint
	 * \param port TCP-port
	 * \param hostAsAddress Consider host as IP-address flag
	 */
	TcpEndpoint(const std::string& host, int port, bool hostAsAddress = false);
	//! Destructs TCP-endpoint
	~TcpEndpoint();

	//! Returns a pointer to 'struct addrinfo' structure for TCP-endpoint
	struct addrinfo * addrinfo() {
		return _addrinfo;
	}
private:
	struct addrinfo * _addrinfo;
};

} // namespace net
} // namespace NST

#endif // TCP_ENPOINT_H
