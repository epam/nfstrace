//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Helpers for parsing NETBios structures.
// Copyright (c) 2014 EPAM Systems
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

#include "protocols/netbios/netbios_header.h"
#include <arpa/inet.h>

using namespace NST::protocols::NetBIOS;


size_t MessageHeader::len() const
{
    return htons(length);
}

const struct MessageHeader * NST::protocols::NetBIOS::get_header(const u_int8_t* data) {
    const MessageHeader* header {reinterpret_cast<const MessageHeader*>(data)};
    if (header->start == 0x00) {
        return header;
    }
    return nullptr;
}

