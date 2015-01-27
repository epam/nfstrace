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
//------------------------------------------------------------------------------
#include <arpa/inet.h>

#include "protocols/netbios/netbios.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::NetBIOS;

int8_t MessageHeader::start() const
{
    return _start;
}

size_t MessageHeader::len() const
{
    return htons(length);
}
