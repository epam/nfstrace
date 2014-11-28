//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Helpers for parsing CIFS structures.
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
#include <cstring>
#include <map>
#include <string>

#include "protocols/cifs/cifs.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::CIFSv1;

static const char* const smbProtocolName = "SMB";

const NST::protocols::CIFSv1::MessageHeader* NST::protocols::CIFSv1::get_header(const uint8_t* data)
{
    const MessageHeader* header (reinterpret_cast<const MessageHeader*>(data));
    if (std::memcmp(header->head.protocol, smbProtocolName, sizeof(header->head.protocol)) == 0)//FIXME: get rid of memcmp
    {
        if (header->head.protocol_code == ProtocolCodes::SMB1)
        {
            return header;
        }
    }
    return nullptr;
}
