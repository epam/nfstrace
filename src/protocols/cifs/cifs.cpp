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
#include "protocols/cifs/cifs.h"
//------------------------------------------------------------------------------
using namespace NST::protocols::CIFSv1;

union SMBCode {
    const uint8_t codes[4] = {static_cast<uint8_t>(ProtocolCodes::SMB1), 'S', 'M', 'B'};
    uint32_t code;
};

const NST::protocols::CIFSv1::MessageHeader* NST::protocols::CIFSv1::get_header(const uint8_t* data)
{
    static SMBCode code;
    const MessageHeader* header (reinterpret_cast<const MessageHeader*>(data));
    if (header->head_code == code.code)
    {
        return header;
    }
    return nullptr;
}

bool MessageHeader::isFlag(const Flags flag) const
{
    return static_cast<const uint8_t>(flag) & static_cast<const uint8_t>(flags);
}
