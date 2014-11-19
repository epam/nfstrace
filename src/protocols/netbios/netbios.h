//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Helpers for parsing NetBIOS structures.
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
#ifndef NETBIOS_HEADER_H
#define NETBIOS_HEADER_H
//------------------------------------------------------------------------------
#include <sys/types.h>
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NetBIOS
{

#pragma pack(push,1)

/*! \class NetBIOS message header in SMB-direct case
 */
struct MessageHeader {
    int8_t start;//!< In SMB direct always 0x00
    int8_t flag;//!< Packet flags
    size_t len() const;
private:
    int16_t length;//!< Packet length
};

#pragma pack(pop)

/*! Check is data valid NetBIOS message's header and return header or nullptr
 * \param data - raw packet data
 * \return pointer to input data which is casted to header structure or nullptr (if it is not valid header)
 */
const struct MessageHeader * get_header(const u_int8_t* data);

}
}
}

#endif // NETBIOS_HEADER_H
