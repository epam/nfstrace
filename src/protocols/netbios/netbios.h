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
#include <stdlib.h>
#include <cstdint>
//------------------------------------------------------------------------------
namespace NST
{
namespace protocols
{
namespace NetBIOS
{

/*! \class NetBIOS message header in SMB-direct case
 */
struct RawMessageHeader
{
    int8_t _start;//!< In SMB direct always 0x00
    int8_t _;
    int16_t length;//!< Packet length
} __attribute__ ((__packed__));

/*! \class NetBIOS message header wrapper
 */
struct MessageHeader : private RawMessageHeader
{
    int8_t start() const;
    size_t len() const;
};

/*! Check is data valid NetBIOS message's header and return header or nullptr
 * \param data - raw packet data
 * \return pointer to input data which is casted to header structure or nullptr (if it is not valid header)
 */
inline const struct MessageHeader* get_header(const uint8_t* data)
{
    const MessageHeader* header (reinterpret_cast<const MessageHeader*>(data));
    if (header->start() == 0x00)
    {
        return header;
    }
    return nullptr;
}

} // namespace NetBIOS
} // namespace protocols
} // namespace NST
//------------------------------------------------------------------------------
#endif//NETBIOS_HEADER_H
//------------------------------------------------------------------------------
