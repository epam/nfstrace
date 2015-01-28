//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Converters to LE for CIFS v2 constants.
// Copyright (c) 2015 EPAM Systems
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
#ifndef PC_TO_NET_H
#define PC_TO_NET_H
//------------------------------------------------------------------------------
#include <cstdint>

#include <endian.h>
//------------------------------------------------------------------------------

namespace NST
{
namespace API
{
namespace SMBv2
{

# if __BYTE_ORDER == __BIG_ENDIAN

/*!
 * Converter. Not very fast,
 * try to not use
 */
template<class T>
constexpr T pc_to_net(T t)
{
    static_assert(false, "try to not use pc_to_net w/o specialization");
    return t;
}

/*!
 * gets only 1 byte
 * Internal function
 * \param number - number of byte
 * \param t - source number
 * \return 1 byte in right place of whole number
 */
template<int number, class T>
constexpr T switch_1_byte(T t)
{
    return ((t & (static_cast<T>(0xff) << number*8)) << ((sizeof(T) - 1 - number)*8));
}

/*!
 * Compile-time converter BE to LE for 32 bit numbers
 * \param t - source number
 * \return converted number
 */
template<>
constexpr uint32_t pc_to_net(uint32_t t)
{
    return switch_1_byte<0>(t) | switch_1_byte<1>(t) | switch_1_byte<2>(t) | switch_1_byte<3>(t);
}

/*!
 * Compile-time converter BE to LE for 16 bit numbers
 * \param t - source number
 * \return converted number
 */
template<>
constexpr uint16_t pc_to_net(uint16_t t)
{
    return switch_1_byte<0>(t) | switch_1_byte<1>(t);
}

# else
#  if __BYTE_ORDER == __LITTLE_ENDIAN

/*!
 * Does nothing for Intel
 */
template<class T>
constexpr T pc_to_net(T t)
{
    return t;
}

#  endif
#endif

} // CIFSv2

} // protocols
} // NST
//------------------------------------------------------------------------------
#endif // PC_TO_NET_H
//------------------------------------------------------------------------------
