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
//------------------------------------------------------------------------------
#if defined(__linux__) || defined(__GNU__)
#include <endian.h>
#define NFSTRACE_BYTE_ORDER __BYTE_ORDER
#define NFSTRACE_BIG_ENDIAN __BIG_ENDIAN
#define NFSTRACE_LITTLE_ENDIAN __LITTLE_ENDIAN
#else
#include <sys/param.h>
#include <machine/endian.h>
#define NFSTRACE_BYTE_ORDER BYTE_ORDER
#define NFSTRACE_BIG_ENDIAN BIG_ENDIAN
#define NFSTRACE_LITTLE_ENDIAN LITTLE_ENDIAN
#endif
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{
namespace SMBv2
{

# if NFSTRACE_BYTE_ORDER == NFSTRACE_BIG_ENDIAN

/*!
 * Converter. Not very fast,
 * try to not use
 */
template<class T>
constexpr T pc_to_net(T t)
{
    static_assert(t == 0, "try to not use pc_to_net w/o specialization");
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
#  if NFSTRACE_BYTE_ORDER == NFSTRACE_LITTLE_ENDIAN

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

} // SMBv2
} // API
} // NST
//------------------------------------------------------------------------------
#endif//PC_TO_NET_H
//------------------------------------------------------------------------------
