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

// TODO: rename this function template to LEconstant2host

template<class T>
constexpr T pc_to_net(T t)
{
    static_assert(t == T{}, "try to not use pc_to_net w/o specialization");
    return t;
}

template<>
constexpr std::uint64_t pc_to_net(std::uint64_t t)
{
    return ((t & 0xFF00000000000000) >> 56)
         | ((t & 0x00FF000000000000) >> 40)
         | ((t & 0x0000FF0000000000) >> 24)
         | ((t & 0x000000FF00000000) >> 8)
         | ((t & 0x00000000FF000000) << 8)
         | ((t & 0x0000000000FF0000) << 24)
         | ((t & 0x000000000000FF00) << 40)
         | ((t & 0x00000000000000FF) << 56);
}

template<>
constexpr uint32_t pc_to_net(uint32_t t)
{
    return ((t & 0xFF000000) >> 24)
         | ((t & 0x00FF0000) >> 8)
         | ((t & 0x0000FF00) << 8)
         | ((t & 0x000000FF) << 24);
}

template<>
constexpr uint16_t pc_to_net(uint16_t t)
{
    return ((t & 0xFF00) >> 8)
         | ((t & 0x00FF) << 8);
}

template<>
constexpr std::uint8_t pc_to_net(std::uint8_t v)
{
    return v;
}

template<>
constexpr std::int64_t pc_to_net(std::int64_t v)
{
    return pc_to_net((std::uint64_t)v);
}

template<>
constexpr std::int32_t pc_to_net(std::int32_t v)
{
    return pc_to_net((std::uint32_t)v);
}

template<>
constexpr std::int16_t pc_to_net(std::int16_t v)
{
    return pc_to_net((std::uint16_t)v);
}

template<>
constexpr std::int8_t pc_to_net(std::int8_t v)
{
    return pc_to_net((std::uint8_t)v);
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
