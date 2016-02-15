//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Definition of XDR structures.
// Copyright (c) 2013 EPAM Systems
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
#ifndef XDR_TYPES_H
#define XDR_TYPES_H
//------------------------------------------------------------------------------
#include <cstddef>
#include <cstdint>
//------------------------------------------------------------------------------
namespace NST
{
namespace API
{
struct Opaque
{
    inline void set(const uint8_t* p, uint32_t n)
    {
        ptr = p;
        len = n;
    }

    inline uint8_t operator[](size_t i) const { return ptr[i]; }
    inline const uint8_t*            data() const { return ptr; }
    inline uint32_t                  size() const { return len; }
    const uint8_t*                   ptr;
    uint32_t                         len;
};

} // namespace API
} // namespace NST
//------------------------------------------------------------------------------
#endif //XDR_TYPES_H
//------------------------------------------------------------------------------
