//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Interface to print out user information
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
#ifndef OUT_H
#define OUT_H
//------------------------------------------------------------------------------
#include <iostream>

#include "utils/noncopyable.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{
class Out final : noncopyable, public std::ostream
{
public:
    enum class Level : int // verbosity level
    {
        Silent = 0,
        Info   = 1,
        All    = 2,
    };

    // helper for creation and destruction global level of verbosity
    struct Global final : noncopyable
    {
        explicit Global(const Level verbose_level);
        ~Global();

        static Level get_level();      // return global level of verbosity
        static void  set_level(Level); // set global level of verbosity
    };

    explicit Out(Level level = Level::Info); // verbose level of message
    ~Out();
};

inline bool operator>=(const Out::Level a, const Out::Level b)
{
    return (int)a >= (int)b;
}

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif // OUT_H
//------------------------------------------------------------------------------
