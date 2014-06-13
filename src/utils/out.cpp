//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: User output
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
#include "utils/out.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

static Out::Level global = Out::Level::Info;

Out::Global::Global(const Level verbose_level)
{
    global = verbose_level;
}
Out::Global::~Global()
{
}

Out::Level Out::Global::get_level()
{
    return global;
}

Out::Out(Level level)
: std::ostream{ (global >= level) ? std::cout.rdbuf() : nullptr }
{
}
Out::~Out()
{
    std::ostream::put('\n');
}

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
