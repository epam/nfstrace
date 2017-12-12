//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: The helper type for preventing copying instance via inheritance.
// Copyright (c) 2017 EPAM Systems
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
#ifndef NONCOPYABLE_H
#define NONCOPYABLE_H
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{
struct noncopyable
{
protected:
    noncopyable()                              = default;
    ~noncopyable()                             = default;
    noncopyable(const noncopyable&)            = delete;
    noncopyable& operator=(const noncopyable&) = delete;
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif // NONCOPYABLE_H
//------------------------------------------------------------------------------
