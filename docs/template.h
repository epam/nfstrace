//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: A template for headers.
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
#ifndef TEMPLATE_H
#define TEMPLATE_H
//------------------------------------------------------------------------------
#include <string>
//------------------------------------------------------------------------------
#define MY_MIN(a,b) (((a) < (b)) ? (a) : (b))
//------------------------------------------------------------------------------
namespace hello
{

class SayHello
{
public:
    SayHello();
    ~SayHello();

    SayHello(const SayHello&);              // undefined
    SayHello& operator=(const SayHello&);   // undefined

    // small functions may be implemented in-place
    inline const std::string& say() const { return text; }

    unsigned int get() const;
    void set(unsigned int v);

private:
    std::string text;
    unsigned int value; // just a value for get/set methods

    static const unsigned int BAD_COFFEE;
};

} // namespace hello
//------------------------------------------------------------------------------
#endif//TEMPLATE_H
//------------------------------------------------------------------------------
