//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Place for description of module. A template for source files.
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
#include <cassert> // include language headers in alphabetical order
#include <iostream>

#include <unistd.h> // then include libraries and platform headers in alphabetical order

#include "template.h" // include headers of project modules in alphabetical order
//------------------------------------------------------------------------------
// place for constants and macros
const unsigned int SayHello::BAD_COFFEE = 0xBADC0FFE;
//------------------------------------------------------------------------------
namespace hello
{

SayHello::SayHello() : text{"Hello, World!"}, value{0}
{
}
SayHello::~SayHello()
{
}

void SayHello::set_value(std::uint32_t v)
{
    value = v;
}

std::uint32_t SayHello::get_value() const
{
    return value;
}

} // namespace hello

int main(int argc, char** argv)
{
    hello::SayHello hello;
    std::cout << hello.say() << std::endl;

    hello.set(42);

    assert(42 == hello.get());

    // FizzBuzz
    for(std::size_t i=1; i<=100; i++)
    {
        if((i % 15) == 0)
        {
            std::cout << "FizzBuzz\n";
        }
        else if(i % 3 == 0) std::cout << "Fizz\n";
        else if(i % 5 == 0) std::cout << "Buzz\n";
        else
        {
            std::cout << i << '\n';
        }
    }

    return 0;
}
//------------------------------------------------------------------------------
