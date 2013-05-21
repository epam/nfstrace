//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Place for description of module. A template for source files.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
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

SayHello::SayHello():text("Hello, World!"),value(0)
{
}
SayHello::~SayHello()
{
}

void SayHello::set_value(unsigned int v)
{
    value = v;
}

unsigned int SayHello::get_value()const
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

    return 0;
}
//------------------------------------------------------------------------------
