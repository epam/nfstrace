//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: User output
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "utils/out.h"
//------------------------------------------------------------------------------
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
