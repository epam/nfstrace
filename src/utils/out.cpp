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

inline bool operator >=(const Out::Level a, const Out::Level b)
{
    return (int)a >= (int)b;
}

static Out::Level global = Out::Level::Info;

Out::Global::Global(const Level verbose_level)
{
    global = verbose_level;
}
Out::Global::~Global()
{
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
