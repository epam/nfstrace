//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Interface to print out user information
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef OUT_H
#define OUT_H
//------------------------------------------------------------------------------
#include <iostream>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

class Out : public std::ostream
{
public:
    enum class Level : int // verbosity level
    {
        Silent = 0,
        Info   = 1,
        All    = 2,
    };

    // helper for creation and destruction global level of messages
    struct Global
    {
        Global(const Level verbose_level);
        ~Global();
        Global(const Global&)            = delete;
        Global& operator=(const Global&) = delete;
    };

    Out(Level level=Level::Info);  // verbose level
    ~Out();
    Out(const Out&)            = delete;
    Out& operator=(const Out&) = delete;
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//OUT_H
//------------------------------------------------------------------------------
