//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Thread-safe logger implementation
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <stdexcept>

#include <sys/file.h>

#include "utils/logger.h"
//------------------------------------------------------------------------------
/*  http://www.unix.org/whitepapers/reentrant.html
    The POSIX.1 and C-language functions that operate on character streams
    (represented by pointers to objects of type FILE) are required by POSIX.1c
    to be implemented in such a way that reentrancy is achieved
    (see ISO/IEC 9945:1-1996, §8.2). This requirement has a drawback; it imposes
    substantial performance penalties because of the synchronization that must
    be built into the implementations of the functions for the sake of reentrancy.
*/
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{


namespace logger
{

static FILE* log = nullptr;
static bool  own = false;

Global::Global(const std::string& path)
{
    if(log != nullptr)
    {
        throw std::runtime_error{"Global Logger already have been created"};
    }

    // default is stderr, used if below code is going to throw exception
    log = ::stderr;


    FILE* file = fopen(path.c_str(), "w");
    if(file == nullptr)
    {
        throw std::runtime_error{"Logger can not open file for write: " + path};
    }

    if(flock(fileno(file), LOCK_EX | LOCK_NB))
    {
        fclose(file);
        throw std::runtime_error{"File: " + path + " opened in another thread"};
    }

    log = file;
    own = true;
}

Global::~Global()
{
    if(own)
    {
        flock(fileno(log), LOCK_UN);
        fclose(log);
    }
}


Buffer::Buffer()
: std::stringbuf {ios_base::out}
, std::ostream   {nullptr}
{
    std::stringbuf::setp(buffer, buffer+sizeof(buffer));
    std::ostream::init(static_cast<std::stringbuf*>(this));
    std::ostream::put('\n');
}
Buffer::~Buffer()
{
    size_t len = pptr() - pbase();
    fwrite(pbase(), len, 1, log);
}

void print(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(log, format, args);
    va_end(args);
}
void flush()
{
    fflush(log);
}


} // namespace logger


}
}
//------------------------------------------------------------------------------
