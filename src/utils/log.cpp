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

#include "utils/log.h"
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

static FILE* log_file = nullptr;
static bool  own_file = false;

Log::Global::Global(const std::string& path)
{
    if(log_file != nullptr)
    {
        throw std::runtime_error{"Global Logger already have been created"};
    }

    // default is stderr
    if(path.empty())
    {
        log_file = ::stderr;
        return;
    }

    FILE* file = fopen(path.c_str(), "w");
    if(file == NULL)
    {
        throw std::runtime_error{"Logger can not open file for write: " + path};
    }

    if(flock(fileno(file), LOCK_EX | LOCK_NB))
    {
        fclose(file);
        throw std::runtime_error{"File: " + path + " opened in another thread"};
    }

    log_file = file;
    own_file = true;
}
Log::Global::~Global()
{
    if(own_file)
    {
        flock(fileno(log_file), LOCK_UN);
        fclose(log_file);
    }
}

Log::Log()
: std::stringbuf {ios_base::out}
, std::ostream   {nullptr}
{
    std::stringbuf::setp(buffer, buffer+sizeof(buffer));
    std::ostream::init(static_cast<std::stringbuf*>(this));
    std::ostream::put('\n');
}
Log::~Log()
{
    size_t len = pptr() - pbase();
    fwrite(pbase(), len, 1, log_file);
}

void Log::message(const char* format, ...)
{
    va_list args;
    va_start(args, format);
    vfprintf(log_file, format, args);
    va_end(args);
}

void Log::flush()
{
    fflush(log_file);
}

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
