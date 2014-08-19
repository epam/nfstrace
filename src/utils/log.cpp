//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Reentrant logger implementation
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
#include <cstdarg>
#include <cstdio>
#include <iostream>
#include <stdexcept>

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "utils/log.h"
#include "utils/out.h"
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

namespace // unnanmed
{
//static std::string get_pid()
//{
//    char buff[8] = {"\0"};
//    sprintf(buff,"%d",getpid());
//    return std::string{buff};
//}

static FILE* try_open(const std::string& file_name)
{
    FILE* file = fopen(file_name.c_str(), "w");
    if(file == nullptr)
    {
        return nullptr;
    }
    chmod(file_name.c_str(), S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH); //0666
    if(flock(fileno(file), LOCK_EX | LOCK_NB))
    {
        fclose(file);
        return nullptr;
    }
    return file;
}

} // unnamed unnamed

Log::Global::Global(const std::string& path)
{
    const std::string LOG_PATH{"/tmp/nfstrace"};
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

    struct stat s;
    if (stat(LOG_PATH.c_str(), &s)) // check destination folder exists
    {
        if(mkdir(LOG_PATH.c_str(), ALLPERMS)) // create directory for nfs logs
        {
            throw std::runtime_error{"Logger can not create log directory: " + LOG_PATH};
        }
    }
    std::string tmp{LOG_PATH + "/" + path + ".log"};
    FILE* file = try_open(tmp);
    if(file == nullptr)
    {
        tmp = LOG_PATH + "/" + path + "-" + std::to_string(getpid()) + ".log";
        file = try_open(tmp);
        if(file == nullptr)
        {
            throw std::runtime_error{"Logger can not open file for write: " + path};
        }
    }
    if(utils::Out message{})
    {
        message << "Log folder: " << LOG_PATH;
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
