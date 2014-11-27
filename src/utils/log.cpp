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
#include <cerrno>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <stdexcept>
#include <system_error>

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

static FILE* log_file {nullptr};
static bool  own_file {false};
static std::string log_file_path {};
static std::mutex mut{};

namespace // unnanmed
{

static FILE* try_open(const std::string& file_name)
{
    FILE* file {fopen(file_name.c_str(), "w")};
    if(file == nullptr)
    {
        throw std::system_error{errno, std::system_category(),
            (std::string("Error in opening file: ") + file_name).c_str()};
    }
    chmod(file_name.c_str(), S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
    if(flock(fileno(file), LOCK_EX | LOCK_NB))
    {
        fclose(file);
        throw std::system_error{errno, std::system_category(),
            ("Log file already locked: " + file_name).c_str()};
    }
    return file;
}

} // namespace unnamed

Log::Global::Global(const std::string& path)
{
    if(own_file) return;
    std::string path_file(path);
    if(!path_file.empty())
    {
        if(path_file[path_file.size()-1] == '/') // this is path to folder
        {
            path_file = path_file + ("nfstrace_logfile.log");
        }
    }
    else
    {
        path_file = path_file + ("./nfstrace_logfile.log");
    }
    FILE* file {nullptr};
    file = try_open(path_file);
    if(file == nullptr || file == NULL)
    {
        throw std::system_error{errno, std::system_category(),
            (std::string("Can't create log file: ") + path_file).c_str()};
    }
    if(utils::Out message{})
    {
        message << "Log folder: " << path_file;
    }

    log_file = file;
    own_file = true;
    log_file_path = path_file;
}

static void closeLog()
{
    flock(fileno(log_file), LOCK_UN);
    fclose(log_file);
    own_file = false;
    log_file = ::stderr;
}

Log::Global::~Global()
{
    if(own_file)
    {
        closeLog();
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
    std::unique_lock<std::mutex> lck(mut);
    vfprintf(log_file, format, args);
    va_end(args);
}

void Log::flush()
{
    fflush(log_file);
}

void Log::reopen()
{
    if(log_file == ::stderr || log_file == ::stdout || log_file == nullptr)
        return;

    if(log_file_path.empty()) return;
    std::unique_lock<std::mutex> lck(mut);
    closeLog();
    std::time_t t = std::time(NULL);
    std::string tmp{log_file_path + std::asctime(std::localtime(&t))};
    if(rename(log_file_path.c_str(), tmp.c_str()))
        throw std::system_error{errno, std::system_category(),
            (std::string{"Can't rename previous log file."} + log_file_path).c_str()};
    log_file = try_open(log_file_path);
    if(log_file == nullptr || log_file == NULL)
    {
        throw std::system_error{errno, std::system_category(),
        "Can't reopen file."};
    }
    //main unlock
}
} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
