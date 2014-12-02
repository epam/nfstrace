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

static FILE* log_file {::stderr};
static bool  own_file {false};
static std::string log_file_path {};
static std::string default_file_name{"nfstrace_logfile"};

namespace // unnanmed
{

static FILE* try_open(const std::string& file_name)
{
    FILE* file = fopen(file_name.c_str(), "w");
    if(file == nullptr)
    {
        throw std::system_error{errno, std::system_category(),
                               {"Error in opening file: " + file_name}};
    }
    chmod(file_name.c_str(), S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
    if(flock(fileno(file), LOCK_EX | LOCK_NB))
    {
        fclose(file);
        throw std::system_error{errno, std::system_category(),
                               {"Log file already locked: " + file_name}};
    }
    return file;
}

} // namespace unnamed

Log::Global::Global(const std::string& path)
{
    if(own_file)
    {
        throw std::runtime_error{"Global Logger already have been created."};
    }
    std::string path_file(path);
    if(!path_file.empty())
    {
        struct stat st;
        if(!stat(path_file.c_str(), &st) && S_ISDIR(st.st_mode))
        {
            if(path_file[path_file.size() - 1] == '/')
                path_file = path_file + default_file_name;
            else
                path_file = path_file + '/' + default_file_name;
        }
        default_file_name = path_file;
    }
    else
    {
        path_file = default_file_name;
    }
    log_file_path = addtimestamp(path_file);
    FILE* file = try_open(log_file_path);
    if(file == nullptr)
    {
        throw std::system_error{errno, std::system_category(),
                               {std::string{"Can't create log file: "} + log_file_path}};
    }
    if(utils::Out message{})
    {
        message << "Log folder: " << log_file_path;
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
        own_file = false;
        log_file = ::stderr;
    }
}

void Log::Global::reopen()
{
    if(!own_file || log_file == ::stderr || log_file == ::stdout || log_file == nullptr)
        return;
    FILE* temp = freopen(log_file_path.c_str(), "a+", log_file);
    if(temp == nullptr)
    {
        throw std::system_error{errno, std::system_category(),
                               {std::string{"Can't reopen file: "} + log_file_path}};
    }
    log_file = temp;
}

const std::string Log::Global::addtimestamp(const std::string& path_file)
{
    std::string tmp_path;
    const std::string extention{".log"};
    // check if log file path endings with the extension string
    if(path_file.size() > extention.size() && (std::string(path_file.end() - extention.size(), path_file.end()) + '\0').compare(extention))
        tmp_path = std::string(path_file.begin(), (path_file.end() - extention.size())) + "_" + std::to_string(std::time(NULL));
    else
        tmp_path = path_file + "_" + std::to_string(std::time(NULL));
    tmp_path += extention;
    return tmp_path;
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
