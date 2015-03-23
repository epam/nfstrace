//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Reentrant logger interface
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
#ifndef LOG_H
#define LOG_H
//------------------------------------------------------------------------------
#include <sstream>
//------------------------------------------------------------------------------
#ifdef NDEBUG
#define TRACE(...)
#else
#define STRINGIZE(x) DO_STRINGIZE(x)
#define DO_STRINGIZE(x) #x
// TODO: DANGEROUS MACRO ! Passing custom client string as format to printf().
// May be cause of SIGSEGV
#define TRACE(...) {\
    NST::utils::Log::message(__FILE__ ":" STRINGIZE(__LINE__) ": " __VA_ARGS__);\
    NST::utils::Log::message("\n");\
    NST::utils::Log::flush();\
}
#endif

#define LOG(...) {\
    NST::utils::Log::message(__VA_ARGS__);\
    NST::utils::Log::message("\n");\
}

#define LOGONCE(...) {\
    static bool notyet = true; \
    if(notyet) { LOG(__VA_ARGS__); notyet = false; }\
}
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

class Log : private std::stringbuf, public std::ostream
{
public:
    // helper for creation and destruction logging subsystem
    // isn't thread-safe!
    struct Global
    {
        explicit Global(const std::string& file_path);
        ~Global();
        Global(const Global&)            = delete;
        Global& operator=(const Global&) = delete;
        void reopen();
    private:
        std::string log_file_path;
    };

    Log();
    ~Log();
    Log(const Log&)            = delete;
    Log& operator=(const Log&) = delete;

    // lightweight logging
    static void message(const char* format, ...);
    static void flush();
private:
    char buffer[256];
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//LOG_H
//------------------------------------------------------------------------------
