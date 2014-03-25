//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Thread-safe logger interface
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
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
    NST::utils::Log::message("\n" __FILE__ ":" STRINGIZE(__LINE__) ": " __VA_ARGS__);\
    NST::utils::Log::flush();\
}
#endif

#define LOG(...) {\
    NST::utils::Log::message("\n" __VA_ARGS__);\
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
