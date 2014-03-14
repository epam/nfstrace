//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Thread-safe logger interface
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef LOGGER_H
#define LOGGER_H
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
    NST::utils::logger::print("\n" __FILE__ ":" STRINGIZE(__LINE__) ": " __VA_ARGS__);\
    NST::utils::logger::flush();\
}
#endif

#define LOG(...) {\
    NST::utils::logger::print("\n" __VA_ARGS__);\
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


namespace logger
{
    // helper for creation and destruction logging subsystem
    // isn't thread-safe!
    struct Global
    {
        Global(const std::string& file_path);
        ~Global();
        Global(const Global&)            = delete;
        Global& operator=(const Global&) = delete;
    };

    // buffer for logging composite messages
    class Buffer : private std::stringbuf, public std::ostream
    {
    public:
        Buffer();
        ~Buffer();
        Buffer(const Buffer&)            = delete;
        Buffer& operator=(const Buffer&) = delete;
    private:
        char buffer[256];
    };

    // lightweight logging
    void print(const char* format, ...);
    void flush();
} // namespace logger


} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif //LOGGER_H
//------------------------------------------------------------------------------
