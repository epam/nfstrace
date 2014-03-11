//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Multithread compatible logger
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef LOGGER_H
#define LOGGER_H
//------------------------------------------------------------------------------
#include <cstdarg>
#include <cstdio>
#include <stdexcept>
#include <sstream>

#include <sys/file.h>
//------------------------------------------------------------------------------
/*  http://www.unix.org/whitepapers/reentrant.html
    The POSIX.1 and C-language functions that operate on character streams 
    (represented by pointers to objects of type FILE) are required by POSIX.1c 
    to be implemented in such a way that reentrancy is achieved 
    (see ISO/IEC 9945:1-1996, §8.2). This requirement has a drawback; it imposes
    substantial performance penalties because of the synchronization that must
    be built into the implementations of the functions for the sake of reentrancy.
*/
#ifdef NDEBUG
#define TRACE(...)
#else
#define STRINGIZE(x) DO_STRINGIZE(x)
#define DO_STRINGIZE(x) #x
// TODO: DANGEROUS MACRO ! Passing custom client string as format to printf().
// May be cause of SIGSEGV
#define TRACE(...) {\
    NST::utils::Logger& log = NST::utils::Logger::get_global();\
    log.print("\n" __FILE__ ":" STRINGIZE(__LINE__) ": " __VA_ARGS__);\
    log.flush();\
}
#endif

#define LOG(...) {\
    NST::utils::Logger& log = NST::utils::Logger::get_global();\
    log.print("\n" __VA_ARGS__);\
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

class Logger
{
public:
    Logger(FILE* out=nullptr) : owner{false}, file{out}
    {
    }
    Logger(const Logger&)            = delete;
    Logger& operator=(const Logger&) = delete;
    ~Logger()
    {
        if(owner)
        {
            flock(fileno(file), LOCK_UN);
            fclose(file);
        }
    }

    class Buffer : public std::ostream
    {
    public:
        inline Buffer(Logger& logger = Logger::get_global())
                : std::ostream(NULL)
                , log(logger)
                , buf(ios_base::out)
        {
            std::ostream::init(&buf);
        }
        inline ~Buffer()
        {
            log.print("\n%s", buf.str().c_str());
        }

    private:
        Logger& log;
        std::stringbuf buf;
    };

    inline static void set_global(Logger* global)
    {
        if(global_logger)
        {
            throw std::runtime_error("Global Logger already have been set");
        }
        global_logger = global;
    }
    inline static Logger& get_global()
    {
        return *global_logger;
    }
    void set_output_file(const std::string& file_path)
    {
        if(!(file = fopen(file_path.c_str(), "w")))
        {
            throw std::runtime_error(std::string("Logger cannot open file: " + file_path));
        }
        if(flock(fileno(file), LOCK_EX | LOCK_NB))
        {
            throw std::runtime_error(std::string("File: " + file_path + " opened in another thread"));
        }

        owner = true;
    }
    void set_output_err()
    {
        file = stderr;
    }
    void set_output_out()
    {
        file = stdout;
    }
    void print(const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        vfprintf(file, format, args);
        va_end(args);
    }
    void flush()
    {
        fflush(file);
    }

private:
    static Logger* global_logger;
    bool     owner; // Is logger file owner?
    FILE*    file;
};

} // utils
} // NST
//------------------------------------------------------------------------------
#endif //LOGGER_H
//------------------------------------------------------------------------------
