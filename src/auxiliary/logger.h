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
#include <sstream>

#include <sys/file.h>

#include "exception.h"
//------------------------------------------------------------------------------
/*  http://www.unix.org/whitepapers/reentrant.html
    The POSIX.1 and C-language functions that operate on character streams 
    (represented by pointers to objects of type FILE) are required by POSIX.1c 
    to be implemented in such a way that reentrancy is achieved 
    (see ISO/IEC 9945:1-1996, §8.2). This requirement has a drawback; it imposes
    substantial performance penalties because of the synchronization that must
    be built into the implementations of the functions for the sake of reentrancy.
*/
#ifdef DEBUG
#define STRINGIZE(x) DO_STRINGIZE(x)
#define DO_STRINGIZE(x) #x
// TODO: DANGEROUS MACRO !!! Passing custom client string as format to printf().
// May SIGSEGV
#define TRACE(...) {\
    NST::auxiliary::Logger& log = NST::auxiliary::Logger::get_global();\
    log.print("\n" __FILE__ ":" STRINGIZE(__LINE__) ": " __VA_ARGS__);\
    log.flush();\
}
#else
#define TRACE(format, ...)
#endif

#define LOG(...) {\
    NST::auxiliary::Logger& log = NST::auxiliary::Logger::get_global();\
    log.print("\n" __VA_ARGS__);\
}
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class Logger
{
public:
    Logger(FILE* out=NULL) : owner(false), file(out)
    {
    }
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
        inline Buffer(Logger& logger = Logger::get_global()) : std::ostream(NULL), log(logger), buf(ios_base::out)
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
            throw Exception(std::string("Global Logger have been set"));
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
            throw Exception(std::string("Logger cannot open file: " + file_path));
        }
        if(flock(fileno(file), LOCK_EX | LOCK_NB))
        {
            throw Exception(std::string("File: " + file_path + " opened in another thread"));
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
    Logger(const Logger&);
    void operator=(const Logger&);

    static Logger* global_logger;
    bool     owner; // Is logger file owner?
    FILE*    file;
};

} // auxiliary
} // NST
//------------------------------------------------------------------------------
#endif //LOGGER_H
//------------------------------------------------------------------------------
