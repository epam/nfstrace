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
#include <fstream>
#include <sstream>

#include <sys/file.h>

#include "exception.h"
#include "spinlock.h"
//------------------------------------------------------------------------------
#ifdef DEBUG
#define TRACE(format, ...) {\
    NST::auxiliary::Logger& log = NST::auxiliary::Logger::get_global();\
    NST::auxiliary::Spinlock::Lock lock(log.get_spinlock());\
    log.print("%s %d: "format, __FILE__, __LINE__, __VA_ARGS__);\
    log.flush();\
}
#else
#define TRACE(format, ...)
#endif

/*
 * Non-blocking logging.
 * Should be used inside LOCK_LOG and UNLOCK_LOG section.
 */
#define NBLK_LOG(format, ...) {\
    NST::auxiliary::Logger& log = NST::auxiliary::Logger::get_global();\
    log.print(format, __VA_ARGS__);\
}
// Allow lock GLOBAL logger
#define LOCK_LOG {\
    NST::auxiliary::Logger& log = NST::auxiliary::Logger::get_global();\
    NST::auxiliary::Spinlock::Lock lock(log.get_spinlock());
// Unlock locked logger
#define UNLOCK_LOG }
// Atomic write data in the global log
#define LOG(format, ...)\
    LOCK_LOG\
    NBLK_LOG(format, __VA_ARGS__)\
    UNLOCK_LOG
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class Logger 
{
public:
    Logger() : owner(false), file(NULL) 
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
        Buffer(Logger& logger = Logger::get_global()) : std::ostream(NULL), log(logger), buf(ios_base::out)
        {
            init(&buf);
        }
        ~Buffer()
        {
            Spinlock::Lock lock(log.get_spinlock());
            log.print("%s", buf.str().c_str());
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
        owner = true;

        if(!(file = fopen(file_path.c_str(), "w")))
        {
            throw Exception(std::string("Logger cannot open file: " + file_path));
        }
        if(flock(fileno(file), LOCK_EX | LOCK_NB))
        {
            throw Exception(std::string("File: " + file_path + " opened in another thread"));
        }
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
    Spinlock& get_spinlock()
    {
        return spinlock;
    }

private:
    Logger(const Logger&);
    void operator=(const Logger&);

    static Logger* global_logger;
    bool     owner; // Is logger file owner?
    FILE*    file;
    Spinlock spinlock;
};

} // auxiliary
} // NST
//------------------------------------------------------------------------------
#endif //LOGGER_H
//------------------------------------------------------------------------------
