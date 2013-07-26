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

#define LOG(format, ...) {\
    NST::auxiliary::Logger& log = NST::auxiliary::Logger::get_global();\
    NST::auxiliary::Spinlock::Lock lock(log.get_spinlock());\
    log.print("%s %d: "format, __FILE__, __LINE__, __VA_ARGS__);\
}
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
    bool     owner; // Is logger is file owner? 
    FILE*    file;
    Spinlock spinlock;
};

} // auxiliary
} // NST
//------------------------------------------------------------------------------
#endif //LOGGER_H
//------------------------------------------------------------------------------
