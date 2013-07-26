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
    NST::auxiliary::Spinlock::Lock lock(NST::auxiliary::g_Logger->get_spinlock());\
    NST::auxiliary::g_Logger->print("%s %d. TYPE: TRACE. MSG -- "format, __FILE__, __LINE__, __VA_ARGS__);\
    NST::auxiliary::g_Logger->flush();\
}
#else
#define TRACE(format, ...)
#endif

#define LOG(format, ...) {\
    NST::auxiliary::Spinlock::Lock lock(NST::auxiliary::g_Logger->get_spinlock());\
    NST::auxiliary::g_Logger->print("%s %d. TYPE: LOG. MSG -- "format, __FILE__, __LINE__, __VA_ARGS__);\
}
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class Logger 
{
public:
    Logger(const std::string& file_path) : file(NULL)
    {
        if(!(file = fopen(file_path.c_str(), "w")))
        {
            throw Exception(std::string("Logger cannot open file: " + file_path)); 
        }
        if(flock(fileno(file), LOCK_EX | LOCK_NB))
        {
            throw Exception(std::string("File: " + file_path + " opened in another thread"));
        }
    }
    ~Logger()
    {
        flock(fileno(file), LOCK_UN);
        fclose(file);
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

    FILE*    file;
    Spinlock spinlock;
};

static Logger* g_Logger = NULL;

} // auxiliary
} // NST
//------------------------------------------------------------------------------
#endif //LOGGER_H
//------------------------------------------------------------------------------
