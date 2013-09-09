//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin which encapsulate all requests to shared object library.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_H
#define PLUGIN_H
//------------------------------------------------------------------------------
#include <string>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

namespace NST
{
namespace analyzer
{

class Plugin
{
    typedef void* (*create_t)    (const char* opts);     // create analyzer and return context 
    typedef void  (*destroy_t)   (void* context);   // destroy analyzer 

public:
    Plugin(const std::string& path, const std::string& args);
    ~Plugin();
    void* provide_func(const std::string& function);

private:
    Plugin(const Plugin&);            // undefiend
    Plugin& operator=(const Plugin&); // undefiend

    void* handle;
    void* context;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PLUGIN_H
//------------------------------------------------------------------------------
