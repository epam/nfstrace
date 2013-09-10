//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin which encapsulate all requests to shared object library.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_H
#define PLUGIN_H
//------------------------------------------------------------------------------
#include <string>

#include "../api/plugin_api.h"
#include "../auxiliary/exception.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Exception;
//------------------------------------------------------------------------------

namespace NST
{
namespace analyzer
{

class PluginException : public Exception
{
public:
    explicit PluginException(const std::string& msg) : Exception(msg) { }

    virtual const PluginException* dynamic_clone() const { return new PluginException(*this); }
    virtual void                   dynamic_throw() const { throw *this; }
};

class Plugin
{
    typedef void* (*create_t)    (const char* opts);// create analyzer and return context 
    typedef void  (*destroy_t)   (void* context);   // destroy analyzer 

public:
    Plugin(const std::string& path, const std::string& args);
    ~Plugin();

private:
    Plugin(const Plugin&);            // undefiend
    Plugin& operator=(const Plugin&); // undefiend

    BaseAnalyzer2* analyzer;
    void*          handle;
    destroy_t      destroy;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PLUGIN_H
//------------------------------------------------------------------------------
