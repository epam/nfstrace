//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugin which encapsulate all requests to shared object library.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_H
#define PLUGIN_H
//------------------------------------------------------------------------------
#include <string>

#include "../auxiliary/dynamic_load.h"
#include "analyzers/base_analyzer_struct.h"
//------------------------------------------------------------------------------
using NST::analyzer::analyzers::BaseAnalyzer;
//------------------------------------------------------------------------------

namespace NST
{
namespace analyzer
{

class Plugin : private NST::auxiliary::DynamicLoad
{
public:

    typedef void* (*create_t)    (const char* opts);// create analyzer and return context
    typedef void  (*destroy_t)   (void* context);   // destroy analyzer

public:
    Plugin(const std::string& path, const std::string& args);
    ~Plugin();

    inline BaseAnalyzer* get_analyzer() { return analyzer; }

private:
    Plugin(const Plugin&);            // undefiend
    Plugin& operator=(const Plugin&); // undefiend

    BaseAnalyzer* analyzer;
    destroy_t      destroy;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PLUGIN_H
//------------------------------------------------------------------------------
