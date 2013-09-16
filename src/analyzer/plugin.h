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
    Plugin(const std::string& path, const std::string& args);
    ~Plugin();

    BaseAnalyzer* get_analyzer();

private:
    Plugin(const Plugin&);            // undefiend
    Plugin& operator=(const Plugin&); // undefiend

    analyzers::plugin_usage_func   usage;
    analyzers::plugin_create_func  create;
    analyzers::plugin_destroy_func destroy;

    BaseAnalyzer* analyzer;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PLUGIN_H
//------------------------------------------------------------------------------
