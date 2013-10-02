//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Plugin which encapsulate all requests to shared object library.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGIN_H
#define PLUGIN_H
//------------------------------------------------------------------------------
#include <string>

#include "../auxiliary/dynamic_load.h"
#include "ianalyzer.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class Plugin : private NST::auxiliary::DynamicLoad
{
public:
    static const std::string usage_of(const std::string& path);

private:
    Plugin(const Plugin&);            // undefiend
    Plugin& operator=(const Plugin&); // undefiend

protected:
    Plugin(const std::string& path);

    plugin_usage_func   usage;
    plugin_create_func  create;
    plugin_destroy_func destroy;
};

class PluginInstance : private Plugin
{
public:
    PluginInstance(const std::string& path, const std::string& args);
    ~PluginInstance();

    inline IAnalyzer* instance() const { return analyzer; }

private:
    PluginInstance(const PluginInstance&);            // undefiend
    PluginInstance& operator=(const PluginInstance&); // undefiend

    IAnalyzer* analyzer;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PLUGIN_H
//------------------------------------------------------------------------------
