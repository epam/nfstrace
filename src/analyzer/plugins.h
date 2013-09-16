//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Plugins storage. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PLUGINS_H
#define PLUGINS_H
//------------------------------------------------------------------------------
#include <string>
#include <vector>

#include "plugin.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class Plugins
{
    typedef std::vector<PluginInstance*> Storage;

public:
    typedef Storage::iterator Iterator;

    Plugins()
    {
    }
    ~Plugins()
    {
        Storage::iterator i = plugins.begin();
        Storage::iterator end = plugins.end();
        for(; i != end; ++i)
            delete *i;
    }

    inline Iterator begin() { return plugins.begin(); }
    inline Iterator end() { return plugins.end(); }
    inline size_t size() const { return plugins.size(); }

    void add(const std::string& path, const std::string& args)
    {
        plugins.push_back(new PluginInstance(path, args));
    }

private:
    Storage plugins;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PLUGINS_H
//------------------------------------------------------------------------------
