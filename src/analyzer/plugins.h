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
    typedef std::vector<Plugin*> Storage;

    typedef void  (*stage_t)     (void* context);   // signal about new processing epoch 
    typedef void  (*analyse_t)   (void* context);   // analyse data
    typedef const char* (*name_t)();                // provide analyzer name

public:
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

    void add(const std::string& path, const std::string& args)
    {
        plugins.push_back(new Plugin(path, args));
    }

private:
    Storage plugins;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//PLUGINS_H
//------------------------------------------------------------------------------
