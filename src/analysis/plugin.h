//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Plugin which encapsulate all requests to shared object library.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef PLUGIN_H
#define PLUGIN_H
//------------------------------------------------------------------------------
#include <string>

#include "utils/dynamic_load.h"
#include "analysis/ianalyzer.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class Plugin : private NST::utils::DynamicLoad
{
public:
    static const std::string usage_of(const std::string& path);

protected:
    explicit Plugin(const std::string& path);
    Plugin(const Plugin&)            = delete;
    Plugin& operator=(const Plugin&) = delete;

    plugin_usage_func   usage;
    plugin_create_func  create;
    plugin_destroy_func destroy;
};

class PluginInstance : private Plugin
{
public:
    PluginInstance(const std::string& path, const std::string& args);
    PluginInstance(const PluginInstance&)            = delete;
    PluginInstance& operator=(const PluginInstance&) = delete;
    ~PluginInstance();

    inline IAnalyzer* instance() const { return analysis; }

private:
    IAnalyzer* analysis;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//PLUGIN_H
//------------------------------------------------------------------------------
