//------------------------------------------------------------------------------
// Author: Dzianis Huznou
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
#include <stdexcept>

#include "analysis/plugin.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

Plugin::Plugin(const std::string& path, const std::string& default_location)
    : DynamicLoad{path, default_location}
    , usage  {nullptr}
    , create {nullptr}
    , destroy{nullptr}
{
    plugin_get_entry_points_func nst_get_entry_points{nullptr};

    load_address_of("nst_get_entry_points", nst_get_entry_points);
    const auto& entry_points = nst_get_entry_points();

    if(!entry_points)
    {
        throw std::runtime_error{path + ": can't load plugin entry points!"};
    }

    switch(entry_points->vers)
    {
    // case NST_PLUGIN_API_VERSION_2_0:
    // Add 2.0 specific initialization here
    case NST_PLUGIN_API_VERSION:
    default:
        usage   = entry_points->usage;
        create  = entry_points->create;
        destroy = entry_points->destroy;
    }

    if(!usage  || !create || !destroy)
    {
        throw std::runtime_error{path + ": can't load entry point for some plugin function(s)"};
    }
}

const std::string Plugin::usage_of(const std::string& path, const std::string& default_location)
{
    Plugin instance{path, default_location};
    return instance.usage();
}

PluginInstance::PluginInstance(const std::string& path, const std::string& args, const std::string& default_location)
    : Plugin{path, default_location}
{
    analysis = create(args.c_str());
    if(!analysis) throw std::runtime_error{path + ": create call returns NULL-pointer"};
}

PluginInstance::~PluginInstance()
{
    destroy(analysis);
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
