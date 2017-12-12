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

#include "api/plugin_api.h"
#include "utils/dynamic_load.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{
class Plugin : private NST::utils::DynamicLoad
{
public:
    static const std::string usage_of(const std::string& path);
    bool isSilent();

protected:
    explicit Plugin(const std::string& path);

    plugin_usage_func        usage;
    plugin_create_func       create;
    plugin_destroy_func      destroy;
    plugin_requirements_func requirements;
};

class PluginInstance final : private Plugin
{
public:
    PluginInstance(const std::string& path, const std::string& args);
    ~PluginInstance();

    inline IAnalyzer* instance() const { return analysis; }
    inline bool       silent() { return isSilent(); }
private:
    IAnalyzer* analysis;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif //PLUGIN_H
//------------------------------------------------------------------------------
