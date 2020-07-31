//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage for Analyzers, load plugins and processing
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

#include "analysis/analyzers.h"
#include "analysis/print_analyzer.h"
#include "utils/out.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{
Analyzers::Analyzers(const controller::Parameters& params)
    : _silent{false}
{
    for(const auto& a : params.analysis_modules())
    {
        utils::Out message;
        try // try to load plugin
        {
            message << "Loading module: '" << a.path << "' with args: [" << a.args << "]";
            std::unique_ptr<PluginInstance> plugin{new PluginInstance{a.path, a.args}};
            if(plugin->silent())
            {
                if(!_silent)
                {
                    _silent = true;
                }
            }
            else
            {
                if(_silent)
                {
                    TRACE("Error in plugin %s loading. Already load module with silent option.", a.path.c_str());
                    continue;
                }
            }

            modules.emplace_back(plugin->instance());
            plugins.emplace_back(std::move(plugin));
        }
        catch(std::runtime_error& e)
        {
            message << " failed with: " << e.what();
        }
    }

    if(params.trace()) // add special module for tracing RPC procedures
    {
        std::unique_ptr<IAnalyzer> tracer{new PrintAnalyzer{std::cout}};
        modules.emplace_back(tracer.get());
        builtin.emplace_back(std::move(tracer));
    }
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
