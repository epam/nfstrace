//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage for populating Analyzers
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <utility>

#include "utils/logger.h"
#include "analysis/analyzers.h"
#include "analysis/print_analyzer.h"
//------------------------------------------------------------------------------
using NST::utils::Logger;
using NST::controller::Parameters;
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

Analyzers::Analyzers(const Parameters& params)
{
    for(const auto& a : params.analysiss())
    {
        Logger::Buffer message;
        try // try to load plugin
        {
            message << "Loading module: '" << a.path << "' with args: [" << a.args << "]";

            std::unique_ptr<PluginInstance> plugin{new PluginInstance(a.path, a.args)};
            analysiss.push_back(plugin->instance());
            plugins.push_back(std::move(plugin));
        }
        catch(std::runtime_error& e)
        {
            message << " failed with: " << e.what();
        }
    }

    if(params.is_verbose()) // add special analysis for trace out RPC calls
    {
        std::unique_ptr<IAnalyzer> print{new PrintAnalyzer(std::cout)};
        analysiss.push_back(print.get());
        builtin.push_back(std::move(print));
    }
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
