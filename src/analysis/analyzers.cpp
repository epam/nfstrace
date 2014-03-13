//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage for Analyzers, load plugins and processing
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "analysis/analyzers.h"
#include "analysis/print_analyzer.h"
#include "utils/logger.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

Analyzers::Analyzers(const controller::Parameters& params)
{
    for(const auto& a : params.analysis_modules())
    {
        utils::Logger::Buffer message;
        try // try to load plugin
        {
            message << "Loading module: '" << a.path << "' with args: [" << a.args << "]";

            std::unique_ptr<PluginInstance> plugin{new PluginInstance{a.path, a.args}};
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
