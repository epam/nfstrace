//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage for populating Analyzers
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "../auxiliary/logger.h"
#include "../controller/cmdline_args.h"
#include "analyzers.h"
#include "print_analyzer.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Logger;
using NST::auxiliary::UniquePtr;
using NST::controller::AParams;
using NST::controller::Parameters;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

Analyzers::Analyzers(const Parameters& params)
{
    std::vector<AParams> requested_analyzers = params.analyzers();

    for(unsigned int i = 0; i < requested_analyzers.size(); ++i)
    {
        const AParams& r = requested_analyzers[i];

        Logger::Buffer message;
        try // try to load plugin
        {
            message << "Loading module: '" << r.path << "' with args: [" << r.arguments << "]";

            UniquePtr<PluginInstance> plugin(new PluginInstance(r.path, r.arguments));
            analyzers.push_back(plugin->instance());
            plugins.push_back(plugin);
        }
        catch(Exception& e)
        {
            message << " failed with: " << e.what();
        }
    }

    if(params.is_verbose()) // add special analyzer for trace out RPC calls
    {
        UniquePtr<IAnalyzer> print(new PrintAnalyzer(std::cout));
        analyzers.push_back(print.get());
        builtin.push_back(print);
    }
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
