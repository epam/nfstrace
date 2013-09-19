//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage for populating Analyzers
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "../auxiliary/logger.h"
#include "../controller/cmdline_args.h"
#include "analyzers.h"
#include "analyzers/breakdown_analyzer.h"
#include "analyzers/ofdws_analyzer.h"
#include "analyzers/ofws_analyzer.h"
#include "analyzers/print_analyzer.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Logger;
using NST::auxiliary::UniquePtr;
using NST::analyzer::analyzers::BaseAnalyzer;
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

        if(r.path == NST::controller::cmdline::Args::ob_analyzer)
        {
            UniquePtr<BaseAnalyzer> ob(new analyzers::BreakdownAnalyzer(std::cout /*r.arguments*/));
            analyzers.push_back(ob.get());
            builtin.push_back(ob);
            continue;
        }
        if(r.path == NST::controller::cmdline::Args::ofws_analyzer)
        {
            UniquePtr<BaseAnalyzer> ofws(new analyzers::OFWSAnalyzer(std::cout /*r.arguments*/));
            analyzers.push_back(ofws.get());
            builtin.push_back(ofws);
            continue;
        }
        if(r.path == NST::controller::cmdline::Args::ofdws_analyzer)
        {
            UniquePtr<BaseAnalyzer> ofdws(new analyzers::OFDWSAnalyzer(std::cout, params.block_size(), params.bucket_size() /*r.arguments*/));
            analyzers.push_back(ofdws.get());
            builtin.push_back(ofdws);
            continue;
        }

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
        UniquePtr<BaseAnalyzer> print(new analyzers::PrintAnalyzer(std::cout));
        analyzers.push_back(print.get());
        builtin.push_back(print);
    }
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
