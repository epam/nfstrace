//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage.for populating Analyzers
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <vector>

#include "../auxiliary/logger.h"
#include "../controller/parameters.h"
#include "analyzers/base_analyzer.h"
#include "analyzers/breakdown_analyzer.h"
#include "analyzers/ofdws_analyzer.h"
#include "analyzers/ofws_analyzer.h"
#include "analyzers/print_analyzer.h"
#include "plugin.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Logger;
using NST::analyzer::analyzers::BaseAnalyzer;
using NST::controller::AParams;
using NST::controller::Parameters;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class Analyzers
{
    typedef std::vector<PluginInstance*> Plugins;
    typedef std::vector<BaseAnalyzer*> BuiltIns;
    typedef std::vector<BaseAnalyzer*> Storage;
public:
    Analyzers(const Parameters& params)
    {
        std::vector<AParams> requested_analyzers = params.analyzers();

        for(unsigned int i = 0; i < requested_analyzers.size(); ++i)
        {
            const AParams& r = requested_analyzers[i];

            if(r.path == "ob")
            {
                builtin.push_back(new analyzers::BreakdownAnalyzer(std::cout /*r.arguments*/));
                analyzers.push_back(builtin.back());
                continue;
            }
            if(r.path == "ofws")
            {
                builtin.push_back(new analyzers::OFWSAnalyzer(std::cout /*r.arguments*/));
                analyzers.push_back(builtin.back());
                continue;
            }
            if(r.path == "ofdws")
            {
                builtin.push_back(new analyzers::OFDWSAnalyzer(std::cout, params.block_size(), params.bucket_size() /*r.arguments*/));
                analyzers.push_back(builtin.back());
                continue;
            }

            Logger::Buffer message;
            try // try to load plugin
            {
                message << "Loading module: '" << r.path << "' with args: [" << r.arguments << "]";
                plugins.push_back(new PluginInstance(r.path, r.arguments));
                analyzers.push_back(*plugins.back());
            }
            catch(Exception& e)
            {
                message << " failed with: " << e.what();
            }
        }

        if(params.is_verbose()) // add special analyzer for trace out RPC calls
        {
            builtin.push_back(new analyzers::PrintAnalyzer(std::cout));
            analyzers.push_back(builtin.back());
        }
    }

    ~Analyzers()
    {
        {   // delete built-in analyzers
            BuiltIns::iterator i = builtin.begin();
            BuiltIns::iterator end = builtin.end();
            for(; i != end; ++i)
                delete *i;
        }

        {   // delete plugin analyzers
            Plugins::iterator i = plugins.begin();
            Plugins::iterator end = plugins.end();
            for(; i != end; ++i)
                delete *i;
        }
    }

    template
    <
        typename Handle,
        typename Procedure
    >
    void operator()(Handle handle, const Procedure& proc)
    {
        const typename Procedure::Arg*const arg = &(proc.arg);
        const typename Procedure::Res*const res = &(proc.res);

        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            ((*i)->*handle)(&proc, arg, res);
        }
    }

    void flush_statistics()
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->flush_statistics();
        }
    }

private:
    Storage  analyzers;
    Plugins  plugins;
    BuiltIns builtin;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
