//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Analyzers storage. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <vector>

#include "../controller/parameters.h"
#include "analyzers/base_analyzer_struct.h"
//#include "analyzers/breakdown_analyzer.h"
//#include "analyzers/ofdws_analyzer.h"
//#include "analyzers/ofws_analyzer.h"
#include "analyzers/print_analyzer.h"
#include "plugins.h"
//------------------------------------------------------------------------------
using NST::analyzer::analyzers::BaseAnalyzer;
using NST::analyzer::RPC::RPCProcedure;
using NST::controller::AParams;
using NST::controller::Parameters;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class Analyzers
{
    typedef std::vector<BaseAnalyzer*> Storage;
public:
    Analyzers(const Parameters& params)
    {
        if(params.is_verbose()) // add special analyzer for trace out RPC calls
            analyzers.push_back(new analyzers::PrintAnalyzer(std::clog));

    /*
        std::vector<AParams> active_analyzers = params.analyzers();
        for(uint32_t i = 0; i < active_analyzers.size(); ++i)
            plugins.add(active_analyzers[i].path, active_analyzers[i].arguments);

        Plugins::Iterator i = plugins.begin();
        Plugins::Iterator end = plugins.end();
        for(; i != end; ++i)
            analyzers.push_back((*i)->get_analyzer());
    */
    }
 
    ~Analyzers()
    {
        if(plugins.size() != analyzers.size())
            delete *analyzers.begin();
    }

    template
    <
        typename Handle,
        typename Args,
        typename Res
    >
    void process(Handle* handle, const RPCProcedure* proc, const Args* args, const Res* res)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
            ((*i)->*handle)(proc, args, res);
    }

private:
    Storage analyzers;
    Plugins plugins;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
