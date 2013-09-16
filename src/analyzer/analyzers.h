//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Analyzers storage. 
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <vector>

#include "../auxiliary/logger.h"
#include "../controller/parameters.h"
#include "analyzers/base_analyzer_struct.h"
//#include "analyzers/breakdown_analyzer.h"
//#include "analyzers/ofdws_analyzer.h"
//#include "analyzers/ofws_analyzer.h"
#include "analyzers/print_analyzer.h"
#include "plugins.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Logger;
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
//    typedef std::vector<PluginInstance*> Plugins;
    typedef std::vector<BaseAnalyzer*> BuiltIns;
    typedef std::vector<BaseAnalyzer*> Storage;
public:
    Analyzers(const Parameters& params)
    {
        std::vector<AParams> requested_analyzers = params.analyzers();

        for(unsigned int i = 0; i < requested_analyzers.size(); ++i)
        {
            const AParams& r = requested_analyzers[i];
            std::cout << "path:" << r.path << " args: " << r.arguments << std::endl;
            
            
            Logger::Buffer message;
            try // try to load plugin
            {
                message << "Loading module: '" << r.path << "' with args: [" << r.arguments << "]";
                plugins.add(r.path, r.arguments);
            }
            catch(Exception& e)
            {
                message << " failed with: " << e.what();
            }
        }

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
    void process(Handle handle, const RPCProcedure* proc, const Args* args, const Res* res)
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
            ((*i)->*handle)(proc, args, res);
    }

private:
    Storage analyzers;
    Plugins plugins;
    Storage builtin;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
