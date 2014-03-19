//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage for Analyzers, load plugins and processing
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <memory>
#include <vector>

#include "analysis/ianalyzer.h"
#include "analysis/plugin.h"
#include "controller/parameters.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class Analyzers
{
    using Storage = std::vector<IAnalyzer*>;
    using Plugins = std::vector< std::unique_ptr<PluginInstance> >;
    using BuiltIns= std::vector< std::unique_ptr<IAnalyzer> >;

public:
    Analyzers(const controller::Parameters& params);
    Analyzers(const Analyzers&)            = delete;
    Analyzers& operator=(const Analyzers&) = delete;

    template
    <
        typename Handle,
        typename Procedure
    >
    inline void operator()(Handle handle, const Procedure& proc)
    {
        for(const auto a : modules)
        {
            (a->*handle)(&proc, proc.parg, proc.pres);
        }
    }

    inline void flush_statistics()
    {
        for(const auto a : modules)
        {
            a->flush_statistics();
        }
    }

private:
    Storage  modules; // pointers to all modules (plugins and builtins)
    Plugins  plugins;
    BuiltIns builtin;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
