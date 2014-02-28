//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage for populating Analyzers
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <memory>
#include <vector>

#include "controller/parameters.h"
#include "analysis/ianalyzer.h"
#include "analysis/plugin.h"
//------------------------------------------------------------------------------
using NST::controller::Parameters;
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
    Analyzers(const Parameters& params);
    Analyzers(const Analyzers&)            = delete;
    Analyzers& operator=(const Analyzers&) = delete;

    template
    <
        typename Handle,
        typename Procedure
    >
    inline void operator()(Handle handle, const Procedure& proc)
    {
        const auto*const arg = &(proc.arg);
        const auto*const res = &(proc.res);

        for(const auto a : analysiss)
        {
            (a->*handle)(&proc, arg, res);
        }
    }

    inline void flush_statistics()
    {
        for(const auto a : analysiss)
        {
            a->flush_statistics();
        }
    }

private:
    Storage  analysiss;
    Plugins  plugins;
    BuiltIns builtin;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
