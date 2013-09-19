//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage for populating Analyzers
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <vector>

#include "../auxiliary/unique_ptr.h"
#include "../controller/parameters.h"
#include "analyzers/base_analyzer.h"
#include "plugin.h"
//------------------------------------------------------------------------------
using NST::auxiliary::UniquePtr;
using NST::analyzer::analyzers::BaseAnalyzer;
using NST::controller::Parameters;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class Analyzers
{
    typedef std::vector<BaseAnalyzer*>               Storage;
    typedef std::vector< UniquePtr<PluginInstance> > Plugins;
    typedef std::vector< UniquePtr<BaseAnalyzer> >   BuiltIns;

public:
    Analyzers(const Parameters& params);

    template
    <
        typename Handle,
        typename Procedure
    >
    inline void operator()(Handle handle, const Procedure& proc)
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

    inline void flush_statistics()
    {
        Storage::iterator i = analyzers.begin();
        Storage::iterator end = analyzers.end();
        for(; i != end; ++i)
        {
            (*i)->flush_statistics();
        }
    }

private:
    Analyzers(const Analyzers&);            // undefiend
    Analyzers& operator=(const Analyzers&); // undefiend

    Storage  analyzers;
    Plugins  plugins;
    BuiltIns builtin;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYZERS_H
//------------------------------------------------------------------------------
