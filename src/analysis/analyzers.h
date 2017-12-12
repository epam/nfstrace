//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Storage for Analyzers, load plugins and processing
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef ANALYZERS_H
#define ANALYZERS_H
//------------------------------------------------------------------------------
#include <memory>
#include <vector>

#include "analysis/plugin.h"
#include "api/plugin_api.h"
#include "controller/parameters.h"
#include "utils/noncopyable.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{
class Analyzers final : utils::noncopyable
{
    using Storage  = std::vector<IAnalyzer*>;
    using Plugins  = std::vector<std::unique_ptr<PluginInstance>>;
    using BuiltIns = std::vector<std::unique_ptr<IAnalyzer>>;

public:
    Analyzers(const controller::Parameters& params);

    //! This function is used for passing ALL possible procedures to analyzers
    template <
        typename Handle,
        typename Procedure>
    inline void operator()(Handle handle, const Procedure& proc)
    {
        for(const auto a : modules)
        {
            (a->*handle)(&proc, proc.parg, proc.pres);
        }
    }

    //! This function is used for passing args- or res-only NFS4.x operations (ex. NFSv4 ILLEGAL) to analyzers
    template <
        typename Handle,
        typename ArgOrResType>
    inline void operator()(Handle handle, const RPCProcedure* rpc, ArgOrResType* arg_or_res)
    {
        for(const auto a : modules)
        {
            (a->*handle)(rpc, arg_or_res);
        }
    }

    //! This function is used for passing args + res NFS4.x operations (ex. NFSv4.x ACCESS) to analyzers
    template <
        typename Handle,
        typename ArgopType,
        typename ResopType>
    inline void operator()(Handle handle, const RPCProcedure* rpc, ArgopType* arg, ResopType* res)
    {
        for(const auto a : modules)
        {
            (a->*handle)(rpc, arg, res);
        }
    }

    inline void flush_statistics()
    {
        for(const auto a : modules)
        {
            a->flush_statistics();
        }
    }

    inline void on_unix_signal(int signo)
    {
        for(const auto a : modules)
        {
            a->on_unix_signal(signo);
        }
    }
    inline bool isSilent()
    {
        return _silent;
    }

private:
    Storage  modules; // pointers to all modules (plugins and builtins)
    Plugins  plugins;
    BuiltIns builtin;
    bool     _silent;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif //ANALYZERS_H
//------------------------------------------------------------------------------
