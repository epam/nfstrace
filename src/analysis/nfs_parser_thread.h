//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of the NFS Data.
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
#ifndef NFS_PARSER_THREAD_H
#define NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
#include <atomic>
#include <thread>

#include "analysis/analyzers.h"
#include "analysis/rpc_sessions.h"
#include "controller/running_status.h"
#include "protocols/nfs/nfs_procedure.h"
#include "utils/filtered_data.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class NFSParserThread
{
    using NFS40CompoundType = NST::protocols::NFS4::NFSPROC4RPCGEN_COMPOUND;
    using NFS41CompoundType = NST::protocols::NFS41::NFSPROC41RPCGEN_COMPOUND;
    using RunningStatus     = NST::controller::RunningStatus;
    using FilteredDataQueue = NST::utils::FilteredDataQueue;
public:
    NFSParserThread(FilteredDataQueue& q, Analyzers& a, RunningStatus& rs);
    ~NFSParserThread();

    void start();
    void stop();

private:
    inline void thread();
    inline void process_queue();

    void parse_data(FilteredDataQueue::Ptr&& data);
    void analyze_nfs_procedure(FilteredDataQueue::Ptr&& call,
                               FilteredDataQueue::Ptr&& reply,
                               RPCSession* session);

    //! Common internal function for parsing NFSv4.x's COMPOUND procedure
    //! It's supposed to be used inside analyze_nfs_procedure only
    template
    <
        typename ArgopType,
        typename ResopType,
        typename NFS4CompoundType
    >
    void analyze_nfs4_operations(NFS4CompoundType& nfs4_compound_procedure);

    inline void analyze_nfs40_operations(NFS40CompoundType& nfs40_compound_procedure)
    {
        analyze_nfs4_operations<NST::API::NFS4::nfs_argop4,
                                NST::API::NFS4::nfs_resop4,
                                NFS40CompoundType>(nfs40_compound_procedure);
    }

    inline void analyze_nfs41_operations(NFS41CompoundType& nfs41_compound_procedure)
    {
        analyze_nfs4_operations<NST::API::NFS41::nfs_argop4,
                                NST::API::NFS41::nfs_resop4,
                                NFS41CompoundType>(nfs41_compound_procedure);
    }

    //! Internal function for proper passing NFSv4.0's operations to analyzers
    //! It's supposed to be used inside analyze_nfs4_operations only
    void nfs4_ops_switch(const RPCProcedure* rpc_procedure,
                         const NST::API::NFS4::nfs_argop4* arg,
                         const NST::API::NFS4::nfs_resop4* res);

    //! Internal function for proper passing NFSv4.1's operations to analyzers
    //! It's supposed to be used inside analyze_nfs4_operations only
    void nfs4_ops_switch(const RPCProcedure* rpc_procedure,
                         const NST::API::NFS41::nfs_argop4* arg,
                         const NST::API::NFS41::nfs_resop4* res);

    RunningStatus& status;
    Analyzers& analyzers;
    FilteredDataQueue& queue;
    RPCSessions sessions;

    std::thread parsing;
    std::atomic_flag running;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
