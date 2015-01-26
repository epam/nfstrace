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
