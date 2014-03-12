//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of the NFS Data.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PARSER_THREAD_H
#define NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
#include <atomic>
#include <thread>

#include "analysis/analyzers.h"
#include "analysis/rpc_sessions.h"
#include "controller/running_status.h"
#include "utils/filtered_data.h"
//------------------------------------------------------------------------------
using NST::utils::FilteredDataQueue;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class NFSParserThread
{
public:
    NFSParserThread(FilteredDataQueue& q, Analyzers& a, RunningStatus& rs);
    ~NFSParserThread();

    void start();
    void stop();

private:
    inline void thread();
    inline void process_queue();

    void parse_data(FilteredDataQueue::Ptr&& data);
    void analyze_nfs_operation(FilteredDataQueue::Ptr&& call,
                               FilteredDataQueue::Ptr&& reply,
                               RPCSession* session);

    RunningStatus& status;
    Analyzers& analysiss;
    FilteredDataQueue& queue;
    RPCSessions sessions;

    std::thread parsing;
    std::atomic_flag runing;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
