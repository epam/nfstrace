//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of the NFS Data.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef NFS_PARSER_THREAD_H
#define NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
#include "../auxiliary/filtered_data.h"
#include "../auxiliary/thread.h"
#include "../controller/running_status.h"
#include "analyzers.h"
#include "rpc_sessions.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredDataQueue;
using NST::auxiliary::Thread;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class NFSParserThread : public Thread
{
public:
    NFSParserThread(FilteredDataQueue& q, Analyzers& a, RunningStatus &rs);
    ~NFSParserThread();

    virtual void* run();
    virtual void stop();

private:
    inline void process_queue();

    class RPCOperation* parse_data(FilteredDataQueue::Ptr& data);

    RunningStatus& status;
    Analyzers& analyzers;
    FilteredDataQueue& queue;
    RPCSessions sessions;
    volatile bool exec;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
