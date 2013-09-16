//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manager for all instances created inside analyzer module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <string>

#include "analysis_manager.h"
#include "nfs_parser_thread.h"
//------------------------------------------------------------------------------
using NST::controller::AParams;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

AnalysisManager::AnalysisManager(RunningStatus& running_status)
                                 : queue(NULL)
                                 , parser_thread(NULL)
                                 , status(running_status)
                                 , analyzers(NULL)
{
}

AnalysisManager::~AnalysisManager()
{
}

FilteredDataQueue& AnalysisManager::init(const Parameters& params)
{
    uint32_t q_capacity = params.queue_capacity();
    uint32_t q_size = 64;
    uint32_t q_limit= 1;
    if(q_capacity <= q_size)
        q_size  = q_capacity;
    else
        q_limit = 1 + q_capacity / q_size;

    queue.reset(new FilteredDataQueue(q_size, q_limit));

    analyzers = new Analyzers(params);
    parser_thread.reset(new NFSParserThread(*queue, *analyzers, status));

    return *queue;
}

void AnalysisManager::start()
{
    if(parser_thread.get())
        parser_thread->create();
}

void AnalysisManager::stop()
{
    if(parser_thread.get())
        parser_thread->stop();
//    analyzers.print(std::cout);
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
