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
                                 : status(running_status)
                                 , analyzers(NULL)
                                 , queue(NULL)
                                 , parser_thread(NULL)
{
}

AnalysisManager::~AnalysisManager()
{
}

FilteredDataQueue& AnalysisManager::init(const Parameters& params)
{
    analyzers.reset(new Analyzers(params));

    queue.reset(new FilteredDataQueue(params.queue_capacity(), 1));

    parser_thread.reset(new NFSParserThread(*queue, *analyzers, status));

    return *queue;
}

void AnalysisManager::start()
{
    if(parser_thread)
    {
        parser_thread->create();
    }
}

void AnalysisManager::stop()
{
    if(parser_thread)
    {
        parser_thread->stop();
    }

    if(analyzers)
    {
        analyzers->flush_statistics();
    }
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
