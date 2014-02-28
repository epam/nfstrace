//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manager for all instances created inside analysis module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include "analysis/analysis_manager.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

AnalysisManager::AnalysisManager(RunningStatus& status, const Parameters& params)
                                 : analysiss{nullptr}
                                 , queue{nullptr}
                                 , parser_thread{nullptr}
{
    analysiss.reset(new Analyzers(params));

    queue.reset(new FilteredDataQueue(params.queue_capacity(), 1));

    parser_thread.reset(new NFSParserThread(*queue, *analysiss, status));
}

void AnalysisManager::start()
{
    parser_thread->start();
}

void AnalysisManager::stop()
{
    parser_thread->stop();

    analysiss->flush_statistics();
}

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
