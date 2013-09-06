//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manager for all instances created inside analyzer module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <string>

#include "analysis_manager.h"
#include "analyzers/breakdown_analyzer.h"
#include "analyzers/ofdws_analyzer.h"
#include "analyzers/ofws_analyzer.h"
#include "analyzers/print_analyzer.h"
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
    {
        q_size  = q_capacity;
    }
    else
    {
        q_limit = 1 + q_capacity / q_size;
    }

    queue.reset(new FilteredDataQueue(q_size, q_limit));
    parser_thread.reset(new NFSParserThread(*queue, analyzers, status));

    populate_analyzers(params);

    return *queue;
}

void AnalysisManager::start()
{
    if(parser_thread.get())
    {
        parser_thread->create();
    }
}

void AnalysisManager::stop()
{
    if(parser_thread.get())
    {
        parser_thread->stop();
    }
    analyzers.print(std::cout);
}

void AnalysisManager::populate_analyzers(const Parameters& params)
{
    std::vector<AParams> active_analyzers = params.analyzers();
    for(unsigned int i = 0; i < active_analyzers.size(); ++i)
    {
        if(active_analyzers[i].path == std::string("ob"))
        {
            analyzers.add(new analyzers::BreakdownAnalyzer());
            continue;
        }
        if(active_analyzers[i].path == std::string("ofws"))
        {
            analyzers.add(new analyzers::OFWSAnalyzer());
            continue;
        }
        if(active_analyzers[i].path == std::string("ofdws"))
        {
            analyzers.add(new analyzers::OFDWSAnalyzer(params.block_size(), params.bucket_size()));
            continue;
        }
        // TODO: load from shared object by path and provide arguments
    }

    if(params.is_verbose()) // add special analyzer for trace out RPC calls
    {
        analyzers.add(new analyzers::PrintAnalyzer(std::clog));
    }
}

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
