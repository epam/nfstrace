//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside analyzer module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYSIS_MANAGER_H
#define ANALYSIS_MANAGER_H
//------------------------------------------------------------------------------
#include <memory> // std::auto_ptr

#include "../auxiliary/filtered_data.h"
#include "../auxiliary/exception.h"
#include "../auxiliary/thread.h"
#include "../controller/parameters.h"
#include "../controller/running_status.h"
#include "analyzers.h"
#include "analyzers/breakdown_analyzer.h"
#include "analyzers/print_analyzer.h"
#include "nfs_parser_thread.h"
//------------------------------------------------------------------------------
using namespace NST::analyzer::analyzers;

using NST::auxiliary::FilteredData;
using NST::auxiliary::FilteredDataQueue;
using NST::auxiliary::Exception;
using NST::auxiliary::Thread;
using NST::controller::Parameters;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class AnalysisManager
{
public:
    AnalysisManager(RunningStatus& running_status) : parser_thread(NULL), queue(NULL), status(running_status)
    {
    }
    ~AnalysisManager()
    {
    }

    FilteredDataQueue& init(const Parameters& params)
    {
        uint32_t q_capacity = params.queue_capacity();
        uint32_t q_size = 64;
        uint32_t q_limit= 1;
        if(q_capacity < q_size)
        {
            q_size  = q_capacity;
        }
        else
        {
            q_limit = 1 + q_capacity / q_size;
        }
        
        queue.reset(new FilteredDataQueue(q_size, q_limit));
        parser_thread.reset(new NFSParserThread(*queue, analyzers, status));

        if(params.is_verbose()) // add special analyzer for trace out RPC calls
        {
            analyzers.add(new PrintAnalyzer(std::clog));

        }

        std::vector<std::string> active_analyzers = params.analyzers();
        for(unsigned int i = 0; i < active_analyzers.size(); ++i)
        {
            if(active_analyzers[i] == std::string("ob"))
                breakdown_analyzer();
        }

        return *queue;
    }

    void breakdown_analyzer()
    {
        analyzers.add(new BreakdownAnalyzer());
    }

    void start()
    {
        if(parser_thread.get())
        {
            parser_thread->create();
        }
    }

    void stop()
    {
        if(parser_thread.get())
        {
            parser_thread->stop();
        }
        analyzers.print(std::cout);
    }

private:
    AnalysisManager(const AnalysisManager& object);            // Uncopyable object
    AnalysisManager& operator=(const AnalysisManager& object); // Uncopyable object

    std::auto_ptr<Thread> parser_thread;
    std::auto_ptr<FilteredDataQueue> queue;
    RunningStatus& status;
    Analyzers analyzers;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYSIS_MANAGER_H
//------------------------------------------------------------------------------
