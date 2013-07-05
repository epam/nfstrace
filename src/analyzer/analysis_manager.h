//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside analyzer module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYSE_MANAGER_H
#define ANALYSE_MANAGER_H
//------------------------------------------------------------------------------
#include <memory> // std::auto_ptr

#include "../auxiliary/filtered_data.h"
#include "../auxiliary/exception.h"
#include "../auxiliary/thread.h"
#include "../controller/running_status.h"
#include "analyzers.h"
#include "nfs_parser_thread.h"
#include "print_analyzer.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredData;
using NST::auxiliary::FilteredDataQueue;
using NST::auxiliary::Exception;
using NST::auxiliary::Thread;
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

    FilteredDataQueue& init(bool verbose, uint32_t q_size = 256, uint32_t q_limit = 16)
    {
        queue.reset(new FilteredDataQueue(q_size, q_limit));
        parser_thread.reset(new NFSParserThread(*queue, analyzers, status));

        if(verbose) // add special analyzer for trace out RPC calls
        {
            std::auto_ptr<BaseAnalyzer> a(new PrintAnalyzer(std::clog));
            analyzers.add(a.release());
        }

        return *queue;
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
#endif//ANALYSE_MANAGER_H
//------------------------------------------------------------------------------
