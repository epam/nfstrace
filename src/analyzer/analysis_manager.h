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
#include "../auxiliary/thread.h"
#include "../controller/parameters.h"
#include "../controller/running_status.h"
#include "analyzers.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredDataQueue;
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
//    typedef std::list<Plugin> Plugins;
public:
    AnalysisManager(RunningStatus& running_status);
    ~AnalysisManager();

    FilteredDataQueue& init(const Parameters& params);

    void start();
    void stop();

private:

    void populate_analyzers(const Parameters& params);

    AnalysisManager(const AnalysisManager&);            // undefiend
    AnalysisManager& operator=(const AnalysisManager&); // undefiend

    std::auto_ptr<FilteredDataQueue> queue;
    std::auto_ptr<Thread> parser_thread;
    RunningStatus& status;
    Analyzers analyzers;
//    Plugins plugins;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYSIS_MANAGER_H
//------------------------------------------------------------------------------
