//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside analyzer module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYSIS_MANAGER_H
#define ANALYSIS_MANAGER_H
//------------------------------------------------------------------------------
#include "../auxiliary/filtered_data.h"
#include "../auxiliary/thread.h"
#include "../auxiliary/unique_ptr.h"
#include "../controller/parameters.h"
#include "../controller/running_status.h"
#include "analyzers.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredDataQueue;
using NST::auxiliary::Thread;
using NST::auxiliary::UniquePtr;
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
    AnalysisManager(RunningStatus& running_status);
    ~AnalysisManager();

    FilteredDataQueue& init(const Parameters& params);

    void start();
    void stop();

private:
    AnalysisManager(const AnalysisManager&);            // undefiend
    AnalysisManager& operator=(const AnalysisManager&); // undefiend

    RunningStatus& status;
    UniquePtr<Analyzers> analyzers;
    UniquePtr<FilteredDataQueue> queue;
    UniquePtr<Thread> parser_thread;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYSIS_MANAGER_H
//------------------------------------------------------------------------------
