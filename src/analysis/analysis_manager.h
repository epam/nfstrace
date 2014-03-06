//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside analysis module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYSIS_MANAGER_H
#define ANALYSIS_MANAGER_H
//------------------------------------------------------------------------------
#include <memory>

#include "analysis/analyzers.h"
#include "analysis/nfs_parser_thread.h"
#include "controller/parameters.h"
#include "controller/running_status.h"
#include "utils/filtered_data.h"
//------------------------------------------------------------------------------
using NST::controller::Parameters;
using NST::controller::RunningStatus;
using NST::utils::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

class AnalysisManager
{
public:
    AnalysisManager(RunningStatus& status, const Parameters& params);
    AnalysisManager(const AnalysisManager&)            = delete;
    AnalysisManager& operator=(const AnalysisManager&) = delete;
    ~AnalysisManager() = default;

    FilteredDataQueue& get_queue() { return *queue; }

    void start();
    void stop();

private:
    std::unique_ptr<Analyzers> analysiss;
    std::unique_ptr<FilteredDataQueue> queue;
    std::unique_ptr<NFSParserThread> parser_thread;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYSIS_MANAGER_H
//------------------------------------------------------------------------------
