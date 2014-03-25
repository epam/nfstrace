//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside filtration module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FILTRATION_MANAGER_H
#define FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
#include <memory>
#include <vector>

#include "controller/parameters.h"
#include "controller/running_status.h"
#include "filtration/processing_thread.h"
#include "utils/filtered_data.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

class FiltrationManager
{
    using Parameters        = NST::controller::Parameters;
    using RunningStatus     = NST::controller::RunningStatus;
    using FilteredDataQueue = NST::utils::FilteredDataQueue;

public:
    FiltrationManager(RunningStatus& s);
    ~FiltrationManager();
    FiltrationManager(const FiltrationManager&)            = delete;
    FiltrationManager& operator=(const FiltrationManager&) = delete;

    void add_online_dumping  (const Parameters& params);  // dump to file
    void add_online_analysis (const Parameters& params, FilteredDataQueue& queue);    // capture to queue
    void add_offline_analysis(const std::string& ifile, FilteredDataQueue& queue);    // read file to queue

    void start();
    void stop();

private:

    RunningStatus& status;

    std::vector< std::unique_ptr<ProcessingThread> > threads;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
