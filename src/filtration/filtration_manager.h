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

#include "utils/filtered_data.h"
#include "controller/parameters.h"
#include "controller/running_status.h"
#include "filtration/processing_thread.h"
//------------------------------------------------------------------------------
using NST::utils::FilteredDataQueue;
using NST::controller::Parameters;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

class FiltrationManager
{
public:
    FiltrationManager(RunningStatus& s, const Parameters& params);                              // dump to file
    FiltrationManager(RunningStatus& s, FilteredDataQueue& queue, const Parameters& params);    // capture to queue
    FiltrationManager(RunningStatus& s, FilteredDataQueue& queue, const std::string& ifile);    // read file to queue
    ~FiltrationManager();

    void start();
    void stop();

private:
    FiltrationManager(const FiltrationManager&)            = delete;
    FiltrationManager& operator=(const FiltrationManager&) = delete;

    RunningStatus& status;

    std::vector< std::unique_ptr<ProcessingThread> > threads;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
