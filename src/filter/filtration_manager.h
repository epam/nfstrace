//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside filter module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FILTRATION_MANAGER_H
#define FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
#include "../auxiliary/filtered_data.h"
#include "../auxiliary/thread_group.h"
#include "../controller/parameters.h"
#include "../controller/running_status.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredDataQueue;
using NST::auxiliary::ThreadGroup;
using NST::controller::Parameters;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
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
    FiltrationManager(const FiltrationManager&);            // undefined
    FiltrationManager& operator=(const FiltrationManager&); // undefined

    ThreadGroup threads;
    RunningStatus& status;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTRATION_MANAGER_H
//------------------------------------------------------------------------------
