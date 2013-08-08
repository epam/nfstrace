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
    FiltrationManager(RunningStatus& s);
    ~FiltrationManager();

    void dump_to_file    (const Parameters& params);
    void capture_to_queue(FilteredDataQueue& queue, const Parameters& params);
    void read_to_queue   (FilteredDataQueue& queue, const Parameters& params);

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
