//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside filter module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYSE_MANAGER_H
#define ANALYSE_MANAGER_H
//------------------------------------------------------------------------------
#include <memory> // std::auto_ptr

#include "../controller/running_status.h"
#include "../auxiliary/thread.h"
#include "../auxiliary/queue.h"
//------------------------------------------------------------------------------
using NST::controller::RunningStatus;
using NST::auxiliary::Thread;
using NST::auxiliary::Queue;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class AnalyseManager
{
    // OnlineAnalyzingThread and OfflineAnalyzingThread typedefs will be added later.
public:
    AnalyseManager(RunningStatus &running_status, Queue &q) : excpts_holder(running_status), queue(q)
    {
    }
    ~AnalyseManager()
    {
        thread_group.stop();
    }

    // STUB
    void status_analyzer()
    {
        // Creating real status_analyzer and r
    }

    void start()
    {
        thread_group.start();
    }

    void stop()
    {
        thread_group.stop();
    }

private:
    AnalyseManager(const AnalyseManager& object); // Uncopyable object
    AnalyseManager& operator=(const AnalyseManager& object); // Uncopyable object

private:
    RunningStatus &excpts_holder;
    Queue &queue;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYSE_MANAGER_H
//------------------------------------------------------------------------------
