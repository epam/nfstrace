//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manage entire filtration processes.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PROCESSING_THREAD_H
#define PROCESSING_THREAD_H
//------------------------------------------------------------------------------
#include <memory>
#include <stdexcept>

#include "utils/thread.h"
#include "controller/running_status.h"
//------------------------------------------------------------------------------
using NST::utils::Thread;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

template<typename Processor>
class ProcessingThread : public Thread
{
public:
    explicit ProcessingThread(std::unique_ptr<Processor>& p, RunningStatus& s)
    : processor {std::move(p)}
    , status    (s)
    {
    }
    ~ProcessingThread()
    {
    }

    virtual void* run()
    {
        try
        {
            processor->run();
        }
        catch(...)
        {
            status.push_current_exception();
        }
        return NULL;
    }

    virtual void stop()
    {
        processor->stop();
    }

private:
    ProcessingThread(const ProcessingThread&)            = delete;
    ProcessingThread& operator=(const ProcessingThread&) = delete;

    std::unique_ptr<Processor> processor;
    RunningStatus& status;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif //PROCESSING_THREAD_H
//------------------------------------------------------------------------------
