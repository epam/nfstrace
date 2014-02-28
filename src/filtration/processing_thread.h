//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manage entire filtration processes.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PROCESSING_THREAD_H
#define PROCESSING_THREAD_H
//------------------------------------------------------------------------------
#include <stdexcept>

#include "utils/thread.h"
#include "utils/unique_ptr.h"
#include "controller/running_status.h"
//------------------------------------------------------------------------------
using NST::utils::Thread;
using NST::utils::UniquePtr;
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
    ProcessingThread(UniquePtr<Processor>& p, RunningStatus &s) : processor(p), status(s)
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
    ProcessingThread(const ProcessingThread&);           // undefined
    ProcessingThread& operator=(const ProcessingThread&);// undefined

    UniquePtr<Processor> processor;
    RunningStatus& status;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif //PROCESSING_THREAD_H
//------------------------------------------------------------------------------
