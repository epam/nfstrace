//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manage entire filtration processes.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PROCESSING_THREAD_H
#define PROCESSING_THREAD_H
//------------------------------------------------------------------------------
#include <thread>

#include "controller/running_status.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

class ProcessingThread
{
protected:
    ProcessingThread(NST::controller::RunningStatus& s)
    : status     (s)
    , processing {}
    {
    }
public:
    virtual ~ProcessingThread()
    {
        if(processing.joinable())
        {
            processing.join();
        }
    }

    void start()
    {
        if(processing.joinable()) return;   // already started

        processing = std::thread(&ProcessingThread::thread, this);
    }

    virtual void stop()= 0;

private:
    virtual void run() = 0;

    inline void thread()
    {
        try
        {
            this->run();    // virtual call
        }
        catch(...)
        {
            status.push_current_exception();
        }
    }

    NST::controller::RunningStatus& status;
    std::thread processing;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif //PROCESSING_THREAD_H
//------------------------------------------------------------------------------
