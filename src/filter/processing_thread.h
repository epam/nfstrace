//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manage entire filtration processes.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PROCESSING_THREAD_H
#define PROCESSING_THREAD_H
//------------------------------------------------------------------------------
#include "../auxiliary/exception.h"
#include "../auxiliary/thread.h"
#include "../controller/running_status.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Exception;
using NST::auxiliary::Thread;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

template<typename Processor>
class ProcessingThread : public Thread
{
public:
    ProcessingThread(std::auto_ptr<Processor>& p, RunningStatus &s) : processor(p), status(s)
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
        catch(Exception& e)
        {
            status.push(e);
        }
        catch(std::exception& e)
        {
            status.push(e);
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

    std::auto_ptr<Processor> processor;
    RunningStatus& status;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif //PROCESSING_THREAD_H
//------------------------------------------------------------------------------
