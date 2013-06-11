//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manage eniter processing process.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PROCESSING_THREAD_H
#define PROCESSING_THREAD_H
//------------------------------------------------------------------------------
#include "../auxiliary/thread.h"
#include "../controller/running_status.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Thread;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

/*
 * Manage whole process for reading and processing data from interfaces.
 */
template<typename Reader, typename Processor>
class ProcessingThread : public Thread
{
public:
    ProcessingThread(Reader* r, Processor* p, RunningStatus &running_status) : reader(r), proc(p), excpts_holder(running_status)
    {
    }
    ~ProcessingThread()
    {
        delete reader;
        delete proc;
    }

    virtual void* run()
    {   
        try
        {
            reader->loop(*proc);
        }
        catch(std::exception* exception)
        {
            excpts_holder.push(exception);
        }
        return NULL;
    }

    virtual void stop()
    {
        reader->break_loop();
    }

private:
    Reader* reader;
    Processor* proc;
    RunningStatus& excpts_holder;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif //PROCESSING_THREAD_H
//------------------------------------------------------------------------------
