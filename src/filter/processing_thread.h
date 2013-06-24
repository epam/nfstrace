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

/*
 * Manage whole process for reading and processing data from interfaces.
 */
template<typename Reader, typename Processor>
class ProcessingThread : public Thread
{
public:
    ProcessingThread(Reader* r, Processor* p, RunningStatus &s) : reader(r), proc(p), status(s)
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
        reader->break_loop();
    }

private:
    Reader* reader;
    Processor* proc;
    RunningStatus& status;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif //PROCESSING_THREAD_H
//------------------------------------------------------------------------------
