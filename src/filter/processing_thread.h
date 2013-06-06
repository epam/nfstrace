//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manage eniter processing process.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef PROCESSING_THREAD_H
#define PROCESSING_THREAD_H
//------------------------------------------------------------------------------
#include "../auxiliary/thread.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Thread;
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
    ProcessingThread(Reader* r, Processor* p) : reader(r), proc(p)
    {
    }
    ~ProcessingThread()
    {
        delete reader;
        delete proc;
    }

    virtual void run()
    {
        reader->loop(*proc);
    }

    virtual void stop()
    {
        reader->break_loop();
    }

private:
    Reader* reader;
    Processor* proc;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif //PROCESSING_THREAD_H
//------------------------------------------------------------------------------
