//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Manage entire filtration processes.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef PROCESSING_THREAD_H
#define PROCESSING_THREAD_H
//------------------------------------------------------------------------------
#include <thread>

#include "controller/running_status.h"
#include "utils/noncopyable.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
class ProcessingThread : utils::noncopyable
{
protected:
    ProcessingThread(NST::controller::RunningStatus& s)
        : status(s)
        , processing{}
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
        if(processing.joinable()) return; // already started

        processing = std::thread(&ProcessingThread::thread, this);
    }

    virtual void stop() = 0;

private:
    virtual void run() = 0;

    inline void thread()
    {
        try
        {
            this->run(); // virtual call
        }
        catch(...)
        {
            status.push_current_exception();
        }
    }

protected:
    NST::controller::RunningStatus& status;
    std::thread                     processing;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif // PROCESSING_THREAD_H
//------------------------------------------------------------------------------
