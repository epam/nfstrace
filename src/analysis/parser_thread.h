//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Parser of the NFS Data.
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
#ifndef NFS_PARSER_THREAD_H
#define NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
#include <atomic>
#include <thread>

#include "analysis/analyzers.h"
#include "controller/running_status.h"
#include "utils/filtered_data.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace analysis
{

template <typename Parser>
class ParserThread
{
    using RunningStatus     = NST::controller::RunningStatus;
    using FilteredDataQueue = NST::utils::FilteredDataQueue;
public:
    ParserThread(Parser p, FilteredDataQueue& q, RunningStatus& s)
    : status   (s)
    , queue    (q)
    , running  {ATOMIC_FLAG_INIT} // false
    , parser(p)
    {
    }

    ~ParserThread()
    {
        if (parsing.joinable()) stop();
    }

    void start()
    {
        if(running.test_and_set()) return;
        parsing = std::thread(&ParserThread::thread, this);
    }

    void stop()
    {
        running.clear();
        parsing.join();
    }


private:

    inline void thread()
    {
        try
        {
            while(running.test_and_set())
            {
                // process all available items from queue
                process_queue();

                // then sleep this thread
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
            process_queue(); // flush data from queue
        }
        catch(...)
        {
            status.push_current_exception();
        }
    }

    inline void process_queue()
    {
        while(true)
        {
            // take all items from the queue
            FilteredDataQueue::List list{queue};
            if(!list)
            {
                return; // list from queue is empty, break infinity loop
            }

            do
            {
                FilteredDataQueue::Ptr data = list.get_current();
                parser.parse_data(data);
            }
            while(list);
        }
    }

    RunningStatus& status;
    FilteredDataQueue& queue;

    std::thread parsing;
    std::atomic_flag running;
    Parser parser;
};

} // namespace analysis
} // namespace NST
//------------------------------------------------------------------------------
#endif//NFS_PARSER_THREAD_H
//------------------------------------------------------------------------------
