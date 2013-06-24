//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Manager for all instances created inside analyzer module.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef ANALYSE_MANAGER_H
#define ANALYSE_MANAGER_H
//------------------------------------------------------------------------------
#include <memory> // std::auto_ptr

#include "../controller/running_status.h"
#include "../auxiliary/exception.h"
#include "../auxiliary/thread.h"
#include "../auxiliary/queue.h"
#include "print_analyzer.h"
#include "analyzers.h"
#include "nfs_data.h"
//------------------------------------------------------------------------------
using NST::controller::RunningStatus;
using NST::auxiliary::Exception;
using NST::auxiliary::Thread;
using NST::auxiliary::Queue;
//------------------------------------------------------------------------------
namespace NST
{
namespace analyzer
{

class AnalyseManager : public Thread
{
    typedef Queue<NFSData> Buffer;
public:
    AnalyseManager(RunningStatus &running_status, uint32_t queue_size = 256, uint32_t queue_limit = 16) : status(running_status), exec(false), queue(queue_size, queue_limit)
    {
    }
    ~AnalyseManager()
    {
    }

    void print_analyzer()
    {
        std::auto_ptr<BaseAnalyzer> a(new PrintAnalyzer);
        analyzers.add(a.release());
    }

    void* run()
    {
        // Allow processing data contained in the queue
        exec = true;

        try
        {
            process();
        }
        catch(std::exception& exception)
        {
            status.push(exception);
        }
        return NULL;
    }

    void stop()
    {
        exec = false;   // Deny processing data
        join();
    }
    
    Buffer& get_queue()
    {
        return queue;
    }

private:
    AnalyseManager(const AnalyseManager& object);            // Uncopyable object
    AnalyseManager& operator=(const AnalyseManager& object); // Uncopyable object

    inline void process()
    {
        while(exec)
        {
            Buffer::List list = queue.pop_list();

            // Read all data from the received queue
            while(list)
            {
                const NFSData& data = list.data();

                analyzers.process(data);
                list.free_current();
            }
        }
    }

private:
    RunningStatus& status;
    Analyzers analyzers;
    volatile bool exec;
    Buffer queue;
};

} // namespace analyzer
} // namespace NST
//------------------------------------------------------------------------------
#endif//ANALYSE_MANAGER_H
//------------------------------------------------------------------------------
