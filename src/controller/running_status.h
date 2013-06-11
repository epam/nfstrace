//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Thread protected container for exceptions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RUNNING_STATUS_H
#define RUNNING_STATUS_H
//------------------------------------------------------------------------------
#include <exception>
#include <list>

#include <pthread.h>

#include "../auxiliary/conditional_variable.h"
//------------------------------------------------------------------------------
using NST::auxiliary::ConditionalVariable;
using NST::auxiliary::Mutex;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class RunningStatus
{
    typedef std::list<std::exception* /*, Allocator*/> List;
public:
    RunningStatus()
    {
    }
    ~RunningStatus()
    {
        Mutex::Lock lock(mutex);

        List::iterator i_beg = fifo.begin();
        List::iterator i_end = fifo.end();
        for(; i_beg != i_end; ++i_beg)
        {
            delete *i_beg;
        }
    }

    void push(std::exception* exception)
    {
        Mutex::Lock lock(mutex);
        fifo.push_back(exception);
        condition.signal();
    }

    std::exception* pop_wait()
    {
        Mutex::Lock lock(mutex);
        while(fifo.empty())
        {
            condition.wait(mutex);
        }
        std::exception* e = fifo.front();
        fifo.pop_front();    
        return e;
    }
    
    void print(std::ostream& out)
    {
        Mutex::Lock lock(mutex);

        List::iterator i_beg = fifo.begin();
        List::iterator i_end = fifo.end();
        for(; i_beg != i_end; ++i_beg)
        {
            out << (*i_beg)->what() << std::endl;
        }
    }

private:
    RunningStatus(const RunningStatus&); //Unrealized
    RunningStatus& operator=(const RunningStatus&); //Unrealized

private:
    List fifo;
    Mutex mutex; // Used for condition, show that 
    ConditionalVariable condition;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //RUNNING_STATUS_H
//------------------------------------------------------------------------------
