//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Container for storing threads' exceptions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RUNNING_STATUS_H
#define RUNNING_STATUS_H
//------------------------------------------------------------------------------
#include <exception>
#include <list>
#include <ostream> // for std::endl;

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

        List::iterator i = fifo.begin();
        List::iterator end = fifo.end();
        for(; i != end; ++i)
        {
            delete *i;
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
        if(!fifo.empty())
        {
            List::iterator i = fifo.begin();
            List::iterator end = fifo.end();
            out << "list of caught exceptions:" << std::endl;
            for(; i != end; ++i)
            {
                out << '\t' << (*i)->what() << std::endl;
            }
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
