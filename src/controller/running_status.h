//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Container for storing threads' exceptions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef RUNNING_STATUS_H
#define RUNNING_STATUS_H
//------------------------------------------------------------------------------
#include <list>
#include <ostream>

#include "../auxiliary/conditional_variable.h"
#include "../auxiliary/exception.h"
//------------------------------------------------------------------------------
using NST::auxiliary::ConditionalVariable;
using NST::auxiliary::Exception;
using NST::auxiliary::Mutex;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class RunningStatus
{
    typedef std::list<const Exception*> List;
public:
    RunningStatus()
    {
    }
    ~RunningStatus()
    {
        List::iterator i = fifo.begin();
        List::iterator end = fifo.end();
        for(; i != end; ++i)
        {
            delete *i;
        }
    }

    inline void push(const Exception& e)
    {
        push(e.dynamic_clone());
    }

    inline void push(const std::exception& e)
    {
        push(new Exception(e));
    }

    inline void push(const std::string& str)
    {
        push(new Exception(str));
    }

    const Exception* wait_exception() // return value must be deleted by client
    {
        Mutex::Lock lock(mutex);
            while(fifo.empty())
            {
                condition.wait(mutex);
            }
            const Exception* e = fifo.front();
            fifo.pop_front();
            return e;
    }

    void wait_and_rethrow_exception()
    {
        std::auto_ptr<const Exception> e(wait_exception());
        e->dynamic_throw();
    }

    void print(std::ostream& out)
    {
        Mutex::Lock lock(mutex);
            if(!fifo.empty())
            {
                List::iterator i = fifo.begin();
                List::iterator end = fifo.end();
                out << "list of collected exceptions:" << std::endl;
                for(; i != end; ++i)
                {
                    out << '\t' << (*i)->what() << std::endl;
                }
            }
    }

private:
    RunningStatus(const RunningStatus&);            // undefined
    RunningStatus& operator=(const RunningStatus&); // undefined

    void push(const Exception* e)
    {
        Mutex::Lock lock(mutex);
            fifo.push_back(e);
            condition.signal();
    }

    List fifo;
    Mutex mutex; // Used for condition, show that 
    ConditionalVariable condition;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif //RUNNING_STATUS_H
//------------------------------------------------------------------------------
