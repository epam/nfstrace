//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Container for thread objects.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef TREAD_GROUP_H
#define TREAD_GROUP_H
//------------------------------------------------------------------------------
#include <list>
#include <iostream>

#include "thread.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class ThreadGroup
{    
    typedef std::list<Thread*> list;

public:
    ThreadGroup()
    {
    }
    ~ThreadGroup()
    {
        stop(); // Additional checking before cleaning table
        list::iterator i_beg = threads.begin();
        list::iterator i_end = threads.end();
        for(;i_beg != i_end; ++i_beg)
        {
            delete *i_beg;
        }
    }

    void start()
    {
        list::iterator i_beg = threads.begin();
        list::iterator i_end = threads.end();
        for(;i_beg != i_end; ++i_beg)
        {
            (*i_beg)->create();
        }
    }

    void stop()
    {
        list::iterator i_beg = threads.begin();
        list::iterator i_end = threads.end();
        for(;i_beg != i_end; ++i_beg)
        {
            (*i_beg)->stop();
        }
    }

    void add(Thread *thread)
    {
        threads.push_back(thread);
    }

private:
    list threads;
};

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//TREAD_GROUP_H
//------------------------------------------------------------------------------
