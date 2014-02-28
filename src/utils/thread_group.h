//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Container for thread objects.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef TREAD_GROUP_H
#define TREAD_GROUP_H
//------------------------------------------------------------------------------
#include <list>

#include "utils/thread.h"
#include "utils/unique_ptr.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

class ThreadGroup
{
public:
    ThreadGroup()
    {
    }
    ~ThreadGroup()
    {
        stop(); // Additional checking before cleaning table
    }

    void start()
    {
        for(auto& t : threads)
        {
            t->create();
        }
    }

    void stop()
    {
        for(auto& t : threads)
        {
            t->stop();
        }
    }

    void add(UniquePtr<Thread>& thread)
    {
        threads.push_back(thread);
    }

private:
    std::list< UniquePtr<Thread> > threads;
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//TREAD_GROUP_H
//------------------------------------------------------------------------------
