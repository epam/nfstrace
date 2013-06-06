//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Container for thread objects.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef TREAD_GROUP_H
#define TREAD_GROUP_H
//------------------------------------------------------------------------------
#include <list>

#include "thread.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
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
        for_each(threads.begin(), threads.end(), destroy_thread);
    }

    void start()
    {
        std::for_each(threads.begin(), threads.end(), start_thread);
    }

    void stop()
    {
        std::for_each(threads.begin(), threads.end(), stop_thread);
    }

    void add(Thread *thread)
    {
        threads.push_back(thread);
    }

private:
    static void destroy_thread(Thread *thread)
    {
        delete thread;
    }

    static void stop_thread(Thread* thread)
    {
        thread->stop();
    }

    static void start_thread(Thread* thread)
    {
        thread->create();
    }
private:
    std::list<Thread*> threads;
};

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//TREAD_GROUP_H
//------------------------------------------------------------------------------
