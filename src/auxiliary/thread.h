//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Wrapper arround thread.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef THREAD_H
#define THREAD_H
//------------------------------------------------------------------------------
#include <pthread.h>
//#include <unistd.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class Thread
{
public:
    Thread() : thread(0)
    {
    }
    virtual ~Thread()
    {
        if(thread)
        {
            pthread_join(thread, NULL);
        }
    }
    static void* thread_function(void* usr_data)
    {
        Thread& thread = *(Thread *)(usr_data);
        thread.run();
    }

    bool create() 
    {
        return pthread_create(&thread, NULL, thread_function, (void*)this) == 0;
    }
    virtual void run() = 0;
    virtual void stop() = 0;

private:
    pthread_t thread;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//THREAD_H
//------------------------------------------------------------------------------
