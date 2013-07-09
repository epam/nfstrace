//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Wrapper arround thread.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef THREAD_H
#define THREAD_H
//------------------------------------------------------------------------------
#include <pthread.h>
#include <signal.h>
#include <iostream>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class Thread
{
public:
    Thread(bool detached = false) : thread(0), is_detached(detached)
    {
    }
    virtual ~Thread()
    {
        if((thread != 0) && (!is_detached))
        {
            join();
        }
    }

    static void* thread_function(void* usr_data)
    {
        return ((Thread *)(usr_data))->run();
    }

    bool create()
    {   
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        if(is_detached)
        {
            pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        }
        int ret = pthread_create(&thread, &attr, thread_function, (void*)this);
        pthread_attr_destroy(&attr);
        return ret == 0;
    }

    void* join()
    {
        void* retval = NULL;
        pthread_join(thread, &retval);
        return retval;
    }

    virtual void* run() = 0;
    virtual void stop() = 0;

private:
    pthread_t thread;
    bool is_detached;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//THREAD_H
//------------------------------------------------------------------------------
