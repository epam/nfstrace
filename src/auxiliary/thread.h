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
        return NULL;
    }

    bool create()
    {
        /*
        sigset_t parent_mask, child_mask;
        sigfillset(&child_mask);
        pthread_sigmask(SIG_SETMASK, NULL, &parent_mask);   // Saving main thread mask
        pthread_sigmask(SIG_BLOCK, &child_mask, NULL);      // Apply new mask, all signals will be blocked
        */
        // Create child thread
        bool res = pthread_create(&thread, NULL, thread_function, (void*)this) == 0;

        //pthread_sigmask(SIG_SETMASK, &parent_mask, NULL);   // Restoring main thread mask
        return res;
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
