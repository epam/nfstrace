//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Java-like thread wrapper.
// Warning:     ThreadStd class is not thread-safe.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef THREAD_STD_H
#define THREAD_STD_H
//------------------------------------------------------------------------------
#include <pthread.h>
#include <signal.h>

#include "exception.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

template<typename Runnable>
class ThreadStd
{
public:
    ThreadStd(const Runnable& runnable) throw(Exception)
    {
        if(pthread_create(&thread, NULL, Runnable::run, (void*)runnable.get_runarg()))
            throw Exception("ThreadStd cannot be created");
    }

    ~ThreadStd()
    {
        // What behaviour is more predictable? thread_cancell or thread_join???
        join();
    }

    bool join(void* retval = NULL)
    {
        /*
         * ERRORS:
         *    EDEADLK - A deadlock was detected (e.g., two threads tried to join with each other); or thread specifies the calling thread.
         *    EINVAL  - Another thread is already waiting to join with this thread.
         *    EINVAL  - Thread is not a joinable thread. Cannot be truth for current implementation.
         *    ESRCH   - No thread with the ID thread could be found.
         */
        return pthread_join(thread, &retval) == 0;
    }

    bool cancel()
    {
        /* ERRORS:
         *    ESRCH   - No thread with the ID thread could be found.
         */
        return pthread_cancel(thread) == 0;
    }

private:
    pthread_t thread;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//THREAD_STD_H
//------------------------------------------------------------------------------
