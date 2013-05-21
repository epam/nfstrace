//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Wrapper for mutex and lock guard based on RAII idiom.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef MUTEX_H
#define MUTEX_H
//------------------------------------------------------------------------------
#include <pthread.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class Mutex
{
public:
    Mutex()
    {
        pthread_mutex_init(&mutex, NULL);
    }
    ~Mutex()
    {
        pthread_mutex_destroy(&mutex);
    }

    class Lock
    {
    public:
        Lock(const Mutex& m):locked(m)
        {
            pthread_mutex_lock(&locked.mutex);
        }
        ~Lock()
        {
            pthread_mutex_unlock(&locked.mutex);
        }

        Lock(const Lock&);              // undefined
        Lock& operator=(const Lock&);   // undefined
    private:
        const Mutex& locked;
    };

    Mutex(const Mutex&);            // undefined
    Mutex& operator=(const Mutex&); // undefined

private:
    mutable pthread_mutex_t mutex;
};

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//MUTEX_H
//------------------------------------------------------------------------------
