//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Wrapper for spinlock and lock guard based on RAII idiom.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SPINLOCK_H
#define SPINLOCK_H
//------------------------------------------------------------------------------
#include <pthread.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

class Spinlock
{
public:
    Spinlock()
    {
        pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE);
    }
    ~Spinlock()
    {
        pthread_spin_destroy(&spinlock);
    }

    class Lock
    {
    public:
        Lock(const Spinlock& m) : locked(m)
        {
            pthread_spin_lock(&locked.spinlock);
        }
        ~Lock()
        {
            pthread_spin_unlock(&locked.spinlock);
        }

        Lock(const Lock&);              // undefined
        Lock& operator=(const Lock&);   // undefined
    private:
        const Spinlock& locked;
    };

    Spinlock(const Spinlock&);            // undefined
    Spinlock& operator=(const Spinlock&); // undefined

private:
    mutable pthread_spinlock_t spinlock;
};

} // auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//SPINLOCK_H
//------------------------------------------------------------------------------
