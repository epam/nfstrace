//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Wrapper for pthread spinlock. It implements BasicLockable concept.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SPINLOCK_H
#define SPINLOCK_H
//------------------------------------------------------------------------------
#include <mutex>    // for std::lock_guard

#include <pthread.h>
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
{

class Spinlock
{
public:
    Spinlock() noexcept
    {
        pthread_spin_init(&spinlock, PTHREAD_PROCESS_PRIVATE);
    }
    Spinlock(const Spinlock&)            = delete;
    Spinlock& operator=(const Spinlock&) = delete;
    ~Spinlock() noexcept
    {
        pthread_spin_destroy(&spinlock);
    }

    bool try_lock() noexcept
    {
        return 0 == pthread_spin_trylock(&spinlock);
    }

    void lock() noexcept
    {
        pthread_spin_lock(&spinlock);
    }

    void unlock() noexcept
    {
        pthread_spin_unlock(&spinlock);
    }

    using Lock = std::lock_guard<Spinlock>;

private:
    mutable pthread_spinlock_t spinlock;
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//SPINLOCK_H
//------------------------------------------------------------------------------
