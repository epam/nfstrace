//------------------------------------------------------------------------------
// Author: Yauheni Azaranka
// Description: Wrapper for pthread spinlock. It implements BasicLockable concept.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef SPINLOCK_H
#define SPINLOCK_H
//------------------------------------------------------------------------------
#include <mutex> // for std::lock_guard

#include <pthread.h>
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
    Spinlock(const Spinlock&) = delete;
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
#endif // SPINLOCK_H
//------------------------------------------------------------------------------
