//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Thread safe fifo-structure, which realized as wrapper around std::list.
//              Realized as non-blocking queue.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef FIFO_H
#define FIFO_H
//------------------------------------------------------------------------------
#include <list>

#include "spinlock.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

template<typename Data, typename Allocator = int>
// Second template parameter will be replaced by real allocator
class FIFO
{
    typedef std::list<Data/*, Allocator*/> List;

public:
    enum Result
    {
        SUCCESS = 0,
        EAGAIN = 1
    };

    FIFO()
    {
    }
    // How can I create multithread protected destructor?
    ~FIFO()
    {
    }

    FIFO(const FIFO&);              // undefined
    FIFO& operator=(const FIFO&);   // undefined

    Result push(const Data& data)
    {
        Spinlock::Lock lock(spinlock);
        fifo.push_back(data);
        return SUCCESS;
    }

    Result pop(Data& data)
    {
        Spinlock::Lock lock(spinlock);
        if(fifo.empty())
            return EAGAIN;
        data = fifo.front();
        fifo.pop_front();    
        return SUCCESS;
    }

    bool empty()
    {
        Spinlock::Lock lock(spinlock);
        return fifo.empty();
    }

private:
    Spinlock spinlock;
    List fifo;
};

} // auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//FIFO_H
//------------------------------------------------------------------------------
