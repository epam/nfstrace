//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Special Queue for fixed size elements without copying them
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef QUEUE_H
#define QUEUE_H
//------------------------------------------------------------------------------
#include "block_allocator.h"
#include "spinlock.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace auxiliary
{

template <typename T>
class Queue
{
    struct Element // an element of the queue
    {
        Element* prev;
        T data;
    };

public:

    class List  // List of elements for client code
    {
    public:

        inline operator bool() const { return ptr; }
        inline T* get()
        {
            T* data = &ptr->data;
            ptr = ptr->prev;
            return data;
        }

        inline List(Element* first):ptr(first){}
        inline List(const List& a):ptr(a.ptr){}
    private:
        List& operator=(const List&);   // undefined

        Element* ptr;
    };


    Queue(uint32_t size, uint32_t limit):last(NULL), first(NULL)
    {
        allocator.init_allocation(sizeof(Element), size, limit);
    }
    ~Queue()
    {
    }

    inline T*const allocate()
    {
        Element* e;
        {
            Spinlock::Lock lock(a_spinlock);
                e = (Element*)allocator.allocate();
        }
        return (e) ? &(e->data) : NULL;
    }

    inline void deallocate(T* data)
    {
        Element* e = element(data);
        Spinlock::Lock lock(a_spinlock);
            allocator.deallocate((BlockAllocator::Chunk*)e);
    }

    inline void push(T* data)
    {
        Element* e = element(data);
        Spinlock::Lock lock(q_spinlock);
            if(last)
            {
                last->prev = e;
                last = e;
            }
            else    // queue is empty
            {
                last = first = e;
            }
    }
    
    inline List pop_list() // take out list of all queued elements
    {
        Spinlock::Lock lock(q_spinlock);
            last->prev = NULL;  // set end of list
            last = NULL;
            return List(first);
    }

private:

    static inline Element* element(T* data)
    {
        return (Element*)( ((char*)data) - sizeof(Element*) );
    }

    BlockAllocator allocator;
    Spinlock a_spinlock; // for memory reusage allocate/deallocate
    Spinlock q_spinlock; // for queue push/pop

    // queue empty:  last->NULL<-first
    // queue filled: last->e<-e<-e<-e<-first
    Element* last;
    Element* first;

};

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUE_H
//------------------------------------------------------------------------------
