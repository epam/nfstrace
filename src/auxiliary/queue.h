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

    class Allocated
    {
    public:
        inline Allocated(Queue& q):queue(&q)
        {
            ptr = queue->allocate();
        }
        inline ~Allocated()
        {
            queue->push(ptr);
        }

        inline    operator T*const() const { return ptr; }
        inline T*const operator ->() const { return ptr; }

    private:
        Allocated(const Allocated&);            // undefined
        Allocated& operator=(const Allocated&); // undefined
    
        Queue*const queue;
        T*            ptr;
    };

    class List  // List of elements for client code
    {
    friend class Queue;
    public:

        inline operator bool() const { return ptr;       } // is empty?
        inline const T& data() const { return ptr->data; } // get data
        inline void free_current() // deallocate element and switch to next
        {
            Element* tmp = ptr->prev;
            queue->deallocate(ptr);
            ptr = tmp;
        }

        inline List(Element* first, Queue* q):ptr(first),queue(q){}
        inline List(const List& list):ptr(list.ptr),queue(list.queue)
        {
            // move elements from list to this, without deallocation in list
            list.ptr   = NULL;
            list.queue = NULL;
        }
        inline ~List()
        {
            while(ptr)
            {
                free_current();
            }
        }
    private:
        List& operator=(const List&); // undefined

        mutable Element* ptr;
        mutable Queue* queue;
    };


    Queue(uint32_t size, uint32_t limit):last(NULL), first(NULL)
    {
        allocator.init_allocation(sizeof(Element), size, limit);
    }
    ~Queue()
    {
    }

    inline T* const allocate()
    {
        Element* e = (Element*)allocator.allocate();
        return (e) ? &(e->data) : NULL;
    }

    inline void push(T* data)
    {
        Element* e = (Element*)( ((char*)data) - sizeof(Element*) );
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
        Element* list = NULL;
        if(last)    // a reader will check this pointer without locking spinlock
        {
            Spinlock::Lock lock(q_spinlock);
                last->prev = NULL;  // set end of list
                list = first;
                last = first = NULL;
        }
        return List(list, this);
    }

private:
    inline void deallocate(Element* e)  // accessible from Queue::List
    {
        allocator.deallocate((BlockAllocator::Chunk*)e);
    }

    BlockAllocator allocator;
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
