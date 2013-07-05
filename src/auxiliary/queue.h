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

    class ElementPtr
    {
    public:
        inline ElementPtr(Queue& q):queue(&q)
        {
            ptr = queue->allocate();
        }
        inline ~ElementPtr()
        {
            if(ptr) // isn't explicitly pushed back to queue?
            {
                queue->deallocate(ptr);
            }
        }

        inline void push()
        {
            queue->push(ptr);
            ptr = NULL;
        }

        inline    operator T*const() const { return ptr; }
        inline T*const operator ->() const { return ptr; }

    private:
        ElementPtr(const ElementPtr&);            // undefined
        ElementPtr& operator=(const ElementPtr&); // undefined
    
        Queue*const queue;
        T*            ptr;
    };

    class ElementList  // List of elements for client code
    {
    friend class Queue;
    public:
        inline ElementList(Queue& q):queue(&q)
        {
            ptr = queue->pop_list();
        }
        inline ~ElementList()
        {
            while(ptr)
            {
                free_current();
            }
        }

        inline operator bool() const { return ptr;       } // is empty?
        inline const T& data() const { return ptr->data; } // get data
        inline void free_current() // deallocate element and switch to next
        {
            Element* tmp = ptr->prev;
            queue->deallocate(ptr);
            ptr = tmp;
        }
    private:
        ElementList(const ElementList&);            // undefined
        ElementList& operator=(const ElementList&); // undefined

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

    inline void deallocate(T* ptr)
    {
        Element* e = (Element*)( ((char*)ptr) - sizeof(Element*) );
        deallocate(e);
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

    inline Element* pop_list() // take out list of all queued elements
    {
        Element* list = NULL;
        if(last)
        {
            Spinlock::Lock lock(q_spinlock);
                if(last)
                {
                    list = first;
                    last->prev = NULL;  // set end of list
                    last = first = NULL;
                }
        }
        return list;
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
