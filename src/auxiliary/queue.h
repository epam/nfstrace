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
#include "unique_ptr.h"
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

    struct ElementDeleter
    {
        inline explicit ElementDeleter() : queue(NULL) {}
        inline explicit ElementDeleter(Queue* q) : queue(q) { }

        inline void operator()(T* const pointer) const
        {
            if(pointer /*&& queue dont check - optimization*/)
            {
                queue->deallocate(pointer);
            }
        }

        Queue* queue;
    };

public:

    typedef UniquePtr<T, ElementDeleter> Ptr;

    class List  // List of elements for client code
    {
    public:
        inline List(Queue& q):queue(&q)
        {
            ptr = queue->pop_list();
        }
        inline ~List()
        {
            while(ptr)
            {
                free_current();
            }
        }

        inline operator bool() const { return ptr;       } // is empty?
        inline const T& data() const { return ptr->data; } // get data
        inline Ptr get_current() // return element and switch to next
        {
            Element* tmp = ptr;
            ptr = ptr->prev;
            return Ptr(&tmp->data, ElementDeleter(queue));
        }
        inline void free_current() // deallocate element and switch to next
        {
            Element* tmp = ptr->prev;
            queue->deallocate(ptr);
            ptr = tmp;
        }
    private:
        List(const List&);            // undefined
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
        Element* e = (Element*)allocator.allocate(); // may throw std::bad_alloc
        return &(e->data);
    }

    inline void deallocate(T* ptr)
    {
        Element* e = (Element*)( ((char*)ptr) - sizeof(Element*) );
        deallocate(e);
    }

    inline void push(T* ptr)
    {
        Element* e = (Element*)( ((char*)ptr) - sizeof(Element*) );
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
    // accessible from Queue::List and Queue::Ptr
    inline void deallocate(const Element* e)
    {
        allocator.deallocate((BlockAllocator::Chunk*)e);
    }

    BlockAllocator allocator;
    Spinlock q_spinlock; // for queue push/pop

    // queue empty:   last->NULL<-first
    // queue filled:  last->e<-e<-e<-e<-first
    // queue push(i): last->i<-e<-e<-e<-e<-first
    Element* last;
    Element* first;
};

} // namespace auxiliary
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUE_H
//------------------------------------------------------------------------------
