//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Special Queue for fixed size elements without copying them
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef QUEUE_H
#define QUEUE_H
//------------------------------------------------------------------------------
#include <memory>

#include "utils/block_allocator.h"
#include "utils/spinlock.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace utils
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
        inline explicit ElementDeleter() : queue{nullptr} {}
        inline explicit ElementDeleter(Queue* q) : queue{q} { }

        inline void operator()(T* const pointer) const
        {
            if(pointer /*&& queue - dont check - optimization*/)
            {
                queue->deallocate(pointer);
            }
        }

        Queue* queue;
    };

public:

    using Ptr = std::unique_ptr<T, ElementDeleter>;

    class List  // List of elements for client code
    {
    public:
        inline List(Queue& q) : queue{&q}
        {
            ptr = queue->pop_list();
        }
        List(const List&)            = delete;
        List& operator=(const List&) = delete;
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
        Element* ptr;
        Queue* queue;
    };


    Queue(uint32_t size, uint32_t limit) : last{nullptr}, first{nullptr}
    {
        allocator.init_allocation(sizeof(Element), size, limit);
    }
    ~Queue()
    {
        List list{*this};   // deallocate items by destructor of List
    }

    inline T* allocate()
    {
        Spinlock::Lock lock{a_spinlock};
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
        Spinlock::Lock lock{q_spinlock};
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
        Element* list = nullptr;
        if(last)
        {
            Spinlock::Lock lock{q_spinlock};
                if(last)
                {
                    list = first;
                    last->prev = nullptr;  // set end of list
                    last = first = nullptr;
                }
        }
        return list;
    }

private:
    // accessible from Queue::List and Queue::Ptr
    inline void deallocate(Element* e)
    {
        Spinlock::Lock lock{a_spinlock};
            allocator.deallocate(e);
    }

    BlockAllocator allocator;
    Spinlock a_spinlock; // for allocate/deallocate
    Spinlock q_spinlock; // for queue push/pop

    // queue empty:   last->nullptr<-first
    // queue filled:  last->e<-e<-e<-e<-first
    // queue push(i): last->i<-e<-e<-e<-e<-first
    Element* last;
    Element* first;
};

} // namespace utils
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUE_H
//------------------------------------------------------------------------------
