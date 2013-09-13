//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Push FilteredData to queue for further analysis.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef QUEUEING_H
#define QUEUEING_H
//------------------------------------------------------------------------------
#include <iostream>
#include <string>

#include "../../auxiliary/filtered_data.h"
#include "../../auxiliary/logger.h"
#include "../../auxiliary/session.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredData;
using NST::auxiliary::FilteredDataQueue;
using NST::auxiliary::Session;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class Queueing
{
    typedef FilteredDataQueue Queue;
    typedef FilteredData      Data;
public:

    class Collection
    {
    public:
        inline Collection(): queue(NULL), ptr(NULL)
        {
        }

        inline void operator=(const Queueing& t) // initialization
        {
            queue = &t.queue;
            ptr = queue->allocate();
            if(ptr)
            {
                reset();
            }
            else
            {
                LOG("free elements of the Queue are exhausted");
            }
        }
        inline ~Collection()
        {
            if(ptr)
            {
                queue->deallocate(ptr);
            }
        }

//        Collection(const Collection&);            // undefiend
//        Collection& operator=(const Collection&); // undefiend
        inline Collection(const Collection& p) // move
        {
            queue = p.queue;
            ptr   = p.ptr;
            p.queue = NULL;
            p.ptr   = NULL;
        }
        inline Collection& operator=(const Collection& p) // move
        {
            queue = p.queue;
            ptr   = p.ptr;
            p.queue = NULL;
            p.ptr   = NULL;
            return *this;
        }

        inline void reset()
        {
            if(ptr)
            {
                ptr->dlen = 0;
                ptr->data = ptr->memory;
            }
        }

        inline void push(const PacketInfo& info, const uint32_t len)
        {
            uint8_t* const offset_ptr = ptr->data + ptr->dlen;
            const uint32_t capacity = sizeof(ptr->memory) - (offset_ptr - ptr->memory);
            if(len > capacity)
            {
                LOG("data in Collection is overrun collection size:%u, limit:%u, new chunk size:%u", ptr->dlen, capacity, len);
                assert(capacity >= len);
            }
            memcpy(offset_ptr, info.data, len);
            ptr->dlen += len;
        }

        // TODO: workaround
        // we should remove RM(uin32_t) from collected data
        inline void skip_first(const uint32_t len)
        {
            ptr->dlen -= len;
            ptr->data += len;
        }

        void complete(const PacketInfo& info)
        {
            assert(ptr);
            assert(ptr->dlen > 0);

            ptr->timestamp = info.header->ts;

            // TODO: replace this code with correct reading of current Conversation (Session)
            info.fill(ptr->session);

            queue->push(ptr);
            ptr = NULL;
        }

        inline const uint32_t    size() const { return ptr->dlen; }
        inline const uint8_t*    data() const { return ptr->data; }
        inline    operator bool const() const { return ptr != NULL; }

    private:
        mutable Queue*      queue;
        mutable Data*       ptr;
    };

    Queueing(FilteredDataQueue& q) : queue(q)
    {
    }
    ~Queueing()
    {
    }

private:
    Queueing(const Queueing&);            // undefined
    Queueing& operator=(const Queueing&); // undefined

    Queue& queue;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUEING_H
//------------------------------------------------------------------------------
