//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Push FilteredData to queue for further analysis.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef QUEUEING_H
#define QUEUEING_H
//------------------------------------------------------------------------------
#include <string>

#include "utils/filtered_data.h"
#include "utils/log.h"
#include "utils/session.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

class Queueing
{
    using Queue = NST::utils::FilteredDataQueue;
    using Data  = NST::utils::FilteredData;

public:

    class Collection
    {
    public:
        inline Collection()
        : queue   {nullptr}
        , ptr     {nullptr}
        , session {nullptr}
        {
        }
        inline Collection(Queueing* q, utils::NetworkSession* s)
        : queue   {&q->queue}
        , ptr     {nullptr}
        , session {s}
        {
        }
        inline ~Collection()
        {
            if(ptr)
            {
                queue->deallocate(ptr);
            }
        }
        Collection(Collection&&)                 = delete;
        Collection(const Collection&)            = delete;
        Collection& operator=(const Collection&) = delete;

        inline void set(Queueing& q, utils::NetworkSession* s)
        {
            queue = &q.queue;
            session = s;
        }

        inline void allocate()
        {
            // we have a reference to queue, just do allocate and reset
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
            assert(info.direction != utils::Session::Direction::Unknown);

            ptr->session   = session;
            ptr->timestamp = info.header->ts;
            ptr->direction = info.direction;

            queue->push(ptr);
            ptr = nullptr;
        }

        inline uint32_t size() const { return ptr->dlen; }
        inline uint8_t* data() const { return ptr->data; }
        inline operator bool() const { return ptr != nullptr; }

    private:
        Queue* queue;
        Data*  ptr;
        utils::NetworkSession* session;
    };

    Queueing(Queue& q)
    : queue(q)
    {
    }
    ~Queueing()
    {
    }
    Queueing(Queueing&&)                 = delete;
    Queueing(const Queueing&)            = delete;
    Queueing& operator=(const Queueing&) = delete;

private:
    Queue& queue;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUEING_H
//------------------------------------------------------------------------------
