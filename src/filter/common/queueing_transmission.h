//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Push FilteredData to queue for further analysis.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef QUEUEING_TRANSMISSION_H
#define QUEUEING_TRANSMISSION_H
//------------------------------------------------------------------------------
#include <iostream>
#include <string>

#include "../../auxiliary/logger.h"
#include "../../auxiliary/session.h"
#include "../../auxiliary/filtered_data.h"
//------------------------------------------------------------------------------
using NST::auxiliary::FilteredData;
using NST::auxiliary::FilteredDataQueue;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

class QueueingTransmission
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

        inline void operator=(const QueueingTransmission& t) // initialization
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

        inline void push(const PacketInfo& info)
        {
            copy_data_to_collection(info.data, info.dlen);
        }

        inline void push(const PacketInfo& info, const uint32_t len)
        {
            copy_data_to_collection(info.data, len);
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

            // TODO: replace this code with correct reading of current Conversation (Session)
            ptr->timestamp = info.header->ts;
            if(info.ipv4)
            {
                ptr->session.ip_type = auxiliary::Session::v4;
                ptr->session.ip.v4.addr[0] = info.ipv4->src();
                ptr->session.ip.v4.addr[1] = info.ipv4->dst();
            }

            if(info.tcp)
            {
                ptr->session.type = auxiliary::Session::TCP;
                ptr->session.port[0] = info.tcp->sport();
                ptr->session.port[1] = info.tcp->dport();
            }

            queue->push(ptr);
            ptr = NULL;
        }

        inline const uint32_t    size() const { return ptr->dlen; }
        inline uint8_t*          data() const { return ptr->data; }
        inline    operator bool const() const { return ptr != NULL; }

    private:
        inline void copy_data_to_collection(const uint8_t* p, const uint32_t len)
        {
            uint8_t* const offset_ptr = ptr->data + ptr->dlen;
            const uint32_t capacity = sizeof(ptr->memory) - (offset_ptr - ptr->memory);
            if(len > capacity)
            {
                LOG("data in Collection is overrun collection size:%u, limit:%u, new chunk size:%u", ptr->dlen, capacity, len);
                assert(capacity >= len);
            }
            memcpy(offset_ptr, p, len);
            ptr->dlen += len;
        }

        mutable Queue*      queue;
        mutable Data*       ptr;
    };

    QueueingTransmission(FilteredDataQueue& q) : queue(q)
    {
    }
    ~QueueingTransmission()
    {
    }

private:
    QueueingTransmission(const QueueingTransmission&);            // undefined
    QueueingTransmission& operator=(const QueueingTransmission&); // undefined

    Queue& queue;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//QUEUEING_TRANSMISSION_H
//------------------------------------------------------------------------------
