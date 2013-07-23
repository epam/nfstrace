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
        inline Collection(): queue(NULL), ptr(NULL), size(0)
        {
        }
        inline Collection(Queue& q):queue(&q), size(0)
        {
            ptr = queue->allocate();
            if(ptr == NULL)
            {
                std::clog << "free elements of the Queue are exhausted" << std::endl;
            }
        }
        inline Collection(const Collection& p):size(0) // move
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
            size  = 0;
            p.queue = NULL;
            p.ptr   = NULL;

            return *this;
        }
        inline ~Collection()
        {
            if(ptr)
            {
                queue->deallocate(ptr);
            }
        }

        void push(const PacketInfo& info)
        {
            assert((sizeof(ptr->data)-size) >= info.dlen);
            memcpy(ptr->data+size, info.data, info.dlen);
            size += info.dlen;
        }

        void push(const PacketInfo& info, const uint32_t len)
        {
            assert((sizeof(ptr->data)-size) >= len);
            memcpy(ptr->data+size, info.data, len);
            size += len;
        }
        
        // TODO: workaround
        // we should remove RM(uin32_t) from collected data
        inline void skip_first(const uint32_t len)
        {
            size = size-len;
            // TODO: performance drop! unnecessary memmove!!!!
            memmove(ptr->data, ptr->data+len, size);
        }

        void complete(const PacketInfo& info)
        {
            assert(size > 0);
            if(ptr)
            {
                //std::cout << "collection complete len: " << sizeof(ptr->data) << " size: " << size << std::endl;

                ptr->dlen = size;

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
            size = 0;
        }

        inline void             reset() { size = 0; }
        inline const uint32_t data_size() const { return size; }
        inline uint8_t*          data() const { return ptr->data; }
        inline    operator Data*const() const { return ptr; }
        inline Data*const operator ->() const { return ptr; }

        mutable Queue*      queue;
        mutable Data*       ptr;
        mutable uint32_t    size;
    };

    QueueingTransmission(FilteredDataQueue& q) : queue(q)
    {
    }
    ~QueueingTransmission()
    {
    }
    
    void collect(const PacketInfo& info)
    {
    }

    inline Collection alloc()
    {
        return Collection(queue);
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
