//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Push FilteredData to queue for further analysis.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#ifndef QUEUING_H
#define QUEUING_H
//------------------------------------------------------------------------------
#include <string>

#include "utils/filtered_data.h"
#include "utils/log.h"
#include "utils/sessions.h"
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

        inline void allocate(size_t bytes)
        {
            assert(nullptr == ptr);
            if (nullptr != ptr)
            {
                ptr->deallocate();
            }
            else {
                // we have a reference to queue, just do allocate and reset
                ptr = queue->allocate();
            }
            if(ptr)
            {
                ptr->allocate(bytes);
            }
            else
            {
                LOG("free elements of the Queue are exhausted");
            }
        }

        void deallocate()
        {
            if(ptr)
            {
                queue->deallocate(ptr);
                ptr = nullptr;
            }
        }

        inline void reset()
        {
            if(ptr)
            {
                ptr->reset();
            }
        }

        inline void push(const PacketInfo& info, const uint32_t len)
        {
            assert(nullptr != ptr);

            if (!ptr)
                return;

            uint8_t* offset_ptr = ptr->data + ptr->dlen;
            const uint32_t avail = ptr->capacity() - ptr->dlen; 
            if(len > avail)
            {
                LOG("data in Collection is overrun collection size:%u, limit:%u, new chunk size:%u", ptr->dlen, avail, len);
                //assert(avail >= len);
                ptr->extend(len - avail); // [! infinite extension !]
                offset_ptr = ptr->data + ptr->dlen; // update pointer
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

        inline uint32_t data_size() const { return ptr->dlen; }
        inline uint32_t capacity() const { return ptr->capacity(); }
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
#endif//QUEUING_H
//------------------------------------------------------------------------------
