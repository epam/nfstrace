//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Abstract impementation of filtrator class
// TODO: THIS CODE MUST BE TOTALLY REFACTORED!
// Copyright (c) 2014 EPAM Systems
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
#ifndef IFILTRATOR_H
#define IFILTRATOR_H
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
/*!
 * Filtering TCP stream strategy (implementation)
 * Implemented via Curiously recurring template pattern, (see http://en.wikipedia.org/wiki/Curiously_recurring_template_pattern)
 */
template<typename Filtrator, typename Writer>
class FiltratorImpl
{
    size_t msg_len;  // length of current RPC message + RM
    size_t to_be_copied;  // length of readable piece of RPC message. Initially msg_len or 0 in case of unknown msg
    using Collection = typename Writer::Collection;
    Collection collection;// storage for collection packet data

    FiltratorImpl(FiltratorImpl&&)                 = delete;
    FiltratorImpl(const FiltratorImpl&)            = delete;
    FiltratorImpl& operator=(const FiltratorImpl&) = delete;
public:
    FiltratorImpl()
    {
        reset();
    }

    inline void reset()
    {
        msg_len = 0;
        to_be_copied = 0;
        collection.reset();
    }

    /*!
     * Implementation of checking, does the filtrator work now?
     * \param info - packet
     * \param collection - link to collection class
     * \param filtrator - pointer to observer
     */
    inline bool inProgress(PacketInfo& info)
    {
        Filtrator* filtrator = static_cast<Filtrator* >(this);
        const size_t callHeaderLen = filtrator->lengthOfBaseHeader();
        if (msg_len || to_be_copied)
        {
            return true;
        }

        if (!collection) // collection isn't allocated
        {
            collection.allocate(); // allocate new collection from writer
        }
        const size_t data_size = collection.data_size();

        if (data_size + info.dlen > callHeaderLen)
        {
            static uint8_t buffer[callHeaderLen];
            const uint8_t* header = info.data;

            if (data_size > 0)
            {
                // Coping happends only once per TCP-session
                memcpy(buffer, collection.data(), data_size);
                memcpy(buffer + data_size, info.data, callHeaderLen - data_size);
                header = buffer;
            }

            // It is right header
            if (filtrator->isRightHeader(header))
            {
                return true;
            }

            filtrator->reset();
        }
        else
        {
            collection.push(info, info.dlen);
        }

        return false;
    }

    inline void lost(const uint32_t n) // we are lost n bytes in sequence
    {
        Filtrator* filtrator = static_cast<Filtrator* >(this);
        if (msg_len != 0)
        {
            if (to_be_copied == 0 && msg_len >= n)
            {
                TRACE("We are lost %u bytes of payload marked for discard", n);
                msg_len -= n;
            }
            else
            {
                TRACE("We are lost %u bytes of useful data. lost:%u msg_len:%u", n - msg_len, n, msg_len);
                filtrator->reset();
            }
        }
        else
        {
            TRACE("We are lost %u bytes of unknown payload", n);
        }
    }

    inline void push(PacketInfo& info)
    {
        Filtrator* filtrator = static_cast<Filtrator* >(this);
        //FIXME: Code has been dublicated
        assert(info.dlen != 0);

        while (info.dlen) // loop over data in packet
        {
            if (msg_len)   // we are on-stream and we are looking to some message
            {
                if (to_be_copied)
                {
                    // hdr_len != 0, readout a part of header of current message
                    if (to_be_copied > info.dlen) // got new part of header (not the all!)
                    {
                        //TRACE("got new part of header (not the all!)");
                        collection.push(info, info.dlen);
                        to_be_copied -= info.dlen;
                        msg_len -= info.dlen;
                        info.dlen = 0;  // return from while
                    }
                    else // hdr_len <= dlen, current message will be complete, also we have some additional data
                    {
                        //TRACE("current message will be complete, also we have some additional data");
                        collection.push(info, to_be_copied);
                        info.dlen   -= to_be_copied;
                        info.data   += to_be_copied;

                        msg_len -= to_be_copied;
                        to_be_copied = 0;

                        collection.skip_first(filtrator->lengthOfFirstSkipedPart());
                        collection.complete(info);    // push complete message to queue
                    }
                }
                else
                {
                    // message header is readout, discard the unused tail of message
                    if (msg_len >= info.dlen) // discard whole new packet
                    {
                        //TRACE("discard whole new packet");
                        msg_len -= info.dlen;
                        return; //info.dlen = 0;  // return from while
                    }
                    else  // discard only a part of packet payload related to current message
                    {
                        //TRACE("discard only a part of packet payload related to current message");
                        info.dlen -= msg_len;
                        info.data += msg_len;
                        msg_len = 0;
                        filtrator->find_message(info); // <- optimization
                    }
                }
            }
            else // msg_len == 0, no one message is on reading, try to find next message
            {
                filtrator->find_message(info);
            }
        }
    }

    // Find next message in packet info
    inline void find_message(PacketInfo& info)
    {
        assert(msg_len == 0);   // Message still undetected
        Filtrator* filtrator = static_cast<Filtrator* >(this);

        if (!filtrator->collect_header(info))
        {
            return ;
        }

        assert(collection);     // collection must be initialized

        if (filtrator->find_and_read_message(info, collection))
        {
            return;
        }

        assert(msg_len == 0);   // message is not found
        assert(to_be_copied == 0);   // header should be skipped
        collection.reset();     // skip collected data
        //[ Optimization ] skip data of current packet at all
        info.dlen = 0;
    }

protected:
    inline void setMsgLen(size_t value)
    {
        msg_len = value;
    }

    inline void setToBeCopied(size_t value)
    {
        to_be_copied = value;
    }

    inline void setWriterImpl(utils::NetworkSession* session_ptr,  Writer* w, uint32_t )
    {
        assert(w);
        collection.set(*w, session_ptr);
    }

    inline bool collect_header(PacketInfo& info, size_t callHeaderLen, size_t replyHeaderLen)
    {
        if (collection && (collection.data_size() > 0)) // collection is allocated
        {

            assert(collection.capacity() >= callHeaderLen);
            const size_t tocopy {callHeaderLen - collection.data_size()};
            assert(tocopy != 0);
            if (info.dlen < tocopy)
            {
                collection.push(info, info.dlen);
                info.data += info.dlen;// optimization
                info.dlen = 0;
                return false;
            }
            else // info.dlen >= tocopy
            {
                collection.push(info, tocopy); // collection.data_size <= header_len
                info.dlen -= tocopy;
                info.data += tocopy;
            }
        }
        else // collection is empty
        {
            collection.allocate(); // allocate new collection from writer
            if (info.dlen >= callHeaderLen) // is data enough to message validation?
            {
                collection.push(info, callHeaderLen); // probability that message will be rejected / probability of valid message
                info.data += callHeaderLen;
                info.dlen -= callHeaderLen;
            }
            else // (info.dlen < header_len)
            {
                collection.push(info, info.dlen);
                //info.data += info.dlen;//   optimization
                size_t copied = info.dlen;
                info.dlen = 0;
                return copied >= replyHeaderLen;
            }
        }
        return true;
    }

    inline bool read_message(PacketInfo& info)
    {
        assert(msg_len != 0);   // message is found
        assert(msg_len >= collection.data_size());
        assert(to_be_copied <= msg_len);
        Filtrator* filtrator = static_cast<Filtrator* >(this);

        const size_t written {collection.data_size()};
        msg_len -= written; // substract how written (if written)
        to_be_copied -= std::min(to_be_copied, written);
        if (0 == to_be_copied)   // Avoid infinity loop when "msg len" == "data size(collection) (max_header)" {msg_len >= hdr_len}
            // Next find message call will finding next message
        {
            collection.skip_first(filtrator->lengthOfFirstSkipedPart());
            collection.complete(info);
        }
        return true;
    }

};

} // filtration

} // NST
//------------------------------------------------------------------------------
#endif // IFILTRATOR_H
//------------------------------------------------------------------------------
