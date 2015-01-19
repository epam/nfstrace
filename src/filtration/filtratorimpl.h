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
//#include "filtration/packet.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

class FiltratorImpl
{
    FiltratorImpl(FiltratorImpl&&)                 = delete;
    FiltratorImpl(const FiltratorImpl&)            = delete;
    FiltratorImpl& operator=(const FiltratorImpl&) = delete;
public:
    FiltratorImpl() {}

    using IsRightHeader = bool(const uint8_t* header);

    /*!
     * Implementation of checking, does the filtrator work now?
     * \param info - packet
     * \param collection - link to collection class
     * \param filtrator - pointer to observer
     */
    template<size_t callHeaderLen, IsRightHeader isRightHeader,typename Writer, typename Filtrator>
    inline static bool inProgressImpl(PacketInfo& info, Writer& collection, Filtrator* filtrator)
    {
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
            if (isRightHeader(header))
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

    template<typename Filtrator>
    inline void lost(const uint32_t n, Filtrator* filtrator, size_t& to_be_copied, size_t& msg_len) // we are lost n bytes in sequence
    {
        //FIXME: Code has been dublicated
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

    template<typename Writer, typename Filtrator>
    void push(PacketInfo& info, Writer& collection, Filtrator* filtrator, size_t& to_be_copied, size_t& msg_len)
    {
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

    template<size_t callHeaderLen, size_t replyHeaderLen, typename Writer>
    bool collect_header(PacketInfo& info, Writer& collection)
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

};

} // filtration

} // NST
//------------------------------------------------------------------------------
#endif // IFILTRATOR_H
//------------------------------------------------------------------------------
