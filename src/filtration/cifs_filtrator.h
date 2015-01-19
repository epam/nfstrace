//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Generic processor for filtration raw pcap packets.
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
#ifndef CIFS_FILTRATOR_H
#define CIFS_FILTRATOR_H
//------------------------------------------------------------------------------
#include <cassert>

#include <pcap/pcap.h>

#include "filtration/packet.h"
#include "filtration/filtratorimpl.h"
#include "protocols/cifs/cifs.h"
#include "protocols/cifs2/cifs2.h"
#include "protocols/netbios/netbios.h"
#include "utils/log.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

template<typename Writer>
class CIFSFiltrator : private FiltratorImpl
{
    size_t msg_len;  // length of current RPC message + RM
    size_t to_be_copied;  // length of readable piece of RPC message. Initially msg_len or 0 in case of unknown msg

    typename Writer::Collection collection;// storage for collection packet data

public:
    CIFSFiltrator()
        : FiltratorImpl()
        , collection {}
    {
        reset();
    }

    inline void reset()
    {
        msg_len = 0;
        to_be_copied = 0;
        collection.reset(); // data in external memory freed
    }

    inline constexpr static size_t lengthOfBaseHeader()
    {
        return sizeof(NetBIOS::MessageHeader) + sizeof(CIFSv1::MessageHeaderHead);
    }

    inline static bool isRightHeader(const uint8_t* header)
    {
        if (NetBIOS::get_header(header))
        {
            if (CIFSv1::get_header(header + sizeof(NetBIOS::MessageHeader)))
            {
                return true;
            }
            else if (CIFSv2::get_header(header + sizeof(NetBIOS::MessageHeader)))
            {
                return true;
            }
        }
        return false;
    }

    inline bool inProgress(PacketInfo& info)
    {
        if (msg_len || to_be_copied)
        {
            return true;
        }
        return FiltratorImpl::inProgressImpl<lengthOfBaseHeader(), isRightHeader>(info, collection, this);
    }

    inline void lost(const uint32_t n) // we are lost n bytes in sequence
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
                reset();
            }
        }
        else
        {
            TRACE("We are lost %u bytes of unknown payload", n);
        }
    }

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t /*max_rpc_hdr*/)
    {
        assert(w);
        collection.set(*w, session_ptr);
    }

    void push(PacketInfo& info)
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

                        collection.skip_first(sizeof(NetBIOS::MessageHeader));
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
                        find_message(info); // <- optimization
                    }
                }
            }
            else // msg_len == 0, no one message is on reading, try to find next message
            {
                find_message(info);
            }
        }
    }

    bool collect_header(PacketInfo& info)
    {
        static const size_t header_len = lengthOfBaseHeader();
        if (collection && (collection.data_size() > 0)) // collection is allocated
        {

            assert(collection.capacity() >= header_len);
            const size_t tocopy {header_len - collection.data_size()};
            assert(tocopy != 0);
            if (info.dlen < tocopy)
            {
                collection.push(info, info.dlen);
                info.data += info.dlen;//   optimization
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
            if (info.dlen >= header_len) // is data enough to message validation?
            {
                collection.push(info, header_len); // probability that message will be rejected / probability of valid message
                info.data += header_len;
                info.dlen -= header_len;
            }
            else // (info.dlen < header_len)
            {
                collection.push(info, info.dlen);
                info.data += info.dlen;//   optimization
                info.dlen = 0;
                return false;
            }
        }
        return true;
    }

    template<typename Header>
    void read_message(const NetBIOS::MessageHeader* nb_header, const Header*, PacketInfo& info)
    {
        msg_len = nb_header->len() + sizeof(NetBIOS::MessageHeader);
        to_be_copied = msg_len;//(sizeof(NetBIOS::MessageHeader) + sizeof(Header) < msg_len ? sizeof(NetBIOS::MessageHeader) + sizeof(Header) : msg_len);

        assert(msg_len != 0);   // message is found
        assert(msg_len >= collection.data_size());
        assert(to_be_copied <= msg_len);

        const size_t written {collection.data_size()};
        msg_len -= written; // substract how written (if written)
        to_be_copied -= std::min(to_be_copied, written);
        if (0 == to_be_copied)   // Avoid infinity loop when "msg len" == "data size(collection) (max_header)" {msg_len >= hdr_len}
            // Next find message call will finding next message
        {
            collection.skip_first(sizeof(NetBIOS::MessageHeader));
            collection.complete(info);
        }

    }

    // Find next message in packet info
    void find_message(PacketInfo& info)
    {
        assert(msg_len == 0);   // Message still undetected

        if (!collect_header(info))
        {
            return ;
        }

        assert(collection);     // collection must be initialized

        if (const NetBIOS::MessageHeader* nb_header = NetBIOS::get_header(collection.data()))
        {
            if (const CIFSv1::MessageHeader* header = CIFSv1::get_header(collection.data() + sizeof(NetBIOS::MessageHeader)))
            {
                return read_message(nb_header, header, info);
            }
            else if (const CIFSv2::MessageHeader* header = CIFSv2::get_header(collection.data() + sizeof(NetBIOS::MessageHeader)))
            {
                return read_message(nb_header, header, info);
            }
        }

        assert(msg_len == 0);   // message is not found
        assert(to_be_copied == 0);   // header should be skipped
        collection.reset();     // skip collected data
        //[ Optimization ] skip data of current packet at all
        info.dlen = 0;
    }

};

} // filtration

} // NST
//------------------------------------------------------------------------------
#endif // CIFS_FILTRATOR_H
//------------------------------------------------------------------------------
