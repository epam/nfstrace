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
#include <algorithm>
#include <cassert>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include <pcap/pcap.h>

#include "utils/log.h"
#include "utils/out.h"
#include "utils/sessions.h"
#include "controller/parameters.h"
#include "filtration/packet.h"
#include "filtration/sessions_hash.h"
#include "protocols/rpc/rpc_header.h"
#include "protocols/nfs3/nfs3_utils.h"
#include "protocols/nfs4/nfs4_utils.h"
#include "protocols/netbios/netbios.h"
#include "protocols/cifs/cifs.h"
#include "filtration_processor.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

template<typename Writer>
class CIFSFiltrator
{
public:
    CIFSFiltrator()
    : collection{}
    {
        reset();
    }

    CIFSFiltrator(CIFSFiltrator&&)                 = delete;
    CIFSFiltrator(const CIFSFiltrator&)            = delete;
    CIFSFiltrator& operator=(const CIFSFiltrator&) = delete;

    inline void reset()
    {
        msg_len = 0;
        hdr_len = 0;
        collection.reset(); // data in external memory freed
    }

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t /*max_rpc_hdr*/)
    {
        assert(w);
        collection.set(*w, session_ptr);
    }

    inline void lost(const uint32_t n) // we are lost n bytes in sequence
    {
        if(msg_len != 0)
        {
            if(hdr_len == 0 && msg_len >= n)
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

    void push(PacketInfo& info)
    {
        assert(info.dlen != 0);

        while(info.dlen) // loop over data in packet
        {
            if(msg_len)    // we are on-stream and we are looking to some message
            {
                if(hdr_len)
                {// hdr_len != 0, readout a part of header of current message
                    if(hdr_len > info.dlen) // got new part of header (not the all!)
                    {
                        //TRACE("got new part of header (not the all!)");
                        collection.push(info, info.dlen);
                        hdr_len     -= info.dlen;
                        msg_len     -= info.dlen;
                        info.dlen = 0;  // return from while
                    }
                    else // hdr_len <= dlen, current message will be complete, also we have some additional data
                    {
                        //TRACE("current message will be complete, also we have some additional data");
                        collection.push(info, hdr_len);
                        info.dlen   -= hdr_len;
                        info.data   += hdr_len;

                        msg_len -= hdr_len;
                        hdr_len = 0;

                        collection.skip_first(sizeof(NetBIOS::MessageHeader));
                        collection.complete(info);    // push complete message to queue
                    }
                }
                else
                {// message header is readout, discard the unused tail of message
                    if(msg_len >= info.dlen) // discard whole new packet
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

    inline bool collect_header(PacketInfo& info)
    {
        static const size_t header_len {sizeof(NetBIOS::MessageHeader) + sizeof(CIFS::MessageHeader)};

        if(collection && (collection.data_size() > 0)) // collection is allocated
        {
            assert(collection.capacity() >= header_len);
            const unsigned long tocopy {header_len - collection.data_size()};
            assert(tocopy != 0);
            if(info.dlen < tocopy)
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
            if(info.dlen >= header_len) // is data enough to message validation?
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

    // Find next message in packet info
    inline void find_message(PacketInfo& info)
    {
        assert(msg_len == 0);   // Message still undetected

        if (!collect_header(info))
            return;

        assert(collection);     // collection must be initialized

        const NetBIOS::MessageHeader *nb_header = NetBIOS::get_header(collection.data());
        if (nb_header) {
            const CIFS::MessageHeader *header = CIFS::get_header(collection.data() + sizeof(NetBIOS::MessageHeader));
            if (header) {
                msg_len = nb_header->len() + sizeof(nb_header);
                hdr_len = (sizeof(nb_header) + sizeof(header) < msg_len ? sizeof(nb_header) + sizeof(header) : msg_len);

                assert(msg_len != 0);   // message is found
                assert(msg_len >= collection.data_size());
                assert(hdr_len <= msg_len);

                const uint32_t written {collection.data_size()};
                msg_len -= written; // substract how written (if written)
                hdr_len -= std::min(hdr_len, written);
                if (0 == hdr_len)   // Avoid infinity loop when "msg len" == "data size(collection) (max_header)" {msg_len >= hdr_len}
                                    // Next find message call will finding next message
                {
                    collection.skip_first(sizeof(NetBIOS::MessageHeader));
                    collection.complete(info);
                }
                return;
            }
        }

        assert(msg_len == 0);   // message is not found
        assert(hdr_len == 0);   // header should be skipped
        collection.reset();     // skip collected data
        //[ Optimization ] skip data of current packet at all
        info.dlen = 0;
    }

private:
    uint32_t msg_len;  // length of current RPC message + RM
    uint32_t hdr_len;  // length of readable piece of RPC message. Initially msg_len or 0 in case of unknown msg

    typename Writer::Collection collection;// storage for collection packet data
};

}

}

#endif // CIFS_FILTRATOR_H
