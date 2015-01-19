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

    inline constexpr static size_t lengthOfFirstSkipedPart()
    {
        return sizeof(NetBIOS::MessageHeader);
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

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t /*max_rpc_hdr*/)
    {
        assert(w);
        collection.set(*w, session_ptr);
    }

    inline void lost(const uint32_t n) // we are lost n bytes in sequence
    {
        return FiltratorImpl::lost(n, this, to_be_copied, msg_len);
    }

    inline void push(PacketInfo& info)
    {
        return FiltratorImpl::push(info, collection, this, to_be_copied, msg_len);
    }

    inline bool collect_header(PacketInfo& info)
    {
        return FiltratorImpl::collect_header<lengthOfBaseHeader(),lengthOfBaseHeader()>(info, collection);
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
