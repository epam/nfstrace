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
    {
        reset();
    }

    inline void reset()
    {
        msg_len = 0;
        to_be_copied = 0;
        collection.reset();
    }

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t )
    {
        assert(w);
        collection.set(*w, session_ptr);
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

    inline void find_message(PacketInfo& info)
    {
        return FiltratorImpl::find_message(info, collection, this, to_be_copied, msg_len);
    }

    inline bool find_and_read_message(PacketInfo& info)
    {
        if (const NetBIOS::MessageHeader* nb_header = NetBIOS::get_header(collection.data()))
        {
            if (CIFSv1::get_header(collection.data() + sizeof(NetBIOS::MessageHeader)))
            {
                msg_len = nb_header->len() + sizeof(NetBIOS::MessageHeader);
                to_be_copied = msg_len;//(sizeof(NetBIOS::MessageHeader) + sizeof(Header) < msg_len ? sizeof(NetBIOS::MessageHeader) + sizeof(Header) : msg_len);
                return read_message(info, collection, this, to_be_copied, msg_len);
            }
            else if (CIFSv2::get_header(collection.data() + sizeof(NetBIOS::MessageHeader)))
            {
                msg_len = nb_header->len() + sizeof(NetBIOS::MessageHeader);
                to_be_copied = msg_len;//(sizeof(NetBIOS::MessageHeader) + sizeof(Header) < msg_len ? sizeof(NetBIOS::MessageHeader) + sizeof(Header) : msg_len);
                return read_message(info, collection, this, to_be_copied, msg_len);
            }
        }
        return false;
    }

};

} // filtration

} // NST
//------------------------------------------------------------------------------
#endif // CIFS_FILTRATOR_H
//------------------------------------------------------------------------------
