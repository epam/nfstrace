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
class CIFSFiltrator : public FiltratorImpl<CIFSFiltrator<Writer>, Writer>
{
    using BaseImpl = FiltratorImpl<CIFSFiltrator<Writer>, Writer>;
public:

    CIFSFiltrator()
        : BaseImpl()
    {
    }

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t max_rpc_hdr)
    {
        BaseImpl::setWriterImpl(session_ptr, w, max_rpc_hdr);
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

    inline bool collect_header(PacketInfo& info)
    {
        return BaseImpl::collect_header(info, lengthOfBaseHeader(), lengthOfBaseHeader());
    }

    inline bool find_and_read_message(PacketInfo& info, typename Writer::Collection& collection)
    {
        if (const NetBIOS::MessageHeader* nb_header = NetBIOS::get_header(collection.data()))
        {
            if (CIFSv1::get_header(collection.data() + sizeof(NetBIOS::MessageHeader)))
            {
                BaseImpl::setMsgLen(nb_header->len() + sizeof(NetBIOS::MessageHeader));
                BaseImpl::setToBeCopied(nb_header->len() + sizeof(NetBIOS::MessageHeader));//FIXME: restrict msg
                return BaseImpl::read_message(info);
            }
            else if (CIFSv2::get_header(collection.data() + sizeof(NetBIOS::MessageHeader)))
            {
                BaseImpl::setMsgLen(nb_header->len() + sizeof(NetBIOS::MessageHeader));
                BaseImpl::setToBeCopied(nb_header->len() + sizeof(NetBIOS::MessageHeader));//FIXME: restrict msg
                return BaseImpl::read_message(info);
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
