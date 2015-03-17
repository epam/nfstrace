//------------------------------------------------------------------------------
// Author: Andrey Kuznetsov
// Description: Generic processor for filtration raw pcap packets.
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

#include <pcap/pcap.h>

#include "filtration/packet.h"
#include "filtration/filtratorimpl.h"
#include "protocols/cifs/cifs.h"
#include "protocols/cifs2/cifs2.h"
#include "protocols/netbios/netbios.h"
#include "utils/log.h"
#include "api/cifs2_commands.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

using SMBv2Commands = NST::API::SMBv2::SMBv2Commands;

template<typename Writer>
class CIFSFiltrator : public FiltratorImpl<CIFSFiltrator<Writer>, Writer>
{
    using BaseImpl = FiltratorImpl<CIFSFiltrator<Writer>, Writer>;
    size_t rw_hdr_max {512}; // limit for SMB header to truncate messages
public:

    CIFSFiltrator()
        : BaseImpl()
    {
    }

    constexpr static size_t lengthOfReplyHeader()
    {
        return lengthOfBaseHeader();
    }

    constexpr static size_t lengthOfCallHeader()
    {
        return lengthOfBaseHeader();
    }

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t max_hdr)
    {
        rw_hdr_max = max_hdr;
        BaseImpl::setWriterImpl(session_ptr, w, max_hdr);
    }

    constexpr static size_t lengthOfBaseHeader()
    {
        return sizeof(NetBIOS::MessageHeader) + sizeof(CIFSv1::MessageHeaderHead);
    }

    constexpr static size_t lengthOfFirstSkipedPart()
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
            const size_t length = nb_header->len() + sizeof(NetBIOS::MessageHeader);
            if (const CIFSv1::MessageHeader* header = CIFSv1::get_header(collection.data() + sizeof(NetBIOS::MessageHeader)))
            {
                BaseImpl::setMsgLen(length);
                set_msg_size(header, length);
                return BaseImpl::read_message(info);
            }
            else if (const CIFSv2::MessageHeader* header = CIFSv2::get_header(collection.data() + sizeof(NetBIOS::MessageHeader)))
            {
                BaseImpl::setMsgLen(length);
                set_msg_size(header, length);
                return BaseImpl::read_message(info);
            }
        }
        return false;
    }

private:
    inline void set_msg_size(const CIFSv1::MessageHeader* header, const size_t length)
    {
        if ((header->cmd_code == CIFSv1::Commands::READ) || (header->cmd_code == CIFSv1::Commands::WRITE))
        {
            return BaseImpl::setToBeCopied(std::min(length, rw_hdr_max));
        }
        BaseImpl::setToBeCopied(length);
    }

    inline void set_msg_size(const CIFSv2::MessageHeader* header, const size_t length)
    {
        if (((header->cmd_code == SMBv2Commands::READ) || (header->cmd_code == SMBv2Commands::WRITE)) && !header->nextCommand)
        {
            return BaseImpl::setToBeCopied(std::min(length, rw_hdr_max));
        }
        BaseImpl::setToBeCopied(length);
    }

};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//CIFS_FILTRATOR_H
//------------------------------------------------------------------------------
