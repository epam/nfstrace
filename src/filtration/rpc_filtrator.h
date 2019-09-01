//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: RPC filtrator
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
#ifndef RPC_FILTRATOR_H
#define RPC_FILTRATOR_H
//------------------------------------------------------------------------------
#include <algorithm>
#include <cassert>

#include <pcap/pcap.h>

#include "filtration/filtratorimpl.h"
#include "protocols/netbios/netbios.h"
#include "protocols/nfs3/nfs3_utils.h"
#include "protocols/nfs4/nfs4_utils.h"
#include "protocols/rpc/rpc_header.h"
#include "utils/log.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
/*
    Stateful reader of Sun RPC messages
    Reads data from PacketInfo passed via push() method
    aggregates length of current RPC message and length of RPC message useful for analysis
    TODO: add matching Calls and replies by XID of message
*/
template <typename Writer>
class RPCFiltrator final : public FiltratorImpl<RPCFiltrator<Writer>, Writer>
{
    using BaseImpl = FiltratorImpl<RPCFiltrator<Writer>, Writer>;

public:
    RPCFiltrator() = default;

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t max_rpc_hdr)
    {
        assert(w);
        nfs3_rw_hdr_max = max_rpc_hdr;
        BaseImpl::setWriterImpl(session_ptr, w, max_rpc_hdr);
    }

    constexpr static size_t lengthOfBaseHeader()
    {
        return sizeof(RecordMark) + sizeof(ReplyHeader); // Minimum of replay&call headers
    }

    constexpr static size_t lengthOfReplyHeader()
    {
        return sizeof(RecordMark) + sizeof(ReplyHeader);
    }

    constexpr static size_t lengthOfCallHeader()
    {
        return sizeof(RecordMark) + sizeof(CallHeader);
    }

    inline static bool isRightHeader(const uint8_t* header)
    {
        const RecordMark*          rm{reinterpret_cast<const RecordMark*>(header)};
        const MessageHeader* const msg = rm->fragment();
        if(msg->type() == MsgType::REPLY)
        {
            return RPCValidator::check(static_cast<const ReplyHeader*>(msg));
        }
        if(msg->type() == MsgType::CALL)
        {
            return RPCValidator::check(static_cast<const CallHeader*>(msg));
        }
        return false;
    }

    inline constexpr static size_t lengthOfFirstSkipedPart()
    {
        return sizeof(RecordMark);
    }

    inline bool collect_header(PacketInfo& info, typename Writer::Collection&)
    {
        return BaseImpl::collect_header(info, lengthOfCallHeader(), lengthOfReplyHeader());
    }

    inline bool find_and_read_message(PacketInfo& info, typename Writer::Collection& collection)
    {
        const RecordMark* rm{reinterpret_cast<const RecordMark*>(collection.data())};
        //if(rm->is_last()); // TODO: handle sequence field of record mark
        if(collection.data_size() < (sizeof(CallHeader) + sizeof(RecordMark)) && (rm->fragment())->type() != MsgType::REPLY) // if message not Reply, try collect the rest for Call
        {
            return true;
        }
        if(rm->fragment_len() >= sizeof(ReplyHeader)) // incorrect fragment len, not valid rpc message
        {
            if(validate_header(rm->fragment(), rm->fragment_len() + sizeof(RecordMark)))
            {
                return BaseImpl::read_message(info);
            }
        }
        return false;
    }

    inline bool validate_header(const MessageHeader* const msg, const size_t len)
    {
        switch(msg->type())
        {
        case MsgType::CALL:
        {
            auto call = static_cast<const CallHeader*>(msg);
            if(RPCValidator::check(call))
            {
                BaseImpl::setMsgLen(len); // length of current RPC message
                if(protocols::NFS3::Validator::check(call))
                {
                    uint32_t proc{call->proc()};
                    if(API::ProcEnumNFS3::WRITE == proc) // truncate NFSv3 WRITE call message to NFSv3-RW-limit
                    {
                        BaseImpl::setToBeCopied(nfs3_rw_hdr_max < len ? nfs3_rw_hdr_max : len);
                    }
                    else
                    {
                        if(API::ProcEnumNFS3::READ == proc)
                        {
                            nfs3_read_match.insert(call->xid());
                        }
                        BaseImpl::setToBeCopied(len);
                    }
                    //TRACE("%p| MATCH RPC Call  xid:%u len: %u procedure: %u", this, call->xid(), msg_len, call->proc());
                }
                else if(protocols::NFS4::Validator::check(call))
                {
                    BaseImpl::setToBeCopied(len);
                }
                else
                {
                    //* RPC call message must be read out ==> msg_len !=0
                    BaseImpl::setToBeCopied(0); // don't collect headers of unknown calls
                    //TRACE("Unknown RPC call of program: %u version: %u procedure: %u", call->prog(), call->vers(), call->proc());
                }
                return true;
            }
            else
            {
                return false; // isn't RPC Call, stream is corrupt
            }
        }
        break;
        case MsgType::REPLY:
        {
            auto reply = static_cast<const ReplyHeader*>(msg);
            if(RPCValidator::check(reply))
            {
                BaseImpl::setMsgLen(len); // length of current RPC message
                // Truncate NFSv3 READ reply message to NFSv3-RW-limit
                //* Collect fully if reply received before matching call
                if(nfs3_read_match.erase(reply->xid()) > 0)
                {
                    BaseImpl::setToBeCopied(std::min(nfs3_rw_hdr_max, len));
                }
                else
                {
                    BaseImpl::setToBeCopied(len); // length of current RPC message
                }
                //TRACE("%p| MATCH RPC Reply xid:%u len: %u", this, reply->xid(), msg_len);
                return true;
            }
            else // isn't RPC reply, stream is corrupt
            {
                BaseImpl::setMsgLen(0);
                BaseImpl::setToBeCopied(0);
                return false;
            }
        }
        break;
        default:
        {
            //isn't RPC message
        }
        break;
        }

        return false;
    }

private:
    size_t     nfs3_rw_hdr_max{512}; // limit for NFSv3 to truncate WRITE call and READ reply messages
    MessageSet nfs3_read_match;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif // RPC_FILTRATOR_H
//------------------------------------------------------------------------------
