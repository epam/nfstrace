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
#include <cassert>

#include <pcap/pcap.h>

#include "filtration/packet.h"
#include "filtration/filtratorimpl.h"
#include "protocols/nfs3/nfs3_utils.h"
#include "protocols/nfs4/nfs4_utils.h"
#include "protocols/netbios/netbios.h"
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
template<typename Writer>
class RPCFiltrator : private FiltratorImpl
{
    typename Writer::Collection collection;// storage for collection packet data
public:
    RPCFiltrator()
    : collection{}
    {
        reset();
    }

    RPCFiltrator(RPCFiltrator&&)                 = delete;
    RPCFiltrator(const RPCFiltrator&)            = delete;
    RPCFiltrator& operator=(const RPCFiltrator&) = delete;

    inline void reset()
    {
        FiltratorImpl::resetImpl();
        collection.reset();
    }

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t max_rpc_hdr)
    {
        assert(w);
        collection.set(*w, session_ptr);
        nfs3_rw_hdr_max = max_rpc_hdr;
    }

    inline constexpr static size_t lengthOfBaseHeader()
    {
        return sizeof(RecordMark) + sizeof(MessageHeader);
    }

    inline constexpr static size_t lengthOfReplyHeader()
    {
        return sizeof(RecordMark) + sizeof(ReplyHeader);
    }

    inline constexpr static size_t lengthOfCallHeader()
    {
        return sizeof(RecordMark) + sizeof(CallHeader);
    }

    inline static bool isRightHeader(const uint8_t* header)
    {
        const RecordMark* rm {reinterpret_cast<const RecordMark*>(header)};
        if ((rm->fragment()->type() == MsgType::REPLY ) || (rm->fragment()->type() == MsgType::CALL ))
        {
            return true;
        }
        return false;
    }

    inline bool inProgress(PacketInfo& info)
    {
        return FiltratorImpl::inProgressImpl<lengthOfBaseHeader(), isRightHeader>(info, collection, this);
    }

    inline void lost(const uint32_t n) // we are lost n bytes in sequence
    {
        return FiltratorImpl::lost(n, this);
    }

    inline constexpr static size_t lengthOfFirstSkipedPart()
    {
        return sizeof(RecordMark);
    }

    inline void push(PacketInfo& info)
    {
        return FiltratorImpl::push(info, collection, this);
    }

    inline bool collect_header(PacketInfo& info)
    {
        return FiltratorImpl::collect_header<lengthOfCallHeader(), lengthOfReplyHeader()>(info, collection);
    }

    inline bool find_and_read_message(PacketInfo& info)
    {
        const RecordMark* rm {reinterpret_cast<const RecordMark*>(collection.data())};
        //if(rm->is_last()); // TODO: handle sequence field of record mark
        if(collection.data_size() < (sizeof(CallHeader) + sizeof(RecordMark)) && (rm->fragment())->type() != MsgType::REPLY ) // if message not Reply, try collect the rest for Call
        {
            return true;
        }
        if(rm->fragment_len() >= sizeof(ReplyHeader)) // incorrect fragment len, not valid rpc message
        {
            if(validate_header(rm->fragment(), rm->fragment_len() + sizeof(RecordMark) ) )
            {
                return FiltratorImpl::read_message(info, collection, this);
            }
        }
        return false;
    }

    inline void find_message(PacketInfo& info)
    {
        return FiltratorImpl::find_message(info, collection, this);
    }

    inline bool validate_header(const MessageHeader*const msg, const uint32_t len)
    {
        switch(msg->type())
        {
            case MsgType::CALL:
            {
                auto call = static_cast<const CallHeader*const>(msg);
                if(RPCValidator::check(call))
                {
                    FiltratorImpl::setMsgLen(len);   // length of current RPC message
                    if(protocols::NFS3::Validator::check(call))
                    {
                        uint32_t proc {call->proc()};
                        if (API::ProcEnumNFS3::WRITE == proc) // truncate NFSv3 WRITE call message to NFSv3-RW-limit
                            FiltratorImpl::setToBeCopied(nfs3_rw_hdr_max < len ? nfs3_rw_hdr_max : len);
                        else
                        {
                            if (API::ProcEnumNFS3::READ == proc)
                                nfs3_read_match.insert(call->xid());
                            FiltratorImpl::setToBeCopied(len);
                        }
                        //TRACE("%p| MATCH RPC Call  xid:%u len: %u procedure: %u", this, call->xid(), msg_len, call->proc());
                    }
                    else if (protocols::NFS4::Validator::check(call))
                    {
                        FiltratorImpl::setToBeCopied(len);
                    }
                    else
                    {
                        //* RPC call message must be read out ==> msg_len !=0
                        FiltratorImpl::setToBeCopied(0);// don't collect headers of unknown calls
                        //TRACE("Unknown RPC call of program: %u version: %u procedure: %u", call->prog(), call->vers(), call->proc());
                    }
                    return true;
                }
                else
                {
                    return false;   // isn't RPC Call, stream is corrupt
                }
            }
            break;
            case MsgType::REPLY:
            {
                auto reply = static_cast<const ReplyHeader*const>(msg);
                if(RPCValidator::check(reply))
                {
                    FiltratorImpl::setMsgLen(len);   // length of current RPC message
                    // Truncate NFSv3 READ reply message to NFSv3-RW-limit
                    //* Collect fully if reply received before matching call
                    if (nfs3_read_match.erase(reply->xid()) > 0)
                    {
                        FiltratorImpl::setToBeCopied(nfs3_rw_hdr_max < len ? nfs3_rw_hdr_max : len);
                    }
                    else
                    {
                        FiltratorImpl::setToBeCopied(len);// length of current RPC message
                    }
                    //TRACE("%p| MATCH RPC Reply xid:%u len: %u", this, reply->xid(), msg_len);
                    return true;
                }
                else // isn't RPC reply, stream is corrupt
                {
                    FiltratorImpl::setMsgLen(0);
                    FiltratorImpl::setToBeCopied(0);
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
    size_t nfs3_rw_hdr_max {512}; // limit for NFSv3 to truncate WRITE call and READ reply messages
    MessageSet nfs3_read_match;
};

} // analysis
} // NST
//------------------------------------------------------------------------------
#endif // RPC_FILTRATOR_H
//------------------------------------------------------------------------------
