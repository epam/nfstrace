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
class RPCFiltrator
{
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
        msg_len = 0;
        hdr_len = 0;
        collection.reset(); // data in external memory freed
    }

    inline void set_writer(utils::NetworkSession* session_ptr, Writer* w, uint32_t max_rpc_hdr)
    {
        assert(w);
        collection.set(*w, session_ptr);
        nfs3_rw_hdr_max = max_rpc_hdr;
    }

    inline bool inProgress(PacketInfo& info)
    {
        static const size_t header_len = sizeof(RecordMark) + sizeof(MessageHeader);

        if (msg_len || hdr_len)
        {
            return true;
        }

        if (!collection) // collection isn't allocated
        {
            collection.allocate(); // allocate new collection from writer
        }
        const size_t data_size = collection.data_size();

        if (data_size + info.dlen > header_len)
        {
            static uint8_t buffer[header_len];
            const uint8_t* header = info.data;

            if (data_size > 0)
            {
                memcpy(buffer, collection.data(), data_size);
                memcpy(buffer + data_size, info.data, header_len - data_size);
                header = buffer;
            }

            const RecordMark* rm {reinterpret_cast<const RecordMark*>(header)};
            if ((rm->fragment()->type() == MsgType::REPLY ) || (rm->fragment()->type() == MsgType::CALL ))
            {
                return true;
            }
            reset();
        }
        else
        {
            collection.push(info, info.dlen);
        }

        return false;
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
                if(!hdr_len)    // message header is readout, discard the unused tail of message
                {
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
                else // hdr_len != 0, readout a part of header of current message
                {
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

                        // we should remove RM(uin32_t) from collected data
                        collection.skip_first(sizeof(RecordMark));

                        collection.complete(info);    // push complete message to queue
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
        static const size_t max_header       {sizeof(RecordMark) + sizeof(CallHeader) };
        static const size_t max_reply_header {sizeof(RecordMark) + sizeof(ReplyHeader)};

        if(collection && (collection.data_size() > 0)) // collection is allocated
        {
            assert(collection.capacity() >= max_header);
            const size_t tocopy {max_header - collection.data_size()};
            assert(tocopy != 0);
            if(info.dlen < tocopy)
            {
                collection.push(info, info.dlen);
                //info.data += info.dlen;   optimization
                info.dlen = 0;
                return false;
            }
            else // info.dlen >= tocopy
            {
                collection.push(info, tocopy); // collection.data_size <= max_header
                info.dlen -= tocopy;
                info.data += tocopy;
            }
        }
        else // collection is empty
        {
            collection.allocate(); // allocate new collection from writer
            if(info.dlen >= max_header) // is data enough to message validation?
            {
                collection.push(info, max_header); // probability that message will be rejected / probability of valid message
                info.data += max_header;
                info.dlen -= max_header;
            }
            else // (info.dlen < max_header)
            {
                collection.push(info, info.dlen);
                //info.data += info.dlen;   optimization
                return (info.dlen < max_reply_header ? (info.dlen = 0, false):(info.dlen = 0, true) );
            }
        }
        return true;
    }

    // Find next message in packet info
    inline void find_message(PacketInfo& info)
    {
        assert(msg_len == 0);   // RPC Message still undetected

        if (!collect_header(info))
        {
            return;
        }

        assert(collection);     // collection must be initialized

        const RecordMark* rm {reinterpret_cast<const RecordMark*>(collection.data())};
        //if(rm->is_last()); // TODO: handle sequence field of record mark
        if(collection.data_size() < (sizeof(CallHeader) + sizeof(RecordMark)) && (rm->fragment())->type() != MsgType::REPLY ) // if message not Reply, try collect the rest for Call
        {
            return;
        }
        if(rm->fragment_len() >= sizeof(ReplyHeader)) // incorrect fragment len, not valid rpc message
        {
            if(validate_header(rm->fragment(), rm->fragment_len() + sizeof(RecordMark) ) )
            {
                assert(msg_len != 0);   // message is found
                assert(msg_len >= collection.data_size());
                assert(hdr_len <= msg_len);
                const size_t written {collection.data_size()};
                msg_len -= written; // substract how written (if written)
                hdr_len -= std::min(hdr_len, written);
                if (0 == hdr_len)   // Avoid infinity loop when "msg len" == "data size(collection) (max_header)" {msg_len >= hdr_len}
                                    // Next find message call will finding next message
                {
                    collection.skip_first(sizeof(RecordMark));
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

    inline bool validate_header(const MessageHeader*const msg, const uint32_t len)
    {
        switch(msg->type())
        {
            case MsgType::CALL:
            {
                auto call = static_cast<const CallHeader*const>(msg);
                if(RPCValidator::check(call))
                {
                    msg_len = len;   // length of current RPC message
                    if(NFS3::Validator::check(call))
                    {
                        uint32_t proc {call->proc()};
                        if (API::ProcEnumNFS3::WRITE == proc) // truncate NFSv3 WRITE call message to NFSv3-RW-limit
                            hdr_len = (nfs3_rw_hdr_max < msg_len ? nfs3_rw_hdr_max : msg_len);
                        else
                        {
                            if (API::ProcEnumNFS3::READ == proc)
                                nfs3_read_match.insert(call->xid());
                            hdr_len = msg_len;
                        }
                        //TRACE("%p| MATCH RPC Call  xid:%u len: %u procedure: %u", this, call->xid(), msg_len, call->proc());
                    }
                    else if (NFS4::Validator::check(call))
                    {
                        hdr_len = msg_len;  // fully collect of NFSv4 messages
                    }
                    else
                    {
                        //* RPC call message must be read out ==> msg_len !=0
                        hdr_len = 0; // don't collect headers of unknown calls
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
                    msg_len = len;
                    // Truncate NFSv3 READ reply message to NFSv3-RW-limit
                    //* Collect fully if reply received before matching call
                    if (nfs3_read_match.erase(reply->xid()) > 0)
                    {
                        hdr_len = (nfs3_rw_hdr_max < msg_len ? nfs3_rw_hdr_max : msg_len);
                    }
                    else
                        hdr_len = msg_len; // length of current RPC message
                    //TRACE("%p| MATCH RPC Reply xid:%u len: %u", this, reply->xid(), msg_len);
                    return true;
                }
                else // isn't RPC reply, stream is corrupt
                {
                    msg_len = 0;
                    hdr_len = 0;
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
    size_t msg_len;  // length of current RPC message + RM
    size_t hdr_len;  // length of readable piece of RPC message. Initially msg_len or 0 in case of unknown msg

    typename Writer::Collection collection;// storage for collection packet data
    MessageSet nfs3_read_match;
};

} // analysis
} // NST
//------------------------------------------------------------------------------
#endif // RPC_FILTRATOR_H
//------------------------------------------------------------------------------
