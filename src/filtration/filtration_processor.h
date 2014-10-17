//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Generic processor for filtration raw pcap packets.
// TODO: THIS CODE MUST BE TOTALLY REFACTORED!
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
#ifndef FILTRATION_PROCESSOR_H
#define FILTRATION_PROCESSOR_H
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
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{

using namespace NST::protocols::rpc;

/*
 *  uint32_t: Message XID (Call or Reply)
 */
typedef std::unordered_set<uint32_t> MessageSet;
typedef MessageSet::const_iterator  ConstIterator;
typedef MessageSet::iterator        Iterator;
typedef MessageSet::value_type      Pair;

// Represents UDP datagrams interchange between node A and node B
template <typename Writer>
struct UDPSession : public utils::NetworkSession
{
public:
    UDPSession(Writer* w, uint32_t max_rpc_hdr)
    : collection{w, this}
    , nfs3_rw_hdr_max{max_rpc_hdr}
    {
    }
    UDPSession(UDPSession&&)                 = delete;
    UDPSession(const UDPSession&)            = delete;
    UDPSession& operator=(const UDPSession&) = delete;

    void collect(PacketInfo& info)
    {
        // TODO: this code must be generalized with RPCFiltrator class
        uint32_t hdr_len = 0;
        auto msg = reinterpret_cast<const MessageHeader*const>(info.data);
        switch(msg->type())
        {
            case MsgType::CALL:
            {
                auto call = static_cast<const CallHeader*const>(msg);
                if(RPCValidator::check(call))
                {
                    if (NFS3::Validator::check(call))
                    {
                        uint32_t proc = call->proc();
                        if (API::ProcEnumNFS3::WRITE == proc) // truncate NFSv3 WRITE call message to NFSv3-RW-limit
                            hdr_len = (nfs3_rw_hdr_max < info.dlen ? nfs3_rw_hdr_max : info.dlen);
                        else
                        {
                            if (API::ProcEnumNFS3::READ == proc)
                                nfs3_read_match.insert(call->xid());
                            hdr_len = info.dlen;
                        }
                    }
                    else if (NFS4::Validator::check(call))
                    {
                        hdr_len = info.dlen; // fully collect NFSv4 messages
                    }
                    else
                    {
                        return;
                    }
                }
                else
                {
                    return;
                }
            }
            break;
            case MsgType::REPLY:
            {
                auto reply = static_cast<const ReplyHeader*const>(msg);
                if(RPCValidator::check(reply))
                {
                    // Truncate NFSv3 READ reply message to NFSv3-RW-limit
                    //* Collect fully if reply received before matching call
                    if (nfs3_read_match.erase(reply->xid()) > 0)
                    {
                        hdr_len = (nfs3_rw_hdr_max < info.dlen ? nfs3_rw_hdr_max : info.dlen);
                    }
                    else
                        hdr_len = info.dlen;
                }
                else // isn't RPC reply, stream is corrupt
                {
                    return;
                }
            }
            break;
            default:
                return;
        }

        collection.allocate();

        collection.push(info, hdr_len);

        collection.complete(info);
    }

    typename Writer::Collection collection;
    uint32_t nfs3_rw_hdr_max;
    MessageSet nfs3_read_match;
};

// Represents TCP conversation between node A and node B
template <typename StreamReader>
class TCPSession : public utils::NetworkSession
{
public:

    struct Flow
    {
        // Helpers for comparison sequence numbers
        // Idea for gt: either x > y, or y is much bigger (assume wrap)
        inline static bool GT_SEQ(uint32_t x, uint32_t y){ return (int32_t)((y) - (x)) <  0; }
        inline static bool LT_SEQ(uint32_t x, uint32_t y){ return (int32_t)((x) - (y)) <  0; }
        inline static bool GE_SEQ(uint32_t x, uint32_t y){ return (int32_t)((y) - (x)) <= 0; }
        inline static bool LE_SEQ(uint32_t x, uint32_t y){ return (int32_t)((x) - (y)) <= 0; }
        inline static bool EQ_SEQ(uint32_t x, uint32_t y){ return           (x) ==(y);       }

        friend class TCPSession<StreamReader>;

        Flow() : fragments(NULL), sequence(0)
        {
        }
        ~Flow()
        {
            reset();
        }
        Flow(Flow&&)                 = delete;
        Flow(const Flow&)            = delete;
        Flow& operator=(const Flow&) = delete;

        void reset()
        {
            reader.reset(); // reset state of Reader
            while(fragments)
            {
                Packet* c = fragments;
                fragments = c->next;
                Packet::destroy(c);
            }

            sequence = 0;
        }

        void reassemble(PacketInfo& info)
        {
            uint32_t seq = info.tcp->seq();
            uint32_t len = info.dlen;

            if( sequence == 0 ) // this is the first time we have seen this src's sequence number
            {
                sequence = seq + len;
                if( info.tcp->is(tcp_header::SYN) )
                {
                    sequence++;
                }

                if(len > 0)
                {
                    reader.push(info);  // write out the packet data
                }

                return;
            }

            // if we are here, we have already seen this src, let's
            // try and figure out if this packet is in the right place
            if( LT_SEQ(seq, sequence) )
            {
                // this sequence number seems dated, but
                // check the end to make sure it has no more
                // info than we have already seen
                uint32_t newseq = seq + len;
                if( GT_SEQ(newseq, sequence) )
                {

                    // this one has more than we have seen. let's get the
                    // payload that we have not seen
                    uint32_t new_len = sequence - seq;

                    if ( info.dlen <= new_len )
                    {
                        info.data = NULL;
                        info.dlen = 0;
                    }
                    else
                    {
                        assert(info.dlen >= new_len);
                        info.data += new_len;
                        info.dlen -= new_len;
                    }

                    seq = sequence;
                    len = newseq - sequence;

                    // this will now appear to be right on time :)
                }
            }

            if ( EQ_SEQ(seq, sequence) ) // right on time
            {
                sequence += len;
                if( info.tcp->is(tcp_header::SYN) ) sequence++;

                if( info.data && info.dlen > 0)
                {
                    reader.push(info);
                }
                // done with the packet, see if it caused a fragment to fit
                while( check_fragments(0) );
            }
            else // out of order packet
            {
                if(info.dlen > 0 && GT_SEQ(seq, sequence) )
                {
                    //TRACE("ADD FRAGMENT seq: %u dlen: %u sequence: %u", seq, info.dlen, sequence);
                    fragments = Packet::create(info, fragments);
                }
            }
        }

        bool check_fragments(const uint32_t acknowledged)
        {
            Packet* current = fragments;
            if( current )
            {
                Packet* prev = NULL;
                uint32_t lowest_seq = current->tcp->seq();
                while( current )
                {
                    const uint32_t current_seq = current->tcp->seq();
                    const uint32_t current_len = current->dlen;

                    if( GT_SEQ(lowest_seq, current_seq) ) // lowest_seq > current_seq
                    {
                        lowest_seq = current_seq;
                    }

                    if( LT_SEQ(current_seq, sequence) ) // current_seq < sequence
                    {
                        // this sequence number seems dated, but
                        // check the end to make sure it has no more
                        // info than we have already seen
                        uint32_t newseq = current_seq + current_len;
                        if( GT_SEQ(newseq, sequence) )
                        {
                            // this one has more than we have seen. let's get the
                            // payload that we have not seen. This happens when
                            // part of this frame has been retransmitted
                            uint32_t new_pos = sequence - current_seq;

                            sequence += (current_len - new_pos);

                            if ( current->dlen > new_pos )
                            {
                                current->data += new_pos;
                                current->dlen -= new_pos;
                                reader.push(*current);
                            }
                        }

                        // Remove the fragment from the list as the "new" part of it
                        // has been processed or its data has been seen already in 
                        // another packet.
                        if( prev )
                        {
                            prev->next = current->next;
                        }
                        else
                        {
                            fragments = current->next;
                        }

                        Packet::destroy(current);

                        return true;
                    }

                    if( EQ_SEQ(current_seq, sequence) )
                    {
                        // this fragment fits the stream
                        sequence += current_len;
                        if( prev )
                        {
                            prev->next = current->next;
                        }
                        else
                        {
                            fragments = current->next;
                        }

                        reader.push(*current);
                        Packet::destroy(current);

                        return true;
                    }
                    prev = current;
                    current = current->next;
                }// end while

                if( GT_SEQ(acknowledged, lowest_seq) )  // acknowledged > lowest_seq
                {
                    //TRACE("acknowledged(%u) > lowest_seq(%u) seq:%u", acknowledged, lowest_seq, sequence);
                    // There are frames missing in the capture stream that were seen
                    // by the receiving host. Inform stream about it.
                    reader.lost(lowest_seq - sequence);
                    sequence = lowest_seq;
                    return true;
                }
            }

            return false;
        }

    private:
        StreamReader    reader;     // reader of acknowledged data stream
        Packet*         fragments;  // list of not yet acked fragments
        uint32_t        sequence;
    };

    template <typename Writer>
    TCPSession(Writer* w, uint32_t max_rpc_hdr)
    {
        flows[0].reader.set_writer(this, w, max_rpc_hdr);
        flows[1].reader.set_writer(this, w, max_rpc_hdr);
    }
    TCPSession(TCPSession&&)                 = delete;
    TCPSession(const TCPSession&)            = delete;
    TCPSession& operator=(const TCPSession&) = delete;

    void collect(PacketInfo& info)
    {
        const uint32_t ack = info.tcp->ack();

        //check whether this frame acks fragments that were already seen.
        while( flows[1-info.direction].check_fragments(ack) );

        flows[info.direction].reassemble(info);
    }

    Flow flows[2];
};


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
                        msg_len = 0; find_message(info); // <- optimization
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
                        hdr_len -= hdr_len; // set 0

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
        static const size_t max_header = sizeof(RecordMark) + sizeof(CallHeader);
        static const size_t max_reply_header = sizeof(RecordMark) + sizeof(ReplyHeader);

        if(collection && (collection.data_size() > 0)) // collection is allocated
        {
            assert(collection.capacity() >= max_header);
            const uint32_t tocopy = max_header - collection.data_size();
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
            return;

        assert(collection);     // collection must be initialized

        const RecordMark* rm = reinterpret_cast<const RecordMark*>(collection.data());
        //if(rm->is_last()); // TODO: handle sequence field of record mark
        if(rm->fragment_len())
        {
            if(collection.data_size() < (sizeof(CallHeader) + sizeof(RecordMark)) && (rm->fragment())->type() != MsgType::REPLY ) // if message not Reply, try collect the rest for Call
            {
                return;
            }
            if(rm->fragment_len() < sizeof(ReplyHeader)) // incorrect fragment len, not valid rpc message
            {
                TRACE("Incorrect fragment len. Not valid rpc message.");
                assert(msg_len == 0);   // message is not found
                assert(hdr_len == 0);   // header should be skipped
                collection.reset();     // skip collected data
                info.dlen = 0;
                return;
            }
            if(validate_header(rm->fragment(), rm->fragment_len() + sizeof(RecordMark) ) )
            {
                assert(msg_len != 0);   // message is found
                assert(msg_len >= collection.data_size());
                assert(hdr_len <= msg_len);
                const uint32_t written = collection.data_size();
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
                        uint32_t proc = call->proc();
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
    uint32_t    nfs3_rw_hdr_max=512; // limit for NFSv3 to truncate WRITE call and READ reply messages
    uint32_t    msg_len;  // length of current RPC message + RM
    uint32_t    hdr_len;  // length of readable piece of RPC message. Initially msg_len or 0 in case of unknown msg

    typename Writer::Collection collection;// storage for collection packet data
    MessageSet nfs3_read_match;
};

template
<
    typename Reader,
    typename Writer
>
class FiltrationProcessor
{
public:

    explicit FiltrationProcessor(std::unique_ptr<Reader>& r,
                                 std::unique_ptr<Writer>& w)
    : reader{std::move(r)}
    , writer{std::move(w)}
    , ipv4_tcp_sessions{writer.get()}
    , ipv4_udp_sessions{writer.get()}
    , ipv6_tcp_sessions{writer.get()}
    , ipv6_udp_sessions{writer.get()}
    {
        // check datalink layer
        datalink = reader->datalink();
        if(datalink != DLT_EN10MB)
        {
            throw std::runtime_error(std::string("Unsupported Data Link Layer: ") + Reader::datalink_description(datalink));
        }
    }
    ~FiltrationProcessor()
    {
        utils::Out message;
        reader->print_statistic(message);
    }

    void run()
    {
        bool done = reader->loop(this, callback);
        if(done)
        {
            throw controller::ProcessingDone("Filtration is done");
        }
    }

    void stop()
    {
        reader->break_loop();
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        auto processor = reinterpret_cast<FiltrationProcessor*>(user);

        PacketInfo info(pkthdr, packet, processor->datalink);

        if(info.tcp)
        {
            if(pkthdr->caplen != pkthdr->len)
            {
                LOGONCE("pcap packet was truncated by snaplen option this "
                        "packed won't correclty reassembled to TCP stream");
                return;
            }

            if(info.ipv4)       // Ethernet:IPv4:TCP
            {
                return processor->ipv4_tcp_sessions.collect_packet(info);
            }
            else if(info.ipv6)  // Ethernet:IPv6:TCP
            {
                return processor->ipv6_tcp_sessions.collect_packet(info);
            }
        }
        else if(info.udp)
        {
            if(info.ipv4)       // Ethernet:IPv4:UDP
            {
                return processor->ipv4_udp_sessions.collect_packet(info);
            }
            else if(info.ipv6)  // Ethernet:IPv6:UDP
            {
                return processor->ipv6_udp_sessions.collect_packet(info);
            }
        }

        LOGONCE("only following stack of protocol is supported: "
                "Ethernet II:IPv4|IPv6(except additional fragments):TCP|UDP");
    }

private:

    std::unique_ptr<Reader> reader;
    std::unique_ptr<Writer> writer;

    SessionsHash< IPv4TCPMapper, TCPSession < RPCFiltrator < Writer > > , Writer > ipv4_tcp_sessions;
    SessionsHash< IPv4UDPMapper, UDPSession < Writer > , Writer >                  ipv4_udp_sessions;

    SessionsHash< IPv6TCPMapper, TCPSession < RPCFiltrator < Writer > > , Writer > ipv6_tcp_sessions;
    SessionsHash< IPv6UDPMapper, UDPSession < Writer > , Writer >                  ipv6_udp_sessions;

    int datalink;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTRATION_PROCESSOR_H
//------------------------------------------------------------------------------
