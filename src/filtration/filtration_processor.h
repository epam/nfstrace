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

#include "controller/parameters.h"
#include "filtration/packet.h"
#include "filtration/sessions_hash.h"
#include "protocols/nfs3/nfs3_utils.h"
#include "protocols/nfs4/nfs4_utils.h"
#include "protocols/rpc/rpc_header.h"
#include "utils/log.h"
#include "utils/noncopyable.h"
#include "utils/out.h"
#include "utils/profiler.h"
#include "utils/sessions.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace filtration
{
using namespace NST::protocols::rpc; //FIXME: It is not good to use "using" in headers - should be removed
using ProcEnumNFS3  = API::ProcEnumNFS3;
using NFS3Validator = NST::protocols::NFS3::Validator;
using NFS4Validator = NST::protocols::NFS4::Validator;

/*
 *  uint32_t: Message XID (Call or Reply)
 */
typedef std::unordered_set<uint32_t> MessageSet;
typedef MessageSet::const_iterator   ConstIterator;
typedef MessageSet::iterator         Iterator;
typedef MessageSet::value_type       Pair;

// Represents UDP datagrams interchange between node A and node B
template <typename Writer>
struct UDPSession final : utils::noncopyable, public utils::NetworkSession
{
public:
    UDPSession(Writer* w, uint32_t max_rpc_hdr)
        : collection{w, this}
        , nfs3_rw_hdr_max{max_rpc_hdr}
    {
    }

    void collect(PacketInfo& info)
    {
        // TODO: this code must be generalized with RPCFiltrator class
        uint32_t hdr_len{0};
        auto     msg = reinterpret_cast<const MessageHeader* const>(info.data);
        switch(msg->type())
        {
        case MsgType::CALL:
        {
            auto call = static_cast<const CallHeader* const>(msg);
            if(RPCValidator::check(call))
            {
                if(NFS3Validator::check(call))
                {
                    uint32_t proc{call->proc()};
                    if(ProcEnumNFS3::WRITE == proc) // truncate NFSv3 WRITE call message to NFSv3-RW-limit
                    {
                        hdr_len = (nfs3_rw_hdr_max < info.dlen ? nfs3_rw_hdr_max : info.dlen);
                    }
                    else
                    {
                        if(ProcEnumNFS3::READ == proc)
                            nfs3_read_match.insert(call->xid());
                        hdr_len = info.dlen;
                    }
                }
                else if(NFS4Validator::check(call))
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
            auto reply = static_cast<const ReplyHeader* const>(msg);
            if(RPCValidator::check(reply))
            {
                // Truncate NFSv3 READ reply message to NFSv3-RW-limit
                //* Collect fully if reply received before matching call
                if(nfs3_read_match.erase(reply->xid()) > 0)
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
    uint32_t                    nfs3_rw_hdr_max;
    MessageSet                  nfs3_read_match;
};

// Represents TCP conversation between node A and node B
template <typename StreamReader>
class TCPSession final : utils::noncopyable, public utils::NetworkSession
{
public:
    struct Flow final : utils::noncopyable
    {
        // Helpers for comparison sequence numbers
        // Idea for gt: either x > y, or y is much bigger (assume wrap)
        inline static bool GT_SEQ(uint32_t x, uint32_t y) { return (int32_t)((y) - (x)) < 0; }
        inline static bool LT_SEQ(uint32_t x, uint32_t y) { return (int32_t)((x) - (y)) < 0; }
        inline static bool GE_SEQ(uint32_t x, uint32_t y) { return (int32_t)((y) - (x)) <= 0; }
        inline static bool LE_SEQ(uint32_t x, uint32_t y) { return (int32_t)((x) - (y)) <= 0; }
        inline static bool EQ_SEQ(uint32_t x, uint32_t y) { return (x) == (y); }
        friend class TCPSession<StreamReader>;

        Flow() = default;
        ~Flow()
        {
            reset();
        }

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
            uint32_t seq{info.tcp->seq()};
            uint32_t len{info.dlen};

            if(sequence == 0) // this is the first time we have seen this src's sequence number
            {
                sequence = seq + len;
                if(info.tcp->is(tcp_header::SYN))
                {
                    sequence++;
                }

                if(len > 0)
                {
                    reader.push(info); // write out the packet data
                }

                return;
            }

            // if we are here, we have already seen this src, let's
            // try and figure out if this packet is in the right place
            if(LT_SEQ(seq, sequence))
            {
                // this sequence number seems dated, but
                // check the end to make sure it has no more
                // info than we have already seen
                uint32_t newseq{seq + len};
                if(GT_SEQ(newseq, sequence))
                {
                    // this one has more than we have seen. let's get the
                    // payload that we have not seen
                    uint32_t new_len{sequence - seq};

                    if(info.dlen <= new_len)
                    {
                        info.data = nullptr;
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

            if(EQ_SEQ(seq, sequence)) // right on time
            {
                sequence += len;
                if(info.tcp->is(tcp_header::SYN)) sequence++;

                if(info.data && info.dlen > 0)
                {
                    reader.push(info);
                }
                // done with the packet, see if it caused a fragment to fit
                while(check_fragments(0))
                    ;
            }
            else // out of order packet
            {
                if(info.dlen > 0 && GT_SEQ(seq, sequence))
                {
                    //TRACE("ADD FRAGMENT seq: %u dlen: %u sequence: %u", seq, info.dlen, sequence);
                    fragments = Packet::create(info, fragments);
                }
            }
        }

        bool check_fragments(const uint32_t acknowledged)
        {
            Packet* current{fragments};
            if(current)
            {
                Packet*  prev{nullptr};
                uint32_t lowest_seq{current->tcp->seq()};
                while(current)
                {
                    const uint32_t current_seq{current->tcp->seq()};
                    const uint32_t current_len{current->dlen};

                    if(GT_SEQ(lowest_seq, current_seq)) // lowest_seq > current_seq
                    {
                        lowest_seq = current_seq;
                    }

                    if(LT_SEQ(current_seq, sequence)) // current_seq < sequence
                    {
                        // this sequence number seems dated, but
                        // check the end to make sure it has no more
                        // info than we have already seen
                        uint32_t newseq{current_seq + current_len};
                        if(GT_SEQ(newseq, sequence))
                        {
                            // this one has more than we have seen. let's get the
                            // payload that we have not seen. This happens when
                            // part of this frame has been retransmitted
                            uint32_t new_pos{sequence - current_seq};

                            sequence += (current_len - new_pos);

                            if(current->dlen > new_pos)
                            {
                                current->data += new_pos;
                                current->dlen -= new_pos;
                                reader.push(*current);
                            }
                        }

                        // Remove the fragment from the list as the "new" part of it
                        // has been processed or its data has been seen already in
                        // another packet.
                        if(prev)
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

                    if(EQ_SEQ(current_seq, sequence))
                    {
                        // this fragment fits the stream
                        sequence += current_len;
                        if(prev)
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
                    prev    = current;
                    current = current->next;
                } // end while

                if(GT_SEQ(acknowledged, lowest_seq)) // acknowledged > lowest_seq
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
        StreamReader reader;    // reader of acknowledged data stream
        Packet*      fragments{nullptr}; // list of not yet acked fragments
        uint32_t     sequence{0};
    };

    template <typename Writer>
    TCPSession(Writer* w, uint32_t max_rpc_hdr)
    {
        flows[0].reader.set_writer(this, w, max_rpc_hdr);
        flows[1].reader.set_writer(this, w, max_rpc_hdr);
    }

    void collect(PacketInfo& info)
    {
        const uint32_t ack{info.tcp->ack()};

        //check whether this frame acks fragments that were already seen.
        while(flows[1 - info.direction].check_fragments(ack))
            ;

        flows[info.direction].reassemble(info);
    }

    Flow flows[2];
};

template <
    typename Reader,
    typename Writer,
    typename Filtrator>
class FiltrationProcessor final : utils::noncopyable
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
        bool done{reader->loop(this, callback)};
        if(done)
        {
            throw controller::ProcessingDone("Filtration is done");
        }
    }

    void stop()
    {
        reader->break_loop();
    }

    static void callback(u_char* user, const struct pcap_pkthdr* pkthdr, const u_char* packet)
    {
        PROF; // Calc how much time was spent in this func
        auto processor = reinterpret_cast<FiltrationProcessor*>(user);

        PacketInfo info(pkthdr, packet, processor->datalink);

        if(info.tcp)
        {
            if(pkthdr->caplen != pkthdr->len)
            {
                LOGONCE(
                    "pcap packet was truncated by snaplen option this "
                    "packed won't correclty reassembled to TCP stream");
                return;
            }

            if(info.ipv4) // Ethernet:IPv4:TCP
            {
                return processor->ipv4_tcp_sessions.collect_packet(info);
            }
            else if(info.ipv6) // Ethernet:IPv6:TCP
            {
                return processor->ipv6_tcp_sessions.collect_packet(info);
            }
        }
        else if(info.udp)
        {
            if(info.ipv4) // Ethernet:IPv4:UDP
            {
                return processor->ipv4_udp_sessions.collect_packet(info);
            }
            else if(info.ipv6) // Ethernet:IPv6:UDP
            {
                return processor->ipv6_udp_sessions.collect_packet(info);
            }
        }

        LOGONCE(
            "only following stack of protocol is supported: "
            "Ethernet II:IPv4|IPv6(except additional fragments):TCP|UDP");
    }

private:
    std::unique_ptr<Reader> reader;
    std::unique_ptr<Writer> writer;

    SessionsHash<IPv4TCPMapper, TCPSession<Filtrator>, Writer> ipv4_tcp_sessions;
    SessionsHash<IPv4UDPMapper, UDPSession<Writer>, Writer>    ipv4_udp_sessions;

    SessionsHash<IPv6TCPMapper, TCPSession<Filtrator>, Writer> ipv6_tcp_sessions;
    SessionsHash<IPv6UDPMapper, UDPSession<Writer>, Writer>    ipv6_udp_sessions;

    int datalink;
};

} // namespace filtration
} // namespace NST
//------------------------------------------------------------------------------
#endif // FILTRATION_PROCESSOR_H
//------------------------------------------------------------------------------
