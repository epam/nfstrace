//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Generic processor for filtration raw pcap packets.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
// TODO: THIS CODE MUST BE TOTALLY REFACTORED!
//------------------------------------------------------------------------------
#ifndef FILTRATION_PROCESSOR_H
#define FILTRATION_PROCESSOR_H
//------------------------------------------------------------------------------
#include <cassert>
#include <algorithm>
#include <memory>
#include <string>
#include <sstream>

#include <tr1/unordered_map>

#include <pcap/pcap.h>

#include "../../auxiliary/exception.h"
#include "../../auxiliary/filtered_data.h"
#include "../../controller/parameters.h"
#include "../packet_info.h"
#include "../conversation.h"
#include "../pcap/packet_dumper.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Exception;
using NST::auxiliary::FilteredData;
using NST::auxiliary::FilteredDataQueue;
using NST::filter::pcap::PacketDumper;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

struct Fragment
{
    Fragment* next;     // pointer to next fragment or NULL

    uint32_t seq;       // sequence number in host byte order
    uint32_t len;
    pcap_pkthdr pcap_header;
    uint32_t dlen;
    uint8_t* data;


    inline const uint8_t* pcap_packet() const { return (const uint8_t*)(this+1); }
    // caplen data of PCAP frame followed by this structure

    static Fragment* create(const PacketInfo& info)
    {
        Fragment* frag = (Fragment*) new uint8_t[sizeof(Fragment) + info.header->caplen];
        void* pcap_data = frag+1;
        memcpy(pcap_data, info.packet, info.header->caplen);
        frag->pcap_header   = *info.header;

        frag->seq           = info.tcp->seq();

        frag->len           = info.header->len;
        frag->data          = ((uint8_t*)pcap_data) + (info.data - info.packet);
        frag->dlen          = info.dlen;

        return frag;
    }

    static void destroy(Fragment* frag)
    {
        uint8_t* ptr = (uint8_t*)frag;
        delete[] ptr;
    }

private:
    Fragment(); // undefiend
};



class FragmentStream
{
public:
    FragmentStream(): first(NULL), last(NULL), length(0), discard(0)
    {
    }
    ~FragmentStream()
    {
        while(first)
        {
            Fragment* c = first;
            first = first->next;
            Fragment::destroy(c);
        }
    }

    inline operator bool() const { return first != NULL; }

    inline void lost(const uint32_t n) // we are lost n bytes in sequence
    {
        if(discard >= n) // discard whole new fragment
        {
            std::clog << "We are lost " << n << " bytes of payload marked for discard\n";
            discard -= n;
        }
        else
        {
            std::clog << "We are lost " << n - discard << " bytes of useful data\n";
            discard = 0;
        }
    }

    void push(PacketInfo& info)
    {
        assert(info.dlen != 0);

        if(discard)
        {
        //    std::clog << "discard new info: " << info.dlen << std::endl;
            if(discard >= info.dlen) // discard whole new fragment
            {
                discard -= info.dlen;
                return;
            }
            else  // discard part of new fragment payload
            {
                info.dlen -= discard;
                info.data += discard;
                discard = 0;
            }
        }

        Fragment* fragment = Fragment::create(info);

        if(last != NULL)
        {
            last->next = fragment;
            last = fragment;
            fragment->next = NULL;
        }
        else // stream is empty
        {
            first = fragment;
            last = fragment;
            fragment->next = NULL;
        }

        length += fragment->dlen;
    }


    void push(Fragment* fragment)
    {
        assert(fragment->dlen != 0);

        if(discard)
        {
        //    std::clog << "discard new fragment: " << fragment->dlen << std::endl;
            if(discard >= fragment->dlen) // discard whole new fragment
            {
                discard -= fragment->dlen;
                Fragment::destroy(fragment);
                return;
            }
            else  // discard part of new fragment payload
            {
                fragment->dlen -= discard;
                fragment->data += discard;
                discard = 0;
            }
        }

        if(last != NULL)
        {
            last->next = fragment;
            last = fragment;
            fragment->next = NULL;
        }
        else // stream is empty
        {
            first = fragment;
            last = fragment;
            fragment->next = NULL;
        }

        length += fragment->dlen;
    }
    
    uint32_t read(uint8_t*const out, uint32_t size) const
    {
        uint8_t* ptr = out;
        Fragment* c = first;    // current fragment
        while(c)
        {
            if(c->dlen <= size)
            {
                memcpy(ptr, c->data, c->dlen);
                ptr     += c->dlen;
                size    -= c->dlen;

                c = c->next;
            }
            else
            {
                memcpy(ptr, c->data, size);
                ptr += size;
                break; // break while loop
            }
        }

        return ptr-out;
    }

    uint32_t readout(uint8_t*const out, uint32_t size)
    {
        uint8_t* ptr = out;
        while(first)
        {
            if(first->dlen <= size)
            {
                memcpy(ptr, first->data, first->dlen);
                ptr += first->dlen;
                size -= first->dlen;

                Fragment* c = first;
                if(last == first)
                {
                    last = first->next;
                }

                first = first->next;
                Fragment::destroy(c);
            }
            else
            {
                memcpy(ptr, first->data, size);
                ptr += size;

                first->data += size;
                first->dlen -= size;
                break; // break while loop
            }
        }
        const uint32_t n = ptr-out;
        length -= n;

        return n;
    }
    
    void skip(uint32_t size)
    {
        while(first)
        {
            if(first->dlen <= size)
            {
                length -= first->dlen;
                size   -= first->dlen;

                Fragment* c = first;
                if(last == first)
                {
                    last = first->next;
                }
                first = first->next;

                Fragment::destroy(c);
            }
            else
            {
                length -= size;

                first->data += size;
                first->dlen -= size;
                break; // break while loop
            }
        }
    }

    inline void set_discard_size(const uint32_t n)
    {
    //    std::clog << "set size of discard payload: " << n << " current len: " << length << std::endl;
        if(length >= n)
        {
            skip(n);
        }
        else // length < n
        {
            discard = n - length;
            skip(length);
        }
    }

//private:
    Fragment* first;
    Fragment* last;
    uint32_t length;

private:
    uint32_t discard;  // drop following N bytes from stream
};

/*
    Stateful reader of Sun RPC messages
    aggregates length of current RPC message
    TODO: add matching Calls and replies by XID of message
*/
class RPCReader
{
public:
    RPCReader() : max_hdr(1024), stream(NULL)
    {
        reset();
    }

    inline void reset()
    {
        msg_len = 0;
        hdr_len = 0;
    }

    inline void set_stream(FragmentStream* s)
    {
        assert(s);
        stream = s;
    }

    inline bool detect_message()
    {
        if(stream->length > 0)
        {
            if(msg_len == 0)    // no current message
            {
                find_message(); // try to find new current message
            }

            return msg_len != 0 && stream->length >= hdr_len;
        }
        return false;
    }

    bool readto(FilteredData* ptr)
    {
        Fragment* frag = stream->first;
        assert(frag);
        if(frag)
        {
            ptr->timestamp = frag->pcap_header.ts; // set timestamp as ts of first fragment

            stream->skip(sizeof(RecordMark));
       //     std::cout << "msg_len: " << msg_len << " hdr_len: " << hdr_len << std::endl;
            hdr_len -= sizeof(RecordMark);
            msg_len -= sizeof(RecordMark);

            ptr->dlen = std::min(hdr_len, ptr->dlen);
            stream->readout(ptr->data, ptr->dlen);

      //      std::cout << "msg_len: " << msg_len << " hdr_len: " << hdr_len << std::endl;
            assert(msg_len >= hdr_len);

       //     std::cout << "msg_len: " << msg_len << " hdr_len: " << hdr_len << " dlen: " << ptr->dlen << std::endl;
            uint32_t to_skip = msg_len - ptr->dlen;
            if(to_skip)
            {
                stream->set_discard_size(to_skip);
            }

            msg_len = 0;

            return true;
        }
        
        return false;
    }

    bool readto(PacketDumper& dumper)
    {
        uint32_t size = hdr_len;
        while(size > 0)
        {
            Fragment* frag = stream->first;
            
            uint32_t dlen = frag->dlen;
            
            if(dlen <= size)
            {
                dumper.dump(&frag->pcap_header, frag->pcap_packet());
                stream->skip(dlen);
                size -= dlen;
            }
            else
            {
                // TODO: fragments may be dumped twice
                dumper.dump(&frag->pcap_header, frag->pcap_packet());
                stream->skip(size);
                size = 0;
            }
        }

        uint32_t to_skip = msg_len - hdr_len;
        if(to_skip)
        {
            stream->set_discard_size(to_skip);
        }

        msg_len = 0;

        return false;
    }

private:

    void find_message()
    {
        while(*stream)
        {
            if(parse_message()) // ok, skip record mark of RPC message
            {
                return;
            }
            else // we are out of sequence of RPC messages in stream
            {
                Fragment* frag = stream->first;
                if(frag)
                {
                    stream->skip(frag->dlen);    // skip first fragment
                }
                reset();    // reset the reader
            }
        }
    }

    bool parse_message()
    {
        // the previous RPC message on stream are processed
        assert(msg_len == 0);
        //assert(hdr_len == 0);

        // required data size for validation next record mark and a RPC message
        static const uint32_t max_header = sizeof(RecordMark) + std::max(sizeof(CallHeader), sizeof(ReplyHeader));

        if(stream->length < max_header) return true;

        uint8_t tmp[max_header];    // temporary array for merged data from separate fragments
        const RecordMark* rm;

        // Prepare data from stream for parsing and validation
        {
            Fragment* frag = stream->first;
            assert(frag);
            
            if(frag->dlen >= max_header)
            {
                rm = reinterpret_cast<const RecordMark*>(frag->data);
            }
            else // first TCP fragment isn't enough
            {
                std::clog << "RPC RM and Message in separate TCP segments. Merge them." << std::endl;
                stream->read(tmp, max_header);
                rm = reinterpret_cast<const RecordMark*>(tmp);
            }
        }

        const MessageHeader*const msg = rm->fragment();

        //if(rm->is_last()); // TODO: handle sequence field of record mark
        msg_len = sizeof(RecordMark) + rm->fragment_len();    // length of current RPC message + RM
        hdr_len = std::min(msg_len, max_hdr);

        switch(msg->type())
        {
            case SUNRPC_CALL:
            {
                const CallHeader*const call = static_cast<const CallHeader*const>(msg);
                if(RPCValidator::check(call))
                {
                    if(NFSv3Validator::check(call))
                    {
                        return true;
                    }
                    else
                    {
               /*         std::cerr << "unknown RPC call(?) of program:" << call->prog()
                                  << " v: "                            << call->vers()
                                  << " procedure: "                    << call->proc()
                                  << '\n';*/
                /*        stream->skip(msg_len);
                        msg_len = 0;
                        hdr_len = 0;  // dont collect header*/
                        return true;
                    }
                }
                else
                {   // ERROR stream is corrupt
               //     std::cerr << "unknown RPC call(?)\n";
                    msg_len = 0;
                    return false;
                }
            }
            break;
            case SUNRPC_REPLY:
            {
                const ReplyHeader*const reply = static_cast<const ReplyHeader*const>(msg);
                if(RPCValidator::check(reply))
                {
                    return true;
                }
                else
                {   // ERROR stream is corrupt
            //        std::cerr << "unknown RPC reply(?)\n";
                    msg_len = 0;
                    return false;
                }
            }
            break;
            default:
            {
            //    std::cerr << "unknown RPC message type(?)\n";
                msg_len = 0;
                return false;
            }
            break;
        }
        return false;
    }

    const uint32_t  max_hdr;  // max length of RPC header
    uint32_t        msg_len;  // length of current RPC message + RM
    uint32_t        hdr_len;  // min(max_hdr, msg_len) or 0 in case of unknown msg

    FragmentStream* stream;
};


// Represents conversation between node A and node B
struct Session
{
public:

    struct Flow
    {
        Flow() : fragments(NULL), base_seq(0), sequence(0)
        {
        }
        ~Flow()
        {
            while(fragments)
            {
                Fragment* c = fragments;
                fragments = c->next;
                Fragment::destroy(c);
            }
        }

        bool check_fragments(const uint32_t acknowledged)
        {
            Fragment* current = fragments;
            if( current )
            {
                Fragment* prev = NULL;
                uint32_t lowest_seq = current->seq;
                while( current )
                {
                    if( lowest_seq > current->seq )
                    {
                        lowest_seq = current->seq;
                    }

                    if( current->seq < sequence )
                    {
                        bool has_data = false;
                        // this sequence number seems dated, but
                        // check the end to make sure it has no more
                        // info than we have already seen
                        uint32_t newseq = current->seq + current->len;
                        if( newseq > sequence )
                        {
                            // this one has more than we have seen. let's get the
                            // payload that we have not seen. This happens when
                            // part of this frame has been retransmitted
                            uint32_t new_pos = sequence - current->seq;

                            sequence += (current->len - new_pos);

                            if ( current->dlen > new_pos )
                            {
                                has_data = true;
                                current->data += new_pos;
                                current->dlen -= new_pos;
                            }

                        }

                        // Remove the fragment from the list as the "new" part of it
                        // has been processed or its data has been seen already in 
                        // another packet.
                        if( prev )
                        {
                          prev->next = current->next;
                        } else
                        {
                          fragments = current->next;
                        }

                        if(has_data)
                        {
                            stream.push(current);
                        }
                        else
                        {
                            Fragment::destroy(current);
                        }

                        return true;
                    }

                    if( current->seq == sequence )
                    {
                        // this fragment fits the stream
                        sequence += current->len;
                        if( prev )
                        {
                            prev->next = current->next;
                        }
                        else
                        {
                            fragments = current->next;
                        }

                        stream.push(current);
                        return true;
                    }
                    prev = current;
                    current = current->next;
                }// end while
                
                if( acknowledged > lowest_seq )
                {
                    // There are frames missing in the capture stream that were seen
                    // by the receiving host. Inform Stream about it.
                    stream.lost(lowest_seq - sequence);
                    sequence = lowest_seq;
                    return true;
                }
            }
            return false;
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
                    stream.push(info);  // write out the packet data
                }

                return;
            }

            // if we are here, we have already seen this src, let's
            // try and figure out if this packet is in the right place
            if( seq < sequence )
            {
                // this sequence number seems dated, but
                // check the end to make sure it has no more
                // info than we have already seen
                uint32_t newseq = seq + len;
                if( newseq > sequence )
                {

                    // this one has more than we have seen. let's get the
                    // payload that we have not seen
                    uint32_t new_len = sequence - seq;

                    if ( info.dlen <= new_len )
                    {
                        info.data = NULL;
                        info.dlen = 0;
                   //     incomplete_tcp_stream = TRUE;
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

            if ( seq == sequence ) // right on time
            {
                sequence += len;
                if( info.tcp->is(tcp_header::SYN) ) sequence++;

                if( info.data && info.dlen > 0)
                {
                    stream.push(info);
                }
                // done with the packet, see if it caused a fragment to fit
                while( check_fragments(0) );
            }
            else // out of order packet
            {
                if(info.dlen > 0 && (seq > sequence) )
                {
                    Fragment* frag = Fragment::create(info);

                    if( fragments )
                    {
                        frag->next = fragments;
                    }
                    else
                    {
                        frag->next = NULL;
                    }
                    fragments = frag;
                }
                else
                {
                 //   std::cout << "drop packet seq:" << seq << " sequence: " << sequence << " dlen: " << info.dlen << '\n';
                }
            }
        }

        FragmentStream  stream;     // acked data stream
        Fragment*       fragments;  // list of not yet acked fragments
        uint32_t        base_seq;   // base seq number (used by relative sequence numbers) or 0 if not yet known
        uint32_t        sequence;
    };

    Session()
    {
    }
    
    ~Session()
    {
    }
    
    void init()
    {
        for(uint32_t i=0; i<2; i++)
        {
            readers[i].set_stream(&flows[i].stream);
        }
    }

    void reassemble_tcp(const Conversation& conversation, Conversation::Direction d, PacketInfo& info)
    {
        const uint32_t ack = info.tcp->ack();

        //check whether this frame acks fragments that were already seen.
        while( flows[1-d].check_fragments(ack) );

        flows[d].reassemble(info);
    }

    Flow flows[2];
    RPCReader readers[2];
};


class TCPSessions: public std::tr1::unordered_map<Conversation, Session, Conversation::Hash>
{

public:
    typedef iterator it;

    TCPSessions()
    {
    }

    ~TCPSessions()
    {
    }

    iterator find_or_create_session(const Conversation& key)
    {
        iterator i = find(key);
        if(i == end())
        {
            std::pair<iterator, bool> res = insert(value_type(key, Session()));
            if(res.second)
            {
                i = res.first;
                // TODO:refactor this session initialization
                i->second.init();
            }
            else
            {
                //std::cout << "session is not created!" << std::endl;
            }
        }
        return i;
    }
};


template
<
    typename Reader,
    typename Writer
>
class FiltrationProcessor
{
public:

    FiltrationProcessor(std::auto_ptr<Reader>& r, std::auto_ptr<Writer>& w) : reader(r), writer(w)
    {
        // check datalink layer
        const int datalink = reader->datalink();
        switch(datalink)
        {
        case DLT_EN10MB: break;
        default:
            throw Exception(std::string("Unsupported Data Link Layer: ") + Reader::datalink_description(datalink));
        }
    }
    ~FiltrationProcessor()
    {
        if(controller::Parameters::instance().is_verbose())
        {
            reader->print_statistic(std::clog);
        }
    }

    void run()
    {
        bool done = reader->loop(*this);
        if(done)
        {
            throw Exception("Filtration is done");
        }
    }

    void stop()
    {
        reader->break_loop();
    }

    u_char* get_user()
    {
        return (u_char*)this;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        FiltrationProcessor* processor = (FiltrationProcessor*) user;

        // TODO: THIS CODE MUST BE TOTALLY REFACTORED!
        // TODO: 1) Design and implement the Readers for each layer
        //       2) Manage separate reades for each session
        //       3) Detect placement of NFS Op data and drop it ASAP
        //       4) Pass filtered NFS Op headers (RPC messages) to Analysis

        PacketInfo info(pkthdr, packet);
        
        if(! info.check_eth())
        {
            return;
        }

        Conversation::Direction direction = Conversation::AtoB;
        Conversation key(info, direction);

        // Following code must be refactored!
        TCPSessions::iterator i = processor->sessions.find_or_create_session(key);
        if(i != processor->sessions.end())
        {
            Session& session = i->second;

            session.reassemble_tcp(i->first, direction, info);

            for(uint32_t i=0; i<2; i++)
            {
                RPCReader& reader = session.readers[i];

                if(reader.detect_message())
                {
                    if(direction == (Conversation::Direction)i)
                    {
                        processor->writer->collect((Conversation::Direction)i, key, reader);
                    }
                    else
                    {
                        std::cerr << "There is missmatch in data flow direction." << std::endl;
                    }
                }

            }
        }
    }

private:
    std::auto_ptr<Reader> reader;
    std::auto_ptr<Writer> writer;
    TCPSessions sessions;
};


} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif//FILTRATION_PROCESSOR_H
//------------------------------------------------------------------------------
