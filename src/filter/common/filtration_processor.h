//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Generic processor for filtration raw pcap packets.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
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


#include "../../analyzer/nfs_data.h"
#include "../ethernet/ethernet_header.h"
#include "../ip/ipv4_header.h"
#include "../rpc/rpc_message.h"
#include "../tcp/tcp_header.h"
//------------------------------------------------------------------------------
using NST::analyzer::NFSData;
using namespace NST::filter::rpc;
using namespace NST::filter::ethernet;
using namespace NST::filter::ip;
using namespace NST::filter::tcp;
//------------------------------------------------------------------------------
namespace NST
{
namespace filter
{

struct FiltrationData
{

    // validation methods return packet length without header they validate or 0 on error
    uint32_t validate_eth(uint32_t len, const uint8_t* packet)
    {
        if(len < sizeof(EthernetHeader)) return 0;

        EthernetHeader* header = (EthernetHeader*)packet;

        eth_header = header;

        return len - sizeof(EthernetHeader);
    }

    uint32_t validate_ipv4(uint32_t len, const uint8_t* packet)
    {
        if(len < sizeof(IPv4Header)) return 0;   // fragmented IPv4 header
        
        IPv4Header* header = (IPv4Header*)packet;
        
        const uint16_t total_len = header->length();
        
     /*   if(total_len != len)
        {
            std::cout << "IP len: " << total_len << " RAW len: " << len << "\n";
        }*/

        if(header->version() != 4) // fragmented payload
        {
            std::cout << "is not IPv4" << std::endl;
            return 0;
        }
        
        if(total_len > len) // fragmented payload
        {
            std::cout << "IPv4 packet is fragmented" << std::endl;
            return 0;
        }

        ipv4_header = header;

        assert(ipv4_header->length() <= len);

        return len - header->ihl();
    }

    uint32_t validate_tcp(uint32_t len, const uint8_t* packet)
    {
        if(len < sizeof(TCPHeader)) return 0;   // fragmented TCP header

        TCPHeader* header = (TCPHeader*)packet;
        uint8_t offset = header->offset();
        if(offset < 20 || offset > 60) return 0; // invalid length of TCP header

        if(len < offset) return 0;

        tcp_header = header;

        tcp_data = packet + offset;


        tcp_dlen  = ipv4_header->length() - (ipv4_header->ihl() + offset);
        //tcp_dlen = len - offset;

        return len - offset;
    }

        // libpcap structures
    const pcap_pkthdr*              header;
    const uint8_t*                  packet;
    // TODO: WARNING!All pointers points to packet data!

    // Ethernet II
    const ethernet::EthernetHeader* eth_header;

    // IP version 4
    const ip::IPv4Header*           ipv4_header;

    // TCP
    const tcp::TCPHeader*           tcp_header;
    const uint8_t* tcp_data;
    size_t tcp_dlen;

    // Sun RPC
    const rpc::MessageHeader*       rpc_header;
    size_t                          rpc_length;
    size_t                          msg_len;
};


struct Nodes
{
    enum Direction
    {
        AtoB = 0, // A -> B
        BtoA = 1, // A <- B
    };

    inline Direction set(const uint32_t& src_address,
                         const uint32_t& dst_address,
                         const uint16_t& src_port,
                         const uint16_t& dst_port)
    {
        Direction src;

        if (src_address < dst_address) src = AtoB;
        else
        if (src_address > dst_address) src = BtoA;
        else // Ok, addresses are equal, compare ports
        src = (src_port < dst_port) ? AtoB : BtoA;

        Direction dst = (Direction)(1 - src);

        addr[src] = src_address;
        addr[dst] = dst_address;
        port[src] = src_port;
        port[dst] = dst_port;

        return src;
    }

    size_t hash() const
    {
        size_t value = port[0] + port[1];

        const uint8_t* a = (const uint8_t*)&addr[0];
        const uint8_t* b = (const uint8_t*)&addr[1];
        for(size_t i=0; i<sizeof(uint32_t); ++i)
        {   // sum bytes of addresses
            value += a[i];
            value += b[i];
        }

        return value;
    }

    struct Hash
    {
      long operator() (const Nodes& key) const { return key.hash(); }
    };

    bool operator==(const Nodes& a) const
    {
        return memcmp(this, &a, sizeof(Nodes)) == 0; // are equal?
    }

    inline const uint32_t src_address(const Direction d) const { return addr[ d ]; }
    inline const uint32_t dst_address(const Direction d) const { return addr[1-d]; }

    inline const uint16_t src_port(const Direction d) const { return port[ d ]; }
    inline const uint16_t dst_port(const Direction d) const { return port[1-d]; }

    void print(std::ostream& out, Direction d) const
    {
        out << ipv4_string(src_address(d)) << ":" << src_port(d);
        out << " -> ";
        out << ipv4_string(dst_address(d)) << ":" << dst_port(d);
    }

    static std::string ipv4_string(uint32_t ip /*host byte order*/ )
    {
        std::stringstream address(std::ios_base::out);
        address << ((ip >> 24) & 0xFF);
        address << '.';
        address << ((ip >> 16) & 0xFF);
        address << '.';
        address << ((ip >> 8) & 0xFF);
        address << '.';
        address << ((ip >> 0) & 0xFF);
        return address.str();
    }

private:
    uint32_t addr[2];
    uint16_t port[2];
};



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

    static Fragment* create(const FiltrationData& data)
    {
        Fragment* frag = (Fragment*) new uint8_t[sizeof(Fragment) + data.header->caplen];
        void* pcap_data = frag+1;
        memcpy(pcap_data, data.packet, data.header->caplen);
        frag->pcap_header   = *data.header;

        frag->seq           = data.tcp_header->seq();

        frag->len           = data.header->len;
        frag->data          = ((uint8_t*)pcap_data) + (data.tcp_data - data.packet);
        frag->dlen      = data.tcp_dlen;// data.ipv4_header->length() - (data.ipv4_header->ihl() + data.tcp_header->offset());

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
            //std::clog << "free fragment of stream len: " << first->dlen << std::endl;
            Fragment* c = first;
            first = first->next;
            Fragment::destroy(c);
        }
    }

    inline operator bool() const { return first != NULL; }

    void push(Fragment* fragment)
    {
        assert(fragment->dlen != 0);

        if(discard)
        {
            //std::clog << "discard new fragment: " << fragment->dlen << std::endl;
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
        std::clog << "set size of discard payload: " << n << std::endl;
        int32_t to_discard = n - length;
        if(to_discard > 0)
        {
            discard = to_discard;
        }
        skip(n); // discard existing part of stream
        assert(length == 0);
    }

//private:
    Fragment* first;
    Fragment* last;
    uint32_t length;

private:
    uint32_t discard;  // drop following N bytes from stream
};

template
<
    uint32_t Program,   // remote program number
    uint32_t Version,   // remote program version number
    uint32_t MinProc,   // min remote procedure number
    uint32_t MaxProc    // max remote procedure number
>
class RPCValidator
{
public:
    RPCValidator()
    {
    }

private:

    inline bool validate(const CallHeader*const call)
    {
        const uint32_t proc = call->proc();

        return          proc >= MinProc &&
                        proc <= MaxProc &&
                call->prog() == Program &&
                call->vers() == Version ;

    }

    inline bool validate(const ReplyHeader*const reply)
    {
        const uint32_t stat = reply->stat();
        
        return stat == SUNRPC_MSG_ACCEPTED ||
               stat == SUNRPC_MSG_DENIED;
    }

    // TODO: add an array of XIDs for matching RPC Calls and RPC Replies
};

/*
    Stateful reader of Sun RPC messages
    aggregates length of current RPC message
    TODO: add matching Calls and replies by XID of message
*/
class RPCReader
{
public:
    RPCReader() : rpc_program(100003),  // SunRPC/NFS program
                  rpc_version(3),       // v3
                  min_proc(0),          // NFSPROC3_NULL
                  max_proc(21),         // NFSPROC3_COMMIT
                  max_hdr(1024),
                  stream(NULL)
    {
        reset();
    }

    inline void reset()
    {
        msg_len = 0;
        hdr_len = 0;
    }

    inline bool validate_rpc_call(const CallHeader*const call)
    {
        return call->rpcvers() == 2;
    }

    inline bool validate_rpc_reply(const ReplyHeader*const reply)
    {
        const uint32_t stat = reply->stat();

        if(stat == SUNRPC_MSG_ACCEPTED) return true;
        if(stat == SUNRPC_MSG_DENIED  ) return true;
        return false;
    }

    inline bool validate_nfs_call(const CallHeader*const call)
    {
        if(call->prog() != rpc_program) return false;
        if(call->vers() != rpc_version) return false;
        if(call->proc() <  min_proc   ) return false;
        if(call->proc() >  max_proc   ) return false;
        return true;
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

    void readto(uint32_t& size, uint8_t*const data)
    {
        size = std::min(hdr_len, size);
        stream->readout(data, size);

        assert(msg_len >= hdr_len);

        uint32_t to_skip = msg_len - size;
        if(to_skip)
        {
            stream->set_discard_size(to_skip);
        }

        msg_len = 0;
    }

private:

    void find_message()
    {
        while(*stream)
        {
            if(parse_message()) // ok, skip record mark of RPC message
            {
                stream->skip(sizeof(RecordMark));
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
        
        
        RPCValidator
        <
        100003, // SunRPC/NFS program
        3,      // v3
        0,      // NFSPROC3_NULL
        21      // NFSPROC3_COMMIT
        > nfs3_validator;

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
        msg_len = rm->fragment_len();    // length of current RPC message
        hdr_len = std::min(msg_len, max_hdr);

        switch(msg->type())
        {
            case SUNRPC_CALL:
            {
                const CallHeader*const call = static_cast<const CallHeader*const>(msg);
                if(validate_rpc_call(call))
                {
                    if(validate_nfs_call(call))
                    {
                        return true;
                    }
                    else
                    {
                        std::cerr << "unknown RPC call(?) of program:" << call->prog()
                                  << " v: "                            << call->vers()
                                  << " procedure: "                    << call->proc()
                                  << '\n';
                        hdr_len = 0;  // dont collect header
                        return true;
                    }
                }
                else
                {   // ERROR stream is corrupt
                    std::cerr << "unknown RPC call(?)\n";
                    msg_len = 0;
                    return false;
                }
            }
            break;
            case SUNRPC_REPLY:
            {
                const ReplyHeader*const reply = static_cast<const ReplyHeader*const>(msg);
                if(validate_rpc_reply(reply))
                {
                    return true;
                }
                else
                {   // ERROR stream is corrupt
                    std::cerr << "unknown RPC reply(?)\n";
                    msg_len = 0;
                    return false;
                }
            }
            break;
            default:
            {
                std::cerr << "unknown RPC message type(?)\n";
                msg_len = 0;
                return false;
            }
            break;
        }
        return false;
    }

    // constants for validation RPC calls
    const uint32_t  rpc_program;    // ID of RPC program
    const uint32_t  rpc_version;
    const uint32_t  min_proc;
    const uint32_t  max_proc;

    const uint32_t  max_hdr;  // max length of RPC header
    uint32_t        msg_len;  // length of current RPC message
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

        bool check_fragments(uint32_t acknowledged)
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
                                current->data     += new_pos;
                                current->dlen -= new_pos;
                          //      sc->dlen = current->dlen - new_pos;
                          //      write_packet_data( idx, sc, current->data + new_pos );
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
                   //     g_free( current->data );
                   //     g_free( current );
                   
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
                     /*   if( current->data )
                        {
                            sc->dlen = current->dlen;
                            write_packet_data( idx, sc, current->data );
                        }*/
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
                        
                    //    g_free( current->data );
                    //    g_free( current );
                        return true;
                    }
                    prev = current;
                    current = current->next;
                }// end while
                
                if( acknowledged > lowest_seq )
                {
                    // There are frames missing in the capture file that were seen
                    // by the receiving host. Add dummy stream chunk with the data
                    // "[xxx bytes missing in capture file]"
    /*
                    gchar* dummy_str = g_strdup_printf("[%d bytes missing in capture file]",
                                    (int)(lowest_seq - sequences[idx]) );
                    sc->dlen = (guint32) strlen(dummy_str);
                    write_packet_data( idx, sc, dummy_str );
                    g_free(dummy_str);*/
                    std::cout << "DUMMMMMY LOST bytes: " << (lowest_seq - sequence) << std::endl;
                    sequence = lowest_seq;
                    return true;
                }
            }
            return false;
        }
        
        
        
        void reassemble(FiltrationData& data)
        {
            uint32_t seq = data.tcp_header->seq();
            uint32_t len = data.ipv4_header->length() - (data.ipv4_header->ihl() + data.tcp_header->offset());

            if( sequence == 0 ) // this is the first time we have seen this src's sequence number
            {
                sequence = seq + len;
                if( data.tcp_header->is(tcp_header::SYN) )
                {
            //        std::cout << "SYN flag" << '\n';
                    sequence++;
                }
            //    std::cout << "sequence number: " << sequence << '\n';

                // write out the packet data
              //  write_packet_data( src_index, &sc, data );
              
                if(len > 0)
                {
                    Fragment* frag = Fragment::create(data);
                    stream.push(frag);
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

                    if ( data.tcp_dlen <= new_len )
                    {
                        data.tcp_data = NULL;
                        data.tcp_dlen = 0;
                   //     incomplete_tcp_stream = TRUE;
                    }
                    else
                    {
                        assert(data.tcp_dlen >= new_len);
                        data.tcp_data += new_len;
                        data.tcp_dlen -= new_len;
                    }
               //     sc.dlen = tcp_dlen;
                    seq = sequence;
                    len = newseq - sequence;

                    // this will now appear to be right on time :)
                }
            }

            if ( seq == sequence ) // right on time
            {
                sequence += len;
                if( data.tcp_header->is(tcp_header::SYN) ) sequence++;

                if( data.tcp_data && data.tcp_dlen > 0)
                {
                    Fragment* frag = Fragment::create(data);
                    stream.push(frag);
                //    write_packet_data( src_index, &sc, data );
                }
                // done with the packet, see if it caused a fragment to fit
            //    while( check_fragments( src_index, &sc, 0 ) );
                while( check_fragments(0) );
            }
            else // out of order packet
            {
                if(data.tcp_dlen > 0 && (seq > sequence) )
                {
                    Fragment* frag = Fragment::create(data);

             //       tmp_frag = (tcp_frag *)g_malloc( sizeof( tcp_frag ) );
             //       tmp_frag->data = (gchar *)g_malloc( dlength );
             //       tmp_frag->seq = sequence;
             //       tmp_frag->len = length;
             //       tmp_frag->dlen = dlength;
             //       memcpy( tmp_frag->data, data, dlength );
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
                    std::cout << "drop packet seq:" << seq << " sequence: " << sequence << " dlen: " << data.tcp_dlen << '\n';
                }
            }
        }

        FragmentStream  stream;     // acked data stream
        Fragment*       fragments;  // list of not yet acked fragments
        uint32_t        base_seq;   // base seq number (used by relative sequence numbers) or 0 if not yet known.
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

    void reassemble_tcp(const Nodes& nodes, Nodes::Direction d, FiltrationData& data)
    {
        const uint32_t ack = data.tcp_header->ack();

        //check whether this frame acks fragments that were already seen.
        while( flows[1-d].check_fragments(ack) );

        flows[d].reassemble(data);
    }

    Flow flows[2];
    RPCReader readers[2];
};



class TCPSessions: public std::tr1::unordered_map<Nodes, Session, Nodes::Hash>
{

public:
    typedef iterator it;

    TCPSessions()
    {
    }

    ~TCPSessions()
    {
    }

    iterator find_or_create_session(Nodes::Direction d, const Nodes& key)
    {
        iterator i = find(key);
        if(i == end())
        {
            std::pair<iterator, bool> res = insert(value_type(key, Session()));
            if(res.second)
            {
                std::cout << "add session" << std::endl;
                i = res.first;
                // TODO:refactor this session initialization
                i->second.init();
            }
            else
            {
                std::cout << "session is not created!" << std::endl;
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
    }
    ~FiltrationProcessor()
    {
    }

    void run()
    {
        reader->loop(*this);
    }

    void stop()
    {
        reader->break_loop();
    }

    u_char* get_user()
    {
        return (u_char*)this;
    }

    inline void discard(const FiltrationData& data)
    {
        writer->discard(data);
    }

    inline void collect(const FiltrationData& data)
    {
        writer->collect(data);
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        FiltrationProcessor* processor = (FiltrationProcessor*) user;

        // TODO: THIS CODE MUST BE TOTALLY REFACTORED!
        // TODO: 1) Design and implement the Readers for each layer
        //       2) Manage separate reades for each session
        //       3) Detect placement of NFS Op data and drop it ASAP
        //       4) Pass filtered NFS Op headers (RPC messages) to Analysis

        FiltrationData data = {0};

        data.header = pkthdr;
        data.packet = packet;

        const uint32_t len = pkthdr->len;

        // parse Data Link Layer
        uint32_t payload = data.validate_eth(len, packet);
        if(!payload)
        {
            return processor->discard(data);
        }

        // parse Internet Layer
        switch(data.eth_header->type())
        {
        case ethernet_header::IP:
            payload = data.validate_ipv4(payload, packet + (len - payload));
            break;
        case ethernet_header::IPV6: // TODO: implement IPv6
        default:
            payload = 0;
        }
        if(!payload)
        {
            return processor->discard(data);
        }

        // parse Transport Layer
        switch(data.ipv4_header->protocol())
        {
        case ipv4_header::TCP:
            payload = data.validate_tcp(payload, packet + (len - payload));
            break;
        case ipv4_header::UDP: // TODO: implement UDP
        default:
            payload = 0;
        }
        if(!payload)
        {
            return processor->discard(data);
        }

        processor->collect(data);


        Nodes key;

        Nodes::Direction direction =key.set(data.ipv4_header->src(),
                                            data.ipv4_header->dst(),
                                            data.tcp_header->sport(),
                                            data.tcp_header->dport());

        TCPSessions::it i = processor->sessions.find_or_create_session(direction, key);
        if(i != processor->sessions.end())
        {
            Session& session = i->second;

            session.reassemble_tcp(i->first, direction, data);

            for(uint32_t i=0; i<2; i++)
            {
                Nodes::Direction d = (Nodes::Direction)i;

                RPCReader& reader = session.readers[i];

                if(reader.detect_message())
                {
                    processor->writer->collect(d, key, reader);
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
