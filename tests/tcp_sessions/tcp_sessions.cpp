//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Detect TCP sessions and reassemble streams.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <map>
#include <memory>
#include <sstream>

#include <tr1/unordered_map>

#include <pcap/pcap.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include <iomanip>

#include "../../src/analyzer/nfs_data.h"
#include "../../src/auxiliary/queue.h"
#include "../../src/auxiliary/spinlock.h"
#include "../../src/controller/cmdline_parser.h"
#include "../../src/filter/pcap/pcap_error.h"
#include "../../src/filter/pcap/packet_capture.h"
#include "../../src/filter/pcap/packet_dumper.h"
#include "../../src/filter/ethernet/ethernet_header.h"
#include "../../src/filter/ip/ipv4_header.h"
#include "../../src/filter/rpc/rpc_message.h"
#include "../../src/filter/tcp/tcp_header.h"
//------------------------------------------------------------------------------
using NST::analyzer::NFSData;
using NST::auxiliary::Spinlock;
using NST::filter::pcap::PcapError;
using NST::filter::pcap::PacketCapture;
using NST::filter::pcap::PacketDumper;
using NST::filter::ethernet::ethernet_header;
using NST::filter::ip::ipv4_header;
using namespace NST::filter::rpc;
using NST::filter::tcp::tcp_header;
//------------------------------------------------------------------------------
PacketCapture* g_capture = NULL;  // used in signal handler

//------------------------------------------------------------------------------
struct Discard // counters definition for discarded packets
{
    enum Counters
    {
        ETH = 0,
        IP = 1,
        TCP = 2,
        RPC = 3,
        NFS = 4,
        num = 5,
    };

    static const char* titles[num];
};

const char* Discard::titles[Discard::num]={ "ETH", "IP", "TCP", "RPC", "NFS" };

/*
    T must have an enum Counters, last element of Counters must be num
    T must have initialized array of titles(up to 16 chars): const char* titles[num]
*/
template<typename T>
class Counters
{
public:

    Counters()
    {
        memset(accumulators, 0, sizeof(accumulators));
        memset(collected, 0, sizeof(collected));
    }

    inline void collect()
    {
        for(int i=0; i<T::num; ++i)
        {
            collected[i] += accumulators[i];
            accumulators[i] = 0;
        }
    }

    void print(std::ostream& out)const
    {
        uint64_t total = 0;
        for(int i=0; i<T::num; ++i)
        {
            total += collected[i];
            out << std::setw(16) << std::left << T::titles[i] << collected[i] << std::endl;
        }
        out << "total: " << total << std::endl;
    }

    inline void operator [](typename T::Type id){ ++accumulators[id]; }

private:
    uint64_t accumulators[T::num];
    uint64_t collected   [T::num];
};
//------------------------------------------------------------------------------
struct Packet // counters definition for packets per protocol
{
    enum Type
    {
        UNKNOWN,
        // Data link layer
        Ethernet,
        // Network layer
        IPv4,
        IPv6,
        // Transport layer
        TCP,
        UDP,
        RPC_CALL,
        RPC_REPLY,
        num,
    };
    static const char* titles[num];
};

const char* Packet::titles[Packet::num]={ "UNKNOWN", "Ethernet", "IPv4", "IPv6", "TCP", "UDP", "RPC_CALL", "RPC_REPLY" };

std::string ipv4_string(uint32_t ip /*host byte order*/ )
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

// Ethernet II (aka DIX v2.0 Ethernet)
struct Ethernet
{
    struct Header:private ethernet_header
    {
        inline const uint8_t*  dst() const { return eth_dhost;      }
        inline const uint8_t*  src() const { return eth_shost;      }
        inline uint16_t       type() const { return ntohs(eth_type);}
    } __attribute__ ((__packed__));

    static inline const Header* parse(Packet::Type& type, const u_char*& ptr, uint32_t& len)
    {
        Header* header = (Header*)ptr;

        if(len - sizeof(Header) <= 0)
        {
            return NULL;
        }

        switch(header->type())
        {
            case ethernet_header::IP:   type = Packet::IPv4;     break;
            case ethernet_header::IPV6: type = Packet::IPv6;     break;
            default:                    type = Packet::UNKNOWN;  break;
        }
        ptr = ptr + sizeof(Header);
        len = len - sizeof(Header);

        return header;
    }
};

struct IPv4
{
    struct Header:private ipv4_header
    {
        inline uint8_t  version()  const { return (ipv4_vhl & 0xf0) >> 4; }
        inline uint8_t  ihl()      const { return (ipv4_vhl & 0x0f)*4;  }
        inline uint16_t length()   const { return ntohs(ipv4_len);      }
        inline uint16_t offset()   const { return ipv4_fragmentation & OFFMASK; }
        inline uint8_t  protocol() const { return ipv4_protocol;        }
        inline uint32_t src()      const { return ntohl(ipv4_src.s_addr); }
        inline uint32_t dst()      const { return ntohl(ipv4_dst.s_addr); }
        inline uint16_t checksum() const { return ntohs(ipv4_checksum); }

        inline const bool is_fragmented()const { return ipv4_fragmentation & (MF | OFFMASK); }
    } __attribute__ ((__packed__));

    static inline const Header* parse(Packet::Type& type, const u_char*& ptr, uint32_t& len)
    {
        Header* header = (Header*)ptr;

        const uint16_t total_len = header->length();
        if(header->version() != 4 || len - total_len < 0)
        {
            return NULL;
        }
        const uint8_t header_len = header->ihl();

        switch(header->protocol())
        {
            case ipv4_header::TCP: type = Packet::TCP;     break;
            case ipv4_header::UDP: type = Packet::UDP;     break;
            default:               type = Packet::UNKNOWN; break;
        }
        ptr = ptr + header_len;
        len = total_len - header_len;
        return header;
    }
};

struct TCP
{
    struct Header:private tcp_header
    {
        inline uint16_t sport() const { return ntohs(tcp_sport); }
        inline uint16_t dport() const { return ntohs(tcp_dport); }
        inline uint32_t   seq() const { return ntohl(tcp_seq); }
        inline uint32_t   ack() const { return ntohl(tcp_ack); }
        inline uint8_t offset() const { return (tcp_rsrvd_off & 0xf0) >> 2; }
        inline bool is(tcp_header::Flag flag) const { return tcp_flags & flag; }
        inline uint16_t window()   const { return ntohs(tcp_win); }
        inline uint16_t checksum() const { return ntohs(tcp_sum); }
        inline uint16_t urgent()   const { return ntohs(tcp_urp); }

    } __attribute__ ((__packed__));

    static inline const Header* parse(Packet::Type& type, const u_char*& ptr, uint32_t& len)
    {
        Header* header = (Header*)ptr;
        uint8_t offset = header->offset();
        if(offset < 20 || offset > 60)
        {
            return NULL;
        }

        type = Packet::UNKNOWN;   // TODO: set TCP segment type
        ptr = ptr + offset;
        len = len - offset;
        return header;
    }
};

struct RPC
{
    static inline const rpc_msg* parse(Packet::Type& type, const u_char*& ptr, uint32_t& len)
    {
        rpc_msg *msg = (rpc_msg*)ptr;

        if (len < (sizeof(msg->xid) + sizeof(msg->mtype))) return NULL;

        MsgType mtype = (MsgType) ntohl(msg->mtype);

        if (mtype == SUNRPC_REPLY)
        {
            size_t offset = sizeof(msg->xid) + sizeof(msg->mtype);

            type = Packet::RPC_REPLY;
            ptr = ptr + offset;
            len = len - offset;
            return msg;
        }

        if (mtype == SUNRPC_CALL)
        {
            size_t offset = sizeof(msg->xid) + sizeof(msg->mtype) + sizeof(msg->body.cbody);
            if(len < offset) return NULL;

            const uint32_t rpcvers= ntohl(msg->body.cbody.cb_rpcvers);
            const uint32_t prog   = ntohl(msg->body.cbody.cb_prog);
            const uint32_t vers   = ntohl(msg->body.cbody.cb_vers);
            const uint32_t proc   = ntohl(msg->body.cbody.cb_proc);

            if(rpcvers != 2)    return NULL;
            if(prog!= 100003)   return NULL;    // portmap NFS v3 TCP 2049
            if(vers != 3)       return NULL;    // NFS v3

            type = Packet::RPC_CALL;
            ptr = ptr + offset;
            len = len - offset;
            return msg;
        }
        return NULL;
    }
};

struct TCPStream
{
//    uint32_t base_seq;  // base seq number (used by relative sequence numbers) or 0 if not yet known.

    uint32_t fin;               // frame number of the final FIN
    uint32_t lastack;           // last seen ack
    struct timeval lastacktime; // Time of the last ack packet
    uint32_t lastnondupack;     // frame number of last seen non dupack
    uint32_t dupacknum;         // dupack number
    uint32_t nextseq;           // highest seen nextseq
    uint32_t maxseqtobeacked;// highest seen continuous seq number (without hole in the stream) from the fwd party,
                             // this is the maximum seq number that can be acked by the rev party in normal case.
                             // If the rev party sends an ACK beyond this seq number it indicates TCP_A_ACK_LOST_PACKET contition
    uint32_t nextseqframe;      // frame number for segment with highest sequence number
    struct timeval nextseqtime; // Time of the nextseq packet so we can  distinguish between retransmission,  fast retransmissions and outoforder
    uint32_t window;            // last seen window
    int16_t  win_scale;         // -1 is we dont know, -2 is window scaling is not used
    int16_t  scps_capable;      // flow advertised scps capabilities
    uint16_t maxsizeacked;      // 0 if not yet known
    bool     valid_bif;         // if lost pkts, disable BiF until ACK is recvd
    

    void open(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
    {
        std::stringstream name(std::ios_base::out);
        name << ipv4_string(src);
        name << '-';
        name << sport;
        name << '-';
        name << ipv4_string(dst);
        name << '-';
        name << dport;
        name << ".tcp";

        std::ios_base::openmode mode = std::ofstream::out | std::ofstream::binary | std::ofstream::trunc;
        file = new std::ofstream(name.str().c_str(), mode);
    }
    
    void write(const char* data, size_t len)
    {
        file->write(data, len);
    }

    void close()
    {
        if(file)
        {
            delete file;
        }
    }

    TCPStream():seq(0)
    {
        close();
    }
    
    uint32_t reassemble(uint32_t sequence, uint32_t acknowledgement, uint32_t length,
                        const unsigned char* data, uint32_t data_length, int synflag)
    {
        return 0;
    }
    uint32_t seq;

    std::ofstream* file;

    //tcp_unacked_t *segments;    // list of segments
};



// Represents conversation between node A and node B
template
<
    typename Address=uint32_t,
    typename Port=uint16_t
>
struct Session
{
    // Direction identifies the data flow direction between nodes A and B
    // and who is source and who is destination.
    enum Direction
    {
        AtoB = 0, // A -> B
        BtoA = 1, // B -> A
        num  = 2
    };
    /*
        The ID contains source and destination address and ports
        based on comparing source and destination

        less address in A,
        greater address in B
        If addresses are equal, comparing the source and destination ports
    */
    struct ID
    {
        Direction set(const Address& src_address, const Address& dst_address,
                      const Port& src_port, const Port& dst_port)
        {
            if(src_address < dst_address)   // A is source, B is destination
            {
                addrA = src_address;
                addrB = dst_address;
                portA = src_port;
                portB = dst_port;
                return AtoB;
            }
            else
            if(src_address > dst_address) // A is destination, B is source
            {
                addrA = dst_address;
                addrB = src_address;
                portA = dst_port;
                portB = src_port;
                return BtoA;
            }
            else
            if (src_port < dst_port) // Ok, addresses are equal, compare ports
            {
                addrA = addrB = src_address;
                portA = src_port;
                portB = dst_port;
                return AtoB;
            }
            else // src_port >= dst_port
            {
                addrA = addrB = src_address;
                portA = dst_port;
                portB = src_port;
                return BtoA;
            }
        }

        size_t hash() const
        {
            size_t value = portA + portB;

            const uint8_t* a = (const uint8_t*)&addrA;
            const uint8_t* b = (const uint8_t*)&addrB;
            for(size_t i=0; i<sizeof(Address); ++i)
            {   // sum bytes of addresses
                value += a[i];
                value += b[i];
            }

            return value;
        }

        bool operator==(const ID& a) const
        {
            /*return addrA == a.addrA &&
                   addrB == a.addrB &&
                   portA == a.portA &&
                   portB == a.portB;*/
            return memcmp(this, &a, sizeof(ID)) == 0; // are equal?
        }

        void print(std::ostream& out) const
        {
            out << ipv4_string(addrA);
            out << ":" << portA;
            out << " <-> ";
            out << ipv4_string(addrB);
            out << ":" << portB;
        }

        Address addrA;
        Address addrB;
        Port    portA;
        Port    portB;
    };

    Session():num_segments(0)
    {
    }
    ~Session()
    {
    }

    TCPStream streams[num]; // one stream per each direction
    uint32_t num_segments;
    struct timeval start;
};

typedef Session<> TCPSession;

namespace std
{
namespace tr1
{
    template<>
    struct hash<TCPSession::ID>
    {
        std::size_t operator()(const TCPSession::ID& key) const { return key.hash(); }
    };
}
}

//typedef std::map<TCPSession::ID, TCPSession> StreamMap;
typedef std::tr1::unordered_map<TCPSession::ID, TCPSession> StreamMap;

class TCPSessions: private StreamMap
{
public:

    typedef StreamMap::iterator it;
    typedef StreamMap::const_iterator cit;

    TCPSessions()
    {
    }

    ~TCPSessions()
    {
    }

    TCPStream& find_session_stream(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
    {
        TCPSession::ID key;
        TCPSession::Direction direction = key.set(src, dst, sport, dport);

        it i = find(key);
        if(i == end())
        {
            std::cout << "add session" << std::endl;
            i = insert( StreamMap::value_type(key, TCPSession() )).first;

            // open files to write tcp streams
            i->second.streams[0].open(src, dst, sport, dport);
            i->second.streams[1].open(dst, src, dport, sport);
        }

        ++(i->second.num_segments);

        return i->second.streams[direction];
    }

    void print(std::ostream& out) const
    {
        for(cit i = begin(); i != end(); ++i)
        {
            i->first.print(std::cout);
            std::cout << " packets: " << i->second.num_segments << std::endl;
        }
    }

};



class ReassembleTCPSessions
{
public:
    ReassembleTCPSessions(const std::string& path):file(path), workload_tid(0), datalink(Packet::UNKNOWN), captured(0), discarded(0)
    {
    }
    ~ReassembleTCPSessions()
    {
    }

    void before_callback(pcap_t* handle)
    {
        // check data link layer type
        const int dlt = pcap_datalink(handle);
        switch(dlt)
        {
        case DLT_EN10MB: datalink = Packet::Ethernet; break;
        default:
            std::stringstream msg(std::ios_base::out);
            msg << "Unsupported link-layer: " << dlt << " "
                << pcap_datalink_val_to_name(dlt) << " ("
                << pcap_datalink_val_to_description(dlt) << ")";

            throw Exception(msg.str());
        }

        // prepare processing
        packets.reset(new PacketDumper(handle, file.c_str()));
        captured    = 0;
        discarded   = 0;

        // start thread
        pthread_create(&workload_tid, NULL, workload_thread, this);
    }

    void after_callback(pcap_t* handle)
    {
        // join thread
        void *res;
        pthread_cancel(workload_tid);
        pthread_join(workload_tid, &res);

        discard.collect();
        discard.print(std::cout);

        // reset processing
        packets.release();
    }

    u_char* get_user()
    {
        return (u_char*)this;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        ReassembleTCPSessions& p = *(ReassembleTCPSessions*) user;

        // dump everything
        p.packets->dump(pkthdr, packet);

        // payload data
        const u_char* data = packet;
        uint32_t      size = pkthdr->caplen;
        Packet::Type  type = p.datalink;

        const IPv4::Header* ip = NULL;
        const TCP::Header* tcp = NULL;

        // parse frame
        const Ethernet::Header* eth = Ethernet::parse(type, data, size);
        if(!eth)
        {
            return; // discard
        }

        if(type == Packet::IPv4)
        {
                ip = IPv4::parse(type, data, size);
                if(!ip)
                {
                    return; // discard
                }
                else
                {
                }
        }

        if(type == Packet::TCP)
        {
                tcp = TCP::parse(type, data, size);
                if(!tcp)
                {
                    return; // discard
                }
                else
                {
                }
        }

        const rpc_msg* msg = RPC::parse(type, data, size);

        if(msg)
        {
            p.captured++;
            p.discarded--;
            p.packets->dump(pkthdr, packet);
        }
    }

private:
    // thread for printing workload
    static void* workload_thread(void *arg)
    {
        const ReassembleTCPSessions& p = *(ReassembleTCPSessions*)arg;
        // blocking signals in this thread so the main thread handles them
        sigset_t sset;
        sigemptyset(&sset);
        sigaddset(&sset, SIGINT);
        sigaddset(&sset, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &sset, NULL);
        while(1)
        {

            std::cout << "\rcaptured: " << p.captured << " discarded: " << p.discarded;
            std::cout.flush();

            sleep(5); // cancellation point
        }
        return NULL;
    }

    std::string file;
    std::auto_ptr<PacketDumper> packets; // all captured packets
    pthread_t workload_tid;
    Packet::Type datalink;

    Counters<Packet> discard;

    uint64_t captured;
    uint32_t discarded;
};
//------------------------------------------------------------------------------
void cleanup(int signo)
{
    if(g_capture)
    {
        g_capture->break_loop();
    }

    std::cout << "stopped by signal " << signo << std::endl;
}

int add_signal_handler(int signo, void(*handler)(int))
{
    // unmask signal
    sigset_t sset;
    sigemptyset(&sset);
    sigaddset(&sset, signo);
    sigprocmask(SIG_UNBLOCK, &sset, NULL);

    struct sigaction newaction;
    memset(&newaction, 0, sizeof(newaction));
    newaction.sa_handler = handler;

    return sigaction(signo, &newaction, NULL);
}

using namespace NST::controller::cmdline;

struct CLI
{
    enum Names { INTERFACE, PORT, SNAPLEN, DUMP, HELP, num };
    static Opt options[num];
};

Opt CLI::options[CLI::num] = {
{ 'i', "interface", Opt::REQUIRED,  NULL,   "interface for capturing", "INTERFACE" },
{ 'p', "port",      Opt::REQUIRED, "2049",  "NFS filtration port", "PORT" },
{ 's', "snaplen",   Opt::REQUIRED, "512",   "length of packet snapshot", "(0..65535)" },
{ 'd', "dump",      Opt::OPTIONAL, "INTERFACE-tcp-PORT-SNAPLEN.dmp", "dump packets to file", "PATH" },
{ 'h', "help",      Opt::NO,       "false", "show this information" },
};

struct Data
{
    int value;
};

int main(int argc, char **argv) try
{
    CmdlineParser<CLI> params;



    typedef NST::auxiliary::Queue<Data> Queue;
    
    Queue queue(10, 1);
    
    for(unsigned int i=0; i<42; i++)
    {
        Data* data = queue.allocate();
        if(data == NULL) break;

        data->value = i;

        queue.push(data);
    }

    Queue::List list = queue.pop_list();

    while(list)
    {
        Data* i = list.get();
        std::cout << i->value << std::endl;
        queue.deallocate(i);
    }

    return 0;

    try
    {
        params.parse(argc, argv);
    }
    catch(CLIError e)  // invalid cmd-line arguments
    {
        std::cerr << e.what() << std::endl;
        CmdlineParser<CLI>::print_usage(std::cerr, argv[0]);
        exit(-1);
    }

    if(params[CLI::HELP].to_bool())
    {
        CmdlineParser<CLI>::print_usage(std::cerr, argv[0]);
        return 0;
    }

    std::string iface       = params[CLI::INTERFACE];
    std::string port        = params[CLI::PORT];
    std::string snaplen_str = params[CLI::SNAPLEN];
    unsigned short snaplen  = params[CLI::SNAPLEN].to_int();
    std::string filter      = "tcp port " + port;

    std::cout << pcap_lib_version() << std::endl;

    const std::string dump_path = params.is_default(CLI::DUMP) ?
                        iface+"-tcp-"+port+"-snaplen-"+snaplen_str+".dmp" :
                        params[CLI::DUMP];

    std::cout << "Starting NFS packets capture on " << iface
              << " filtration by BPF: \"" << filter << '\"'
              << " snaplen: " << snaplen << std::endl;

    PacketCapture capture(iface, filter, snaplen, 32);
    g_capture = &capture;

    // setting SIGINT and SIGTERM handlers
    if(add_signal_handler(SIGINT, cleanup) < 0)
    {
        perror("sigaction");
        exit(-1);
    }
    if(add_signal_handler(SIGTERM, cleanup) < 0)
    {
        perror("sigaction");
        exit(-1);
    }

    capture.print_datalink(std::cout);

    ReassembleTCPSessions reassembler(dump_path);
    capture.loop(reassembler);

    capture.print_statistic(std::cout);

    return 0;
}
catch(Exception& e)
{
    std::cerr << e.what() << std::endl;
}
catch(...)
{
    std::cout << "unknown error" << std::endl;
    exit(-1);
}
//------------------------------------------------------------------------------
