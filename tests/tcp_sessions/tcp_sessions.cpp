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

#include "../../src/auxiliary/spinlock.h"
#include "../../src/controller/cmdline_parser.h"
#include "../../src/filter/common/pcap_error.h"
#include "../../src/filter/common/packet_capture.h"
#include "../../src/filter/common/packet_dumper.h"
#include "../../src/filter/ethernet/ethernet_header.h"
#include "../../src/filter/ip/ipv4_header.h"
#include "../../src/filter/tcp/tcp_header.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Spinlock;
using NST::filter::PcapError;
using NST::filter::PacketCapture;
using NST::filter::PacketDumper;
using NST::filter::ethernet::ethernet_header;
using NST::filter::ip::ipv4_header;
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
        num,
    };
    static const char* titles[num];
};

const char* Packet::titles[Packet::num]={ "UNKNOWN", "Ethernet", "IPv4", "IPv6", "TCP", "UDP" };


void print_ipv4(std::ostream& out, uint32_t ip /*host byte order*/ )
{
    out << ((ip >> 24) & 0xFF);
    out << '.';
    out << ((ip >> 16) & 0xFF);
    out << '.';
    out << ((ip >> 8) & 0xFF);
    out << '.';
    out << ((ip >> 0) & 0xFF);
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

// Represents conversation between node A and node B
template
<
    typename Data,              // the Data of Session
    typename Address=uint32_t,
    typename Port=uint16_t
>
struct Session
{
    struct ID
    {
        inline ID(const Address& a, const Address& b, const Port& pa, const Port& pb):addrA(a), addrB(b), portA(pa), portB(pb){}

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
            // map the A -> B and A <- B to the same Session
            if( addrA == a.addrA &&
                addrB == a.addrB &&
                portA == a.portA &&
                portB == a.portB)
            {
                return true;
            }

            if( addrA == a.addrB &&
                addrB == a.addrA &&
                portA == a.portB &&
                portB == a.portA)
            {
                return true;
            }
            return false;
        }

        Address addrA;
        Address addrB;
        Port    portA;
        Port    portB;
    };

    Data data;
};

struct TCPStreams
{
    uint32_t num;
};

typedef Session<TCPStreams> TCPSession;

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
    typedef StreamMap::iterator it;
    typedef StreamMap::const_iterator cit;
public:
    TCPSessions()
    {
    }

    ~TCPSessions()
    {
    }
    
    void add(uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport)
    {
        key_type key(src, dst, sport, dport);
        it i = find(key);
        if(i == end())
        {
            std::cout << "add session" << std::endl;
            i = insert( StreamMap::value_type(key, TCPSession() )).first;
        }

        i->second.data.num++;
    }

    void print(std::ostream& out) const
    {
       for(cit i = begin(); i != end(); ++i)
        {
            print_ipv4(std::cout, i->first.addrA);
            std::cout << " -> ";
            print_ipv4(std::cout, i->first.addrB);
            std::cout << " packets: " << i->second.data.num << std::endl;
        }
    }

};



class ReassembleTCPSessions
{
public:
    ReassembleTCPSessions(const std::string& path):file(path), workload_tid(0), datalink(Packet::UNKNOWN), captured_size(0), invalid(0)
    {
    }
    ~ReassembleTCPSessions()
    {
    }

private:
    friend class PacketCapture;

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

            std::cout << "\rdumped: " << p.captured_size << " invalid: " << p.invalid;
            std::cout.flush();

            sleep(5); // cancellation point
        }
        return NULL;
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
        unknown.reset(new PacketDumper(handle, "unknown.dmp"));
        captured_size = 0;
        invalid = 0;

        // start thread
        pthread_create(&workload_tid, NULL, workload_thread, this);
    }

    void after_callback(pcap_t* handle)
    {
        // join thread
        void *res;
        pthread_cancel(workload_tid);
        pthread_join(workload_tid, &res);

        sessions.print(std::cout);
        discard.collect();
        discard.print(std::cout);

        // reset processing
        unknown.release();
        packets.release();
    }

    u_char* get_user()
    {
        return (u_char*)this;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        ReassembleTCPSessions& p = *(ReassembleTCPSessions*) user;

        pcap_pkthdr header = *pkthdr;
        // dump everything
        p.packets->dump(pkthdr, packet);
        p.captured_size += pkthdr->caplen;

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
        
        p.sessions.add(ip->src(), ip->dst(), tcp->sport(), tcp->dport());

        p.invalid += size;
        header.caplen = size;
        //p.unknown->dump(&header, data);

    }

    std::string file;
    std::auto_ptr<PacketDumper> packets;
    std::auto_ptr<PacketDumper> unknown; // unknown packets
    pthread_t workload_tid;
    Packet::Type datalink;

    TCPSessions sessions;

    Counters<Packet> discard;

    uint64_t captured_size;
    uint32_t invalid;
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

int main(int argc, char **argv) try
{
    CmdlineParser<CLI> params;

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

    if(iface.empty())
    {
        iface = PacketCapture::get_default_device();
        std::cout << "use default device:" << iface << std::endl;
    }

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
