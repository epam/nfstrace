//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Counting detected NFS headers and discarded TCP packets.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include <pcap/pcap.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include <iomanip>

#include "headers.h"
#include "../../src/auxiliary/spinlock.h"
#include "../../src/controller/cmdline_parser.h"
#include "../../src/filter/pcap/pcap_error.h"
#include "../../src/filter/pcap/capture_reader.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Spinlock;
using NST::filter::pcap::PcapError;
using NST::filter::pcap::BaseReader;
using NST::filter::pcap::CaptureReader;
//------------------------------------------------------------------------------
#define SLEEP_INTERVAL 5

CaptureReader* g_capture = NULL;  // used in signal handler
//------------------------------------------------------------------------------
struct ProcNFS3 // counters definition for NFS v3 procedures. See: RFC 1813
{
    enum Counters {
        NFS_NULL        = 0,
        NFS_GETATTR     = 1,
        NFS_SETATTR     = 2,
        NFS_LOOKUP      = 3,
        NFS_ACCESS      = 4,
        NFS_READLINK    = 5,
        NFS_READ        = 6,
        NFS_WRITE       = 7,
        NFS_CREATE      = 8,
        NFS_MKDIR       = 9,
        NFS_SYMLINK     = 10,
        NFS_MKNOD       = 11,
        NFS_REMOVE      = 12,
        NFS_RMDIR       = 13,
        NFS_RENAME      = 14,
        NFS_LINK        = 15,
        NFS_READDIR     = 16,
        NFS_READDIRPLUS = 17,
        NFS_FSSTAT      = 18,
        NFS_FSINFO      = 19,
        NFS_PATHCONF    = 20,
        NFS_COMMIT      = 21,
        num             = 22,
    };

    static const char* titles[num];
};

const char* ProcNFS3::titles[ProcNFS3::num] = {
      "null",       "getattr",      "setattr",  "lookup",
      "access",     "readlink",     "read",     "write",
      "create",     "mkdir",        "symlink",  "mknod",
      "remove",     "rmdir",        "rename",   "link",
      "readdir",    "readdirplus",  "fsstat",   "fsinfo",
      "pathconf",   "commit",
  };


struct Discard // counters definition for discarded packets
{
    enum Counters
    {
        ETH = 0,
        IP  = 1,
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
            out << std::setw(16) << T::titles[i] << collected[i] << std::endl;
        }
        out << "total: " << total << std::endl;
    }

    inline void inc(typename T::Counters id){ ++accumulators[id]; }

private:
    uint64_t accumulators[T::num];
    uint64_t collected   [T::num];
};
//------------------------------------------------------------------------------
class CountProcessor  // Identify and count packets (accepted and discarded)
{
public:
    CountProcessor(unsigned int workload_sleep):workload_tid(0), sleep_secs(workload_sleep)
    {
        pthread_create(&workload_tid, NULL, workload_thread, this);
    }
    ~CountProcessor()
    {
        void *res;
        pthread_cancel(workload_tid);
        pthread_join(workload_tid, &res);
    }

private:
    friend class BaseReader;

    // thread for printing counters
    static void* workload_thread(void *arg)
    {
        CountProcessor& counter = *(CountProcessor*)arg;
        // blocking signals in this thread so the main thread handles them
        sigset_t sset;
        sigemptyset(&sset);
        sigaddset(&sset, SIGINT);
        sigaddset(&sset, SIGTERM);
        pthread_sigmask(SIG_BLOCK, &sset, NULL);
        while(1)
        {
            {
                Spinlock::Lock lock(counter.spinlock);
                    counter.nfsproc.collect();
                    counter.discard.collect();
            }

            std::cout << setiosflags(std::ios::left);

            counter.nfsproc.print(std::cout);
            counter.discard.print(std::cout);

            std::cout << std::endl << std::endl;
            std::cout << resetiosflags(std::ios::right);

            sleep(counter.sleep_secs); // cancellation point
        }
        return NULL;
    }

    u_char* get_user()
    {
        return (u_char*)this;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        CountProcessor& processor = *(CountProcessor*)user;

        uint32_t len = pkthdr->len;
        uint32_t iplen = processor.validate_eth_frame(len, packet);
        if(!iplen)
        {
            processor.discard.inc(Discard::ETH);
            return;
        }

        uint32_t tcplen = processor.validate_ip_packet(iplen, packet + (len - iplen));
        if(!tcplen)
        {
            processor.discard.inc(Discard::IP);
            return;
        }

        uint32_t sunrpclen = processor.validate_tcp_packet(tcplen, packet + (len - tcplen));
        if(!sunrpclen)
        {
            processor.discard.inc(Discard::TCP);
            return;
        }

        uint32_t authlen = processor.validate_sunrpc_packet(sunrpclen, packet + (len - sunrpclen));
        if(!authlen)
        {
            processor.discard.inc(Discard::RPC);
            return;
        }

        processor.process_sunrpc_packet((const sunrpc_msg*)(packet + (len - sunrpclen)));
    }


    // validation methods return packet length without header they validate or 0 on error
    uint32_t validate_eth_frame(uint32_t framelen, const u_char *packet)
    {
        ethhdr *ehdr = (ethhdr*)packet;
        if(ntohs(ehdr->ether_type) != ETH_P_IP)
            return 0;
        return framelen - sizeof(ethhdr) > 0 ? framelen - sizeof(ethhdr) : 0;
    }

    uint32_t validate_ip_packet(uint32_t packetlen, const u_char *packet)
    {
        struct nfstrace_ip *ippacket = (nfstrace_ip*)packet;
        uint32_t iphdrlen = IP_HL(ippacket) * 4;
        if(ippacket->ip_p != 6)
            return 0;
        return packetlen - iphdrlen > 0 ? packetlen - iphdrlen : 0;
    }

    uint32_t validate_tcp_packet(uint32_t packetlen, const u_char *packet)
    {
        struct nfstrace_tcp *tcppacket = (nfstrace_tcp*)packet;
        uint32_t tcphdrlen = TH_OFF(tcppacket) * 4;
        tcphdrlen += 4;
        return packetlen - tcphdrlen > 0 ? packetlen - tcphdrlen : 0;
    }

    uint32_t validate_sunrpc_packet(uint32_t packetlen, const u_char *packet)
    {
        if (packetlen < 8)
            return 0;

        struct sunrpc_msg *rpcp = (sunrpc_msg*)packet;

        uint32_t rpc_msg_type = ntohl(rpcp->rm_direction);

        if (rpc_msg_type == SUNRPC_REPLY) {
            packetlen -= 8;
            uint32_t rpc_reply_stat = ntohl(rpcp->rm_reply.rp_stat);
            if (rpc_reply_stat == 0) {
                if (packetlen < 4) {
                    //std :: cout << "failed 1" << std::endl;
                    return 0;
                }
                return packetlen - 4;
            }
            else {
                uint32_t size = 4 + sizeof(sunrpc_reject_stat);
                if (packetlen < size) {
                    //std :: cout << "failed 2" << std::endl;
                    return 0;
                }
                return packetlen - size;
            }
        }

        /* make sure that we have the critical parts of the call header */
        uint32_t size = 8 + 16;
        if(packetlen < size) {
            //std :: cout << "failed 3" << std::endl;
            return 0;
        }
        packetlen -= size;

        uint32_t rpcvers = ntohl(rpcp->rm_call.cb_rpcvers);
        uint32_t prog = ntohl(rpcp->rm_call.cb_prog);
        uint32_t vers = ntohl(rpcp->rm_call.cb_vers);
        //uint32_t proc = ntohl(rpcp->rm_call.cb_proc);

        if(rpcvers != 2){
            //std::cout << "failed 4 with rpc vers " << rpcvers << std::endl;
            return 0;
        }
        if (prog != 100003){
            //std :: cout << "failed 5 wirh prog " << prog << std::endl;
            return 0;
        }
        if (vers != 3){
            //std :: cout << "failed 6 with nfs vers " << vers << std::endl;
            return 0;
        }

        /*
        size = sizeof(sunrpc_opaque_auth) + (rpcp->rm_call.cb_cred.oa_len);
        if (rpcp->rm_call.cb_cred.oa_len % sizeof(uint32_t))
            size += (4 - (rpcp->rm_call.cb_cred.oa_len % sizeof(uint32_t)));
        if (packetlen < size)
            return 0;
        packetlen -= size;
        */

        return packetlen;
    }

    void process_sunrpc_packet(const struct sunrpc_msg *packet)
    {
        /* here all logic of rpc and nfs packets processing should be placed */
        // skip replies
        uint32_t rpc_msg_type = ntohl(packet->rm_direction);
        if (rpc_msg_type == SUNRPC_REPLY)
        {
            discard.inc(Discard::NFS);
            return;
        }

        uint32_t proc = ntohl(packet->rm_call.cb_proc);

        Spinlock::Lock lock(spinlock);
        nfsproc.inc((ProcNFS3::Counters) proc);
    }

public:
    Counters<ProcNFS3> nfsproc;
    Counters<Discard>  discard;

    Spinlock spinlock;

    pthread_t workload_tid;
    const unsigned int sleep_secs;
};
//------------------------------------------------------------------------------
class DumpToFileProcessor
{
public:
    DumpToFileProcessor(const std::string& path, pcap_t* handle): dumper(NULL)
    {
        dumper = pcap_dump_open(handle, path.c_str());
        if(NULL == dumper)
        {
            throw PcapError("pcap_dump_open", pcap_geterr(handle));
        }
    }
    ~DumpToFileProcessor()
    {
        pcap_dump_flush(dumper);
        pcap_dump_close(dumper);
    }

private:
    friend class BaseReader;

    u_char* get_user()
    {
        return (u_char*)dumper;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        pcap_dumper_t* dumper = (pcap_dumper_t*) user;

        pcap_dump((u_char*)dumper, pkthdr, packet);
    }

    pcap_dumper_t* dumper;
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
{ 'i', "interface", Opt::REQ,  NULL,   "interface for capturing", "INTERFACE" },
{ 'p', "port",      Opt::REQ, "2049",  "NFS filtration port", "PORT" },
{ 's', "snaplen",   Opt::REQ, "512",   "length of packet snapshot", "(0..65535)" },
{ 'd', "dump",      Opt::OPT, "INTERFACE-tcp-PORT-SNAPLEN.dmp", "dump packets to file", "PATH" },
{ 'h', "help",      Opt::NOA, "false", "show this information" },
};

int main(int argc, char **argv) try
{
    CmdlineParser<CLI> params;

    try
    {
        params.parse(argc, argv);
        if(params[CLI::HELP].to_bool())
        {
            CmdlineParser<CLI>::print_usage(std::cerr, argv[0]);
            return 0;
        }
        params.validate();
    }
    catch(CLIError e)  // invalid cmd-line arguments
    {
        std::cerr << e.what() << std::endl;
        CmdlineParser<CLI>::print_usage(std::cerr, argv[0]);
        exit(-1);
    }

    std::string iface       = params[CLI::INTERFACE];
    std::string port        = params[CLI::PORT];
    std::string snaplen_str = params[CLI::SNAPLEN];
    unsigned short snaplen  = params[CLI::SNAPLEN].to_int();

    std::cout << pcap_lib_version() << std::endl;

    std::string filter = "any";
    if(!port.empty())
    {
        filter = "tcp port " + port;
    }

    std::cout << "Starting NFS packets capture on " << iface
              << " filtration by BPF: \"" << filter << '\"'
              << " snaplen: " << snaplen << std::endl;

    CaptureReader capture(iface, filter, snaplen, 32, 2);
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

    std::cout << CaptureReader::datalink_name(capture.datalink());

    if(params.is_passed(CLI::DUMP))
    {
        const std::string path = params.is_default(CLI::DUMP) ?
                            iface+"-tcp-"+port+"-snaplen-"+snaplen_str+".dmp" :
                            params[CLI::DUMP];
        DumpToFileProcessor dumper(path, capture.get_handle());
        capture.loop(dumper);
    }
    else
    {
        CountProcessor counter(SLEEP_INTERVAL);
        capture.loop(counter);
    }

    capture.print_statistic(std::cout);

    return 0;
}
catch(std::exception& e)
{
    std::cerr << e.what() << std::endl;
    throw;
}
catch(...)
{
    std::cerr << "unknown error" << std::endl;
    exit(-1);
}
//------------------------------------------------------------------------------
