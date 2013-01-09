#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <iostream>
#include <iomanip>
#include <cassert>
#include <pthread.h>
#include <unistd.h>

#include "nfs.h"
#include "tcp_ip_headers.h"

static const char *default_interface = "em1";
static const char *default_port = "2049";
// the last is for # of operations
static uint32_t nfs3_op_stat[NFSPROC3_NOOP + 1] = {0};

#define SNAPLEN 300
#define DEFAULT_SLEEP_INTERVAL 5

/* pcap device handler */
static pcap_t* pcapdev = NULL;

/* output thread id */
static pthread_t tid = 0;
static pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

const char *proc_names[] = {
  "null", "getattr", "setattr", "lookup",
  "access", "readlink", "read", "write",
  "create", "mkdir", "symlink", "mknod",
  "remove", "rmdir", "rename", "link",
  "readdir", "readdirplus", "fsstat", "fsinfo",
  "pathconf", "commit", "noop", };

void print_proc_names (const char **proc_names, int beg, int width, int noop)
{
    for (int i = 0; beg < noop && i < width; ++beg, ++i) {
        std::cout << std::setw(11) << proc_names[beg] << std::setw(6);
        beg < width ? std::cout << "%" : std::cout << " ";
    }
    std::cout << std::endl;
}

void* workload_thread(void *arg)
{
    /* blocking signals in this thread so the main thread handles them */
    sigset_t sset;
    sigemptyset(&sset);
    sigaddset(&sset, SIGINT);
    sigaddset(&sset, SIGTERM);
    pthread_sigmask(SIG_BLOCK, &sset, NULL);

    uint32_t overall[NFSPROC3_NOOP + 1] = {};        //local storage for stats
    float prct = 0;
    while(1)
    {
        pthread_mutex_lock(&mut);
        for(int i = 0; i < NFSPROC3_NOOP + 1; ++i)
        {
            overall[i] += nfs3_op_stat[i];
            nfs3_op_stat[i] = 0;
        }
        pthread_mutex_unlock(&mut);

        //processing here
        std::cout << setiosflags(std::ios::left);
        bool is_proc_names = true;
        for (int i = 0; i < NFSPROC3_NOOP; ++i) {
            if (is_proc_names) {
                print_proc_names ( proc_names, i, 6, NFSPROC3_NOOP);
                is_proc_names = false;
            }
            if (!overall[NFSPROC3_NOOP])
                prct = 0;
            else
                prct = ( (float) overall[i]/overall[NFSPROC3_NOOP]) * 100;
            std::cout << std::setw(11) << overall[i] << std::setprecision(2) 
                << std::setw(6) << prct ;

            if ( (i + 1) % 6 == 0) {
                is_proc_names = true;
                std::cout << std::endl;
            }
        }
        std::cout << std::endl << std::endl;
        std::cout << resetiosflags(std::ios::right);
        sleep(5);
    }
    return NULL;
}

static void pcap_error_trace(const char *function, const char *descr)
{
    assert(function);

    std::cerr << "pcap_error " << function;
    if(descr)
        std::cerr << " " << descr;
    std::cerr << std::endl;
}

void cleanup(int signo)
{
    struct pcap_stat stat;

    /* Can't print the summary if reading from a savefile */
    if(pcapdev && !pcap_file(pcapdev))
    {
        std::cout.flush();
        if(pcap_stats(pcapdev, &stat) < 0)
            pcap_error_trace("pcap_stats", pcap_geterr(pcapdev));
        else
            std::cout << stat.ps_recv << " packets received by filter" << std::endl
                      << stat.ps_drop << " packets dropped by kernel" << std::endl
                      << "stopped by signal " << signo << std::endl;
    }
    pcap_breakloop(pcapdev);
}

int add_signal_handler(int signo, void(*handler)(int))
{
    /* unmask signal */
    sigset_t sset;
    sigemptyset(&sset);
    sigaddset(&sset, signo);
    sigprocmask(SIG_UNBLOCK, &sset, NULL);

    struct sigaction newaction;
    memset(&newaction, 0, sizeof(newaction));
    newaction.sa_handler = handler;

    return sigaction(signo, &newaction, NULL);
}

/* validation methods return packet length without header they validate or 0 on error */

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
    uint32_t proc = ntohl(rpcp->rm_call.cb_proc);

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
        return;

    uint32_t proc = ntohl(packet->rm_call.cb_proc);

    pthread_mutex_lock(&mut);
    ++nfs3_op_stat[NFSPROC3_NOOP];
    ++nfs3_op_stat[proc];
    pthread_mutex_unlock(&mut);
}

void nfscallback(u_char *rock, const struct pcap_pkthdr *pkthdr, const u_char* packet)
{
    uint32_t len = pkthdr->len;

    uint32_t iplen = validate_eth_frame(len, packet);
    if(!iplen)
    {
        std::cerr << "Incorrect ethernet frame, not ip proto next" << std::endl;
        return;
    }

    uint32_t tcplen = validate_ip_packet(iplen, packet + (len - iplen));
    if(!tcplen)
    {
        std::cerr << "Incorrect ip packet" << std::endl;
        return;
    }

    uint32_t sunrpclen = validate_tcp_packet(tcplen, packet + (len - tcplen));
    if(!tcplen)
    {
        std::cerr << "Incorrect tcp packet" << std::endl;
        return;
    }

    uint32_t authlen = validate_sunrpc_packet(sunrpclen, packet + (len - sunrpclen));
    if(!authlen)
    {
        //std::cerr << "Incorrect rpc packet" << std::endl;
        return;
    }

    process_sunrpc_packet((const sunrpc_msg*)(packet + (len - sunrpclen)));
}

int main(int argc, char **argv)
{
    char *iface = NULL;
    char *port = NULL;

    /* very simple command line args parsing */
    int opt = 0;
    int portfound = 0;
    int iffound = 0;
    while ((opt = getopt(argc, argv, "+i:p:h")) != -1)
    {
        switch (opt)
        {
        case 'i':
            iface = (char*)optarg;
            iffound = 1;
            break;
        case 'p':
            port = (char*)optarg;
            portfound = 1;
            break;
        case 'h':
            std::cout << "Usage: " << argv[0] << " [-i interface] [-p port]" << std::endl;
            exit(-1);
        default: /* '?' */
            std::cout << "Usage: " << argv[0] << " [-i interface] [-p port]" << std::endl;
            exit(-1);
        }
    }

    char pcaperrbuf[PCAP_ERRBUF_SIZE] = {};
    
    if(!iffound)
    {
        /* trying to find suitable iface for sniffing using pcap */
        iface = pcap_lookupdev(pcaperrbuf);
        if(!iface)
        {
            pcap_error_trace("pcap_lookupdev", pcaperrbuf);
            exit(-1);
        }
    }

    /* open device for live sniffing */
    pcapdev = pcap_open_live(iface, SNAPLEN, 0, 0, pcaperrbuf);
    if(pcapdev == NULL)
    {
        pcap_error_trace("pcap_open_live", pcaperrbuf);
        exit(-1);
    }

    /* find the IPv4 network number and netmask for a device */
    bpf_u_int32 localnet, netmask;
    if(pcap_lookupnet(iface, &localnet, &netmask, pcaperrbuf) < 0)
    {
        pcap_error_trace("pcap_lookupnet", pcaperrbuf);
        exit(-1);
    }

    /* creating pcap filter */
    struct bpf_program bpffilter = {};
    char filter[20] = "tcp";
    if(port)
    {
		strcat(filter, " port ");
        strcat(filter, port);
	}
    if(pcap_compile(pcapdev, &bpffilter, filter, 1 /* optimize */, netmask) < 0)
    {
        pcap_error_trace("pcap_compile", pcap_geterr(pcapdev));
        exit(-1);
    }

    /* applying pcap fileter */
    if(pcap_setfilter(pcapdev, &bpffilter) < 0)
    {
        pcap_error_trace("pcap_setfilter", pcap_geterr(pcapdev));
        exit(-1);
    }

    /* free bpfprogramm */
    pcap_freecode(&bpffilter);

    /* setting SIGINT and SIGTERM handlers */
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

  	std::cout << "Starting nfs packets capture on " << iface;
  	if(port)
  	   std::cout << ", port " << port;
  	std::cout << std::endl;

    /* starting output thread */
	if(pthread_create(&tid, NULL, workload_thread, NULL))
    {
		perror("pthread_create");
		exit(-1);
	}
    
    /* starting sniffing loop */
    if(pcap_loop(pcapdev, 0, nfscallback, NULL) == -1)
    {
        pcap_error_trace("pcap_loop", pcap_geterr(pcapdev));
        exit(-1);
    }

    pcap_close(pcapdev);
    return 0;
}
