#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <sys/types.h>
#include <signal.h>
#include <string.h>
#include <iostream>
#include <cassert>

#include "tcp_ip_headers.h"

static const char *default_interface = "em1";
static const char *default_port = "2049";

#define SNAPLEN 300

/* pcap device and dumper handlers */
pcap_t* pcapdev = NULL;
//pcap_dumper_t *pcapdump = NULL;

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
	if(ntohs(ehdr->h_proto) != ETH_P_IP)
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
	struct sunrpc_msg *rpcp = (sunrpc_msg*)packet;
	
	/* make sure that we have the critical parts of the call header */
	if(packetlen < (8 + 16))
		return 0;
	uint32_t rpcvers = ntohl(rpcp->rm_call.cb_rpcvers);
	uint32_t prog = ntohl(rpcp->rm_call.cb_prog);
	uint32_t vers = ntohl(rpcp->rm_call.cb_vers);
	uint32_t proc = ntohl(rpcp->rm_call.cb_proc);
	
	if(rpcvers != 2)
		return 0;
	if (prog != 100003)
		return 0;
	if (vers != 3)
	    return 0;
	
	return packetlen;
}

void process_sunrpc_packet(const sunrpc_msg *packet)
{
	/* here all logic of rpc and nfs packets processing should be placed */
	std::cout << "rpc nfs packet captured" << std::endl;
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
	
	process_sunrpc_packet((const sunrpc_msg*)(packet + (len - sunrpclen)));
}

int main(int argc, char **argv)
{
	char *iface = NULL; 
	char *port = NULL;
	
	/* very simple command line args parsing */
	if(argc == 2)
	{
		iface = argv[1];
		port = (char*)default_port;
	}
	else if(argc == 3)
	{
		iface = argv[1];
		port = argv[2];
	}
	else
	{
		iface = (char*)default_interface;
		port = (char*)default_port;
	}
	
	char pcaperrbuf[PCAP_ERRBUF_SIZE];
	
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
	struct bpf_program bpffilter;
	char filter[20] = "tcp port ";
	strcat(filter, port);
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
    
    std::cout << "Starting nfs packets capture on " << iface << ", port " << port << std::endl;
    
    /* starting sniffing loop */
    if(pcap_loop(pcapdev, 0, nfscallback, NULL) == -1)
    {
		pcap_error_trace("pcap_loop", pcap_geterr(pcapdev));
		exit(-1);
	}
    
    pcap_close(pcapdev);
	return 0;
}
