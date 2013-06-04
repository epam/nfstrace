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
#include "../../src/auxiliary/spinlock.h"
#include "../../src/filter/common/pcap_error.h"
#include "../../src/filter/common/packet_capture.h"
#include "../../src/filter/common/packet_reader.h"
#include "../../src/filter/common/i_packet_reader.h"
#include <ostream>

using NST::auxiliary::Spinlock;
using NST::filter::PcapError;
using NST::filter::pcap::PacketCapture;
using NST::filter::pcap::PacketReader;
using NST::filter::pcap::IPacketReader;

class PrintProcessor
{
public:
    PrintProcessor(std::ostream &out): stream(out) {}
    ~PrintProcessor() {}

private:
    friend class IPacketReader;

    void before_callback(pcap_t* handle) {}
    void after_callback(pcap_t* handle) {}

    u_char* get_user()
    {
        return (u_char*)this;
    }

    static void callback(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char* packet)
    {
        static int i = 0;
        ((PrintProcessor*)user)->stream << i++ << " " << pkthdr->caplen << " " << packet << "???" << std::endl;
    }

    std::ostream& stream;
};

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

PacketCapture* g_capture = NULL;  // used in signal handler
PacketReader* g_reader = NULL;  // used in signal handler

void cleanup(int signo)
{
    if(g_capture)
    {
        g_capture->break_loop();
    }

    std::cout << "stopped by signal " << signo << std::endl;
}

int main(int argc, char **argv) try
{
    std::string file("test.dmp");
    
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

    PacketReader reader(file, std::string("any"));

    g_reader = &reader;
    PrintProcessor printer(std::cout);
    reader.loop(printer);

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

