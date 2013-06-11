#include "auxiliary/thread.h"
#include "filter/filtration_manager.h"

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

using NST::filter::FiltrationManager;

FiltrationManager* g_manager = NULL;  // used in signal handler
volatile bool g_exec_flag = true;
int count = 0;

void cleanup(int signo)
{
    if(g_manager)
    {
        g_manager->stop();
    }

    if(signo == SIGINT)
        std::cout << "SIGINT" << std::endl;
    if(signo == SIGTERM)
        std::cout << "SIGTERM" << std::endl;
    g_exec_flag = false;
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

int main(int argc, char **argv)
{
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
    FiltrationManager manager; 
    g_manager = &manager;
    manager.dump_to_file(std::string("em1"), std::string("tcp port 80"), 512, 0, std::string("my.txt"));
    manager.start();
    while(g_exec_flag);
    return true;
}
