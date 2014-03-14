//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Handling signals and map them to exceptions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <functional>   // std::ref

#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <string.h> // for strsignal()

#include <sys/wait.h>

#include "controller/signal_handler.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

SignalHandler::Signal::Signal(int sig) : std::runtime_error(::strsignal(sig))
{
}

static void dummy(int) {}

static void handle_signals(const sigset_t /*mask*/, std::atomic_flag& running, RunningStatus& status)
{
    while(running.test_and_set())
    {
        int signo = 0;
        ::sigwait(&mask, &signo);  // synchronously wait signals

        if(signo == SIGCHLD)
        {
            // wait childern(compression in dumping mode may call fork())
            ::wait(NULL);
        }
        else
        {
            status.push(SignalHandler::Signal(signo));
        }
    }
}

SignalHandler::SignalHandler(RunningStatus& s)
: handler{}
, running{ATOMIC_FLAG_INIT} // false
{
    // set dummy handler for SIGCHLD to prevent ignoring it on FreeBSD
    struct sigaction chld;
    memset(&chld, 0, sizeof(chld));
    chld.sa_handler = dummy;
    ::sigaction(SIGCHLD, &chld, NULL);

    sigset_t mask;
    ::sigemptyset(&mask);
    ::sigaddset(&mask, SIGINT);  // correct exit from program by Ctrl-C
    ::sigaddset(&mask, SIGCHLD); // stop sigwait-thread and wait children
    ::pthread_sigmask(SIG_BLOCK, &mask, NULL);

    running.test_and_set();
    handler = std::thread{handle_signals, mask, std::ref(running), std::ref(s)};
}
SignalHandler::~SignalHandler()
{
    running.clear();
    // send signal to stop handler thread execution via unblock sigwait()
    ::pthread_kill(handler.native_handle(), SIGCHLD);
    handler.join();
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------

