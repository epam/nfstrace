//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Handling signals and map them to exceptions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#include <iostream>
#include <functional>

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

static void handle_signals(std::atomic_flag& running, RunningStatus& status)
{
    sigset_t mask;
    ::sigfillset(&mask);
    ::pthread_sigmask(SIG_BLOCK, &mask, NULL);

    ::sigemptyset(&mask);
    ::sigaddset(&mask, SIGINT);
    ::sigaddset(&mask, SIGQUIT);
    ::sigaddset(&mask, SIGCHLD);

    int signo = 0;

    while(running.test_and_set())
    {
        ::sigwait(&mask, &signo);   // synchronously wait of the signals

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
    sigset_t mask;
    ::sigfillset(&mask);
    ::pthread_sigmask(SIG_BLOCK, &mask, NULL);

    running.test_and_set();
    handler = std::thread{handle_signals, std::ref(running), std::ref(s)};
}
SignalHandler::~SignalHandler()
{
    running.clear();
    // send signal ourself to stop thread execution via unblock sigwait()
    ::kill(::getpid(), SIGCHLD);
    handler.join();
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------

