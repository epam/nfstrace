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

static void handle_signals(RunningStatus& status)
{
    sigset_t mask;
    ::sigfillset(&mask);
    ::pthread_sigmask(SIG_BLOCK, &mask, NULL);

    ::sigemptyset(&mask);
    ::sigaddset(&mask, SIGINT);
    ::sigaddset(&mask, SIGQUIT);
    ::sigaddset(&mask, SIGCHLD);
    ::sigaddset(&mask, SIGUSR2);

    int signo = 0;

    while(true)
    {
        ::sigwait(&mask, &signo);   // synchronously wait of the signals

        if(signo == SIGCHLD)
        {
            ::wait(NULL);
            continue;
        }

        if(signo == SIGUSR2)
        {
            ::wait(NULL);
            return;
        }
        status.push(SignalHandler::Signal(signo));
    }
}

SignalHandler::SignalHandler(RunningStatus& s) : handler(handle_signals, std::ref(s))
{
    sigset_t mask;
    ::sigfillset(&mask);
    ::pthread_sigmask(SIG_BLOCK, &mask, NULL);
}
SignalHandler::~SignalHandler()
{
    // send signal ourself to stop thread execution via unblock sigwait()
    ::kill(::getpid(), SIGUSR2);
    handler.join();
}

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------

