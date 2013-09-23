//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Handling signals to the application an to map the to exceptions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SYNCHRONOUS_SIGNAL_HANDLING_H
#define SYNCHRONOUS_SIGNAL_HANDLING_H
//------------------------------------------------------------------------------
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <string.h> // for strsignal()

#include <sys/wait.h>

#include "../auxiliary/logger.h"
#include "../auxiliary/exception.h"
#include "../auxiliary/thread.h"
#include "running_status.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Exception;
using NST::auxiliary::Thread;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class SynchronousSignalHandling : public Thread
{
public:

    class Signal : public Exception
    {
    public:
        explicit Signal(int sig) : Exception(std::string("signal: ") + strsignal(sig)) { }

        virtual const Signal* dynamic_clone() const { return new Signal(*this); }
        virtual void          dynamic_throw() const { throw *this; }
    };

    SynchronousSignalHandling(RunningStatus &s) : status(s)
    {
        sigfillset(&mask);
        pthread_sigmask(SIG_BLOCK, &mask, NULL);
    }
    ~SynchronousSignalHandling()
    {
    }

    virtual void* run()
    {
        sigemptyset(&mask);
        sigaddset(&mask, SIGINT);
        sigaddset(&mask, SIGQUIT);
        sigaddset(&mask, SIGCHLD);
        sigaddset(&mask, SIGUSR2);

        int signo = 0;

        while(true)
        {
            // Synchronously wait of the signals
            sigwait(&mask, &signo);

            if (signo == SIGCHLD)
            {
                wait(NULL);
                continue;
            }

            if (signo == SIGUSR2)
            {
                wait(NULL);
                return NULL;
            }
            status.push(Signal(signo));
        }
        return NULL;
    }

    virtual void stop()
    {
        // Send signal ourself to stop thread execution via unblock sigwait()
        kill(getpid(), SIGUSR2);
    }

private:
    SynchronousSignalHandling(const SynchronousSignalHandling&);            // undefined
    SynchronousSignalHandling& operator=(const SynchronousSignalHandling&); // undefined

    sigset_t mask;
    RunningStatus& status;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif //SYNCHRONOUS_SIGNAL_HANDLING_H
//------------------------------------------------------------------------------

