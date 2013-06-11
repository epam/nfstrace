//------------------------------------------------------------------------------
// Author: Dzianis Huznou
// Description: Design for handling all signals from user.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SYNCHRONOUS_SIGNAL_HANDLING_H
#define SYNCHRONOUS_SIGNAL_HANDLING_H
//------------------------------------------------------------------------------
#include <sstream>

#include <unistd.h>

#include "../auxiliary/thread.h"
#include "../auxiliary/exception.h"
#include "../controller/running_status.h"
//------------------------------------------------------------------------------
using NST::auxiliary::Thread;
using NST::auxiliary::Exception;
using NST::controller::RunningStatus;
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

/*
 * Handle all signals passed to the application.
 */
class SynchronousSignalHandling : public Thread
{
public:
    SynchronousSignalHandling(RunningStatus &running_status) : excpts_holder(running_status)
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
        sigaddset(&mask, SIGUSR2);

        int signo = 0;
        Exception* exception = NULL;

        while(true)
        {
            // Synchronously wait of the signals
            sigwait(&mask, &signo);

            if (signo == SIGUSR2)
            {
                return NULL;
            }
            std::stringstream msg;
            msg << "got signal: " << signo;
            exception = new Exception(msg.str());
            excpts_holder.push(exception);
        }
        return NULL;
    }

    virtual void stop()
    {
        // Send signal ourself to stop thread execution via unblock sigwait()
        kill(getpid(), SIGUSR2);
    }

private:
    sigset_t mask;
    RunningStatus& excpts_holder;
};

} // namespace filter
} // namespace NST
//------------------------------------------------------------------------------
#endif //SYNCHRONOUS_SIGNAL_HANDLING_H
//------------------------------------------------------------------------------

