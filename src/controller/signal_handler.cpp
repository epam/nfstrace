//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Handling signals and map them to exceptions.
// Copyright (c) 2013 EPAM Systems
//------------------------------------------------------------------------------
/*
    This file is part of Nfstrace.

    Nfstrace is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, version 2 of the License.

    Nfstrace is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Nfstrace.  If not, see <http://www.gnu.org/licenses/>.
*/
//------------------------------------------------------------------------------
#include <cerrno>
#include <functional>   // std::ref
#include <system_error>

#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>     // for strsignal()

#include <sys/wait.h>

#include "controller/signal_handler.h"
#include "utils/log.h"
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

SignalHandler::Signal::Signal(int sig) : std::runtime_error{::strsignal(sig)}
{
}

// synchronously wait signals and pass them to RunningStatus as an exception
static void handle_signals(const sigset_t    waitmask,
                           std::atomic_flag& running,
                           RunningStatus&    status)
{
    while(running.test_and_set())
    {
        int signo {0};
        const int err {::sigwait(&waitmask, &signo)};
        if(err != 0)
        {
            status.push(std::system_error{err, std::system_category(),
                                          "error in SignalHandler sigwait"});
            return;
        }

        if(signo == SIGCHLD)
        {
            // wait childern(compression in dumping mode may call fork())
            const pid_t pid {::wait(nullptr)};
            if(pid == -1 && errno != ECHILD)
            {
                status.push(std::system_error{errno, std::system_category(),
                                              "error in SignalHandler wait"});
            }
        }
        else if(signo == SIGINT)
        {
            status.push(ProcessingDone{"Interrupted by user."});
        }
        else if(signo == SIGHUP)
        {
            NST::utils::Log log;
            log.reopen();
        }
        else
        {
            status.push(SignalHandler::Signal{signo});
        }
    }
}

static void dummy(int) {}

SignalHandler::SignalHandler(RunningStatus& s)
: handler{}
, running{ATOMIC_FLAG_INIT} // false
{
    // set dummy handler for SIGCHLD to prevent ignoring it
    // in ::sigwait() on FreeBSD by default
    struct sigaction chld;
    memset(&chld, 0, sizeof(chld));
    chld.sa_handler = dummy;
    if(::sigaction(SIGCHLD, &chld, nullptr) != 0)
    {
        throw std::system_error(errno, std::system_category(),
                                "error in SignalHandler sigaction");
    }

    sigset_t mask;
    ::sigemptyset(&mask);
    ::sigaddset(&mask, SIGINT);  // correct exit from program by Ctrl-C
    ::sigaddset(&mask, SIGCHLD); // stop sigwait-thread and wait children
    ::sigaddset(&mask, SIGHUP);  // signal for losing terminal
    const int err = ::pthread_sigmask(SIG_BLOCK, &mask, nullptr);
    if(err != 0)
    {
        throw std::system_error(err, std::system_category(),
                               "error in SignalHandler pthread_sigmask");
    }

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

