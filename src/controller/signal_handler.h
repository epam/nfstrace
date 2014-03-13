//------------------------------------------------------------------------------
// Author: Pavel Karneliuk
// Description: Handling signals and map them to exceptions.
// Copyright (c) 2013 EPAM Systems. All Rights Reserved.
//------------------------------------------------------------------------------
#ifndef SIGNAL_HANDLER_H
#define SIGNAL_HANDLER_H
//------------------------------------------------------------------------------
#include <atomic>
#include <stdexcept>
#include <thread>

#include "controller/running_status.h"
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
namespace NST
{
namespace controller
{

class SignalHandler
{
public:
    class Signal : public std::runtime_error
    {
    public:
        explicit Signal(int sig);
    };

    SignalHandler(RunningStatus& s);
    SignalHandler(const SignalHandler&)            = delete;
    SignalHandler& operator=(const SignalHandler&) = delete;
    ~SignalHandler();

private:
    std::thread handler;
    std::atomic_flag running;
};

} // namespace controller
} // namespace NST
//------------------------------------------------------------------------------
#endif//SIGNAL_HANDLER_H
//------------------------------------------------------------------------------

